"""Semantic mapper: maps deterministic validation findings to STRIDE threats.

For each threat in the model, determines:
  - confirmed: a medium/high/critical finding matches this threat's STRIDE category + affected node
  - mitigated: an informational/positive-signal finding shows the control is in place
  - unverifiable: no target was reachable or relevant templates didn't apply
  - not_found: target reachable, templates ran, no findings matched
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import ScanFinding, ScanJob, ScanThreatResult
from app.models.threat import Threat

logger = logging.getLogger("threatgenix.scan_mapper")

# Tool/template tags → STRIDE category
_TAG_TO_STRIDE: dict[str, str] = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information-disclosure": "Information Disclosure",
    "information disclosure": "Information Disclosure",
    "denial-of-service": "Denial of Service",
    "denial of service": "Denial of Service",
    "elevation-of-privilege": "Elevation of Privilege",
    "elevation of privilege": "Elevation of Privilege",
    "sqli": "Tampering",
    "xss": "Tampering",
    "xxe": "Tampering",
    "ssti": "Tampering",
    "injection": "Tampering",
    "ssrf": "Elevation of Privilege",
    "rce": "Elevation of Privilege",
    "lfi": "Elevation of Privilege",
    "rfi": "Elevation of Privilege",
    "open-redirect": "Elevation of Privilege",
    "auth-bypass": "Spoofing",
    "default-login": "Spoofing",
    "jwt": "Spoofing",
    "broken-auth": "Spoofing",
    "idor": "Information Disclosure",
    "exposure": "Information Disclosure",
    "takeover": "Information Disclosure",
    "misconfig": "Elevation of Privilege",
    "cve": "Elevation of Privilege",   # default for unclassified CVEs
    "dos": "Denial of Service",
    "audit": "Repudiation",
    "sast": "Tampering",
    "code": "Tampering",
    "dependency": "Tampering",
    "osv": "Tampering",
    "vulnerability": "Tampering",
    "iac": "Elevation of Privilege",
    "misconfiguration": "Elevation of Privilege",
    "dast": "Tampering",
    "passive": "Tampering",
    "clickjacking": "Tampering",
    "csrf": "Tampering",
    "cookie": "Information Disclosure",
    "ai-red-team": "Tampering",
    "owasp-llm": "Tampering",
    "llm01": "Tampering",
    "llm02": "Tampering",
    "llm04": "Denial of Service",
    "llm06": "Information Disclosure",
    "llm07": "Elevation of Privilege",
    "llm08": "Tampering",
    "llm09": "Repudiation",
    "llm10": "Elevation of Privilege",
    "prompt-injection": "Tampering",
    "insecure-output-handling": "Tampering",
    "rag-poisoning": "Tampering",
    "jailbreak": "Elevation of Privilege",
    "sensitive-information-disclosure": "Information Disclosure",
    "training-data-extraction": "Information Disclosure",
    "data-exfiltration": "Information Disclosure",
    "excessive-agency": "Elevation of Privilege",
    "insecure-plugin-design": "Elevation of Privilege",
    "agent-tool-abuse": "Elevation of Privilege",
    "model-dos": "Denial of Service",
    # Positive signals (mitigated)
    "security-headers": None,   # presence means mitigated — handled separately
    "hsts": None,
    "csp": None,
    "tls": None,
}

# Tags that indicate a POSITIVE security control is present (→ mitigated)
_POSITIVE_TAGS = frozenset(["security-headers", "hsts", "csp", "tls", "cors-safe"])

# Informational severity findings that may indicate a control is present
_INFO_SEVERITIES = frozenset(["info"])

# High-signal severities that confirm a vulnerability
_CONFIRMED_SEVERITIES = frozenset(["critical", "high", "medium"])
_GLOBAL_TARGET_KEYS = frozenset(["ingested", "direct", "try_sandbox"])
_PATH_TARGET_TYPES = frozenset(
    ["repository_path", "lockfile", "iac_directory", "ai_system"]
)
_SEVERITY_SCORE = {
    "critical": 95,
    "high": 80,
    "medium": 55,
    "low": 25,
    "info": 10,
    "unknown": 15,
}
_SEMANTIC_TOKEN_RE = re.compile(r"[a-z0-9]+")
_COMPONENT_PHRASE_RE = re.compile(
    r"\b[A-Z][A-Za-z0-9/-]*(?:\s+[A-Z][A-Za-z0-9/-]*){0,5}\s+"
    r"(?:App|Application|Connector|Database|Engine|Gateway|Ledger|Manager|Portal|"
    r"Protection|Server|Service|Store|Vault)\b"
)
_SEMANTIC_ALIASES = {
    "authentication": "auth",
    "authenticating": "auth",
    "authorization": "authz",
    "authorisation": "authz",
    "authorized": "authz",
    "authorised": "authz",
    "bypassed": "bypass",
    "bypassing": "bypass",
    "secrets": "secret",
    "tokens": "token",
    "validation": "validate",
    "validated": "validate",
    "verifies": "verify",
    "verification": "verify",
    "spoofed": "spoof",
    "spoofing": "spoof",
    "requests": "request",
    "injected": "inject",
    "injection": "inject",
}
_SEMANTIC_STOPWORDS = frozenset(
    {
        "access",
        "affected",
        "attacker",
        "boundary",
        "component",
        "control",
        "could",
        "data",
        "flow",
        "from",
        "gateway",
        "internet",
        "manager",
        "network",
        "other",
        "process",
        "security",
        "service",
        "signals",
        "store",
        "system",
        "this",
        "tier",
        "trust",
        "unauthorized",
        "with",
    }
)


def _tags_to_stride(tags: list[str]) -> str | None:
    """Return the STRIDE category for a list of Nuclei tags, or None."""
    for tag in tags:
        category = _TAG_TO_STRIDE.get(tag.lower())
        if category is not None:
            return category
    return None


def _finding_confirms(finding: ScanFinding) -> bool:
    return finding.severity in _CONFIRMED_SEVERITIES


def _finding_mitigates(finding: ScanFinding) -> bool:
    """Returns True if this finding is a positive signal (control is present)."""
    if finding.severity in _INFO_SEVERITIES:
        tag_set = {t.lower() for t in (finding.tags or [])}
        if tag_set & _POSITIVE_TAGS:
            return True
    return False


def _finding_evidence_summary(
    finding: ScanFinding,
    *,
    evidence_scope: str = "node_bound",
    confidence_label: str = "validated",
    match_explanation: str = "",
    matched_node_ids: list[str] | None = None,
) -> dict:
    risk_score = _finding_risk_score(finding, confidence_label)
    proof_class = _finding_proof_class(finding)
    summary = {
        "finding_id": str(finding.id),
        "template_id": finding.template_id,
        "template_name": finding.template_name,
        "severity": finding.severity,
        "matched_at": finding.matched_at,
        "cve_ids": finding.cve_ids,
        "tool_name": finding.tool_name,
        "tool_version": finding.tool_version,
        "validation_target": finding.validation_target,
        "deterministic": finding.deterministic,
        "evidence_scope": evidence_scope,
        "confidence_label": confidence_label,
        "risk_score": risk_score,
        "proof_class": proof_class,
        "evidence_quality": _evidence_quality(confidence_label, proof_class),
        "match_explanation": match_explanation,
        "matched_node_ids": matched_node_ids or [],
    }
    if finding.evidence_origin:
        summary["evidence_origin"] = finding.evidence_origin
    if finding.synthetic is not None:
        summary["synthetic"] = finding.synthetic
    return summary


def _finding_risk_score(finding: ScanFinding, confidence_label: str) -> int:
    multiplier = {"validated": 1.0, "indicated": 0.75, "untested": 0.45}.get(confidence_label, 0.4)
    score = _SEVERITY_SCORE.get(str(finding.severity or "unknown").lower(), _SEVERITY_SCORE["unknown"])
    return max(0, min(100, int(score * multiplier)))


def _finding_proof_class(finding: ScanFinding) -> str:
    if finding.deterministic is True:
        return "deterministic"
    if finding.deterministic is False:
        return "ai_assisted"
    return "unknown"


def _evidence_quality(confidence_label: str, proof_class: str) -> str:
    if confidence_label == "validated" and proof_class == "deterministic":
        return "strong"
    if confidence_label in {"validated", "indicated"}:
        return "moderate"
    return "weak"


def _node_bound_explanation(
    finding: ScanFinding,
    *,
    stride_category: str,
    target: str,
    matched_node_ids: set[str],
) -> str:
    nodes = ", ".join(sorted(matched_node_ids))
    tool = finding.tool_name or "validation tool"
    return (
        f"{tool} finding matched {stride_category} evidence on target {target} "
        f"and was bound to affected DFD node(s): {nodes}."
    )


def _node_bound_semantic_gap_explanation(
    finding: ScanFinding,
    *,
    stride_category: str,
    target: str,
    matched_node_ids: set[str],
) -> str:
    nodes = ", ".join(sorted(matched_node_ids))
    tool = finding.tool_name or "validation tool"
    return (
        f"{tool} finding matched {stride_category} evidence on target {target} "
        f"and affected DFD node(s): {nodes}, but it does not share mechanism "
        "keywords with the threat description. Treat as indicated until reviewed."
    )


def _node_bound_stride_gap_explanation(
    finding: ScanFinding,
    *,
    stride_category: str,
    target: str,
    matched_node_ids: set[str],
) -> str:
    nodes = ", ".join(sorted(matched_node_ids))
    tool = finding.tool_name or "validation tool"
    return (
        f"{tool} finding was bound to affected DFD node(s): {nodes} on target {target}, "
        f"but its scanner category does not exactly match {stride_category}. Treat as "
        "indicated component evidence until reviewed."
    )


def _global_target_explanation(
    finding: ScanFinding,
    *,
    stride_category: str,
) -> str:
    tool = finding.tool_name or "validation tool"
    return (
        f"{tool} finding matched {stride_category} evidence on a global scan target. "
        "Treat as indicated until the target is bound to the affected DFD node."
    )


async def run_semantic_mapping(db: AsyncSession, scan_job_id: UUID) -> None:
    """Post-process a completed scan job: map findings to threat model threats.

    Called after Nuclei completes. Creates/updates ScanThreatResult rows.
    """
    # Load job + findings
    job_result = await db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
    job = job_result.scalar_one_or_none()
    if job is None:
        return

    findings_result = await db.execute(
        select(ScanFinding).where(ScanFinding.scan_job_id == scan_job_id)
    )
    findings = list(findings_result.scalars().all())

    # Load threats for this threat model
    threats_result = await db.execute(
        select(Threat).where(
            Threat.threat_model_id == job.threat_model_id,
            Threat.status.not_in(["Dismissed"]),
        )
    )
    threats = list(threats_result.scalars().all())

    if not threats:
        return

    # Build target URL → set[node_id] reverse map (from job.targets: {node_id: url}).
    # Use a set per URL to handle multiple nodes that share the same target URL.
    targets: dict[str, str] = job.targets or {}
    url_to_node_ids: dict[str, set[str]] = {}
    global_targets: set[str] = set()
    for nid, url in targets.items():
        normalized_id = str(nid)
        if normalized_id in _GLOBAL_TARGET_KEYS or normalized_id.startswith(("direct:", "ingested:")):
            global_targets.add(url)
        else:
            url_to_node_ids.setdefault(url, set()).add(normalized_id)

    target_type = str(getattr(job, "target_type", "") or "").strip()
    path_global_targets_are_unbound = bool(
        target_type in _PATH_TARGET_TYPES and global_targets and not url_to_node_ids
    )
    if path_global_targets_are_unbound:
        # Path scanners prove code evidence, but they cannot identify which DFD
        # component is affected unless the run is explicitly bound to a node.
        logger.info(
            "semantic_mapping_skipped_unbound_path_target job=%s target_type=%s findings=%d",
            scan_job_id,
            target_type,
            len(findings),
        )
        return
    allow_global_target_matching = target_type not in _PATH_TARGET_TYPES

    # Group findings by STRIDE category for fast lookup
    findings_by_stride: dict[str, list[ScanFinding]] = defaultdict(list)
    mitigating_findings: list[ScanFinding] = []
    for f in findings:
        if _finding_mitigates(f):
            mitigating_findings.append(f)
            continue
        stride = _tags_to_stride(f.tags or [])
        if stride:
            findings_by_stride[stride].append(f)
        else:
            # No STRIDE tag but confirmed severity — assign to general bucket
            if _finding_confirms(f):
                findings_by_stride["__unclassified__"].append(f)

    has_targets = bool(targets)

    for threat in threats:
        affected_node_ids = {str(nid) for nid in (threat.affected_node_ids or [])}

        # Determine if any finding targets an affected node
        stride_findings = findings_by_stride.get(threat.stride_category, [])

        # Match findings whose matched_at URL corresponds to an affected node's target
        matched: list[tuple[ScanFinding, dict]] = []
        for f in stride_findings:
            # Find which node(s) this finding's URL belongs to
            for url, nids in url_to_node_ids.items():
                matched_node_ids = nids & affected_node_ids
                if _finding_matches_target(f, url) and matched_node_ids:
                    semantically_matched = _finding_semantically_matches_threat(f, threat)
                    confidence_label = "validated" if semantically_matched else "indicated"
                    matched.append(
                        (
                            f,
                            {
                                "evidence_scope": (
                                    "node_bound"
                                    if semantically_matched
                                    else "node_bound_semantic_gap"
                                ),
                                "confidence_label": confidence_label,
                                "match_explanation": (
                                    _node_bound_explanation(
                                        f,
                                        stride_category=threat.stride_category,
                                        target=url,
                                        matched_node_ids=matched_node_ids,
                                    )
                                    if semantically_matched
                                    else _node_bound_semantic_gap_explanation(
                                        f,
                                        stride_category=threat.stride_category,
                                        target=url,
                                        matched_node_ids=matched_node_ids,
                                    )
                                ),
                                "matched_node_ids": sorted(matched_node_ids),
                            },
                        )
                    )
                    break
            else:
                if allow_global_target_matching and _finding_matches_global_target(f, global_targets):
                    matched.append(
                        (
                            f,
                            {
                                "evidence_scope": "global_target",
                                "confidence_label": "indicated",
                                "match_explanation": _global_target_explanation(
                                    f,
                                    stride_category=threat.stride_category,
                                ),
                                "matched_node_ids": [],
                            },
                        )
                    )

        if not matched:
            fallback_findings = [
                finding
                for category, category_findings in findings_by_stride.items()
                if category != threat.stride_category
                for finding in category_findings
            ]
            for f in fallback_findings:
                for url, nids in url_to_node_ids.items():
                    matched_node_ids = nids & affected_node_ids
                    if _finding_matches_target(f, url) and matched_node_ids:
                        matched.append(
                            (
                                f,
                                {
                                    "evidence_scope": "node_bound_stride_gap",
                                    "confidence_label": "indicated",
                                    "match_explanation": _node_bound_stride_gap_explanation(
                                        f,
                                        stride_category=threat.stride_category,
                                        target=url,
                                        matched_node_ids=matched_node_ids,
                                    ),
                                    "matched_node_ids": sorted(matched_node_ids),
                                },
                            )
                        )
                        break

        # Build evidence list
        evidence = [_finding_evidence_summary(finding, **match_meta) for finding, match_meta in matched]

        cve_ids = list({cve for f, _match_meta in matched for cve in (f.cve_ids or [])})

        # Determine scan status
        if matched:
            # Any non-positive matched finding is vulnerability evidence. Keep
            # severity in the evidence risk score, but do not call a low or
            # unknown-severity failure "mitigated".
            scan_status = "confirmed"
        elif not has_targets:
            scan_status = "unverifiable"
        elif not global_targets and not any(nids & affected_node_ids for nids in url_to_node_ids.values()):
            # No target URL configured for any affected node
            scan_status = "unverifiable"
        else:
            # Target was scanned, nothing found for this threat's STRIDE category
            # Check if a mitigating finding covers an affected node
            mitigation_match = any(
                any(
                    f.matched_at.startswith(url)
                    for url, nids in url_to_node_ids.items()
                    if nids & affected_node_ids
                )
                for f in mitigating_findings
            )
            scan_status = "mitigated" if mitigation_match else "not_found"

        # Upsert ScanThreatResult
        existing_result = await db.execute(
            select(ScanThreatResult).where(
                ScanThreatResult.scan_job_id == scan_job_id,
                ScanThreatResult.threat_id == threat.id,
            )
        )
        threat_result = existing_result.scalar_one_or_none()
        if threat_result is None:
            threat_result = ScanThreatResult(
                scan_job_id=scan_job_id,
                threat_id=threat.id,
                scan_status=scan_status,
                evidence=evidence,
                cve_ids=cve_ids,
            )
            db.add(threat_result)
        else:
            threat_result.scan_status = scan_status
            threat_result.evidence = evidence
            threat_result.cve_ids = cve_ids

    # Caller (scan_worker) owns the commit — do not commit here.
    logger.info("semantic_mapping_staged job=%s threats_mapped=%d", scan_job_id, len(threats))


def _finding_matches_global_target(finding: ScanFinding, global_targets: set[str]) -> bool:
    if not global_targets:
        return False
    for target in global_targets:
        if _finding_matches_target(finding, target):
            return True
    return False


def _finding_matches_target(finding: ScanFinding, target: str) -> bool:
    validation_target = (finding.validation_target or "").strip()
    matched_at = (finding.matched_at or "").strip()
    normalized = target.strip()
    if not normalized:
        return False
    if _typed_target_matches(finding, normalized):
        return True
    if validation_target == normalized:
        return True
    if _target_prefix_matches(matched_at, normalized):
        return True
    return False


def _typed_target_matches(finding: ScanFinding, target: str) -> bool:
    prefix, separator, value = target.partition(":")
    if not separator or prefix not in {"path", "package", "resource", "image", "ai", "text"}:
        return False
    needle = value.strip().casefold()
    if not needle:
        return False
    values = [
        str(finding.validation_target or ""),
        str(finding.matched_at or ""),
        str(finding.extracted_results or ""),
        str(finding.template_id or ""),
        str(finding.template_name or ""),
        " ".join(finding.cve_ids or []),
        " ".join(finding.tags or []),
        str(finding.raw_output or ""),
    ]
    haystack = "\n".join(values).casefold()
    if prefix == "path":
        return _path_ref_matches(haystack, needle)
    return _semantic_ref_matches(haystack, needle)


def _finding_semantically_matches_threat(finding: ScanFinding, threat: Threat) -> bool:
    threat_tokens = _threat_semantic_tokens(threat)
    if not threat_tokens:
        return True
    finding_tokens = _finding_semantic_tokens(finding)
    return bool(threat_tokens & finding_tokens)


def _threat_semantic_tokens(threat: Threat) -> set[str]:
    parts = [
        str(getattr(threat, "description", "") or ""),
        str(getattr(threat, "threat_subtype", "") or ""),
        str(getattr(threat, "rule_id", "") or ""),
        str(getattr(threat, "relevance_rationale", "") or ""),
    ]
    return _semantic_tokens("\n".join(parts), strip_component_phrases=True)


def _finding_semantic_tokens(finding: ScanFinding) -> set[str]:
    parts = [
        str(finding.template_id or ""),
        str(finding.template_name or ""),
        str(finding.matched_at or ""),
        str(finding.extracted_results or ""),
        " ".join(finding.cve_ids or []),
        " ".join(finding.tags or []),
        str(finding.raw_output or ""),
    ]
    return _semantic_tokens("\n".join(parts), strip_component_phrases=False)


def _semantic_tokens(text: str, *, strip_component_phrases: bool) -> set[str]:
    prepared = _COMPONENT_PHRASE_RE.sub(" ", text) if strip_component_phrases else text
    tokens: set[str] = set()
    for raw_token in _SEMANTIC_TOKEN_RE.findall(prepared.casefold()):
        token = _SEMANTIC_ALIASES.get(raw_token, raw_token)
        if len(token) < 3 or token in _SEMANTIC_STOPWORDS:
            continue
        tokens.add(token)
    return tokens


def _target_prefix_matches(value: str, target: str) -> bool:
    normalized_value = value.strip()
    normalized_target = target.strip().rstrip("/")
    if not normalized_value or not normalized_target:
        return False
    return (
        normalized_value == normalized_target
        or normalized_value.startswith(f"{normalized_target}/")
        or normalized_value.startswith(f"{normalized_target}?")
        or normalized_value.startswith(f"{normalized_target}#")
    )


def _path_ref_matches(haystack: str, value: str) -> bool:
    candidate = value.strip().strip("/").replace("\\", "/").casefold()
    if not candidate:
        return False
    normalized_haystack = haystack.replace("\\", "/")
    pattern = rf"(?<![a-z0-9._-]){re.escape(candidate)}(?![a-z0-9._/-])"
    return re.search(pattern, normalized_haystack) is not None


def _semantic_ref_matches(haystack: str, value: str) -> bool:
    candidate = value.strip().casefold()
    if not candidate:
        return False
    pattern = rf"(?<![a-z0-9._/-]){re.escape(candidate)}(?![a-z0-9._/-])"
    return re.search(pattern, haystack) is not None

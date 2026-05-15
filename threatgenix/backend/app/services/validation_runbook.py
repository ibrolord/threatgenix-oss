"""Runbook summaries for validation evidence."""
from __future__ import annotations

from collections import Counter
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import ScanExecutionArtifact, ScanFinding, ScanJob, ScanThreatResult
from app.models.threat import Threat
from app.schemas.scan import (
    ValidationRunbookCoverageResponse,
    ValidationRunbookFindingResponse,
    ValidationRunbookResponse,
    ValidationRunbookThreatResponse,
)

_GLOBAL_TARGET_KEYS = frozenset(["ingested", "direct", "try_sandbox"])
_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}
_SEVERITY_SCORE = {
    "critical": 95,
    "high": 80,
    "medium": 55,
    "low": 25,
    "info": 10,
    "unknown": 15,
}


async def build_validation_runbook(
    db: AsyncSession,
    scan_job_id: UUID,
) -> ValidationRunbookResponse | None:
    scan_result = await db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
    scan_job = scan_result.scalar_one_or_none()
    if scan_job is None:
        return None

    findings_result = await db.execute(
        select(ScanFinding).where(ScanFinding.scan_job_id == scan_job_id)
    )
    findings = list(findings_result.scalars().all())

    artifacts_result = await db.execute(
        select(ScanExecutionArtifact).where(ScanExecutionArtifact.scan_job_id == scan_job_id)
    )
    artifacts = list(artifacts_result.scalars().all())

    threat_results_result = await db.execute(
        select(ScanThreatResult, Threat)
        .join(Threat, Threat.id == ScanThreatResult.threat_id)
        .where(ScanThreatResult.scan_job_id == scan_job_id)
    )
    threat_rows = list(threat_results_result.all())

    active_threats_result = await db.execute(
        select(Threat).where(
            Threat.threat_model_id == scan_job.threat_model_id,
            Threat.status.not_in(["Dismissed"]),
        )
    )
    active_threats = list(active_threats_result.scalars().all())

    mapped_threats = sorted(
        [_threat_runbook_entry(result, threat) for result, threat in threat_rows],
        key=_threat_entry_sort_key,
    )
    validated_threat_count = sum(1 for item in mapped_threats if item.confidence_label == "validated")
    indicated_threat_count = sum(1 for item in mapped_threats if item.confidence_label == "indicated")
    untested_threat_count = max(
        0,
        len(active_threats) - validated_threat_count - indicated_threat_count,
    )
    mapped_finding_ids = _mapped_finding_ids(threat_rows)
    unbound_findings = [
        _unbound_finding_entry(finding)
        for finding in sorted(findings, key=_finding_sort_key)
        if finding.id not in mapped_finding_ids
    ]
    confidence_counts = Counter(item.confidence_label for item in mapped_threats)
    confidence_counts["untested"] += untested_threat_count

    coverage = ValidationRunbookCoverageResponse(
        scan_job_id=scan_job.id,
        scan_completed_at=scan_job.completed_at,
        tool_names=_tool_names(scan_job, findings, artifacts),
        target_binding=_target_binding(scan_job.targets or {}),
        finding_count=len(findings),
        deterministic_finding_count=sum(1 for finding in findings if finding.deterministic is not False),
        assisted_finding_count=sum(1 for finding in findings if finding.deterministic is False),
        artifact_count=len(artifacts),
        mapped_threat_count=len(mapped_threats),
        validated_threat_count=validated_threat_count,
        indicated_threat_count=indicated_threat_count,
        unbound_finding_count=len(unbound_findings),
        untested_threat_count=untested_threat_count,
        confidence_counts=dict(confidence_counts),
        validated_risk_score=_aggregate_risk_scores(
            item.risk_score for item in mapped_threats if item.confidence_label == "validated"
        ),
        indicated_risk_score=_aggregate_risk_scores(
            item.risk_score for item in mapped_threats if item.confidence_label == "indicated"
        ),
        ai_assisted_risk_score=_aggregate_risk_scores(
            _finding_risk_score(finding, confidence_label="indicated")
            for finding in findings
            if finding.deterministic is False
        ),
    )
    gaps = _coverage_gaps(
        coverage=coverage,
        scan_job=scan_job,
        artifacts=artifacts,
    )
    return ValidationRunbookResponse(
        coverage=coverage,
        executive_summary=_executive_summary(coverage),
        gaps=gaps,
        mapped_threats=mapped_threats,
        unbound_findings=unbound_findings,
    )


def _threat_runbook_entry(
    threat_result: ScanThreatResult,
    threat: Threat,
) -> ValidationRunbookThreatResponse:
    evidence = threat_result.evidence or []
    confidence_label = _threat_confidence(evidence)
    risk_score = _threat_risk_score(threat, threat_result.scan_status, confidence_label, evidence)
    proof_class = _threat_proof_class(evidence, threat_result.scan_status)
    evidence_quality = _threat_evidence_quality(confidence_label, proof_class, evidence)
    tools = sorted(
        {
            str(item.get("tool_name")).strip()
            for item in evidence
            if item.get("tool_name")
        }
    )
    return ValidationRunbookThreatResponse(
        threat_id=threat.id,
        threat_display_id=threat.display_id,
        threat_description=threat.description,
        severity=threat.severity,
        stride_category=threat.stride_category,
        scan_status=threat_result.scan_status,
        confidence_label=confidence_label,
        explanation=_threat_explanation(threat_result.scan_status, confidence_label, evidence),
        evidence_count=len(evidence),
        risk_score=risk_score,
        evidence_quality=evidence_quality,
        proof_class=proof_class,
        next_action=_threat_next_action(threat_result.scan_status, confidence_label, evidence),
        cve_ids=threat_result.cve_ids or [],
        validation_tools=tools,
    )


def _threat_confidence(evidence: list[dict]) -> str:
    labels = {str(item.get("confidence_label") or "") for item in evidence}
    if "validated" in labels:
        return "validated"
    if "indicated" in labels:
        return "indicated"
    return "untested"


def _threat_explanation(scan_status: str, confidence_label: str, evidence: list[dict]) -> str:
    explanations = [
        str(item.get("match_explanation") or "").strip()
        for item in evidence
        if item.get("match_explanation")
    ]
    if explanations:
        return explanations[0]
    if scan_status == "not_found":
        return "The configured target was scanned and no matching deterministic finding was observed."
    if scan_status == "mitigated":
        return "The scan evidence indicates the expected control is present or no exploitable finding remains."
    if scan_status == "unverifiable":
        return "No suitable validation target was available for the affected model component."
    if confidence_label == "indicated":
        return "Evidence exists, but it is not bound to a specific affected DFD node."
    return "No validation evidence is bound to this threat yet."


def _mapped_finding_ids(threat_rows: list[tuple[ScanThreatResult, Threat]]) -> set[UUID]:
    finding_ids: set[UUID] = set()
    for threat_result, _threat in threat_rows:
        for item in threat_result.evidence or []:
            if item.get("confidence_label") not in {"validated", "indicated"}:
                continue
            raw_id = item.get("finding_id")
            try:
                finding_ids.add(UUID(str(raw_id)))
            except (TypeError, ValueError):
                continue
    return finding_ids


def _unbound_finding_entry(finding: ScanFinding) -> ValidationRunbookFindingResponse:
    proof_class = _finding_proof_class(finding)
    return ValidationRunbookFindingResponse(
        finding_id=finding.id,
        title=finding.template_name or finding.template_id,
        severity=finding.severity,
        tool_name=finding.tool_name,
        target=finding.validation_target,
        matched_at=finding.matched_at,
        cve_ids=finding.cve_ids or [],
        tags=finding.tags or [],
        confidence_label="untested",
        evidence_scope="unbound",
        proof_class=proof_class,
        evidence_quality="moderate" if proof_class == "deterministic" else "weak",
        risk_score=_finding_risk_score(finding, confidence_label="untested"),
        next_action="Bind this finding to an affected DFD node or mark it not applicable.",
        explanation=(
            "Finding was retained as validation evidence, but it is not bound "
            "to a semantic threat because no affected DFD node binding matched."
        ),
    )


def _finding_sort_key(finding: ScanFinding) -> tuple[int, str]:
    return (_SEVERITY_RANK.get(finding.severity, 99), finding.template_name or finding.template_id)


def _threat_entry_sort_key(item: ValidationRunbookThreatResponse) -> tuple[int, int, str]:
    confidence_rank = {"validated": 0, "indicated": 1, "untested": 2}
    return (
        confidence_rank.get(item.confidence_label, 99),
        _SEVERITY_RANK.get(item.severity.lower(), 99),
        item.threat_display_id,
    )


def _tool_names(
    scan_job: ScanJob,
    findings: list[ScanFinding],
    artifacts: list[ScanExecutionArtifact],
) -> list[str]:
    names = {scan_job.tool_name} if scan_job.tool_name else set()
    names.update(str(finding.tool_name) for finding in findings if finding.tool_name)
    names.update(str(artifact.tool_name) for artifact in artifacts if artifact.tool_name)
    return sorted(name for name in names if name)


def _target_binding(targets: dict) -> str:
    if not targets:
        return "none"
    has_global = False
    has_node = False
    for raw_key in targets:
        key = str(raw_key)
        if key in _GLOBAL_TARGET_KEYS or key.startswith(("direct:", "ingested:")):
            has_global = True
        else:
            has_node = True
    if has_global and has_node:
        return "mixed"
    if has_node:
        return "node_bound"
    return "global"


def _coverage_gaps(
    *,
    coverage: ValidationRunbookCoverageResponse,
    scan_job: ScanJob,
    artifacts: list[ScanExecutionArtifact],
) -> list[str]:
    gaps: list[str] = []
    if coverage.target_binding == "global":
        gaps.append(
            "Validation targets were not bound to DFD nodes; path and dependency evidence stays unvalidated until a modeled component is selected."
        )
    if coverage.unbound_finding_count:
        gaps.append(
            f"{coverage.unbound_finding_count} validation finding(s) are retained as evidence but not bound to a semantic threat."
        )
    if coverage.validated_threat_count == 0 and coverage.finding_count:
        gaps.append("No threat has node-bound validation evidence yet.")
    if coverage.untested_threat_count:
        gaps.append(
            f"{coverage.untested_threat_count} active threat(s) still need validation evidence."
        )
    problem_artifacts = [
        artifact for artifact in artifacts
        if artifact.status in {"failed", "timed_out", "blocked"} or artifact.output_limit_exceeded
    ]
    if problem_artifacts:
        gaps.append(
            f"{len(problem_artifacts)} validation artifact(s) need operator review before relying on this run."
        )
    if scan_job.status != "completed":
        gaps.append(f"Scan status is {scan_job.status}; wait for completion before treating coverage as final.")
    if not gaps:
        gaps.append("No validation coverage gaps were detected in this runbook.")
    return gaps


def _severity_score(value: str | None) -> int:
    return _SEVERITY_SCORE.get(str(value or "unknown").lower(), _SEVERITY_SCORE["unknown"])


def _aggregate_risk_scores(scores: object) -> int:
    total = 0
    for score in scores:  # type: ignore[assignment]
        try:
            total += int(score)
        except (TypeError, ValueError):
            continue
    return max(0, min(100, total))


def _finding_risk_score(finding: ScanFinding, *, confidence_label: str) -> int:
    multiplier = {"validated": 1.0, "indicated": 0.75, "untested": 0.55}.get(confidence_label, 0.4)
    return max(0, min(100, int(_severity_score(finding.severity) * multiplier)))


def _evidence_item_risk_score(item: dict, *, confidence_label: str) -> int:
    raw_score = item.get("risk_score")
    if isinstance(raw_score, (int, float)):
        return max(0, min(100, int(raw_score)))
    multiplier = {"validated": 1.0, "indicated": 0.75, "untested": 0.45}.get(confidence_label, 0.4)
    return max(0, min(100, int(_severity_score(str(item.get("severity") or "unknown")) * multiplier)))


def _threat_risk_score(
    threat: Threat,
    scan_status: str,
    confidence_label: str,
    evidence: list[dict],
) -> int:
    if evidence:
        return max(_evidence_item_risk_score(item, confidence_label=confidence_label) for item in evidence)
    if scan_status == "not_found":
        return 0
    if scan_status == "mitigated":
        return max(0, int(_severity_score(threat.severity) * 0.15))
    if scan_status == "unverifiable":
        return max(0, int(_severity_score(threat.severity) * 0.45))
    return max(0, int(_severity_score(threat.severity) * 0.35))


def _finding_proof_class(finding: ScanFinding) -> str:
    if finding.deterministic is True:
        return "deterministic"
    if finding.deterministic is False:
        return "ai_assisted"
    if finding.tool_name in {
        "nuclei",
        "semgrep",
        "osv-scanner",
        "trivy",
        "checkov",
        "trufflehog",
        "ai-red-team",
    }:
        return "deterministic"
    return "unknown"


def _threat_proof_class(evidence: list[dict], scan_status: str) -> str:
    if any(item.get("deterministic") is True for item in evidence):
        return "deterministic"
    if any(item.get("deterministic") is False for item in evidence):
        return "ai_assisted"
    if scan_status in {"mitigated", "not_found"}:
        return "runtime"
    return "unknown"


def _threat_evidence_quality(confidence_label: str, proof_class: str, evidence: list[dict]) -> str:
    if confidence_label == "validated" and proof_class == "deterministic":
        return "strong"
    if confidence_label in {"validated", "indicated"} and evidence:
        return "moderate"
    return "weak"


def _threat_next_action(scan_status: str, confidence_label: str, evidence: list[dict]) -> str:
    if confidence_label == "validated":
        return "Verify owner, remediation plan, and retest window."
    if confidence_label == "indicated":
        return "Bind the target to a modeled component and rerun validation."
    if scan_status == "not_found":
        return "Keep as monitored; rerun after material architecture or dependency changes."
    if scan_status == "mitigated":
        return "Retain the evidence and monitor for regression."
    if evidence:
        return "Review evidence quality and decide whether the threat is validated or not applicable."
    return "Add deterministic validation evidence from the current tool set."


def _executive_summary(coverage: ValidationRunbookCoverageResponse) -> str:
    finding_summary = f"{coverage.finding_count} validation finding(s)"
    if coverage.assisted_finding_count:
        finding_summary = (
            f"{coverage.deterministic_finding_count} deterministic and "
            f"{coverage.assisted_finding_count} non-deterministic finding(s)"
        )
    return (
        f"{', '.join(coverage.tool_names) or 'Validation'} produced "
        f"{finding_summary}, "
        f"{coverage.validated_threat_count} validated threat(s), "
        f"{coverage.indicated_threat_count} indicated threat(s), and "
        f"{coverage.unbound_finding_count} unbound finding(s). "
        f"{coverage.untested_threat_count} active threat(s) still need validation evidence."
    )

"""Deterministic binder mapping ScanFinding evidence to STRIDE threat templates.

This module is the moat: every finding produced by a validation adapter is
classified into a STRIDE category, a high-level threat template, a binding
confidence, an optional ATT&CK technique, and a false-positive flag — using
hardcoded rules. There are no LLM calls here. The mapping is fully
explainable: given a (tool, finding) pair, the same BoundThreat is returned
every time.

The binder is intentionally conservative:
- Nuclei "info"-severity templates and known noisy tech-detect templates are
  suppressed as false positives instead of being mapped to STRIDE.
- Unrecognized tools/findings fall through to STRIDE: Tampering with low
  confidence rather than guessing aggressively.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.scan import ScanFinding
from app.services.validation_artifact_contract import validation_metadata_from_raw

# STRIDE constants — keep aligned with the rules engine's stride_category vocabulary.
STRIDE_SPOOFING = "Spoofing"
STRIDE_TAMPERING = "Tampering"
STRIDE_REPUDIATION = "Repudiation"
STRIDE_INFORMATION_DISCLOSURE = "Information Disclosure"
STRIDE_DENIAL_OF_SERVICE = "Denial of Service"
STRIDE_ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

# Template names — short, consistent labels surfaced in the UI/PDF.
TEMPLATE_CREDENTIAL_EXPOSURE = "Credential/Secret Exposure"
TEMPLATE_DEPENDENCY_CVE = "Dependency Exploitation via Known CVE"
TEMPLATE_INJECTION = "Injection (SQL/Command/Code)"
TEMPLATE_XSS = "Cross-Site Scripting"
TEMPLATE_HARDCODED_SECRET = "Hardcoded Secret in Source"
TEMPLATE_CONTAINER_CVE = "Vulnerable Container Image"
TEMPLATE_PUBLIC_STORAGE = "Data Exfiltration via Misconfigured Cloud Storage"
TEMPLATE_IAM_MISCONFIG = "Excessive IAM Privilege"
TEMPLATE_AUTH_BYPASS = "Authentication Bypass"
TEMPLATE_RCE = "Remote Code Execution"
TEMPLATE_SSRF = "Server-Side Request Forgery"
TEMPLATE_GENERIC_WEB_VULN = "Web Application Vulnerability"
TEMPLATE_SUPPRESSED_LOW_SIGNAL = "Suppressed (Low Signal)"
TEMPLATE_UNCLASSIFIED = "Unclassified Finding"

# ATT&CK technique IDs — only set when the mapping is unambiguous.
ATTACK_UNSECURED_CREDENTIALS = "T1552"
ATTACK_EXPLOIT_PUBLIC_FACING_APP = "T1190"
ATTACK_DRIVE_BY_COMPROMISE = "T1189"
ATTACK_SUPPLY_CHAIN_SOFTWARE = "T1195.002"
ATTACK_DATA_FROM_CLOUD_STORAGE = "T1530"
ATTACK_VALID_ACCOUNTS = "T1078"
ATTACK_COMMAND_AND_SCRIPTING = "T1059"
ATTACK_PROXY = "T1090"

# Nuclei templates / template-id substrings that fire on benign reconnaissance
# and should be treated as false positives rather than threats.
_NUCLEI_NOISE_SUBSTRINGS: tuple[str, ...] = (
    "tech-detect",
    "header-disclosure",
    "options-method",
    "x-powered-by",
)


@dataclass(frozen=True)
class BoundThreat:
    """Deterministic STRIDE classification for a single ScanFinding."""

    stride_category: str
    threat_template: str
    binding_confidence: str  # "high" | "medium" | "low"
    false_positive: bool
    attack_technique: str | None


class ScanThreatBinder:
    """Deterministic finding -> STRIDE threat binder.

    Public API: ``bind(finding)`` returns a ``BoundThreat``. Pure function with
    no side effects. Safe to call from sync or async code.
    """

    def bind(self, finding: ScanFinding) -> BoundThreat:
        tool = (finding.tool_name or "").lower().strip()
        if not tool:
            # Fall back to inspecting raw_output metadata if the property is missing.
            tool = self._infer_tool_from_raw(finding)

        if tool == "trufflehog":
            return self._bind_trufflehog(finding)
        if tool in ("osv-scanner", "osv_scanner", "osv"):
            return self._bind_osv(finding)
        if tool == "semgrep":
            return self._bind_semgrep(finding)
        if tool == "trivy":
            return self._bind_trivy(finding)
        if tool == "checkov":
            return self._bind_checkov(finding)
        if tool == "nuclei":
            return self._bind_nuclei(finding)

        return BoundThreat(
            stride_category=STRIDE_TAMPERING,
            threat_template=TEMPLATE_UNCLASSIFIED,
            binding_confidence="low",
            false_positive=False,
            attack_technique=None,
        )

    # ------------------------------------------------------------------
    # Tool-specific binding rules
    # ------------------------------------------------------------------

    def _bind_trufflehog(self, finding: ScanFinding) -> BoundThreat:
        # raw_output["Verified"] is the canonical signal; tags include "verified"
        # only when truly verified by the live detector.
        verified = bool((finding.raw_output or {}).get("Verified")) or "verified" in (
            finding.tags or []
        )
        confidence = "high" if verified else "low"
        # Information Disclosure is the primary STRIDE category for exposed secrets.
        # Tampering is also implicated (an attacker with the secret can modify state)
        # — we report the dominant category and let the rules engine layer add the
        # secondary category in a downstream rule if needed.
        return BoundThreat(
            stride_category=STRIDE_INFORMATION_DISCLOSURE,
            threat_template=TEMPLATE_CREDENTIAL_EXPOSURE,
            binding_confidence=confidence,
            false_positive=False,
            attack_technique=ATTACK_UNSECURED_CREDENTIALS,
        )

    def _bind_osv(self, finding: ScanFinding) -> BoundThreat:
        score = finding.cvss_score
        if score is not None and score >= 7.0:
            confidence = "high"
        else:
            confidence = "medium"
        return BoundThreat(
            stride_category=STRIDE_TAMPERING,
            threat_template=TEMPLATE_DEPENDENCY_CVE,
            binding_confidence=confidence,
            false_positive=False,
            attack_technique=ATTACK_SUPPLY_CHAIN_SOFTWARE,
        )

    def _bind_semgrep(self, finding: ScanFinding) -> BoundThreat:
        rule_id = (finding.template_id or "").lower()
        # Secret/credential rules — Information Disclosure
        if any(k in rule_id for k in ("hardcoded", "secret", "credential")):
            return BoundThreat(
                stride_category=STRIDE_INFORMATION_DISCLOSURE,
                threat_template=TEMPLATE_HARDCODED_SECRET,
                binding_confidence="high",
                false_positive=False,
                attack_technique=ATTACK_UNSECURED_CREDENTIALS,
            )
        # Injection-family rules — Tampering
        if "sql" in rule_id or "injection" in rule_id:
            return BoundThreat(
                stride_category=STRIDE_TAMPERING,
                threat_template=TEMPLATE_INJECTION,
                binding_confidence="high",
                false_positive=False,
                attack_technique=ATTACK_EXPLOIT_PUBLIC_FACING_APP,
            )
        if "xss" in rule_id:
            return BoundThreat(
                stride_category=STRIDE_TAMPERING,
                threat_template=TEMPLATE_XSS,
                binding_confidence="high",
                false_positive=False,
                attack_technique=None,
            )
        # Unknown semgrep rule — default to Tampering low confidence, no ATT&CK.
        return BoundThreat(
            stride_category=STRIDE_TAMPERING,
            threat_template=TEMPLATE_UNCLASSIFIED,
            binding_confidence="low",
            false_positive=False,
            attack_technique=None,
        )

    def _bind_trivy(self, finding: ScanFinding) -> BoundThreat:
        severity = (finding.severity or "").lower()
        if severity in ("critical", "high"):
            confidence = "high"
        elif severity in ("medium", "low"):
            confidence = "medium"
        else:
            confidence = "low"
        return BoundThreat(
            stride_category=STRIDE_TAMPERING,
            threat_template=TEMPLATE_CONTAINER_CVE,
            binding_confidence=confidence,
            false_positive=False,
            attack_technique=ATTACK_SUPPLY_CHAIN_SOFTWARE,
        )

    def _bind_checkov(self, finding: ScanFinding) -> BoundThreat:
        check_id = (finding.template_id or "").upper()
        # IAM-related findings — Elevation of Privilege
        if "IAM" in check_id or "ROLE" in check_id or "POLICY" in check_id:
            return BoundThreat(
                stride_category=STRIDE_ELEVATION_OF_PRIVILEGE,
                threat_template=TEMPLATE_IAM_MISCONFIG,
                binding_confidence="high",
                false_positive=False,
                attack_technique=ATTACK_VALID_ACCOUNTS,
            )
        # Public storage / open buckets — Information Disclosure
        if "S3" in check_id or "PUBLIC" in check_id or "OPEN" in check_id:
            return BoundThreat(
                stride_category=STRIDE_INFORMATION_DISCLOSURE,
                threat_template=TEMPLATE_PUBLIC_STORAGE,
                binding_confidence="high",
                false_positive=False,
                attack_technique=ATTACK_DATA_FROM_CLOUD_STORAGE,
            )
        # Unknown IaC misconfig — default to Tampering low confidence.
        return BoundThreat(
            stride_category=STRIDE_TAMPERING,
            threat_template=TEMPLATE_UNCLASSIFIED,
            binding_confidence="low",
            false_positive=False,
            attack_technique=None,
        )

    def _bind_nuclei(self, finding: ScanFinding) -> BoundThreat:
        severity = (finding.severity or "").lower()
        template_id = (finding.template_id or "").lower()
        tags = {t.lower() for t in (finding.tags or []) if isinstance(t, str)}

        # Suppress info-severity and known-noisy templates as false positives.
        if severity == "info" or any(
            noisy in template_id for noisy in _NUCLEI_NOISE_SUBSTRINGS
        ):
            return BoundThreat(
                stride_category=STRIDE_INFORMATION_DISCLOSURE,
                threat_template=TEMPLATE_SUPPRESSED_LOW_SIGNAL,
                binding_confidence="low",
                false_positive=True,
                attack_technique=None,
            )

        if severity == "critical" or severity == "high":
            confidence = "high"
        elif severity == "medium":
            confidence = "medium"
        else:
            # low / unknown — bind but at low confidence.
            confidence = "low"

        # Map by tags to a STRIDE category. Order matters: more specific tags first.
        if "sqli" in tags or "injection" in tags:
            return BoundThreat(
                stride_category=STRIDE_TAMPERING,
                threat_template=TEMPLATE_INJECTION,
                binding_confidence=confidence,
                false_positive=False,
                attack_technique=ATTACK_EXPLOIT_PUBLIC_FACING_APP,
            )
        if "rce" in tags:
            return BoundThreat(
                stride_category=STRIDE_ELEVATION_OF_PRIVILEGE,
                threat_template=TEMPLATE_RCE,
                binding_confidence=confidence,
                false_positive=False,
                attack_technique=ATTACK_COMMAND_AND_SCRIPTING,
            )
        if "ssrf" in tags:
            return BoundThreat(
                stride_category=STRIDE_INFORMATION_DISCLOSURE,
                threat_template=TEMPLATE_SSRF,
                binding_confidence=confidence,
                false_positive=False,
                attack_technique=ATTACK_PROXY,
            )
        if "auth" in tags or "auth-bypass" in tags:
            return BoundThreat(
                stride_category=STRIDE_SPOOFING,
                threat_template=TEMPLATE_AUTH_BYPASS,
                binding_confidence=confidence,
                false_positive=False,
                attack_technique=None,
            )
        # Default Nuclei mapping: Tampering, no ATT&CK.
        return BoundThreat(
            stride_category=STRIDE_TAMPERING,
            threat_template=TEMPLATE_GENERIC_WEB_VULN,
            binding_confidence=confidence,
            false_positive=False,
            attack_technique=None,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_tool_from_raw(finding: ScanFinding) -> str:
        raw = finding.raw_output or {}
        if not isinstance(raw, dict):
            return ""
        meta = validation_metadata_from_raw(raw)
        if isinstance(meta, dict):
            value = meta.get("tool_name")
            if isinstance(value, str):
                return value.lower().strip()
        return ""

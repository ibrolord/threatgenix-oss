"""Unit tests for the Trufflehog/Prowler adapters and the ScanThreatBinder.

These tests run with no Docker and no real binaries — adapters are exercised
via parse_json_line() / is_available(), and the binder is exercised on
in-memory ScanFinding objects.
"""

from __future__ import annotations

import uuid

from app.models.scan import ScanFinding
from app.services.scan_threat_binder import (
    ATTACK_SUPPLY_CHAIN_SOFTWARE,
    ATTACK_UNSECURED_CREDENTIALS,
    BoundThreat,
    STRIDE_INFORMATION_DISCLOSURE,
    STRIDE_TAMPERING,
    ScanThreatBinder,
    TEMPLATE_CREDENTIAL_EXPOSURE,
    TEMPLATE_DEPENDENCY_CVE,
    TEMPLATE_SUPPRESSED_LOW_SIGNAL,
)
from app.services.validation_tools import (
    ProwlerValidationAdapter,
    TrufflehogValidationAdapter,
    default_validation_tool_registry,
)


# ----------------------------------------------------------------------
# Trufflehog adapter
# ----------------------------------------------------------------------


def test_trufflehog_parse_verified_secret_is_high_severity() -> None:
    adapter = TrufflehogValidationAdapter()
    line = {
        "SourceMetadata": {
            "Data": {
                "Git": {"file": "src/secrets.py", "line": 42, "commit": "deadbeef"}
            }
        },
        "DetectorName": "AWS",
        "DetectorType": 2,
        "Verified": True,
        "Raw": "AKIA...",
    }
    evidence = adapter.parse_json_line("/tmp/repo", line)
    assert evidence is not None
    assert evidence.severity == "high"
    assert evidence.tool_name == "trufflehog"
    assert "verified" in evidence.tags
    assert evidence.matched_url.endswith("src/secrets.py:42")


def test_trufflehog_parse_unverified_secret_is_low_severity() -> None:
    adapter = TrufflehogValidationAdapter()
    line = {
        "SourceMetadata": {"Data": {"Git": {"file": "README.md"}}},
        "DetectorName": "Slack",
        "Verified": False,
        "Raw": "xoxb-fake",
    }
    evidence = adapter.parse_json_line("/tmp/repo", line)
    assert evidence is not None
    assert evidence.severity == "low"
    assert "unverified" in evidence.tags


def test_trufflehog_command_uses_offline_filesystem_scan() -> None:
    adapter = TrufflehogValidationAdapter()

    assert adapter.build_command("/tmp/repo") == [
        "trufflehog",
        "filesystem",
        "/tmp/repo",
        "--json",
        "--no-update",
        "--no-verification",
        "--results=verified,unknown,unverified",
        "--filter-unverified",
        "--force-skip-binaries",
        "--force-skip-archives",
    ]


# ----------------------------------------------------------------------
# Prowler stub
# ----------------------------------------------------------------------


def test_prowler_stub_is_not_available() -> None:
    adapter = ProwlerValidationAdapter()
    assert adapter.is_available() is False
    assert adapter.name == "prowler"


def test_default_registry_includes_trufflehog_not_prowler() -> None:
    registry = default_validation_tool_registry()
    names = [t.name for t in registry.list()]
    assert "trufflehog" in names
    assert "prowler" not in names


# ----------------------------------------------------------------------
# ScanThreatBinder
# ----------------------------------------------------------------------


def _finding(
    *,
    tool_name: str,
    template_id: str = "",
    severity: str = "unknown",
    tags: list[str] | None = None,
    cvss_score: float | None = None,
    raw_output: dict | None = None,
) -> ScanFinding:
    """Build an in-memory ScanFinding with the binding-relevant fields populated."""
    raw = dict(raw_output or {})
    raw.setdefault("threatgenix_validation", {"tool_name": tool_name})
    return ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=uuid.uuid4(),
        template_id=template_id,
        template_name=template_id or "test",
        severity=severity,
        matched_at="https://example.test",
        extracted_results=None,
        cve_ids=[],
        tags=tags or [],
        cvss_score=cvss_score,
        raw_output=raw,
    )


def test_binder_trufflehog_verified_maps_to_credential_exposure_high() -> None:
    binder = ScanThreatBinder()
    finding = _finding(
        tool_name="trufflehog",
        severity="high",
        tags=["trufflehog", "verified"],
        raw_output={"Verified": True},
    )
    bound = binder.bind(finding)
    assert isinstance(bound, BoundThreat)
    assert bound.stride_category == STRIDE_INFORMATION_DISCLOSURE
    assert bound.threat_template == TEMPLATE_CREDENTIAL_EXPOSURE
    assert bound.binding_confidence == "high"
    assert bound.false_positive is False
    assert bound.attack_technique == ATTACK_UNSECURED_CREDENTIALS


def test_binder_nuclei_tech_detect_is_suppressed() -> None:
    binder = ScanThreatBinder()
    finding = _finding(
        tool_name="nuclei",
        template_id="tech-detect/php-detect",
        severity="info",
        tags=["tech"],
    )
    bound = binder.bind(finding)
    assert bound.false_positive is True
    assert bound.threat_template == TEMPLATE_SUPPRESSED_LOW_SIGNAL


def test_binder_reads_semantic_review_validation_metadata_alias() -> None:
    binder = ScanThreatBinder()
    finding = ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=uuid.uuid4(),
        template_id="tech-detect/php-detect",
        template_name="tech-detect/php-detect",
        severity="info",
        matched_at="https://example.test",
        extracted_results=None,
        cve_ids=[],
        tags=["tech"],
        cvss_score=None,
        raw_output={"semantic_review_validation": {"tool_name": "nuclei"}},
    )

    bound = binder.bind(finding)

    assert bound.false_positive is True
    assert bound.threat_template == TEMPLATE_SUPPRESSED_LOW_SIGNAL


def test_binder_osv_high_cvss_maps_to_dependency_cve_high() -> None:
    binder = ScanThreatBinder()
    finding = _finding(
        tool_name="osv-scanner",
        template_id="GHSA-xxxx",
        severity="high",
        cvss_score=9.8,
    )
    bound = binder.bind(finding)
    assert bound.stride_category == STRIDE_TAMPERING
    assert bound.threat_template == TEMPLATE_DEPENDENCY_CVE
    assert bound.binding_confidence == "high"
    assert bound.attack_technique == ATTACK_SUPPLY_CHAIN_SOFTWARE

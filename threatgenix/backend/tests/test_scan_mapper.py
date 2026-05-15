"""Tests for the semantic vulnerability scanner mapper."""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.scan import ScanFinding
from app.services.scan_mapper import (
    _finding_confirms,
    _finding_mitigates,
    _finding_matches_global_target,
    _tags_to_stride,
    run_semantic_mapping,
)
from app.services.validation_tools import (
    CheckovValidationAdapter,
    NucleiValidationAdapter,
    OSVScannerValidationAdapter,
    SemgrepValidationAdapter,
    TrivyValidationAdapter,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(tags: list[str], severity: str) -> ScanFinding:
    return ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=uuid.uuid4(),
        template_id="test-template",
        template_name="Test Template",
        severity=severity,
        matched_at="https://api.example.com/test",
        cve_ids=[],
        tags=tags,
        raw_output={},
    )


class _ScalarOneResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _ScalarsAllResult:
    def __init__(self, values):
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values


def _fake_db(*results):
    added = []
    return SimpleNamespace(
        execute=AsyncMock(side_effect=results),
        add=added.append,
        added=added,
    )


def _job(
    scan_job_id: uuid.UUID,
    threat_model_id: uuid.UUID,
    targets: dict[str, str],
    *,
    target_type: str = "url",
):
    return SimpleNamespace(
        id=scan_job_id,
        threat_model_id=threat_model_id,
        targets=targets,
        target_type=target_type,
    )


def _threat(
    threat_id: uuid.UUID,
    node_id: uuid.UUID,
    *,
    stride_category: str,
    description: str = "",
):
    return SimpleNamespace(
        id=threat_id,
        status="Open",
        affected_node_ids=[node_id],
        stride_category=stride_category,
        description=description,
        threat_subtype=None,
        rule_id=None,
        relevance_rationale=None,
    )


# ---------------------------------------------------------------------------
# _tags_to_stride
# ---------------------------------------------------------------------------


def test_tags_to_stride_sqli_returns_tampering():
    assert _tags_to_stride(["sqli"]) == "Tampering"


def test_tags_to_stride_ssrf_returns_elevation_of_privilege():
    assert _tags_to_stride(["ssrf"]) == "Elevation of Privilege"


def test_tags_to_stride_auth_bypass_returns_spoofing():
    assert _tags_to_stride(["auth-bypass"]) == "Spoofing"


def test_tags_to_stride_exposure_returns_information_disclosure():
    assert _tags_to_stride(["exposure"]) == "Information Disclosure"


def test_tags_to_stride_dos_returns_denial_of_service():
    assert _tags_to_stride(["dos"]) == "Denial of Service"


def test_tags_to_stride_unknown_tag_returns_none():
    assert _tags_to_stride(["unknown-tag"]) is None


def test_tags_to_stride_empty_list_returns_none():
    assert _tags_to_stride([]) is None


def test_tags_to_stride_cve_maps_to_elevation_of_privilege():
    """'cve' tag is the default fallback for unclassified CVEs."""
    assert _tags_to_stride(["cve"]) == "Elevation of Privilege"


def test_tags_to_stride_semgrep_jwt_maps_to_spoofing():
    assert _tags_to_stride(["semgrep", "sast", "jwt"]) == "Tampering"
    assert _tags_to_stride(["jwt", "semgrep", "sast"]) == "Spoofing"


def test_tags_to_stride_dependency_maps_to_tampering():
    assert _tags_to_stride(["osv", "dependency"]) == "Tampering"


def test_tags_to_stride_iac_misconfiguration_maps_to_elevation():
    assert _tags_to_stride(["iac", "misconfiguration"]) == "Elevation of Privilege"


def test_tags_to_stride_multi_tag_first_match_wins():
    """['sqli', 'owasp'] — sqli matches first, owasp has no mapping."""
    result = _tags_to_stride(["sqli", "owasp"])
    assert result == "Tampering"


def test_tags_to_stride_non_matching_before_matching():
    """Unknown tag before a known tag — should keep scanning."""
    result = _tags_to_stride(["owasp", "dos"])
    assert result == "Denial of Service"


def test_tags_to_stride_positive_tag_returns_none():
    """Tags like 'hsts' map to None (positive signal, not a STRIDE threat)."""
    assert _tags_to_stride(["hsts"]) is None


def test_tags_to_stride_case_insensitive():
    """Tag matching must be case-insensitive."""
    assert _tags_to_stride(["SQLI"]) == "Tampering"
    assert _tags_to_stride(["Exposure"]) == "Information Disclosure"


def test_global_target_matching_requires_boundary_after_path_prefix():
    finding = _finding(["sast"], "high")
    finding.matched_at = "/repository-other/app.py:12"
    finding.raw_output = {
        "threatgenix_validation": {
            "tool_name": "semgrep",
            "target": "/different",
            "deterministic": True,
        }
    }

    assert _finding_matches_global_target(finding, {"/repo"}) is False

    finding.matched_at = "/repo/app.py:12"
    assert _finding_matches_global_target(finding, {"/repo"}) is True


# ---------------------------------------------------------------------------
# _finding_confirms
# ---------------------------------------------------------------------------


def test_finding_confirms_critical_is_true():
    assert _finding_confirms(_finding([], "critical")) is True


def test_finding_confirms_high_is_true():
    assert _finding_confirms(_finding([], "high")) is True


def test_finding_confirms_medium_is_true():
    assert _finding_confirms(_finding([], "medium")) is True


def test_finding_confirms_low_is_false():
    assert _finding_confirms(_finding([], "low")) is False


def test_finding_confirms_info_is_false():
    assert _finding_confirms(_finding([], "info")) is False


def test_finding_confirms_unknown_is_false():
    assert _finding_confirms(_finding([], "unknown")) is False


# ---------------------------------------------------------------------------
# _finding_mitigates
# ---------------------------------------------------------------------------


def test_finding_mitigates_info_with_hsts_is_true():
    assert _finding_mitigates(_finding(["hsts"], "info")) is True


def test_finding_mitigates_info_with_csp_is_true():
    assert _finding_mitigates(_finding(["csp"], "info")) is True


def test_finding_mitigates_info_with_tls_is_true():
    assert _finding_mitigates(_finding(["tls"], "info")) is True


def test_finding_mitigates_info_with_security_headers_is_true():
    assert _finding_mitigates(_finding(["security-headers"], "info")) is True


def test_finding_mitigates_info_with_sqli_is_false():
    """sqli is not a positive signal."""
    assert _finding_mitigates(_finding(["sqli"], "info")) is False


def test_finding_mitigates_high_with_hsts_is_false():
    """Even a positive tag won't mitigate if severity is not info."""
    assert _finding_mitigates(_finding(["hsts"], "high")) is False


def test_finding_mitigates_critical_with_hsts_is_false():
    assert _finding_mitigates(_finding(["hsts"], "critical")) is False


def test_finding_mitigates_info_empty_tags_is_false():
    assert _finding_mitigates(_finding([], "info")) is False


def test_finding_mitigates_info_with_cors_safe_is_true():
    assert _finding_mitigates(_finding(["cors-safe"], "info")) is True


def test_finding_mitigates_tag_case_insensitive():
    """Positive tag matching should be case-insensitive."""
    assert _finding_mitigates(_finding(["HSTS"], "info")) is True


@pytest.mark.asyncio
async def test_run_semantic_mapping_confirms_matching_threat_with_cves():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    finding = ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=scan_job_id,
        template_id="cves/2026/vendor-auth-bypass",
        template_name="Vendor Auth Bypass",
        severity="high",
        matched_at="https://api.example.com/callbacks/vendor",
        cve_ids=["CVE-2026-1111"],
        tags=["auth-bypass", "cve"],
        raw_output={},
    )
    db = _fake_db(
        _ScalarOneResult(_job(scan_job_id, threat_model_id, {str(node_id): "https://api.example.com"})),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult(
            [
                _threat(
                    threat_id,
                    node_id,
                    stride_category="Spoofing",
                    description="Authentication Service JWT validation can be bypassed.",
                )
            ]
        ),
        _ScalarOneResult(None),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert len(db.added) == 1
    result = db.added[0]
    assert result.scan_job_id == scan_job_id
    assert result.threat_id == threat_id
    assert result.scan_status == "confirmed"
    assert result.cve_ids == ["CVE-2026-1111"]
    assert result.evidence == [
        {
            "finding_id": str(finding.id),
            "template_id": "cves/2026/vendor-auth-bypass",
            "template_name": "Vendor Auth Bypass",
            "severity": "high",
            "matched_at": "https://api.example.com/callbacks/vendor",
            "cve_ids": ["CVE-2026-1111"],
            "tool_name": None,
            "tool_version": None,
            "validation_target": None,
            "deterministic": None,
            "evidence_scope": "node_bound",
            "confidence_label": "validated",
            "risk_score": 80,
            "proof_class": "unknown",
            "evidence_quality": "moderate",
            "match_explanation": (
                "validation tool finding matched Spoofing evidence on target "
                "https://api.example.com and was bound to affected DFD node(s): "
                f"{node_id}."
            ),
            "matched_node_ids": [str(node_id)],
        }
    ]


@pytest.mark.asyncio
async def test_run_semantic_mapping_confirms_nuclei_adapter_finding():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    evidence = NucleiValidationAdapter().parse_json_line(
        "https://api.example.com",
        {
            "template-id": "http/cves/2026/vendor-auth-bypass",
            "info": {
                "name": "Vendor Auth Bypass",
                "severity": "high",
                "tags": "auth-bypass,cve",
                "classification": {"cve-id": "CVE-2026-1111"},
            },
            "matched-at": "https://api.example.com/callbacks/vendor",
        },
    )
    assert evidence is not None
    finding = evidence.to_scan_finding(scan_job_id)
    finding.id = uuid.uuid4()
    db = _fake_db(
        _ScalarOneResult(_job(scan_job_id, threat_model_id, {str(node_id): "https://api.example.com"})),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult([_threat(threat_id, node_id, stride_category="Spoofing")]),
        _ScalarOneResult(None),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert len(db.added) == 1
    result = db.added[0]
    assert result.scan_status == "confirmed"
    assert result.cve_ids == ["CVE-2026-1111"]
    assert result.evidence[0]["template_id"] == "http/cves/2026/vendor-auth-bypass"
    assert result.evidence[0]["tool_name"] == "nuclei"
    assert result.evidence[0]["validation_target"] == "https://api.example.com"
    assert result.evidence[0]["deterministic"] is True
    assert result.evidence[0]["confidence_label"] == "validated"
    assert result.evidence[0]["evidence_scope"] == "node_bound"


@pytest.mark.asyncio
async def test_run_semantic_mapping_skips_unbound_repository_evidence():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    evidence = SemgrepValidationAdapter().parse_json_document(
        "/repo",
        {
            "results": [
                {
                    "check_id": "python.jwt.decode-without-verify",
                    "path": "app/auth.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "JWT verification disabled",
                        "severity": "ERROR",
                        "metadata": {"technology": ["jwt"], "category": "security"},
                    },
                }
            ]
        },
    )[0]
    finding = evidence.to_scan_finding(scan_job_id)
    finding.id = uuid.uuid4()
    db = _fake_db(
        _ScalarOneResult(
            _job(
                scan_job_id,
                threat_model_id,
                {"direct": "/repo"},
                target_type="repository_path",
            )
        ),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult([_threat(threat_id, node_id, stride_category="Spoofing")]),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert db.added == []


@pytest.mark.asyncio
async def test_run_semantic_mapping_confirms_node_bound_semgrep_evidence():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    evidence = SemgrepValidationAdapter().parse_json_document(
        "/repo",
        {
            "results": [
                {
                    "check_id": "python.jwt.decode-without-verify",
                    "path": "app/auth.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "JWT verification disabled",
                        "severity": "ERROR",
                        "metadata": {"technology": ["jwt"], "category": "security"},
                    },
                }
            ]
        },
    )[0]
    finding = evidence.to_scan_finding(scan_job_id)
    finding.id = uuid.uuid4()
    db = _fake_db(
        _ScalarOneResult(
            _job(
                scan_job_id,
                threat_model_id,
                {str(node_id): "/repo"},
                target_type="repository_path",
            )
        ),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult([_threat(threat_id, node_id, stride_category="Spoofing")]),
        _ScalarOneResult(None),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert len(db.added) == 1
    result = db.added[0]
    assert result.scan_status == "confirmed"
    assert result.evidence[0]["tool_name"] == "semgrep"
    assert result.evidence[0]["validation_target"] == "/repo"
    assert result.evidence[0]["confidence_label"] == "validated"
    assert result.evidence[0]["matched_node_ids"] == [str(node_id)]


@pytest.mark.asyncio
async def test_run_semantic_mapping_demotes_node_bound_semantic_mismatch_to_indicated():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    evidence = SemgrepValidationAdapter().parse_json_document(
        "/repo",
        {
            "results": [
                {
                    "check_id": "python.jwt.decode-without-verify",
                    "path": "services/auth/token.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "JWT verification disabled",
                        "severity": "ERROR",
                        "metadata": {"technology": ["jwt"], "category": "security"},
                    },
                }
            ]
        },
    )[0]
    finding = evidence.to_scan_finding(scan_job_id)
    finding.id = uuid.uuid4()
    db = _fake_db(
        _ScalarOneResult(
            _job(
                scan_job_id,
                threat_model_id,
                {str(node_id): "/repo"},
                target_type="repository_path",
            )
        ),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult(
            [
                _threat(
                    threat_id,
                    node_id,
                    stride_category="Spoofing",
                    description=(
                        "The Key/secret retrieval data flow from Authentication Service "
                        "to Secrets Manager could be spoofed to inject forged requests."
                    ),
                )
            ]
        ),
        _ScalarOneResult(None),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert len(db.added) == 1
    result = db.added[0]
    assert result.scan_status == "confirmed"
    assert result.evidence[0]["confidence_label"] == "indicated"
    assert result.evidence[0]["evidence_scope"] == "node_bound_semantic_gap"
    assert "does not share mechanism keywords" in result.evidence[0]["match_explanation"]


@pytest.mark.asyncio
async def test_run_semantic_mapping_surfaces_node_bound_cross_stride_evidence_as_indicated():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    evidence = SemgrepValidationAdapter().parse_json_document(
        "/repo",
        {
            "results": [
                {
                    "check_id": "python.jwt.decode-without-verify",
                    "path": "app/auth.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "JWT verification disabled",
                        "severity": "ERROR",
                        "metadata": {"technology": ["jwt"], "category": "security"},
                    },
                }
            ]
        },
    )[0]
    finding = evidence.to_scan_finding(scan_job_id)
    finding.id = uuid.uuid4()
    db = _fake_db(
        _ScalarOneResult(
            _job(
                scan_job_id,
                threat_model_id,
                {str(node_id): "/repo"},
                target_type="repository_path",
            )
        ),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult(
            [
                _threat(
                    threat_id,
                    node_id,
                    stride_category="Tampering",
                    description="Payment request tampering reaches the auth component.",
                )
            ]
        ),
        _ScalarOneResult(None),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert len(db.added) == 1
    result = db.added[0]
    assert result.scan_status == "confirmed"
    assert result.evidence[0]["confidence_label"] == "indicated"
    assert result.evidence[0]["evidence_scope"] == "node_bound_stride_gap"
    assert result.evidence[0]["matched_node_ids"] == [str(node_id)]


@pytest.mark.asyncio
async def test_run_semantic_mapping_marks_global_url_evidence_as_indicated():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    evidence = NucleiValidationAdapter().parse_json_line(
        "https://api.example.com",
        {
            "template-id": "http/cves/2026/vendor-auth-bypass",
            "info": {
                "name": "Vendor Auth Bypass",
                "severity": "high",
                "tags": "auth-bypass,cve",
                "classification": {"cve-id": "CVE-2026-1111"},
            },
            "matched-at": "https://api.example.com/callbacks/vendor",
        },
    )
    assert evidence is not None
    finding = evidence.to_scan_finding(scan_job_id)
    finding.id = uuid.uuid4()
    db = _fake_db(
        _ScalarOneResult(_job(scan_job_id, threat_model_id, {"direct": "https://api.example.com"})),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult([_threat(threat_id, node_id, stride_category="Spoofing")]),
        _ScalarOneResult(None),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert len(db.added) == 1
    result = db.added[0]
    assert result.scan_status == "confirmed"
    assert result.evidence[0]["confidence_label"] == "indicated"
    assert result.evidence[0]["evidence_scope"] == "global_target"
    assert result.evidence[0]["matched_node_ids"] == []
    assert "Treat as indicated" in result.evidence[0]["match_explanation"]


@pytest.mark.asyncio
async def test_real_world_bank_scenario_keeps_unbound_global_evidence_out_of_mapping():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threats = [
        _threat(uuid.uuid4(), node_id, stride_category="Spoofing"),
        _threat(uuid.uuid4(), node_id, stride_category="Tampering"),
        _threat(uuid.uuid4(), node_id, stride_category="Information Disclosure"),
        _threat(uuid.uuid4(), node_id, stride_category="Elevation of Privilege"),
    ]
    semgrep = SemgrepValidationAdapter().parse_json_document(
        "/repo",
        {
            "results": [
                {
                    "check_id": "python.jwt.decode-without-verify",
                    "path": "app/auth.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "JWT verification disabled",
                        "severity": "ERROR",
                        "metadata": {"technology": ["jwt"], "category": "security"},
                    },
                }
            ]
        },
    )[0]
    osv = OSVScannerValidationAdapter().parse_json_document(
        "/repo/package-lock.json",
        {
            "results": [
                {
                    "source": {"path": "package-lock.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "left-pad", "version": "1.3.0", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-aaaa-bbbb-cccc",
                                    "aliases": ["CVE-2026-2222"],
                                    "summary": "Prototype pollution",
                                    "severity": [{"type": "CVSS_V3", "score": "7.5/CVSS:3.1"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    )[0]
    checkov = CheckovValidationAdapter().parse_json_document(
        "/repo/infra",
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "check_name": "S3 bucket allows public read",
                        "file_path": "/s3.tf",
                        "file_line_range": [8, 20],
                        "resource": "aws_s3_bucket.public",
                        "severity": "HIGH",
                    }
                ]
            }
        },
    )[0]
    trivy = TrivyValidationAdapter().parse_json_document(
        "/repo",
        {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Class": "config",
                    "Type": "dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "AVD-DS-0002",
                            "Title": "Root user",
                            "Severity": "HIGH",
                            "CauseMetadata": {"Resource": "USER root", "StartLine": 12},
                        }
                    ],
                }
            ]
        },
    )[0]
    findings = []
    for evidence in [semgrep, osv, checkov, trivy]:
        finding = evidence.to_scan_finding(scan_job_id)
        finding.id = uuid.uuid4()
        findings.append(finding)

    db = _fake_db(
        _ScalarOneResult(
            _job(
                scan_job_id,
                threat_model_id,
                {
                    "direct:repo": "/repo",
                    "direct:lockfile": "/repo/package-lock.json",
                    "direct:iac": "/repo/infra",
                },
                target_type="repository_path",
            )
        ),
        _ScalarsAllResult(findings),
        _ScalarsAllResult(threats),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert db.added == []


@pytest.mark.asyncio
async def test_osv_package_finding_binds_to_modeled_dfd_component():
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    evidence = OSVScannerValidationAdapter().parse_json_document(
        "/repo/requirements.txt",
        {
            "results": [
                {
                    "source": {"path": "requirements.txt", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "django",
                                "version": "3.2.0",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-django-dependency-tampering",
                                    "aliases": ["CVE-2026-4242"],
                                    "summary": "Django dependency vulnerability permits request tampering",
                                    "severity": [
                                        {"type": "CVSS_V3", "score": "8.1/CVSS:3.1"}
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    )[0]

    unbound_scan_job_id = uuid.uuid4()
    unbound_finding = evidence.to_scan_finding(
        unbound_scan_job_id,
        target_type="lockfile",
    )
    unbound_finding.id = uuid.uuid4()
    unbound_db = _fake_db(
        _ScalarOneResult(
            _job(
                unbound_scan_job_id,
                threat_model_id,
                {"ingested": "/repo/requirements.txt"},
                target_type="lockfile",
            )
        ),
        _ScalarsAllResult([unbound_finding]),
        _ScalarsAllResult(
            [
                _threat(
                    threat_id,
                    node_id,
                    stride_category="Tampering",
                    description="Django dependency vulnerability permits package tampering.",
                )
            ]
        ),
    )

    await run_semantic_mapping(unbound_db, unbound_scan_job_id)

    assert unbound_db.added == []

    bound_scan_job_id = uuid.uuid4()
    bound_finding = evidence.to_scan_finding(
        bound_scan_job_id,
        target_type="lockfile",
    )
    bound_finding.id = uuid.uuid4()
    bound_db = _fake_db(
        _ScalarOneResult(
            _job(
                bound_scan_job_id,
                threat_model_id,
                {str(node_id): "package:django"},
                target_type="lockfile",
            )
        ),
        _ScalarsAllResult([bound_finding]),
        _ScalarsAllResult(
            [
                _threat(
                    threat_id,
                    node_id,
                    stride_category="Tampering",
                    description="Django dependency vulnerability permits package tampering.",
                )
            ]
        ),
        _ScalarOneResult(None),
    )

    await run_semantic_mapping(bound_db, bound_scan_job_id)

    assert len(bound_db.added) == 1
    result = bound_db.added[0]
    assert result.scan_status == "confirmed"
    assert result.cve_ids == ["CVE-2026-4242"]
    assert result.evidence[0]["tool_name"] == "osv-scanner"
    assert result.evidence[0]["confidence_label"] == "validated"
    assert result.evidence[0]["evidence_scope"] == "node_bound"
    assert result.evidence[0]["matched_node_ids"] == [str(node_id)]


@pytest.mark.asyncio
async def test_run_semantic_mapping_marks_matching_positive_control_as_mitigated():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    finding = ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=scan_job_id,
        template_id="http/hsts-present",
        template_name="HSTS Present",
        severity="info",
        matched_at="https://api.example.com/login",
        cve_ids=[],
        tags=["hsts", "security-headers"],
        raw_output={},
    )
    db = _fake_db(
        _ScalarOneResult(_job(scan_job_id, threat_model_id, {str(node_id): "https://api.example.com"})),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult([_threat(threat_id, node_id, stride_category="Spoofing")]),
        _ScalarOneResult(None),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert len(db.added) == 1
    result = db.added[0]
    assert result.scan_status == "mitigated"
    assert result.evidence == []
    assert result.cve_ids == []


@pytest.mark.asyncio
async def test_run_semantic_mapping_confirms_low_negative_finding_instead_of_mitigated():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    finding = ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=scan_job_id,
        template_id="threatgenix-missing-security-headers",
        template_name="Missing security headers",
        severity="low",
        matched_at="https://api.example.com/",
        cve_ids=[],
        tags=["misconfig", "headers"],
        raw_output={},
    )
    db = _fake_db(
        _ScalarOneResult(_job(scan_job_id, threat_model_id, {str(node_id): "https://api.example.com"})),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult(
            [
                _threat(
                    threat_id,
                    node_id,
                    stride_category="Elevation of Privilege",
                    description="Missing security headers on the API service.",
                )
            ]
        ),
        _ScalarOneResult(None),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert len(db.added) == 1
    result = db.added[0]
    assert result.scan_status == "confirmed"
    assert result.evidence[0]["confidence_label"] == "validated"
    assert result.evidence[0]["risk_score"] == 25


@pytest.mark.asyncio
async def test_run_semantic_mapping_marks_unscanned_affected_node_unverifiable():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    scanned_node_id = uuid.uuid4()
    affected_node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    db = _fake_db(
        _ScalarOneResult(
            _job(scan_job_id, threat_model_id, {str(scanned_node_id): "https://api.example.com"})
        ),
        _ScalarsAllResult([]),
        _ScalarsAllResult([_threat(threat_id, affected_node_id, stride_category="Tampering")]),
        _ScalarOneResult(None),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert len(db.added) == 1
    assert db.added[0].scan_status == "unverifiable"

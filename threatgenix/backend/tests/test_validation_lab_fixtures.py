from __future__ import annotations

from pathlib import Path

from app.services.validation_tools import (
    CheckovValidationAdapter,
    OSVScannerValidationAdapter,
    SemgrepValidationAdapter,
    TrivyValidationAdapter,
)

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "validation_lab"
OUTPUTS = FIXTURE_ROOT / "outputs"


def _fixture(name: str) -> str:
    return (OUTPUTS / name).read_text(encoding="utf-8")


def test_validation_lab_semgrep_jwt_finding_parses_to_spoofing_signal():
    findings = SemgrepValidationAdapter().parse_output(
        str(FIXTURE_ROOT),
        _fixture("semgrep-jwt.json"),
    )

    assert len(findings) == 1
    assert findings[0].tool_name == "semgrep"
    assert findings[0].severity == "high"
    assert "jwt" in findings[0].tags
    assert "sast" in findings[0].tags


def test_validation_lab_osv_dependency_finding_preserves_cve():
    findings = OSVScannerValidationAdapter().parse_output(
        str(FIXTURE_ROOT / "requirements.txt"),
        _fixture("osv-requirements.json"),
    )

    assert len(findings) == 1
    assert findings[0].tool_name == "osv-scanner"
    assert findings[0].cve_ids == ["CVE-2022-29217"]
    assert "dependency" in findings[0].tags


def test_validation_lab_trivy_mixed_findings_parse_vuln_container_and_iac():
    findings = TrivyValidationAdapter().parse_output(
        str(FIXTURE_ROOT),
        _fixture("trivy-fs.json"),
    )

    assert {finding.template_id for finding in findings} == {
        "CVE-2022-29217",
        "AVD-DS-0002",
        "AVD-AWS-0086",
    }
    assert {finding.severity for finding in findings} == {"high"}
    assert (FIXTURE_ROOT / "Dockerfile").is_file()
    assert any(finding.matched_url == "Dockerfile:8" for finding in findings)


def test_validation_lab_checkov_public_storage_finding_gets_exposure_tag():
    findings = CheckovValidationAdapter().parse_output(
        str(FIXTURE_ROOT / "infra"),
        _fixture("checkov-s3.json"),
    )

    assert len(findings) == 1
    assert findings[0].tool_name == "checkov"
    assert findings[0].template_id == "CKV_AWS_55"
    assert "iac" in findings[0].tags
    assert "exposure" in findings[0].tags

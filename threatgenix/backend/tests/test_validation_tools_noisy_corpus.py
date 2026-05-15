from __future__ import annotations

from pathlib import Path

import pytest

from app.services.validation_tools import (
    CheckovValidationAdapter,
    NucleiValidationAdapter,
    OSVScannerValidationAdapter,
    SemgrepValidationAdapter,
    TrivyValidationAdapter,
    TrufflehogValidationAdapter,
    ValidationToolAdapter,
)


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "validation_noisy_outputs"


@pytest.mark.parametrize(
    ("adapter", "target", "fixture_name", "expected_template_ids"),
    [
        (
            NucleiValidationAdapter(),
            "https://api.example.com",
            "nuclei-noisy.jsonl",
            {
                "http/cves/2026/vendor-auth-bypass",
                "http/exposures/debug-panel",
            },
        ),
        (
            SemgrepValidationAdapter(),
            "/repo",
            "semgrep-noisy.json",
            {"python.jwt.decode-without-verify"},
        ),
        (
            OSVScannerValidationAdapter(),
            "/repo/package-lock.json",
            "osv-noisy.json",
            {"GHSA-aaaa-bbbb-cccc"},
        ),
        (
            TrivyValidationAdapter(),
            "/repo",
            "trivy-noisy.json",
            {"AVD-DS-0002", "CVE-2026-3333"},
        ),
        (
            CheckovValidationAdapter(),
            "/repo/infra",
            "checkov-noisy.json",
            {"CKV_AWS_20"},
        ),
        (
            TrufflehogValidationAdapter(),
            "/repo",
            "trufflehog-noisy.jsonl",
            {"trufflehog-aws", "trufflehog-slack"},
        ),
    ],
)
def test_validation_adapters_keep_signal_from_noisy_corpus(
    adapter: ValidationToolAdapter,
    target: str,
    fixture_name: str,
    expected_template_ids: set[str],
) -> None:
    output = (FIXTURE_ROOT / fixture_name).read_text(encoding="utf-8")

    findings = adapter.parse_output(target, output)

    assert {finding.template_id for finding in findings} == expected_template_ids
    assert len(findings) == len(expected_template_ids)
    assert all(finding.tool_name == adapter.name for finding in findings)
    assert all(finding.finding_title for finding in findings)
    assert all(finding.matched_url for finding in findings)

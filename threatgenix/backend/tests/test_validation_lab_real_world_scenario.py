from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.scan import ScanFinding
from app.services.scan_mapper import run_semantic_mapping
from app.services.validation_tools import (
    CheckovValidationAdapter,
    NucleiValidationAdapter,
    OSVScannerValidationAdapter,
    SemgrepValidationAdapter,
    TrivyValidationAdapter,
)


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "validation_lab"
OUTPUTS = FIXTURE_ROOT / "outputs"


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


def _job(scan_job_id: uuid.UUID, threat_model_id: uuid.UUID, target: str, node_id: uuid.UUID, target_type: str):
    return SimpleNamespace(
        id=scan_job_id,
        threat_model_id=threat_model_id,
        targets={str(node_id): target},
        target_type=target_type,
    )


def _threat(threat_id: uuid.UUID, node_id: uuid.UUID, stride_category: str):
    return SimpleNamespace(
        id=threat_id,
        status="Open",
        affected_node_ids=[node_id],
        stride_category=stride_category,
    )


async def _map_single_evidence(evidence, *, target_type: str, expected_stride: str):
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    finding: ScanFinding = evidence.to_scan_finding(scan_job_id)
    finding.id = uuid.uuid4()
    db = _fake_db(
        _ScalarOneResult(
            _job(scan_job_id, threat_model_id, evidence.target, node_id, target_type)
        ),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult([_threat(threat_id, node_id, expected_stride)]),
        _ScalarOneResult(None),
    )

    await run_semantic_mapping(db, scan_job_id)

    assert len(db.added) == 1
    return db.added[0]


@pytest.mark.asyncio
async def test_real_world_banking_validation_tools_map_to_semantic_threats():
    """Seasoned-engineer scenario: bank payment API evidence qualifies semantic threats."""
    api_url = "https://api.northstar-bank.example"

    cases = [
        (
            "nuclei",
            NucleiValidationAdapter().parse_json_line(
                api_url,
                {
                    "template-id": "http/cves/2026/vendor-auth-bypass",
                    "info": {
                        "name": "Vendor auth bypass in payment callback",
                        "severity": "high",
                        "tags": "auth-bypass,cve",
                        "classification": {"cve-id": "CVE-2026-1111"},
                    },
                    "matched-at": f"{api_url}/callbacks/vendor",
                },
            ),
            "url",
            "Spoofing",
            "deterministic",
        ),
        (
            "semgrep",
            SemgrepValidationAdapter().parse_output(
                str(FIXTURE_ROOT),
                (OUTPUTS / "semgrep-jwt.json").read_text(encoding="utf-8"),
            )[0],
            "repository_path",
            "Spoofing",
            "deterministic",
        ),
        (
            "osv-scanner",
            OSVScannerValidationAdapter().parse_output(
                str(FIXTURE_ROOT / "requirements.txt"),
                (OUTPUTS / "osv-requirements.json").read_text(encoding="utf-8"),
            )[0],
            "lockfile",
            "Tampering",
            "deterministic",
        ),
        (
            "trivy",
            TrivyValidationAdapter().parse_output(
                str(FIXTURE_ROOT),
                (OUTPUTS / "trivy-fs.json").read_text(encoding="utf-8"),
            )[0],
            "repository_path",
            "Tampering",
            "deterministic",
        ),
        (
            "checkov",
            CheckovValidationAdapter().parse_output(
                str(FIXTURE_ROOT / "infra"),
                (OUTPUTS / "checkov-s3.json").read_text(encoding="utf-8"),
            )[0],
            "iac_directory",
            "Information Disclosure",
            "deterministic",
        ),
    ]

    for expected_tool, evidence, target_type, expected_stride, expected_proof_class in cases:
        assert evidence is not None
        result = await _map_single_evidence(
            evidence,
            target_type=target_type,
            expected_stride=expected_stride,
        )

        assert result.scan_status == "confirmed"
        assert result.evidence[0]["tool_name"] == expected_tool
        assert result.evidence[0]["confidence_label"] == "validated"
        assert result.evidence[0]["evidence_scope"] == "node_bound"
        assert result.evidence[0]["proof_class"] == expected_proof_class
        assert result.evidence[0]["risk_score"] >= 55

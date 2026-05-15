from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.scan import ScanExecutionArtifact, ScanFinding, ScanJob, ScanThreatResult
from app.services.validation_runbook import build_validation_runbook


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


class _RowsResult:
    def __init__(self, values):
        self.values = values

    def all(self):
        return self.values


def _fake_db(*results):
    return SimpleNamespace(execute=AsyncMock(side_effect=results))


def _threat(threat_id: uuid.UUID, *, display_id: str = "T-001"):
    return SimpleNamespace(
        id=threat_id,
        display_id=display_id,
        description="JWT verification can be bypassed",
        severity="High",
        stride_category="Spoofing",
        status="Open",
    )


@pytest.mark.asyncio
async def test_validation_runbook_reports_unbound_repository_evidence():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    finding = ScanFinding(
        id=uuid.uuid4(),
        scan_job_id=scan_job_id,
        template_id="python.jwt.decode-without-verify",
        template_name="JWT verification disabled",
        severity="high",
        matched_at="app/auth.py:42",
        cve_ids=[],
        tags=["semgrep", "jwt", "sast"],
        raw_output={
            "threatgenix_validation": {
                "tool_name": "semgrep",
                "target": "/repo",
                "deterministic": True,
            }
        },
    )
    artifact = ScanExecutionArtifact(
        scan_job_id=scan_job_id,
        source="ingest",
        tool_name="semgrep",
        target_type="repository_path",
        target="repo (sha256:test)",
        status="completed",
        deterministic=True,
        sandboxed=False,
        command=[],
        command_redacted=True,
        timed_out=False,
        output_limit_exceeded=False,
        stdout_bytes=256,
    )
    scan_job = ScanJob(
        id=scan_job_id,
        threat_model_id=threat_model_id,
        owner_id=uuid.uuid4(),
        status="completed",
        scan_type="unauthenticated",
        scope="external",
        tool_name="semgrep",
        target_type="repository_path",
        targets={"direct": "/repo"},
        finding_count=1,
        completed_at=datetime(2026, 4, 25, tzinfo=timezone.utc),
    )
    active_threat = _threat(uuid.uuid4())
    db = _fake_db(
        _ScalarOneResult(scan_job),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult([artifact]),
        _RowsResult([]),
        _ScalarsAllResult([active_threat]),
    )

    runbook = await build_validation_runbook(db, scan_job_id)

    assert runbook is not None
    assert runbook.coverage.target_binding == "global"
    assert runbook.coverage.finding_count == 1
    assert runbook.coverage.unbound_finding_count == 1
    assert runbook.coverage.untested_threat_count == 1
    assert runbook.unbound_findings[0].title == "JWT verification disabled"
    assert "not bound to a semantic threat" in runbook.unbound_findings[0].explanation
    assert "1 active threat(s) still need validation evidence." in runbook.gaps


@pytest.mark.asyncio
async def test_validation_runbook_counts_node_bound_validated_threat():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    finding = ScanFinding(
        id=finding_id,
        scan_job_id=scan_job_id,
        template_id="http/cves/2026/vendor-auth-bypass",
        template_name="Vendor Auth Bypass",
        severity="high",
        matched_at="https://api.example.com/admin",
        cve_ids=["CVE-2026-1111"],
        tags=["auth-bypass", "cve"],
        raw_output={
            "threatgenix_validation": {
                "tool_name": "nuclei",
                "target": "https://api.example.com",
                "deterministic": True,
            }
        },
    )
    scan_job = ScanJob(
        id=scan_job_id,
        threat_model_id=threat_model_id,
        owner_id=uuid.uuid4(),
        status="completed",
        scan_type="unauthenticated",
        scope="external",
        tool_name="nuclei",
        target_type="url",
        targets={str(node_id): "https://api.example.com"},
        finding_count=1,
        completed_at=datetime(2026, 4, 25, tzinfo=timezone.utc),
    )
    threat_result = ScanThreatResult(
        scan_job_id=scan_job_id,
        threat_id=threat_id,
        scan_status="confirmed",
        evidence=[
            {
                "finding_id": str(finding_id),
                "template_id": finding.template_id,
                "template_name": finding.template_name,
                "severity": finding.severity,
                "matched_at": finding.matched_at,
                "cve_ids": finding.cve_ids,
                "tool_name": "nuclei",
                "validation_target": "https://api.example.com",
                "deterministic": True,
                "confidence_label": "validated",
                "evidence_scope": "node_bound",
                "match_explanation": "nuclei finding matched Spoofing evidence.",
                "matched_node_ids": [str(node_id)],
            }
        ],
        cve_ids=["CVE-2026-1111"],
    )
    active_threat = _threat(threat_id)
    db = _fake_db(
        _ScalarOneResult(scan_job),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult([]),
        _RowsResult([(threat_result, active_threat)]),
        _ScalarsAllResult([active_threat]),
    )

    runbook = await build_validation_runbook(db, scan_job_id)

    assert runbook is not None
    assert runbook.coverage.target_binding == "node_bound"
    assert runbook.coverage.validated_threat_count == 1
    assert runbook.coverage.unbound_finding_count == 0
    assert runbook.coverage.untested_threat_count == 0
    assert runbook.mapped_threats[0].confidence_label == "validated"


@pytest.mark.asyncio
async def test_validation_runbook_does_not_double_count_indicated_findings_as_unbound():
    scan_job_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    finding = ScanFinding(
        id=finding_id,
        scan_job_id=scan_job_id,
        template_id="http/cves/2026/vendor-auth-bypass",
        template_name="Vendor Auth Bypass",
        severity="high",
        matched_at="https://api.example.com/admin",
        cve_ids=["CVE-2026-1111"],
        tags=["auth-bypass", "cve"],
        raw_output={
            "threatgenix_validation": {
                "tool_name": "nuclei",
                "target": "https://api.example.com",
                "deterministic": True,
            }
        },
    )
    scan_job = ScanJob(
        id=scan_job_id,
        threat_model_id=threat_model_id,
        owner_id=uuid.uuid4(),
        status="completed",
        scan_type="unauthenticated",
        scope="external",
        tool_name="nuclei",
        target_type="url",
        targets={"direct": "https://api.example.com"},
        finding_count=1,
        completed_at=datetime(2026, 4, 25, tzinfo=timezone.utc),
    )
    threat_result = ScanThreatResult(
        scan_job_id=scan_job_id,
        threat_id=threat_id,
        scan_status="confirmed",
        evidence=[
            {
                "finding_id": str(finding_id),
                "template_id": finding.template_id,
                "template_name": finding.template_name,
                "severity": finding.severity,
                "matched_at": finding.matched_at,
                "cve_ids": finding.cve_ids,
                "tool_name": "nuclei",
                "validation_target": "https://api.example.com",
                "deterministic": True,
                "confidence_label": "indicated",
                "evidence_scope": "global_target",
                "match_explanation": "Treat as indicated until bound to a DFD node.",
                "matched_node_ids": [],
            }
        ],
        cve_ids=["CVE-2026-1111"],
    )
    active_threat = _threat(threat_id)
    db = _fake_db(
        _ScalarOneResult(scan_job),
        _ScalarsAllResult([finding]),
        _ScalarsAllResult([]),
        _RowsResult([(threat_result, active_threat)]),
        _ScalarsAllResult([active_threat]),
    )

    runbook = await build_validation_runbook(db, scan_job_id)

    assert runbook is not None
    assert runbook.coverage.indicated_threat_count == 1
    assert runbook.coverage.unbound_finding_count == 0
    assert runbook.coverage.untested_threat_count == 0

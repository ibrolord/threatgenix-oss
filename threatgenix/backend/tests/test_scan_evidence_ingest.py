from __future__ import annotations

import json
import hashlib
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import BackgroundTasks, HTTPException, Request

from app.api.scans import create_validation_run, ingest_scan_evidence
from app.models.scan import ScanAuthorization, ScanExecutionArtifact, ScanFinding, ScanJob
from app.schemas.scan import EvidenceIngestRequest, ValidationRunRequest


class FakeUser:
    id = uuid.UUID("00000000-0000-0000-0000-000000000001")


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar_one(self):
        return self._value

    def scalar_one_or_none(self):
        return self._value

    def scalars(self):
        return self

    def all(self):
        return self._value if isinstance(self._value, list) else []


class FakeDB:
    def __init__(self, execute_values: list[object] | None = None) -> None:
        self.added: list[object] = []
        self.created_job: ScanJob | None = None
        self.committed = False
        self.execute_values = execute_values or []

    def add(self, obj: object) -> None:
        self.added.append(obj)
        if isinstance(obj, ScanJob):
            self.created_job = obj
        elif isinstance(obj, ScanFinding) and self.created_job is not None:
            self.created_job.findings.append(obj)
        elif isinstance(obj, ScanExecutionArtifact) and self.created_job is not None:
            self.created_job.execution_artifacts.append(obj)

    async def flush(self) -> None:
        now = datetime(2026, 4, 25, tzinfo=timezone.utc)
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()
            if getattr(obj, "created_at", None) is None:
                obj.created_at = now

    async def commit(self) -> None:
        self.committed = True

    async def refresh(self, obj: object) -> None:
        del obj

    async def execute(self, statement):
        del statement
        if self.execute_values:
            return _Result(self.execute_values.pop(0))
        return _Result(self.created_job)


class FakeAdapter:
    name = "semgrep"

    def is_available(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_ingest_scan_evidence_parses_semgrep_without_executing_tool():
    raw_output = json.dumps(
        {
            "results": [
                {
                    "check_id": "python.jwt.decode-without-verify",
                    "path": "app/auth.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "JWT verification disabled",
                        "severity": "ERROR",
                        "metadata": {"category": "security", "technology": ["python", "jwt"]},
                    },
                }
            ]
        }
    )
    db = FakeDB()
    body = EvidenceIngestRequest(
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        raw_output=raw_output,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        patch("app.api.scans.run_semantic_mapping", new=AsyncMock()) as mapping,
    ):
        response = await ingest_scan_evidence(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert db.committed is True
    assert mapping.await_count == 1
    assert response.tool_name == "semgrep"
    assert response.target_type == "repository_path"
    assert response.finding_count == 1
    findings = [item for item in db.added if isinstance(item, ScanFinding)]
    assert len(findings) == 1
    assert findings[0].tool_name == "semgrep"
    assert findings[0].evidence_origin == "import"
    assert findings[0].synthetic is False
    assert findings[0].template_id == "python.jwt.decode-without-verify"
    assert findings[0].matched_at == "app/auth.py:42"
    artifacts = [item for item in db.added if isinstance(item, ScanExecutionArtifact)]
    assert len(artifacts) == 1
    assert artifacts[0].source == "ingest"
    assert artifacts[0].tool_name == "semgrep"
    assert artifacts[0].target.startswith("repo (sha256:")
    assert artifacts[0].stdout_bytes == len(raw_output.encode("utf-8"))
    assert artifacts[0].output_sha256 == hashlib.sha256(raw_output.encode("utf-8")).hexdigest()
    assert response.execution_artifacts[0].source == "ingest"


@pytest.mark.asyncio
async def test_create_validation_run_persists_job_authorization_and_background_task(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv("THREATGENIX_VALIDATION_SEMGREP_ENABLED", "true")
    db = FakeDB()
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 12345)})
    background_tasks = BackgroundTasks()
    body = ValidationRunRequest(
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        authorization_acknowledged=True,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        patch("app.api.scans._get_validation_tool_or_422", return_value=FakeAdapter()),
    ):
        response = await create_validation_run(
            uuid.uuid4(),
            body,
            request,
            background_tasks,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert db.committed is True
    assert response.tool_name == "semgrep"
    assert response.target_type == "repository_path"
    assert response.targets == {"direct": "/repo"}
    assert any(isinstance(item, ScanAuthorization) for item in db.added)
    assert len(background_tasks.tasks) == 1


@pytest.mark.asyncio
async def test_create_validation_run_in_managed_mode_queues_without_api_background_task(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.delenv("THREATGENIX_VALIDATION_EXECUTION_CONTEXT", raising=False)
    db = FakeDB()
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 12345)})
    background_tasks = BackgroundTasks()
    body = ValidationRunRequest(
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        authorization_acknowledged=True,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        patch("app.api.scans._get_validation_tool_or_422", return_value=FakeAdapter()),
    ):
        response = await create_validation_run(
            uuid.uuid4(),
            body,
            request,
            background_tasks,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert db.committed is True
    assert response.status == "pending"
    assert response.tool_name == "semgrep"
    assert any(isinstance(item, ScanAuthorization) for item in db.added)
    assert len(background_tasks.tasks) == 0


@pytest.mark.asyncio
async def test_create_validation_run_blocks_when_runtime_unset(monkeypatch):
    monkeypatch.delenv("THREATGENIX_VALIDATION_RUNTIME_MODE", raising=False)
    db = FakeDB()
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 12345)})
    body = ValidationRunRequest(
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        authorization_acknowledged=True,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        pytest.raises(HTTPException) as exc_info,
    ):
        await create_validation_run(
            uuid.uuid4(),
            body,
            request,
            BackgroundTasks(),
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert exc_info.value.status_code == 403
    assert "Live validation submission is disabled" in str(exc_info.value.detail)
    assert db.added == []


@pytest.mark.asyncio
async def test_create_validation_run_rejects_unsafe_live_url(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    db = FakeDB()
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 12345)})
    body = ValidationRunRequest(
        tool_name="nuclei",
        target_type="url",
        target="http://127.0.0.1:8080",
        authorization_acknowledged=True,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        pytest.raises(HTTPException) as exc_info,
    ):
        await create_validation_run(
            uuid.uuid4(),
            body,
            request,
            BackgroundTasks(),
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert exc_info.value.status_code == 422
    assert db.added == []


@pytest.mark.asyncio
async def test_ingest_scan_evidence_rejects_unsupported_target_type():
    db = FakeDB()
    body = EvidenceIngestRequest(
        tool_name="nuclei",
        target_type="repository_path",
        target="/repo",
        raw_output="{}",
    )

    with patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())):
        with pytest.raises(HTTPException) as exc:
            await ingest_scan_evidence(
                uuid.uuid4(),
                body,
                db,  # type: ignore[arg-type]
                FakeUser(),  # type: ignore[arg-type]
            )

    assert exc.value.status_code == 422
    assert "does not support target type" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_ingest_scan_evidence_can_target_specific_dfd_node():
    raw_output = json.dumps(
        {
            "results": [
                {
                    "check_id": "python.sqlalchemy.sql-injection",
                    "path": "app/repositories.py",
                    "start": {"line": 11},
                    "extra": {
                        "message": "Possible SQL injection",
                        "severity": "WARNING",
                    },
                }
            ]
        }
    )
    node_id = uuid.uuid4()
    db = FakeDB(execute_values=[SimpleNamespace(id=node_id)])
    body = EvidenceIngestRequest(
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        target_node_id=node_id,
        raw_output=raw_output,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        patch("app.api.scans.run_semantic_mapping", new=AsyncMock()),
    ):
        response = await ingest_scan_evidence(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert response.finding_count == 1
    assert db.created_job is not None
    assert db.created_job.targets == {str(node_id): "/repo"}


@pytest.mark.asyncio
async def test_ingest_scan_evidence_rejects_cross_tenant_target_node_without_persisting():
    threat_model_id = uuid.uuid4()
    node_id = uuid.uuid4()
    db = FakeDB(execute_values=[None])
    body = EvidenceIngestRequest(
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        target_node_id=node_id,
        raw_output=json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.tenant-leak",
                        "path": "app/api.py",
                        "extra": {
                            "message": "Missing tenant filter",
                            "severity": "ERROR",
                        },
                    }
                ]
            }
        ),
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())) as lookup,
        pytest.raises(HTTPException) as exc,
    ):
        await ingest_scan_evidence(
            threat_model_id,
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert exc.value.status_code == 422
    assert "target_node_id does not belong to this threat model" in str(exc.value.detail)
    lookup.assert_awaited_once()
    assert lookup.await_args.args[0] == threat_model_id
    assert lookup.await_args.kwargs["permission"] == "write"
    assert db.added == []
    assert db.committed is False


@pytest.mark.asyncio
async def test_ingest_scan_evidence_rejects_oversized_raw_output():
    db = FakeDB()
    body = EvidenceIngestRequest(
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        raw_output="x" * 5_000_001,
    )

    with patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())):
        with pytest.raises(HTTPException) as exc:
            await ingest_scan_evidence(
                uuid.uuid4(),
                body,
                db,  # type: ignore[arg-type]
                FakeUser(),  # type: ignore[arg-type]
            )

    assert exc.value.status_code == 413
    assert "max_output_bytes=5000000" in str(exc.value.detail)
    assert db.added == []


@pytest.mark.asyncio
async def test_ingest_scan_evidence_parses_nuclei_output():
    raw_output = "\n".join(
        [
            json.dumps(
                {
                    "template-id": "http/cves/2026/vendor-auth-bypass",
                    "info": {
                        "name": "Vendor Auth Bypass",
                        "severity": "high",
                        "tags": "auth-bypass,cve",
                        "classification": {"cve-id": ["CVE-2026-1111"]},
                    },
                    "matched-at": "https://api.example.com/admin",
                }
            )
        ]
    )
    db = FakeDB()
    body = EvidenceIngestRequest(
        tool_name="nuclei",
        target_type="url",
        target="https://api.example.com",
        raw_output=raw_output,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        patch("app.api.scans.run_semantic_mapping", new=AsyncMock()),
    ):
        response = await ingest_scan_evidence(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert response.tool_name == "nuclei"
    assert response.finding_count == 1
    findings = [item for item in db.added if isinstance(item, ScanFinding)]
    assert findings[0].cve_ids == ["CVE-2026-1111"]


@pytest.mark.asyncio
async def test_ingest_scan_evidence_parses_osv_output():
    raw_output = json.dumps(
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
        }
    )
    db = FakeDB()
    body = EvidenceIngestRequest(
        tool_name="osv-scanner",
        target_type="lockfile",
        target="/repo/package-lock.json",
        raw_output=raw_output,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        patch("app.api.scans.run_semantic_mapping", new=AsyncMock()),
    ):
        response = await ingest_scan_evidence(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert response.finding_count == 1
    findings = [item for item in db.added if isinstance(item, ScanFinding)]
    assert findings[0].tool_name == "osv-scanner"
    assert findings[0].cve_ids == ["CVE-2026-2222"]


@pytest.mark.asyncio
async def test_ingest_scan_evidence_parses_trivy_output():
    raw_output = json.dumps(
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
                },
                {
                    "Target": "requirements.txt",
                    "Type": "python-pkg",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-3333",
                            "PkgName": "requests",
                            "InstalledVersion": "2.0.0",
                            "Severity": "CRITICAL",
                            "Title": "TLS bypass",
                        }
                    ],
                },
            ]
        }
    )
    db = FakeDB()
    body = EvidenceIngestRequest(
        tool_name="trivy",
        target_type="repository_path",
        target="/repo",
        raw_output=raw_output,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        patch("app.api.scans.run_semantic_mapping", new=AsyncMock()),
    ):
        response = await ingest_scan_evidence(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert response.finding_count == 2
    findings = [item for item in db.added if isinstance(item, ScanFinding)]
    assert {finding.tool_name for finding in findings} == {"trivy"}
    assert {finding.template_id for finding in findings} == {"AVD-DS-0002", "CVE-2026-3333"}


@pytest.mark.asyncio
async def test_ingest_scan_evidence_parses_checkov_output():
    raw_output = json.dumps(
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
        }
    )
    db = FakeDB()
    body = EvidenceIngestRequest(
        tool_name="checkov",
        target_type="iac_directory",
        target="/repo/infra",
        raw_output=raw_output,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        patch("app.api.scans.run_semantic_mapping", new=AsyncMock()),
    ):
        response = await ingest_scan_evidence(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert response.finding_count == 1
    findings = [item for item in db.added if isinstance(item, ScanFinding)]
    assert findings[0].tool_name == "checkov"
    assert findings[0].template_id == "CKV_AWS_20"


@pytest.mark.asyncio
async def test_ingest_scan_evidence_accepts_external_tool_report():
    raw_output = json.dumps(
        {
            "scanner": "Burp Enterprise",
            "findings": [
                {
                    "id": "BURP-1",
                    "title": "API Gateway unsigned JWT accepted",
                    "severity": "high",
                    "stride": "Spoofing",
                    "target": "API Gateway",
                    "description": "Unsigned JWT tokens are accepted by the API Gateway.",
                }
            ],
        }
    )
    db = FakeDB()
    body = EvidenceIngestRequest(
        tool_name="external-report",
        target_type="url",
        target="External assessment",
        raw_output=raw_output,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        patch("app.api.scans.run_semantic_mapping", new=AsyncMock()) as mapping,
    ):
        response = await ingest_scan_evidence(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert response.tool_name == "external-report"
    assert response.finding_count == 1
    assert mapping.await_count == 1
    findings = [item for item in db.added if isinstance(item, ScanFinding)]
    assert findings[0].tool_name == "external-report"
    assert findings[0].matched_at == "API Gateway"
    assert "spoofing" in findings[0].tags
    artifacts = [item for item in db.added if isinstance(item, ScanExecutionArtifact)]
    assert artifacts[0].tool_name == "external-report"
    assert artifacts[0].deterministic is True


@pytest.mark.asyncio
async def test_ingest_scan_evidence_accepts_node_bound_pentest_report():
    node_id = uuid.uuid4()
    raw_output = "High: API Gateway IDOR permits account takeover"
    db = FakeDB(execute_values=[SimpleNamespace(id=node_id)])
    body = EvidenceIngestRequest(
        tool_name="pentest-report",
        target_type="url",
        target="Q2 pentest report",
        target_node_id=node_id,
        raw_output=raw_output,
    )

    with (
        patch("app.api.scans._get_threat_model_for_owner", new=AsyncMock(return_value=object())),
        patch("app.api.scans.run_semantic_mapping", new=AsyncMock()),
    ):
        response = await ingest_scan_evidence(
            uuid.uuid4(),
            body,
            db,  # type: ignore[arg-type]
            FakeUser(),  # type: ignore[arg-type]
        )

    assert response.tool_name == "pentest-report"
    assert db.created_job is not None
    assert db.created_job.targets == {str(node_id): "Q2 pentest report"}
    findings = [item for item in db.added if isinstance(item, ScanFinding)]
    assert findings[0].deterministic is False
    assert findings[0].matched_at == "Q2 pentest report"

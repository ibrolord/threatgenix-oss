from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.models.application_review import ApplicationSecurityReview
from app.models.application_review_bundle import ApplicationReviewBundle
from app.models.scan import ScanExecutionArtifact, ScanJob
from app.schemas.review_harness_ingest import IngestHarnessOutputRequest
from app.services.application_review import tenant_key_for_user
from app.services.application_review_bundles import build_bundle_integrity, compute_bundle_hash
from app.services.managed_sast import (
    ManagedSastImportError,
    build_managed_sast_harness_output,
    build_sarif_harness_output,
)
from app.services.review_harness_ingest import ingest_review_harness_output
from app.services.review_scanner_enqueue import REVIEW_BUNDLE_TARGET_SCHEME


class _Result:
    def __init__(self, item: object | list[object] | None) -> None:
        self.item = item

    def scalar_one_or_none(self):
        return self.item if not isinstance(self.item, list) else None

    def scalars(self):
        return self

    def all(self):
        return self.item if isinstance(self.item, list) else []


class _FakeSession:
    def __init__(self, execute_results: list[object | list[object] | None]) -> None:
        self.execute_results = list(execute_results)
        self.added: list[object] = []
        self.flush_count = 0

    async def execute(self, statement: object):
        del statement
        return _Result(self.execute_results.pop(0) if self.execute_results else None)

    def add(self, item: object) -> None:
        self.added.append(item)

    async def flush(self) -> None:
        self.flush_count += 1


def _user():
    return SimpleNamespace(id=uuid.uuid4(), organization_id=None, email="owner@example.com")


def _review(user) -> ApplicationSecurityReview:
    now = datetime.now(timezone.utc)
    return ApplicationSecurityReview(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        owner_id=user.id,
        organization_id=None,
        threat_model_id=uuid.uuid4(),
        review_lineage_id=uuid.uuid4(),
        app_name="ExampleApp",
        invocation_surface="cli",
        input_kind="diff",
        status="scanning",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key-1",
        requested_tools=["semgrep"],
        scope={},
        context={},
        policy={},
        created_at=now,
        updated_at=now,
    )


def _bundle(user, review_id: uuid.UUID) -> ApplicationReviewBundle:
    now = datetime.now(timezone.utc)
    manifest = [
        {
            "path": "apps/api/users.py",
            "file_kind": "source",
            "sha256": "a" * 64,
            "byte_size": 120,
            "source": "cli",
        }
    ]
    content_hash = compute_bundle_hash("diff", manifest)
    return ApplicationReviewBundle(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        review_id=review_id,
        owner_id=user.id,
        organization_id=None,
        bundle_kind="diff",
        source="cli",
        status="ready",
        manifest=manifest,
        redaction_report={},
        integrity=build_bundle_integrity(
            bundle_kind="diff",
            manifest=manifest,
            content_hash=content_hash,
            byte_size=120,
            file_count=1,
        ),
        storage_backend="database_manifest",
        encryption_status="metadata_only",
        content_hash=content_hash,
        byte_size=120,
        file_count=1,
        legal_hold=False,
        created_at=now,
        updated_at=now,
    )


def _scan_job(user, review: ApplicationSecurityReview, bundle: ApplicationReviewBundle) -> ScanJob:
    return ScanJob(
        id=uuid.uuid4(),
        threat_model_id=review.threat_model_id,
        owner_id=user.id,
        status="running",
        scan_type="unauthenticated",
        scope="internal",
        tool_name="semgrep",
        target_type="repository_path",
        targets={"bundle": f"{REVIEW_BUNDLE_TARGET_SCHEME}{bundle.id}"},
        nuclei_templates=[],
        finding_count=0,
    )


def _semgrep_output(path: str = "apps/api/users.py") -> dict:
    return {
        "results": [
            {
                "check_id": "python.fastapi.missing-authz",
                "path": path,
                "start": {"line": 42},
                "extra": {
                    "message": "Sensitive export route is missing authorization",
                    "severity": "ERROR",
                    "metadata": {"category": "security", "technology": ["python", "fastapi"]},
                },
            }
        ]
    }


def _sarif_output(path: str = "apps/api/users.py") -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/missing-authorization",
                                "name": "Missing authorization",
                                "properties": {"security-severity": "8.5"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/missing-authorization",
                        "level": "error",
                        "message": {"text": "Export endpoint lacks authorization"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": path},
                                    "region": {"startLine": 42, "endLine": 45},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_managed_sast_normalizes_semgrep_json_to_trusted_harness_output():
    user = _user()
    bundle = _bundle(user, uuid.uuid4())

    output = build_managed_sast_harness_output(
        bundle=bundle,
        raw_output=_semgrep_output(),
        tool_version="1.157.0",
        ruleset_version="threatgenix-semgrep-2026-05-02",
        scanner_run_id="sast-run-1",
        scanner_image="semgrep/semgrep@sha256:abc",
        scanner_image_digest="sha256:abc",
        ruleset_digest="sha256:def",
    )

    assert output.tool_name == "semgrep"
    assert output.provenance.output_format == "semgrep-json"
    assert output.provenance.scanner_image == "semgrep/semgrep@sha256:abc"
    assert output.findings[0].rule_id == "python.fastapi.missing-authz"
    assert output.findings[0].path == "apps/api/users.py"
    assert output.findings[0].severity == "High"
    assert output.findings[0].source_type == "sast"


def test_sarif_import_normalizes_codeql_result_to_review_harness_output():
    user = _user()
    bundle = _bundle(user, uuid.uuid4())

    output = build_sarif_harness_output(
        bundle=bundle,
        sarif=_sarif_output(),
        tool_version="codeql-2.17.0",
        ruleset_version="codeql-security-extended",
        scanner_run_id="sarif-run-1",
    )

    assert output.provenance.output_format == "sarif"
    assert output.findings[0].rule_id == "py/missing-authorization"
    assert output.findings[0].title == "Export endpoint lacks authorization"
    assert output.findings[0].severity == "High"
    assert output.raw_artifact_refs == ["artifact://sarif/sarif-run-1"]


def test_managed_sast_rejects_findings_outside_review_bundle_manifest():
    user = _user()
    bundle = _bundle(user, uuid.uuid4())

    with pytest.raises(ManagedSastImportError, match="bundle root"):
        build_managed_sast_harness_output(
            bundle=bundle,
            raw_output=_semgrep_output(path="../outside.py"),
            tool_version="1.157.0",
            ruleset_version="rules",
            scanner_run_id="bad-run",
        )


@pytest.mark.asyncio
async def test_ingested_managed_sast_output_records_execution_artifact_provenance():
    user = _user()
    review = _review(user)
    bundle = _bundle(user, review.id)
    job = _scan_job(user, review, bundle)
    output = build_managed_sast_harness_output(
        bundle=bundle,
        raw_output=_semgrep_output(),
        tool_version="1.157.0",
        ruleset_version="threatgenix-semgrep-2026-05-02",
        scanner_run_id="sast-run-1",
        scanner_image="semgrep/semgrep@sha256:abc",
        scanner_image_digest="sha256:abc",
        ruleset_digest="sha256:def",
    )
    db = _FakeSession([review, bundle, job, []])

    response = await ingest_review_harness_output(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
        scan_job_id=job.id,
        request=IngestHarnessOutputRequest(bundle_id=bundle.id, output=output),
    )

    artifacts = [item for item in db.added if isinstance(item, ScanExecutionArtifact)]
    assert response.status == "completed"
    assert len(artifacts) == 1
    assert artifacts[0].source == "ingest"
    assert artifacts[0].tool_name == "semgrep"
    assert artifacts[0].target == f"{REVIEW_BUNDLE_TARGET_SCHEME}{bundle.id}"
    assert artifacts[0].container_image == "semgrep/semgrep@sha256:abc"
    assert artifacts[0].output_sha256 is not None

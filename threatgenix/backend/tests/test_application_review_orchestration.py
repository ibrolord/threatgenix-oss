from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.schemas.application_review import ApplicationReviewCreate, ApplicationReviewResponse
from app.schemas.application_review_bundle import (
    ApplicationReviewBundleCreate,
    ApplicationReviewBundleManifestItem,
    ApplicationReviewBundleResponse,
)
from app.schemas.application_review_decision import ApplicationReviewDecisionResponse
from app.schemas.application_review_orchestration import ApplicationReviewOrchestrationRequest
from app.schemas.scan import ScanJobResponse
from app.schemas.threat_model import ThreatModelCreate
from app.services.application_review_orchestration import orchestrate_application_review
from app.services.review_scanner_enqueue import ReviewScannerEnqueueError


def _user():
    return SimpleNamespace(id=uuid.uuid4(), email="owner@example.com", organization_id=uuid.uuid4())


def _review_create(**overrides) -> ApplicationReviewCreate:
    data = {
        "app_name": "ExampleApp",
        "invocation_surface": "cli",
        "input_kind": "diff",
        "commit_sha": "abc123",
        "requested_tools": ["semgrep", "trivy"],
        "intake_answers": {
            "business_purpose": "Exports user data for support.",
            "data_classification": "restricted",
            "sensitive_data_types": ["pii"],
            "changed_security_surface": ["authz", "sensitive_data"],
            "scanner_permissions": ["static_code", "dependencies"],
            "upload_permission": True,
            "out_of_scope": ["production data"],
        },
    }
    data.update(overrides)
    return ApplicationReviewCreate(**data)


def _bundle_create() -> ApplicationReviewBundleCreate:
    return ApplicationReviewBundleCreate(
        bundle_kind="diff",
        source="cli",
        manifest=[
            ApplicationReviewBundleManifestItem(
                path="src/users.py",
                file_kind="source",
                sha256="a" * 64,
                byte_size=120,
                source="cli",
            ),
            ApplicationReviewBundleManifestItem(
                path="requirements.txt",
                file_kind="dependency_lock",
                sha256="b" * 64,
                byte_size=40,
                source="cli",
            ),
        ],
    )


def _review_response(review_id: uuid.UUID, owner_id: uuid.UUID, threat_model_id: uuid.UUID):
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)
    return ApplicationReviewResponse(
        id=review_id,
        tenant_key=f"user:{owner_id}",
        owner_id=owner_id,
        organization_id=None,
        threat_model_id=threat_model_id,
        parent_review_id=None,
        review_lineage_id=review_id,
        app_name="ExampleApp",
        invocation_surface="cli",
        input_kind="diff",
        status="created",
        decision=None,
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key",
        requested_tools=["semgrep", "trivy"],
        scope={},
        context={},
        policy={},
        result_summary=None,
        error_message=None,
        created_at=now,
        updated_at=now,
    )


def _bundle_response(bundle_id: uuid.UUID, review_id: uuid.UUID, owner_id: uuid.UUID):
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)
    return ApplicationReviewBundleResponse(
        id=bundle_id,
        tenant_key=f"user:{owner_id}",
        review_id=review_id,
        owner_id=owner_id,
        organization_id=None,
        bundle_kind="diff",
        source="cli",
        status="ready",
        manifest=[],
        content_hash="c" * 64,
        byte_size=160,
        file_count=2,
        created_at=now,
        updated_at=now,
    )


def _scan_job_response(job_id: uuid.UUID, threat_model_id: uuid.UUID):
    now = datetime(2026, 5, 2, tzinfo=timezone.utc)
    return ScanJobResponse(
        id=job_id,
        threat_model_id=threat_model_id,
        status="created",
        scan_type="unauthenticated",
        scope="internal",
        tool_name="semgrep",
        target_type="repository_path",
        targets={"bundle": "tgx-review-bundle://bundle"},
        finding_count=0,
        credential_id=None,
        started_at=None,
        completed_at=None,
        error_message=None,
        created_at=now,
    )


@pytest.mark.asyncio
async def test_orchestrate_review_runs_full_harness_and_returns_evidence_record():
    user = _user()
    db = AsyncMock()
    threat_model_id = uuid.uuid4()
    review_id = uuid.uuid4()
    bundle_id = uuid.uuid4()
    job_id = uuid.uuid4()
    request = ApplicationReviewOrchestrationRequest(
        threat_model=ThreatModelCreate(
            system_name="ExampleApp",
            description="Exports user data for support.",
            data_classification="Restricted",
            regulatory_scope=["SOC2"],
            deployment_model="cloud",
        ),
        review=_review_create(),
        bundle=_bundle_create(),
        scanner_tools=["semgrep"],
    )
    review = SimpleNamespace(id=review_id)
    bundle = SimpleNamespace(id=bundle_id)
    decision = ApplicationReviewDecisionResponse(
        review_id=review_id,
        decision="verify",
        reason="Scanner evidence requires context.",
        evidence_hashes=["d" * 64],
        scanner_only=True,
    )

    with (
        patch(
            "app.services.application_review_orchestration.create_threat_model",
            new_callable=AsyncMock,
            return_value=SimpleNamespace(id=threat_model_id),
        ) as create_model,
        patch(
            "app.services.application_review_orchestration.create_application_review",
            new_callable=AsyncMock,
            return_value=review,
        ) as create_review,
        patch(
            "app.services.application_review_orchestration.serialize_application_review",
            return_value=_review_response(review_id, user.id, threat_model_id),
        ),
        patch(
            "app.services.application_review_orchestration.create_review_bundle",
            new_callable=AsyncMock,
            return_value=bundle,
        ) as create_bundle,
        patch(
            "app.services.application_review_orchestration.serialize_application_review_bundle",
            return_value=_bundle_response(bundle_id, review_id, user.id),
        ),
        patch(
            "app.services.application_review_orchestration.enqueue_review_scanner_jobs",
            new_callable=AsyncMock,
            return_value=[_scan_job_response(job_id, threat_model_id)],
        ) as enqueue,
        patch(
            "app.services.application_review_orchestration.rebuild_review_context_index",
            new_callable=AsyncMock,
            return_value=[object(), object()],
        ) as rebuild,
        patch(
            "app.services.application_review_orchestration.evaluate_application_review_decision",
            new_callable=AsyncMock,
            return_value=decision,
        ) as evaluate,
    ):
        response = await orchestrate_application_review(
            db,
            current_user=user,  # type: ignore[arg-type]
            request=request,
            public_web_base_url="https://threatgenix.vercel.app",
        )

    assert response.status == "completed"
    assert response.failure_reason is None
    assert response.threat_model_id == threat_model_id
    assert response.review and response.review.id == review_id
    assert response.bundle and response.bundle.id == bundle_id
    assert [step.name for step in response.steps] == [
        "threat_model",
        "review",
        "bundle",
        "scanner_enqueue",
        "context_rebuild",
        "decision",
    ]
    assert response.scanner_jobs[0].id == job_id
    assert response.indexed_entry_count == 2
    assert response.decision == decision
    assert response.web_url == f"https://threatgenix.vercel.app/reviews/{review_id}"
    create_model.assert_awaited_once()
    create_review.assert_awaited_once()
    create_bundle.assert_awaited_once()
    enqueue.assert_awaited_once()
    rebuild.assert_awaited_once()
    evaluate.assert_awaited_once()


@pytest.mark.asyncio
async def test_orchestrate_review_returns_partial_failure_after_scanner_enqueue_error():
    user = _user()
    db = AsyncMock()
    threat_model_id = uuid.uuid4()
    review_id = uuid.uuid4()
    bundle_id = uuid.uuid4()
    request = ApplicationReviewOrchestrationRequest(
        review=_review_create(threat_model_id=threat_model_id),
        bundle=_bundle_create(),
        scanner_tools=["nuclei"],
        external_active_authorized=False,
    )

    with (
        patch("app.services.application_review_orchestration.get_threat_model", new_callable=AsyncMock),
        patch("app.services.application_review_orchestration.require_model_permission", Mock()),
        patch(
            "app.services.application_review_orchestration.create_application_review",
            new_callable=AsyncMock,
            return_value=SimpleNamespace(id=review_id),
        ),
        patch(
            "app.services.application_review_orchestration.serialize_application_review",
            return_value=_review_response(review_id, user.id, threat_model_id),
        ),
        patch(
            "app.services.application_review_orchestration.create_review_bundle",
            new_callable=AsyncMock,
            return_value=SimpleNamespace(id=bundle_id),
        ),
        patch(
            "app.services.application_review_orchestration.serialize_application_review_bundle",
            return_value=_bundle_response(bundle_id, review_id, user.id),
        ),
        patch(
            "app.services.application_review_orchestration.enqueue_review_scanner_jobs",
            new_callable=AsyncMock,
            side_effect=ReviewScannerEnqueueError("Active external scanning requires explicit authorization."),
        ),
    ):
        response = await orchestrate_application_review(
            db,
            current_user=user,  # type: ignore[arg-type]
            request=request,
            public_web_base_url="https://threatgenix.vercel.app",
        )

    assert response.status == "failed"
    assert response.review and response.review.id == review_id
    assert response.bundle and response.bundle.id == bundle_id
    assert response.decision is None
    assert response.steps[-1].name == "scanner_enqueue"
    assert response.steps[-1].status == "fail"
    assert "explicit authorization" in (response.failure_reason or "")
    db.rollback.assert_awaited()


def test_orchestration_request_rejects_scanners_without_bundle_or_model():
    with pytest.raises(ValueError, match="scanner_tools requires bundle"):
        ApplicationReviewOrchestrationRequest(
            review=_review_create(),
            scanner_tools=["semgrep"],
        )

    with pytest.raises(ValueError, match="scanner_tools requires threat_model"):
        ApplicationReviewOrchestrationRequest(
            review=_review_create(),
            bundle=_bundle_create(),
            scanner_tools=["semgrep"],
        )

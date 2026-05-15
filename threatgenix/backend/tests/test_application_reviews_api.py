from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import IntegrityError

from app.api.application_reviews import _build_evidence_chains
from app.database import get_db
from app.main import app
from app.schemas.application_review import ApplicationReviewCreate, ApplicationReviewResponse
from app.schemas.application_review_bundle import ApplicationReviewBundleResponse
from app.schemas.application_review_context import ApplicationReviewContextEntryResponse
from app.schemas.review_harness_ingest import IngestHarnessOutputResponse
from app.schemas.review_context_packet import (
    GroundedAIExplanationResponse,
    GroundedAIReviewOutput,
    GroundedAIValidationResult,
    ReviewContextPacket,
)
from app.schemas.application_review_decision import ApplicationReviewDecisionResponse
from app.schemas.application_review_orchestration import (
    ApplicationReviewOrchestrationResponse,
    ReviewOrchestrationStep,
)
from app.services.application_review import generated_idempotency_key
from app.services.application_risk_acceptance import RiskAcceptanceError
from app.services.auth import get_current_user

BASE_URL = "http://test"


def _response_model(
    *,
    review_id: uuid.UUID,
    owner_id: uuid.UUID,
    tenant_key: str,
) -> ApplicationReviewResponse:
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    return ApplicationReviewResponse(
        id=review_id,
        tenant_key=tenant_key,
        owner_id=owner_id,
        organization_id=None,
        threat_model_id=None,
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
        idempotency_key="review-key-1",
        requested_tools=["semgrep"],
        scope={"paths": ["apps/api/users.py"]},
        context={},
        policy={},
        result_summary=None,
        error_message=None,
        created_at=now,
        updated_at=now,
    )


def _intake_answers() -> dict[str, object]:
    return {
        "business_purpose": "Exports customer data for support operations.",
        "data_classification": "restricted",
        "sensitive_data_types": ["pii"],
        "changed_security_surface": ["sensitive_data"],
        "scanner_permissions": ["static_code", "dependencies", "secrets"],
        "upload_permission": True,
        "out_of_scope": ["production database contents"],
    }


def _bundle_response(
    *,
    bundle_id: uuid.UUID,
    review_id: uuid.UUID,
    owner_id: uuid.UUID,
    tenant_key: str,
) -> ApplicationReviewBundleResponse:
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    return ApplicationReviewBundleResponse(
        id=bundle_id,
        tenant_key=tenant_key,
        review_id=review_id,
        owner_id=owner_id,
        organization_id=None,
        bundle_kind="diff",
        source="cli",
        status="ready",
        manifest=[
            {
                "path": "apps/api/users.py",
                "file_kind": "source",
                "sha256": "a" * 64,
                "byte_size": 120,
                "source": "cli",
            }
        ],
        redaction_report={},
        integrity={},
        storage_backend="database_manifest",
        encryption_status="metadata_only",
        content_hash="b" * 64,
        byte_size=120,
        file_count=1,
        legal_hold=False,
        created_at=now,
        updated_at=now,
    )


def _scan_job_response(*, job_id: uuid.UUID, threat_model_id: uuid.UUID) -> SimpleNamespace:
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    return SimpleNamespace(
        id=job_id,
        threat_model_id=threat_model_id,
        status="created",
        scan_type="unauthenticated",
        scope="internal",
        tool_name="semgrep",
        target_type="repository_path",
        targets={"bundle": "tgx-review-bundle://bundle-1"},
        finding_count=0,
        credential_id=None,
        started_at=None,
        completed_at=None,
        error_message=None,
        failure_code=None,
        runner_id=None,
        claimed_at=None,
        heartbeat_at=None,
        lease_expires_at=None,
        attempt_count=0,
        max_attempts=3,
        created_at=now,
    )


def test_build_evidence_chains_keeps_duplicate_content_hash_entries_addressable():
    review_id = uuid.uuid4()
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    entries = [
        ApplicationReviewContextEntryResponse(
            id=uuid.uuid4(),
            review_id=review_id,
            source_type="scan_finding",
            source_object_id=uuid.uuid4(),
            item_type="scanner_finding",
            title=f"Finding {index}",
            body="same normalized evidence body",
            keywords=["finding"],
            facets={"severity": "high"},
            retrieval_text="same normalized evidence body",
            source_refs=[{"type": "path", "path": f"apps/api/users.py:{40 + index}"}],
            content_hash="d" * 64,
            status="active",
            stale_reason=None,
            created_at=now,
            updated_at=now,
        )
        for index in range(2)
    ]

    chains = _build_evidence_chains(entries)

    assert [chain.chain_id for chain in chains] == [f"chain:{entry.id}" for entry in entries]
    assert len({chain.chain_id for chain in chains}) == 2
    assert {chain.content_hash for chain in chains} == {"d" * 64}


def _risk_acceptance_response(
    *,
    acceptance_id: uuid.UUID,
    review_id: uuid.UUID,
    owner_id: uuid.UUID,
    tenant_key: str,
) -> SimpleNamespace:
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    return SimpleNamespace(
        id=acceptance_id,
        tenant_key=tenant_key,
        app_name="ExampleApp",
        review_id=review_id,
        finding_stable_id=None,
        scope_type="route",
        scope_value="apps/api/users.py:42",
        justification="Legacy export route has temporary approval and monitoring.",
        compensating_control="Alert on anomalous export volume.",
        approver_id=owner_id,
        approved_at=now,
        expires_at=now + timedelta(days=14),
        status="active",
        revoked_at=None,
        revoked_by_id=None,
        revoked_reason=None,
        audit_events=[{"action": "granted"}],
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_create_review_checks_threat_model_write_permission_and_commits():
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    threat_model = SimpleNamespace(id=threat_model_id, owner_id=owner_id, owner=user)
    review = SimpleNamespace(id=review_id)
    response_model = _response_model(
        review_id=review_id,
        owner_id=owner_id,
        tenant_key=f"user:{owner_id}",
    )
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch(
                "app.api.application_reviews.get_threat_model",
                new_callable=AsyncMock,
                return_value=threat_model,
            ) as get_model,
            patch(
                "app.api.application_reviews.create_application_review",
                new_callable=AsyncMock,
                return_value=review,
            ) as create_review,
            patch(
                "app.api.application_reviews.serialize_application_review",
                return_value=response_model,
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    "/api/reviews",
                    json={
                        "app_name": "ExampleApp",
                        "threat_model_id": str(threat_model_id),
                        "invocation_surface": "cli",
                        "input_kind": "diff",
                        "commit_sha": "abc123",
                        "requested_tools": ["semgrep"],
                        "intake_answers": _intake_answers(),
                        "idempotency_key": "review-key-1",
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["id"] == str(review_id)
    get_model.assert_awaited_once()
    create_review.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_grant_risk_acceptance_commits_and_returns_scope():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    acceptance_id = uuid.uuid4()
    user = SimpleNamespace(
        id=owner_id,
        email="approver@example.com",
        organization_id=None,
        role="accept_risk_approver",
    )
    acceptance = _risk_acceptance_response(
        acceptance_id=acceptance_id,
        review_id=review_id,
        owner_id=owner_id,
        tenant_key=f"user:{owner_id}",
    )
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.create_application_risk_acceptance",
            new_callable=AsyncMock,
            return_value=acceptance,
        ) as grant:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/reviews/{review_id}/risk-acceptances",
                    json={
                        "scope_type": "route",
                        "scope_value": "apps/api/users.py:42",
                        "justification": "Legacy export route has temporary approval and monitoring.",
                        "compensating_control": "Alert on anomalous export volume.",
                        "expires_at": "2026-05-15T00:00:00+00:00",
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(acceptance_id)
    assert body["scope_type"] == "route"
    assert body["scope_value"] == "apps/api/users.py:42"
    grant.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_grant_risk_acceptance_maps_role_errors_to_forbidden():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None, role="admin")
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.create_application_risk_acceptance",
            new_callable=AsyncMock,
            side_effect=RiskAcceptanceError("accept_risk_approver role is required to accept risk."),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/reviews/{review_id}/risk-acceptances",
                    json={
                        "scope_type": "app",
                        "scope_value": "ExampleApp",
                        "justification": "Temporary app exception pending compensating control rollout.",
                        "expires_at": "2026-05-15T00:00:00+00:00",
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 403
    db.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_intake_questions_requires_auth_and_returns_shared_bank():
    owner_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)

    async def override_user():
        return user

    app.dependency_overrides[get_current_user] = override_user
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get("/api/reviews/intake/questions?review_type=diff")
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "threatgenix_appsec_v1"
    assert body["review_type"] == "diff"
    assert "scanner_permissions" in {question["id"] for question in body["questions"]}


@pytest.mark.asyncio
async def test_validate_intake_rejects_missing_required_answers():
    owner_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)

    async def override_user():
        return user

    app.dependency_overrides[get_current_user] = override_user
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                "/api/reviews/intake/validate",
                json={
                    "version": "threatgenix_appsec_v1",
                    "review_type": "diff",
                    "answers": {},
                },
            )
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert "out_of_scope" in body["missing_required"]


@pytest.mark.asyncio
async def test_create_review_rejects_invalid_intake_before_commit():
    owner_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                "/api/reviews",
                json={
                    "app_name": "ExampleApp",
                    "invocation_surface": "cli",
                    "input_kind": "diff",
                    "commit_sha": "abc123",
                    "requested_tools": ["semgrep"],
                    "intake_answers": {},
                },
            )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 422
    assert "Invalid intake answers" in response.json()["detail"]
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_review_returns_404_outside_current_tenant():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.get_application_review",
            new_callable=AsyncMock,
            return_value=None,
        ) as get_review:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(f"/api/reviews/{review_id}")
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 404
    assert response.json()["detail"] == "Review not found."
    get_review.assert_awaited_once()
    _, kwargs = get_review.await_args
    assert kwargs["tenant_key"] == f"user:{owner_id}"


@pytest.mark.asyncio
async def test_create_review_integrity_retry_uses_generated_idempotency_key():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    tenant_key = f"user:{owner_id}"
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    review = SimpleNamespace(id=review_id)
    response_model = _response_model(
        review_id=review_id,
        owner_id=owner_id,
        tenant_key=tenant_key,
    )
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch(
                "app.api.application_reviews.create_application_review",
                new_callable=AsyncMock,
                side_effect=IntegrityError("insert", {}, Exception("duplicate")),
            ),
            patch(
                "app.api.application_reviews.get_application_review_by_idempotency_key",
                new_callable=AsyncMock,
                return_value=review,
            ) as get_by_key,
            patch(
                "app.api.application_reviews.ensure_idempotent_review_matches",
            ) as ensure_matches,
            patch(
                "app.api.application_reviews.serialize_application_review",
                return_value=response_model,
            ),
        ):
            request_json = {
                "app_name": "ExampleApp",
                "invocation_surface": "cli",
                "input_kind": "diff",
                "commit_sha": "abc123",
                "requested_tools": ["semgrep"],
                "intake_answers": _intake_answers(),
            }
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post("/api/reviews", json=request_json)
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    _, kwargs = get_by_key.await_args
    assert kwargs["tenant_key"] == tenant_key
    expected_request = ApplicationReviewCreate(**request_json)
    assert kwargs["idempotency_key"] == generated_idempotency_key(
        tenant_key,
        expected_request,
    )
    ensure_matches.assert_called_once()


@pytest.mark.asyncio
async def test_orchestrate_review_forwards_public_web_url_and_returns_run_record():
    owner_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()
    review_id = uuid.uuid4()
    service_response = ApplicationReviewOrchestrationResponse(
        status="completed",
        steps=[ReviewOrchestrationStep(name="review", status="pass", detail="created")],
        review=_response_model(
            review_id=review_id,
            owner_id=owner_id,
            tenant_key=f"user:{owner_id}",
        ),
        web_url=f"https://threatgenix.vercel.app/reviews/{review_id}",
    )

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.orchestrate_application_review",
            new_callable=AsyncMock,
            return_value=service_response,
        ) as orchestrate:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://threatgenix-api.fly.dev") as client:
                response = await client.post(
                    "/api/reviews/orchestrations",
                    headers={
                        "x-forwarded-host": "threatgenix.vercel.app",
                        "x-forwarded-proto": "https",
                    },
                    json={
                        "review": {
                            "app_name": "ExampleApp",
                            "input_kind": "diff",
                            "commit_sha": "abc123",
                            "requested_tools": ["semgrep"],
                            "intake_answers": _intake_answers(),
                        }
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert response.json()["web_url"] == f"https://threatgenix.vercel.app/reviews/{review_id}"
    kwargs = orchestrate.await_args.kwargs
    assert kwargs["current_user"] == user
    assert kwargs["public_web_base_url"] == "https://threatgenix.vercel.app"


@pytest.mark.asyncio
async def test_orchestrate_review_rejects_scanner_tools_without_bundle():
    user = SimpleNamespace(id=uuid.uuid4(), email="owner@example.com", organization_id=None)

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                "/api/reviews/orchestrations",
                json={
                    "review": {
                        "app_name": "ExampleApp",
                        "input_kind": "diff",
                        "commit_sha": "abc123",
                    },
                    "scanner_tools": ["semgrep"],
                },
            )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 422
    assert "scanner_tools requires bundle" in response.text


@pytest.mark.asyncio
async def test_create_review_bundle_commits_for_current_tenant_review():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    bundle_id = uuid.uuid4()
    tenant_key = f"user:{owner_id}"
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    bundle = SimpleNamespace(id=bundle_id)
    response_model = _bundle_response(
        bundle_id=bundle_id,
        review_id=review_id,
        owner_id=owner_id,
        tenant_key=tenant_key,
    )
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch(
                "app.api.application_reviews.create_review_bundle",
                new_callable=AsyncMock,
                return_value=bundle,
            ) as create_bundle,
            patch(
                "app.api.application_reviews.serialize_application_review_bundle",
                return_value=response_model,
            ),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/reviews/{review_id}/bundles",
                    json={
                        "bundle_kind": "diff",
                        "source": "cli",
                        "manifest": [
                            {
                                "path": "apps/api/users.py",
                                "file_kind": "source",
                                "sha256": "a" * 64,
                                "byte_size": 120,
                                "source": "cli",
                            }
                        ],
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["id"] == str(bundle_id)
    create_bundle.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_list_review_bundles_returns_404_for_cross_tenant_review():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.get_application_review",
            new_callable=AsyncMock,
            return_value=None,
        ) as get_review:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(f"/api/reviews/{review_id}/bundles")
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 404
    assert response.json()["detail"] == "Review not found."
    _, kwargs = get_review.await_args
    assert kwargs["tenant_key"] == f"user:{owner_id}"


@pytest.mark.asyncio
async def test_get_review_bundle_returns_404_outside_current_tenant():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    bundle_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.get_review_bundle",
            new_callable=AsyncMock,
            return_value=None,
        ) as get_bundle:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(f"/api/reviews/{review_id}/bundles/{bundle_id}")
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 404
    assert response.json()["detail"] == "Review bundle not found."
    _, kwargs = get_bundle.await_args
    assert kwargs["tenant_key"] == f"user:{owner_id}"


@pytest.mark.asyncio
async def test_enqueue_scanner_jobs_commits_and_returns_jobs():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    bundle_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    job_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    job = _scan_job_response(job_id=job_id, threat_model_id=threat_model_id)
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.enqueue_review_scanner_jobs",
            new_callable=AsyncMock,
            return_value=[job],
        ) as enqueue:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/reviews/{review_id}/scanner-jobs",
                    json={"bundle_id": str(bundle_id), "tools": ["semgrep"]},
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["review_id"] == str(review_id)
    assert body["bundle_id"] == str(bundle_id)
    assert body["jobs"][0]["id"] == str(job_id)
    enqueue.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_ingest_scanner_harness_output_commits_and_returns_finding_keys():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    bundle_id = uuid.uuid4()
    job_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()
    service_response = IngestHarnessOutputResponse(
        review_id=review_id,
        bundle_id=bundle_id,
        scan_job_id=job_id,
        status="completed",
        finding_count=1,
        finding_keys=["harness:semgrep:key"],
    )

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.ingest_review_harness_output",
            new_callable=AsyncMock,
            return_value=service_response,
        ) as ingest:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(
                    f"/api/reviews/{review_id}/scanner-jobs/{job_id}/harness-output",
                    json={
                        "bundle_id": str(bundle_id),
                        "output": {
                            "tool_name": "semgrep",
                            "tool_version": "1.2.3",
                            "ruleset_version": "rules-2026-05-01",
                            "scanner_run_id": "run-123",
                            "bundle_id": str(bundle_id),
                            "status": "completed",
                            "findings": [
                                {
                                    "rule_id": "python.fastapi.missing-authz",
                                    "title": "Sensitive export route is missing authorization",
                                    "severity": "High",
                                    "path": "apps/api/users.py",
                                    "start_line": 42,
                                    "end_line": 45,
                                    "evidence_snippet_sha256": "c" * 64,
                                    "confidence": "high",
                                    "source_type": "sast",
                                }
                            ],
                            "raw_artifact_refs": ["artifact://semgrep/run-123"],
                            "provenance": {
                                "issuer": "threatgenix-managed-scanner",
                                "tool_name": "semgrep",
                                "scanner_run_id": "run-123",
                                "bundle_id": str(bundle_id),
                                "output_format": "threatgenix-harness-v1",
                            },
                        },
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["scan_job_id"] == str(job_id)
    assert body["finding_count"] == 1
    assert body["finding_keys"] == ["harness:semgrep:key"]
    ingest.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_rebuild_context_index_commits_and_returns_entry_count():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.rebuild_review_context_index",
            new_callable=AsyncMock,
            return_value=[object(), object()],
        ) as rebuild:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(f"/api/reviews/{review_id}/context-index/rebuild")
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json() == {"review_id": str(review_id), "entry_count": 2}
    rebuild.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_search_context_index_returns_source_referenced_results():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    entry_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    entry = SimpleNamespace(
        id=entry_id,
        review_id=review_id,
        source_type="scan_finding",
        source_object_id=uuid.uuid4(),
        item_type="scanner_finding",
        title="Sensitive export route is missing authorization",
        body="missing authorization export",
        keywords=["missing", "authorization", "export"],
        source_refs=[{"type": "path", "path": "apps/api/users.py:42"}],
        content_hash="d" * 64,
        status="active",
        created_at=now,
        updated_at=now,
    )

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.search_review_context_index",
            new_callable=AsyncMock,
            return_value=[entry],
        ) as search:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(
                    f"/api/reviews/{review_id}/context-index/search?q=missing%20authorization"
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["query"] == "missing authorization"
    assert body["results"][0]["id"] == str(entry_id)
    assert body["results"][0]["source_refs"][0]["path"] == "apps/api/users.py:42"
    search.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_context_packet_returns_grounded_packet():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    packet = ReviewContextPacket(
        review_id=review_id,
        app_name="ExampleApp",
        commit_sha="abc123",
        deterministic_decision="fix",
        policy={},
        evidence_snapshot_hash="f" * 64,
        entries=[],
    )

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.build_review_context_packet",
            new_callable=AsyncMock,
            return_value=packet,
        ) as build_packet:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(f"/api/reviews/{review_id}/context-packet")
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["review_id"] == str(review_id)
    assert body["evidence_snapshot_hash"] == "f" * 64
    build_packet.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_ai_explanation_returns_grounded_validated_output():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    packet = ReviewContextPacket(
        review_id=review_id,
        app_name="ExampleApp",
        commit_sha="abc123",
        deterministic_decision="fix",
        policy={},
        evidence_snapshot_hash="f" * 64,
        entries=[],
    )
    explanation = GroundedAIExplanationResponse(
        review_id=review_id,
        packet=packet,
        output=GroundedAIReviewOutput(
            summary="Deterministic decision is fix.",
            proposed_decision="fix",
            cited_content_hashes=["d" * 64],
        ),
        validation=GroundedAIValidationResult(valid=True, errors=[]),
        explanation_status="ready",
        prompt_contract=["Do not change deterministic decision."],
    )

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.build_grounded_ai_explanation",
            new_callable=AsyncMock,
            return_value=explanation,
        ) as build_explanation:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(f"/api/reviews/{review_id}/ai-explanation")
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["review_id"] == str(review_id)
    assert body["explanation_status"] == "ready"
    assert body["output"]["proposed_decision"] == "fix"
    assert body["validation"]["valid"] is True
    build_explanation.assert_awaited_once()


@pytest.mark.asyncio
async def test_evaluate_review_decision_commits_deterministic_result():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    db = AsyncMock()
    service_response = ApplicationReviewDecisionResponse(
        review_id=review_id,
        decision="verify",
        reason="High-severity scanner evidence needs supporting context.",
        evidence_hashes=["d" * 64],
        scanner_only=True,
    )

    async def override_get_db():
        yield db

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with patch(
            "app.api.application_reviews.evaluate_application_review_decision",
            new_callable=AsyncMock,
            return_value=service_response,
        ) as evaluate:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(f"/api/reviews/{review_id}/decision/evaluate")
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["decision"] == "verify"
    assert response.json()["scanner_only"] is True
    evaluate.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_review_artifact_returns_url_decision_and_redacted_raw_evidence():
    owner_id = uuid.uuid4()
    review_id = uuid.uuid4()
    user = SimpleNamespace(id=owner_id, email="owner@example.com", organization_id=None)
    review = _response_model(
        review_id=review_id,
        owner_id=owner_id,
        tenant_key=f"user:{user.email}",
    ).model_copy(
        update={
            "decision": "verify",
            "context": {
                "deterministic_decision_replay": {
                    "decision": "verify",
                    "reason": "High scanner evidence requires context.",
                    "evidence_snapshot_hash": "e" * 64,
                    "decision_engine_version": "appsec-decision-v1.0.0",
                    "decision_trace": ["engine:appsec-decision-v1.0.0"],
                    "secret": "must-not-render",
                }
            },
        }
    )
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)
    raw_entry = ApplicationReviewContextEntryResponse(
        id=uuid.uuid4(),
        review_id=review_id,
        source_type="scan_finding",
        source_object_id=uuid.uuid4(),
        item_type="scanner_finding",
        title="Sensitive export route is missing authorization",
        body="severity=high api_key=live-secret missing authorization",
        keywords=["severity=high"],
        facets={"api_key": "live-secret", "severity": "high"},
        retrieval_text="api_key=live-secret",
        source_refs=[{"type": "path", "path": "apps/api/users.py:42"}],
        content_hash="d" * 64,
        status="stale",
        stale_reason="superseded_by_rebuild",
        created_at=now,
        updated_at=now,
    )

    async def override_get_db():
        yield AsyncMock()

    async def override_user():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    try:
        with (
            patch(
                "app.api.application_reviews.get_application_review",
                new_callable=AsyncMock,
                return_value=review,
            ) as get_review,
            patch(
                "app.api.application_reviews.search_review_context_index",
                new_callable=AsyncMock,
                return_value=[raw_entry],
            ) as search_context,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.get(
                    f"/api/reviews/{review_id}/artifact",
                    headers={
                        "x-forwarded-host": "threatgenix.example",
                        "x-forwarded-proto": "https",
                    },
                )
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    body = response.json()
    assert body["web_url"] == f"https://threatgenix.example/reviews/{review_id}"
    assert body["review"]["decision"] == "verify"
    assert body["decision_record"]["secret"] == "[REDACTED]"
    assert body["raw_evidence_count"] == 1
    assert body["has_stale_evidence"] is True
    assert body["source_ref_count"] == 1
    assert body["evidence_chains"][0]["title"] == "Sensitive export route is missing authorization"
    assert body["evidence_chains"][0]["status"] == "stale"
    assert body["evidence_chains"][0]["steps"][1]["label"] == "path: apps/api/users.py:42"
    assert body["graph_slice"]["nodes"][0]["node_type"] == "review"
    assert any(edge["relationship"] == "supported_by_source_ref" for edge in body["graph_slice"]["edges"])
    assert body["fix_plan"][0]["title"] == "Resolve cited scanner finding"
    assert body["fix_plan"][1]["title"] == "Refresh stale evidence"
    assert body["accepted_risks"] == []
    assert body["rerun_history"][0]["review_id"] == str(review_id)
    assert body["rerun_history"][0]["evidence_snapshot_hash"] == "e" * 64
    assert "live-secret" not in str(body)
    assert body["raw_evidence"][0]["body"] == "severity=high api_key=[REDACTED] missing authorization"
    get_review.assert_awaited_once()
    search_context.assert_awaited_once()

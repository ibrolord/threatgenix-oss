from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.models.application_review import ApplicationSecurityReview
from app.services.application_review import tenant_key_for_user
from app.services.application_review_context import rebuild_review_context_index
from app.services.code_context_extractor import (
    CodeSourceFile,
    build_code_context_harness_envelope,
    extract_code_context,
)
from app.services.tool_harness import validate_harness_envelope


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
        return _Result(self.execute_results.pop(0) if self.execute_results else [])

    def add(self, item: object) -> None:
        self.added.append(item)

    async def flush(self) -> None:
        self.flush_count += 1


def _user():
    return SimpleNamespace(id=uuid.uuid4(), organization_id=uuid.uuid4(), email="owner@example.com")


def _review(user, *, code_context: list[dict] | None = None) -> ApplicationSecurityReview:
    now = datetime.now(timezone.utc)
    return ApplicationSecurityReview(
        id=uuid.uuid4(),
        tenant_key=tenant_key_for_user(user),
        owner_id=user.id,
        organization_id=user.organization_id,
        threat_model_id=None,
        review_lineage_id=uuid.uuid4(),
        app_name="ExampleApp",
        invocation_surface="cli",
        input_kind="diff",
        status="scanning",
        commit_sha="abc123",
        bundle_hash=None,
        scope_fingerprint="a" * 64,
        idempotency_key="review-key-1",
        requested_tools=["code_context_extractor"],
        scope={"paths": ["apps/api/users.py"]},
        context={"code_context": code_context or []},
        policy={},
        created_at=now,
        updated_at=now,
    )


def test_extracts_fastapi_route_with_auth_data_and_source_refs():
    source = """
from fastapi import APIRouter, Depends
from sqlalchemy import select

router = APIRouter()

@router.get("/v2/users/export")
async def export_users(current_user=Depends(get_current_user), db=Depends(get_db)):
    authorize(current_user, "users:export")
    tenant_id = current_user.tenant_id
    return db.execute(select(User.email).where(User.tenant_id == tenant_id))
"""

    result = extract_code_context(
        [CodeSourceFile(path="apps/api/users.py", content=source)],
        manifest_paths={"apps/api/users.py"},
    )

    assert result.warnings == []
    assert len(result.surfaces) == 1
    surface = result.surfaces[0]
    assert surface.method == "get"
    assert surface.route_path == "/v2/users/export"
    assert surface.handler == "export_users"
    assert surface.source_ref()["path"] == "apps/api/users.py"
    assert surface.source_ref()["start_line"] == 7
    assert "get_current_user" in surface.auth_controls
    assert "authorize" in surface.authorization_checks
    assert "tenant_id" in surface.authorization_checks
    assert "email" in surface.sensitive_signals
    assert "select" in surface.data_touched
    assert surface.uncertainty == []


def test_sensitive_route_with_auth_but_missing_authz_marks_uncertainty():
    source = """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/v2/users/export")
def export_users(current_user=Depends(get_current_user)):
    return [{"email": user.email} for user in users]
"""

    result = extract_code_context(
        [CodeSourceFile(path="apps/api/users.py", content=source)],
        manifest_paths={"apps/api/users.py"},
    )

    surface = result.surfaces[0]
    assert "get_current_user" in surface.auth_controls
    assert "sensitive_route_auth_present_but_authz_not_identified" in surface.uncertainty
    assert "tenant_or_owner_scope_not_identified" in surface.uncertainty


def test_syntax_error_degrades_to_uncertain_file_surface():
    result = extract_code_context(
        [CodeSourceFile(path="apps/api/broken.py", content="def broken(:\n    pass\n")],
        manifest_paths={"apps/api/broken.py"},
    )

    assert len(result.surfaces) == 1
    assert result.surfaces[0].kind == "file"
    assert result.surfaces[0].confidence == 0.1
    assert any(value.startswith("syntax_error:") for value in result.surfaces[0].uncertainty)
    assert result.warnings[0].startswith("Could not parse apps/api/broken.py")


def test_extractor_never_imports_or_executes_customer_code():
    source = """
from fastapi import APIRouter

raise RuntimeError("top-level customer code must not execute")

router = APIRouter()

@router.post("/webhooks/stripe")
def stripe_webhook(payload: dict):
    return {"ok": True}
"""

    result = extract_code_context(
        [CodeSourceFile(path="apps/api/webhooks.py", content=source)],
        manifest_paths={"apps/api/webhooks.py"},
    )

    assert len(result.surfaces) == 1
    assert result.surfaces[0].route_path == "/webhooks/stripe"
    assert "webhook_signature_verification_not_identified" in result.surfaces[0].uncertainty


def test_unsafe_paths_are_skipped_before_extraction():
    result = extract_code_context(
        [CodeSourceFile(path="../evil.py", content="from fastapi import FastAPI\n")],
        manifest_paths=set(),
    )

    assert result.surfaces == []
    assert result.skipped_paths == ["../evil.py"]
    assert "unsafe source path" in result.warnings[0]


def test_builds_valid_evidence_only_harness_envelope():
    review_id = uuid.uuid4()
    bundle_id = uuid.uuid4()
    envelope = build_code_context_harness_envelope(
        tenant_key="user:test@example.com",
        review_id=review_id,
        bundle_id=bundle_id,
        idempotency_key="ctx-1",
        manifest_paths={"apps/api/users.py"},
        files=[
            CodeSourceFile(
                path="apps/api/users.py",
                content='from fastapi import FastAPI\napp = FastAPI()\n@app.get("/health")\ndef health(): return {"ok": True}\n',
            )
        ],
    )

    validate_harness_envelope(
        envelope,
        tenant_key="user:test@example.com",
        review_id=review_id,
        authorized_targets={f"tgx-review-bundle://{bundle_id}"},
    )
    item = envelope.result.evidence_items[0]
    assert item.item_type == "code_context"
    assert item.metadata["surface_count"] == 1
    assert item.metadata["surfaces"][0]["route_path"] == "/health"


@pytest.mark.asyncio
async def test_review_context_index_projects_extracted_code_context_with_source_refs():
    source = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/v2/users/export")
def export_users():
    return [{"email": "customer@example.com"}]
"""
    extraction = extract_code_context(
        [CodeSourceFile(path="apps/api/users.py", content=source)],
        manifest_paths={"apps/api/users.py"},
    )
    user = _user()
    review = _review(user, code_context=extraction.to_context_payloads())
    db = _FakeSession([review, []])

    entries = await rebuild_review_context_index(
        db,  # type: ignore[arg-type]
        current_user=user,  # type: ignore[arg-type]
        review_id=review.id,
    )

    code_entry = next(entry for entry in entries if entry.item_type == "code_context")
    assert code_entry.source_type == "code_context"
    assert code_entry.title == "GET /v2/users/export"
    assert code_entry.facets["framework"] == "fastapi"
    assert code_entry.facets["has_sensitive_signals"] is True
    assert any(ref.get("path") == "apps/api/users.py" for ref in code_entry.source_refs)
    assert db.flush_count == 1

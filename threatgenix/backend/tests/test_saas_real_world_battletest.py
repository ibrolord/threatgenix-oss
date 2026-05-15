from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.orchestration import OrchestrationJob, OrchestrationTask
from app.models.user_provider_key import UserProviderKey
from app.services import llm_client, orchestration_worker
from app.services.auth import get_current_user
from app.services.key_encryption import encrypt_key
from app.services.orchestration_worker import (
    OrchestrationTaskBlocked,
    _execute_agent_reasoning,
    _execute_validation_tool_task,
)

BASE_URL = "http://test"


class _ScopedBYOKResult:
    def __init__(self, values: list[UserProviderKey]) -> None:
        self.values = values

    def scalars(self):
        return self

    def all(self):
        return self.values

    def scalar_one_or_none(self):
        return self.values[0] if self.values else None


class _ScopedBYOKDB:
    def __init__(self, keys: list[UserProviderKey]) -> None:
        self.keys = keys

    async def execute(self, statement):
        params = statement.compile().params
        user_id = next(
            (value for key, value in params.items() if key.startswith("user_id")),
            None,
        )
        provider = next(
            (value for key, value in params.items() if key.startswith("provider")),
            None,
        )
        matches = [key for key in self.keys if key.user_id == user_id]
        if provider is not None:
            matches = [key for key in matches if key.provider == provider]
        return _ScopedBYOKResult(matches)


class _NoWriteDB:
    def add(self, _item: object) -> None:
        raise AssertionError("unsafe validation task reached DB write path")

    async def flush(self) -> None:
        raise AssertionError("unsafe validation task reached DB flush path")

    async def commit(self) -> None:
        raise AssertionError("unsafe validation task reached DB commit path")


class _FakeReasoningClient:
    provider_name = "anthropic"
    model_name = "claude-sonnet-4-20250514"

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def call_with_tools(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "summary": "Northstar payment-initiation review is blocked on proof gaps.",
            "findings": ["Semgrep evidence is node-bound to the API gateway."],
            "assumptions": ["No production exploit evidence was provided."],
            "next_actions": ["Bind the scanner evidence to the payment API threat."],
            "citations": ["semgrep:jwt-missing-audience"],
        }


@pytest.fixture(autouse=True)
def _clean_app_overrides_and_preferences():
    saved_overrides = dict(app.dependency_overrides)
    saved_preferences = dict(llm_client._user_provider_preferences)
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(saved_overrides)
    llm_client._user_provider_preferences.clear()
    llm_client._user_provider_preferences.update(saved_preferences)


def _user(user_id: uuid.UUID, *, email: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=user_id,
        email=email,
        full_name=email.split("@")[0],
        role="admin",
        is_active=True,
        organization_id=uuid.uuid4(),
    )


def _key(user_id: uuid.UUID, provider: str, plaintext: str, model: str | None) -> UserProviderKey:
    row = UserProviderKey(
        id=uuid.uuid4(),
        user_id=user_id,
        provider=provider,
        encrypted_key=encrypt_key(plaintext),
        model_override=model,
    )
    row.created_at = datetime(2026, 4, 29, tzinfo=timezone.utc)
    return row


@pytest.mark.asyncio
async def test_real_world_byok_inventory_is_isolated_between_bank_tenants() -> None:
    northstar_user_id = uuid.uuid4()
    harborpay_user_id = uuid.uuid4()
    db = _ScopedBYOKDB(
        [
            _key(northstar_user_id, "openai", "sk-northstar-aaaa", "gpt-4o-bank"),
            _key(harborpay_user_id, "openai", "sk-harborpay-bbbb", "gpt-4o-issuer"),
        ]
    )

    async def override_db():
        yield db

    async def override_user():
        return _user(northstar_user_id, email="appsec@northstar-bank.example")

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = override_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.get("/api/llm/keys")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["provider"] == "openai"
    assert body[0]["model_override"] == "gpt-4o-bank"
    assert body[0]["masked_key"].endswith("aaaa")
    assert "harborpay" not in str(body).lower()
    assert "bbbb" not in str(body)


@pytest.mark.asyncio
async def test_real_world_byok_provider_switch_uses_tenant_key_without_server_key(monkeypatch) -> None:
    northstar_user_id = uuid.uuid4()
    db = _ScopedBYOKDB(
        [_key(northstar_user_id, "openai", "sk-northstar-aaaa", "gpt-4o-bank")]
    )
    monkeypatch.setattr(llm_client.settings, "openai_api_key", None)

    async def override_db():
        yield db

    async def override_user():
        return _user(northstar_user_id, email="appsec@northstar-bank.example")

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = override_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.post(
            "/api/llm/provider",
            json={"provider": "openai", "model": "gpt-4o-requested"},
        )

    assert response.status_code == 200, response.text
    assert response.json() == {"provider": "openai", "model": "gpt-4o-bank"}
    assert llm_client.settings.openai_api_key is None
    assert llm_client.get_active_provider_info_for_user(northstar_user_id) == {
        "provider": "openai",
        "model": "gpt-4o-bank",
    }


@pytest.mark.asyncio
async def test_real_world_agent_reasoning_uses_owner_scoped_tool_client(monkeypatch) -> None:
    owner_id = uuid.uuid4()
    threat_model_id = uuid.uuid4()
    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=threat_model_id,
        owner_id=owner_id,
        job_kind="security_audit",
        objective="Summarize Northstar Bank payment API validation evidence.",
        requested_tools=["semgrep", "evidence"],
    )
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=job.id,
        threat_model_id=threat_model_id,
        task_kind="agent_reasoning",
        agent_name="security-review-agent",
        input_payload={
            "prompt": "Explain what evidence is proven for the payment-initiation API."
        },
        max_attempts=1,
    )
    task.job = job
    fake_client = _FakeReasoningClient()
    db = SimpleNamespace(name="scoped-db")

    async def fake_context(_db, _task):
        return {
            "tenant": "Northstar Bank",
            "model": "payment-initiation API",
            "prior_task_outputs": [
                {
                    "tool_name": "semgrep",
                    "status": "completed",
                    "output_payload": {"finding": "jwt missing audience validation"},
                }
            ],
        }

    async def fake_get_client(user_id, db_arg):
        assert user_id == owner_id
        assert db_arg is db
        return fake_client

    monkeypatch.setattr(orchestration_worker, "build_orchestration_context", fake_context)
    monkeypatch.setattr(orchestration_worker, "get_llm_client_for_user_async", fake_get_client)

    result = await _execute_agent_reasoning(db, task)  # type: ignore[arg-type]

    assert result["agent_reasoning"]["summary"].startswith("Northstar")
    assert len(fake_client.calls) == 1
    call = fake_client.calls[0]
    assert call["tools"][0]["name"] == "record_agent_reasoning"
    assert "Do not invent facts" in call["system_message"]
    assert "Northstar Bank" in call["user_message"]
    assert "jwt missing audience validation" in call["user_message"]


@pytest.mark.asyncio
async def test_real_world_validation_orchestration_blocks_symlinked_secret_escape(
    tmp_path,
    monkeypatch,
) -> None:
    allowed = tmp_path / "customer-repos"
    repo = allowed / "payment-api"
    external_secret_dir = tmp_path / "outside-secrets"
    allowed.mkdir()
    repo.mkdir()
    external_secret_dir.mkdir()
    (external_secret_dir / "prod.env").write_text("PAYMENT_SECRET=do-not-scan\n")
    (repo / "linked-secrets").symlink_to(external_secret_dir, target_is_directory=True)
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(allowed))
    monkeypatch.setattr(orchestration_worker, "validation_worker_execution_enabled", lambda: True)

    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        job_kind="validation_run",
        objective="Run Semgrep on the customer-authorized payment API repository.",
        requested_tools=["semgrep"],
        policy={},
    )
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=job.id,
        threat_model_id=job.threat_model_id,
        task_kind="tool_execution",
        tool_name="semgrep",
        input_payload={
            "authorization_acknowledged": True,
            "target_type": "repository_path",
            "target": str(repo),
        },
        max_attempts=1,
    )
    task.job = job

    with pytest.raises(OrchestrationTaskBlocked, match="symlink outside"):
        await _execute_validation_tool_task(_NoWriteDB(), task)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_real_world_validation_orchestration_blocks_metadata_service_url(monkeypatch) -> None:
    monkeypatch.setattr(orchestration_worker, "validation_worker_execution_enabled", lambda: True)
    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        job_kind="validation_run",
        objective="Run Nuclei against an authorized public API endpoint.",
        requested_tools=["nuclei"],
        policy={},
    )
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=job.id,
        threat_model_id=job.threat_model_id,
        task_kind="tool_execution",
        tool_name="nuclei",
        input_payload={
            "authorization_acknowledged": True,
            "target_type": "url",
            "target": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
        },
        max_attempts=1,
    )
    task.job = job

    with pytest.raises(OrchestrationTaskBlocked, match="metadata IP"):
        await _execute_validation_tool_task(_NoWriteDB(), task)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_real_world_hosted_saas_blocks_local_validation_execution(tmp_path, monkeypatch) -> None:
    repo = tmp_path / "merchant-portal"
    repo.mkdir()
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(tmp_path))
    monkeypatch.setattr(orchestration_worker, "validation_worker_execution_enabled", lambda: False)
    monkeypatch.setattr(
        orchestration_worker,
        "validation_worker_execution_blocked_reason",
        lambda: "Hosted SaaS mode does not execute customer-local validation tools.",
    )

    job = OrchestrationJob(
        id=uuid.uuid4(),
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        job_kind="validation_run",
        objective="Hosted tenant attempts to run Semgrep against a local path.",
        requested_tools=["semgrep"],
        policy={"authorization_acknowledged": True},
    )
    task = OrchestrationTask(
        id=uuid.uuid4(),
        job_id=job.id,
        threat_model_id=job.threat_model_id,
        task_kind="tool_execution",
        tool_name="semgrep",
        input_payload={
            "target_type": "repository_path",
            "target": str(repo),
        },
        max_attempts=1,
    )
    task.job = job

    with pytest.raises(OrchestrationTaskBlocked, match="Hosted SaaS mode"):
        await _execute_validation_tool_task(_NoWriteDB(), task)  # type: ignore[arg-type]

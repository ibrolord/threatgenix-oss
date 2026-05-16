from __future__ import annotations

from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.services.auth import get_current_user
from app.services.validation_execution_policy import (
    TARGET_AI_SYSTEM,
    TARGET_REPOSITORY_PATH,
    TARGET_URL,
    build_validation_tool_inventory,
    default_validation_execution_policy_registry,
)
from app.services.validation_sandbox import VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV

BASE_URL = "http://test"


class FakeUser:
    id = "00000000-0000-0000-0000-000000000001"
    email = "test@example.com"
    full_name = "Test User"
    role = "admin"
    is_active = True


async def override_get_db():
    yield None


async def override_get_current_user():
    return FakeUser()


@pytest.fixture(autouse=True)
def _apply_overrides():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)


def test_execution_policy_allows_only_active_nuclei_url_execution(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_SEMGREP_ENABLED", "false")
    monkeypatch.delenv("VALIDATION_SEMGREP_ENABLED", raising=False)
    policies = default_validation_execution_policy_registry()

    nuclei_decision = policies.get("nuclei").evaluate(TARGET_URL, "https://api.example.com")
    semgrep_decision = policies.get("semgrep").evaluate(TARGET_REPOSITORY_PATH, "/repo")
    semgrep_parse_decision = policies.get("semgrep").evaluate_parse_only(
        TARGET_REPOSITORY_PATH, "/repo"
    )
    unsupported_decision = policies.get("nuclei").evaluate(TARGET_REPOSITORY_PATH, "/repo")

    assert nuclei_decision.allowed is True
    assert semgrep_decision.allowed is False
    assert "disabled until sandbox enforcement" in semgrep_decision.reason
    assert semgrep_parse_decision.allowed is True
    assert "parse-only evidence ingestion" in semgrep_parse_decision.reason
    assert unsupported_decision.allowed is False
    assert "does not support target type" in unsupported_decision.reason


def test_execution_policy_can_disable_nuclei_for_hosted_saas(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_NUCLEI_ENABLED", "false")

    decision = default_validation_execution_policy_registry().get("nuclei").evaluate(
        TARGET_URL,
        "https://api.example.com",
    )

    assert decision.allowed is False
    assert "disabled until sandbox enforcement" in decision.reason


def test_validation_tool_inventory_reports_sandbox_policy(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    with patch("shutil.which", return_value=None):
        inventory = build_validation_tool_inventory()

    tools = {tool.name: tool for tool in inventory}
    assert set(tools) == {
        "nuclei",
        "semgrep",
        "osv-scanner",
        "trivy",
        "checkov",
        "trufflehog",
        "ai-red-team",
    }
    assert tools["nuclei"].active is True
    assert tools["nuclei"].execution_enabled is True
    assert tools["nuclei"].runs_in_sandbox_required is False
    assert tools["nuclei"].supported_targets == ["url"]
    assert tools["nuclei"].available is False
    assert tools["nuclei"].runtime_strategy == "unavailable"
    assert tools["nuclei"].readiness_status == "cli_missing"
    assert "nuclei CLI is not installed" in tools["nuclei"].blocker_reasons[0]
    assert tools["semgrep"].active is True
    assert tools["semgrep"].execution_enabled is True
    assert tools["semgrep"].runs_in_sandbox_required is True
    assert tools["semgrep"].supported_targets == ["repository_path"]
    assert tools["semgrep"].local_allowlist_required is True
    assert tools["semgrep"].local_allowlist_configured is False
    assert tools["semgrep"].sandbox_mode == "process"
    assert tools["semgrep"].runtime_strategy == "unavailable"
    assert tools["semgrep"].container_image == "semgrep/semgrep:latest"
    assert any("THREATGENIX_VALIDATION_ALLOWED_PATHS" in action for action in tools["semgrep"].setup_actions)
    assert tools["osv-scanner"].execution_enabled is True
    assert tools["trivy"].execution_enabled is True
    assert tools["checkov"].execution_enabled is True
    assert tools["trufflehog"].execution_enabled is True
    assert tools["trufflehog"].supported_targets == ["repository_path"]
    assert tools["trufflehog"].category == "secret_exposure_scan"
    assert tools["ai-red-team"].execution_enabled is True
    assert tools["ai-red-team"].supported_targets == ["ai_system"]
    assert tools["ai-red-team"].runtime_strategy == "in_process"
    assert tools["ai-red-team"].available is True
    assert tools["ai-red-team"].category == "ai_system_red_team"


def test_path_tools_need_allowed_roots_even_when_cli_exists(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.delenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", raising=False)
    monkeypatch.delenv("VALIDATION_SCAN_ALLOWED_PATHS", raising=False)

    with patch("shutil.which", return_value="/usr/local/bin/tool"):
        inventory = build_validation_tool_inventory()

    tools = {tool.name: tool for tool in inventory}
    assert tools["nuclei"].readiness_status == "ready"
    assert tools["nuclei"].runtime_strategy == "host_cli"
    assert tools["semgrep"].readiness_status == "needs_configuration"
    assert "Local path allowlist is not configured." in tools["semgrep"].blocker_reasons
    assert tools["ai-red-team"].readiness_status == "needs_configuration"
    assert "Local path allowlist is not configured." in tools["ai-red-team"].blocker_reasons


def test_container_mode_treats_approved_images_as_tool_host(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv("THREATGENIX_VALIDATION_SANDBOX_MODE", "container")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/repo")

    def fake_which(executable, path=None):
        del path
        return "/usr/local/bin/docker" if executable == "docker" else None

    image_present = type("ImagePresent", (), {"returncode": 0})()
    with (
        patch("shutil.which", side_effect=fake_which),
        patch("app.services.validation_sandbox.subprocess.run", return_value=image_present),
    ):
        inventory = build_validation_tool_inventory()

    tools = {tool.name: tool for tool in inventory}
    assert tools["nuclei"].available is True
    assert tools["nuclei"].runtime_strategy == "container_image"
    assert tools["nuclei"].container_image == "projectdiscovery/nuclei:latest"
    assert tools["nuclei"].container_image_present is True
    assert tools["nuclei"].readiness_status == "ready"
    assert tools["semgrep"].available is True
    assert tools["semgrep"].runtime_strategy == "container_image"
    assert tools["semgrep"].readiness_status == "ready"
    assert tools["semgrep"].setup_actions == [
        "Create or run a validation target with per-run authorization."
    ]


def test_container_mode_blocks_missing_images_when_pull_policy_is_never(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv("THREATGENIX_VALIDATION_SANDBOX_MODE", "container")
    monkeypatch.setenv("THREATGENIX_VALIDATION_CONTAINER_PULL", "never")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/repo")

    def fake_which(executable, path=None):
        del path
        return "/usr/local/bin/docker" if executable == "docker" else None

    image_missing = type("ImageMissing", (), {"returncode": 1})()
    with (
        patch("shutil.which", side_effect=fake_which),
        patch("app.services.validation_sandbox.subprocess.run", return_value=image_missing),
    ):
        inventory = build_validation_tool_inventory()

    tools = {tool.name: tool for tool in inventory}
    assert tools["nuclei"].available is False
    assert tools["nuclei"].runtime_strategy == "container_image"
    assert tools["nuclei"].container_image_present is False
    assert tools["nuclei"].readiness_status == "needs_configuration"
    assert "not present locally" in tools["nuclei"].blocker_reasons[0]
    assert tools["semgrep"].available is False
    assert tools["semgrep"].readiness_status == "needs_configuration"
    assert any("Pre-pull semgrep/semgrep:latest" in action for action in tools["semgrep"].setup_actions)


def test_container_mode_can_use_controlled_image_pulls(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv("THREATGENIX_VALIDATION_SANDBOX_MODE", "container")
    monkeypatch.setenv("THREATGENIX_VALIDATION_CONTAINER_PULL", "missing")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/repo")

    def fake_which(executable, path=None):
        del path
        return "/usr/local/bin/docker" if executable == "docker" else None

    image_missing = type("ImageMissing", (), {"returncode": 1})()
    with (
        patch("shutil.which", side_effect=fake_which),
        patch("app.services.validation_sandbox.subprocess.run", return_value=image_missing),
    ):
        inventory = build_validation_tool_inventory()

    tools = {tool.name: tool for tool in inventory}
    assert tools["nuclei"].available is True
    assert tools["nuclei"].runtime_strategy == "container_image"
    assert tools["nuclei"].container_pull_policy == "missing"
    assert tools["nuclei"].readiness_status == "ready"


def test_try_sandbox_inventory_blocks_live_execution_by_default(monkeypatch):
    monkeypatch.delenv("THREATGENIX_VALIDATION_RUNTIME_MODE", raising=False)
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/repo")

    with patch("shutil.which", return_value="/usr/local/bin/tool"):
        inventory = build_validation_tool_inventory()

    tools = {tool.name: tool for tool in inventory}
    assert tools["nuclei"].readiness_status == "needs_configuration"
    assert "Live validation submission is disabled" in tools["nuclei"].blocker_reasons[0]
    assert "Use Try Sandbox" in tools["semgrep"].setup_actions[0]


def test_managed_inventory_does_not_enable_api_local_execution(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.delenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", raising=False)
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/repo")

    with patch("shutil.which", return_value="/usr/local/bin/tool"):
        inventory = build_validation_tool_inventory()

    tools = {tool.name: tool for tool in inventory}
    assert tools["semgrep"].execution_enabled is True
    assert tools["semgrep"].readiness_status == "needs_configuration"
    assert "Managed validation runner is not enabled" in tools["semgrep"].blocker_reasons[0]


def test_managed_inventory_is_ready_when_runner_and_tool_are_available(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/repo")
    monkeypatch.delenv(VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV, raising=False)

    with patch("shutil.which", return_value="/usr/local/bin/tool"):
        inventory = build_validation_tool_inventory()

    tools = {tool.name: tool for tool in inventory}
    assert tools["nuclei"].readiness_status == "needs_configuration"
    assert any(
        "target_only network policy requires an isolated network runner" in reason
        for reason in tools["nuclei"].blocker_reasons
    )
    assert tools["semgrep"].execution_enabled is True
    assert tools["semgrep"].readiness_status == "ready"
    assert not any("API server" in reason for reason in tools["semgrep"].blocker_reasons)
    assert tools["osv-scanner"].readiness_status == "needs_configuration"
    assert any(
        "advisory_db network policy requires an isolated network runner" in reason
        for reason in tools["osv-scanner"].blocker_reasons
    )


def test_self_hosted_inventory_allows_osv_with_process_advisory_db_opt_in(monkeypatch):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("THREATGENIX_APP_ENV", raising=False)
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/repo")
    monkeypatch.setenv(VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV, "true")

    with patch("shutil.which", return_value="/usr/local/bin/tool"):
        inventory = build_validation_tool_inventory()

    tools = {tool.name: tool for tool in inventory}
    assert tools["osv-scanner"].readiness_status == "ready"
    assert not any(
        "advisory_db network policy requires an isolated network runner" in reason
        for reason in tools["osv-scanner"].blocker_reasons
    )
    assert any(
        VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV in action
        for action in tools["osv-scanner"].setup_actions
    )


def test_self_hosted_production_inventory_rejects_process_advisory_opt_in(
    monkeypatch,
):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("THREATGENIX_APP_ENV", raising=False)
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/repo")
    monkeypatch.setenv(VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV, "true")

    with patch("shutil.which", return_value="/usr/local/bin/tool"):
        inventory = build_validation_tool_inventory()

    tools = {tool.name: tool for tool in inventory}
    assert tools["osv-scanner"].readiness_status == "needs_configuration"
    assert any(
        "advisory_db network policy requires an isolated network runner" in reason
        for reason in tools["osv-scanner"].blocker_reasons
    )


@pytest.mark.parametrize(
    ("env_name", "env_value"),
    [
        ("APP_ENV", "production"),
        ("APP_ENV", "staging"),
        ("THREATGENIX_APP_ENV", "production"),
        ("THREATGENIX_APP_ENV", "staging"),
    ],
)
def test_managed_inventory_rejects_process_advisory_db_opt_in_in_production_like_env(
    monkeypatch,
    env_name,
    env_value,
):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("THREATGENIX_APP_ENV", raising=False)
    monkeypatch.setenv(env_name, env_value)
    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", "/repo")
    monkeypatch.setenv(VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV, "true")

    with patch("shutil.which", return_value="/usr/local/bin/tool"):
        inventory = build_validation_tool_inventory()

    tools = {tool.name: tool for tool in inventory}
    assert tools["osv-scanner"].readiness_status == "needs_configuration"
    assert any(
        "advisory_db network policy requires an isolated network runner" in reason
        for reason in tools["osv-scanner"].blocker_reasons
    )


@pytest.mark.asyncio
async def test_validation_tool_inventory_endpoint_returns_registered_tools():
    with patch("shutil.which", return_value=None):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get("/api/validation-tools")

    assert response.status_code == 200
    body = response.json()
    tools = {tool["name"]: tool for tool in body["tools"]}
    assert tools["nuclei"]["active"] is True
    assert tools["nuclei"]["execution_enabled"] is True
    assert tools["nuclei"]["readiness_status"] == "cli_missing"
    assert tools["nuclei"]["setup_actions"]
    assert tools["semgrep"]["active"] is True
    assert tools["semgrep"]["runs_in_sandbox_required"] is True
    assert tools["semgrep"]["sandbox_mode"] == "process"
    assert tools["semgrep"]["container_image"] == "semgrep/semgrep:latest"
    assert tools["semgrep"]["local_allowlist_required"] is True
    assert tools["trivy"]["supported_targets"] == [
        "repository_path",
        "iac_directory",
    ]
    assert set(tools) == {
        "nuclei",
        "semgrep",
        "osv-scanner",
        "trivy",
        "checkov",
        "trufflehog",
        "ai-red-team",
    }
    assert body["red_team_tools"] == []


def test_semgrep_execution_policy_can_be_enabled_by_env(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_SEMGREP_ENABLED", "true")

    policies = default_validation_execution_policy_registry()
    decision = policies.get("semgrep").evaluate(TARGET_REPOSITORY_PATH, "/repo")

    assert decision.allowed is True


def test_all_sandboxed_execution_policies_can_be_enabled_by_env(monkeypatch):
    monkeypatch.setenv("THREATGENIX_VALIDATION_SEMGREP_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_OSV_SCANNER_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_TRIVY_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_CHECKOV_ENABLED", "true")
    monkeypatch.setenv("THREATGENIX_VALIDATION_TRUFFLEHOG_ENABLED", "true")

    policies = default_validation_execution_policy_registry()

    assert policies.get("semgrep").evaluate("repository_path", "/repo").allowed is True
    assert policies.get("osv-scanner").evaluate("lockfile", "/repo/package-lock.json").allowed is True
    assert policies.get("trivy").evaluate("iac_directory", "/repo/infra").allowed is True
    assert policies.get("checkov").evaluate("iac_directory", "/repo/infra").allowed is True
    assert policies.get("trufflehog").evaluate("repository_path", "/repo").allowed is True
    assert policies.get("ai-red-team").evaluate(TARGET_AI_SYSTEM, "/repo/ai-system.json").allowed is True

from __future__ import annotations

from app.services.validation_env import validation_env_aliases, validation_env_value
from app.services.validation_execution_policy import NETWORK_TARGET_ONLY
from app.services.validation_sandbox import (
    configured_validation_allowed_roots,
    validation_isolated_runner_ready_for,
)


def _clear_validation_env(monkeypatch, name: str) -> None:
    for alias in validation_env_aliases(name):
        monkeypatch.delenv(alias, raising=False)


def test_validation_env_aliases_preserve_legacy_precedence(monkeypatch):
    name = "THREATGENIX_VALIDATION_RUNTIME_MODE"
    _clear_validation_env(monkeypatch, name)
    monkeypatch.setenv("SEMANTIC_REVIEW_VALIDATION_RUNTIME_MODE", "managed")
    monkeypatch.setenv("SSR_VALIDATION_RUNTIME_MODE", "self_hosted")

    assert validation_env_value(name) == "managed"

    monkeypatch.setenv(name, "try_sandbox")

    assert validation_env_value(name) == "try_sandbox"


def test_runtime_mode_accepts_semantic_review_alias(monkeypatch):
    name = "THREATGENIX_VALIDATION_RUNTIME_MODE"
    _clear_validation_env(monkeypatch, name)
    monkeypatch.setenv("SEMANTIC_REVIEW_VALIDATION_RUNTIME_MODE", "self_hosted")

    from app.services.validation_runtime import validation_runtime_mode

    assert validation_runtime_mode() == "self_hosted"


def test_allowed_roots_accept_ssr_alias(monkeypatch, tmp_path):
    name = "THREATGENIX_VALIDATION_ALLOWED_PATHS"
    _clear_validation_env(monkeypatch, name)
    monkeypatch.delenv("VALIDATION_SCAN_ALLOWED_PATHS", raising=False)
    monkeypatch.setenv("SSR_VALIDATION_ALLOWED_PATHS", str(tmp_path))

    assert configured_validation_allowed_roots() == [str(tmp_path)]


def test_isolated_runner_accepts_semantic_review_aliases(monkeypatch):
    env_values = {
        "THREATGENIX_VALIDATION_ISOLATED_RUNNER_BACKEND": "gke",
        "THREATGENIX_VALIDATION_ISOLATED_EGRESS_PROXY_URL": "http://proxy:8080",
        "THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF": "deploy/gcp/isolated-runner/README.md",
        "THREATGENIX_VALIDATION_K8S_API_SERVER": "https://1.2.3.4",
        "THREATGENIX_VALIDATION_K8S_CA_CERT_B64": "LS0tQ0EtLS0t",
        "THREATGENIX_VALIDATION_ISOLATED_IMAGE_NUCLEI": "nuclei@sha256:" + "a" * 64,
    }
    for name, value in env_values.items():
        _clear_validation_env(monkeypatch, name)
        suffix = name.removeprefix("THREATGENIX_VALIDATION_")
        monkeypatch.setenv(f"SEMANTIC_REVIEW_VALIDATION_{suffix}", value)

    assert validation_isolated_runner_ready_for("nuclei", NETWORK_TARGET_ONLY) is True

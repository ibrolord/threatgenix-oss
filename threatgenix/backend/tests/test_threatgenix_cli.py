from __future__ import annotations

import stat
import sys
from types import SimpleNamespace
from pathlib import Path

from app.cli import threatgenix


class FakeClient:
    instances: list["FakeClient"] = []

    def __init__(self, server_url: str, token: str | None) -> None:
        self.server_url = server_url
        self.token = token
        self.calls: list[tuple[str, str, object]] = []
        FakeClient.instances.append(self)

    def get_json(self, path: str, params: dict[str, str] | None = None) -> dict:
        self.calls.append(("GET", path, params or {}))
        if path == "/api/reviews/intake/questions":
            return {
                "version": "threatgenix_appsec_v1",
                "review_type": params["review_type"] if params else "diff",
                "questions": [
                    {"id": "business_purpose", "answer_type": "textarea"},
                    {"id": "data_classification", "answer_type": "single_select"},
                    {"id": "sensitive_data_types", "answer_type": "multi_select"},
                    {"id": "changed_security_surface", "answer_type": "multi_select"},
                    {"id": "scanner_permissions", "answer_type": "multi_select"},
                    {"id": "upload_permission", "answer_type": "boolean"},
                    {"id": "out_of_scope", "answer_type": "string_list"},
                ],
            }
        if path.startswith("/api/agent/reviews/") and path.endswith("/status"):
            return {
                "review": {
                    "id": path.split("/")[-2],
                    "status": "completed",
                    "decision": "pass",
                },
                "web_url": f"https://app.example.com/reviews/{path.split('/')[-2]}",
            }
        if path.startswith("/api/agent/reviews/") and path.endswith("/open"):
            return {
                "review_id": path.split("/")[-2],
                "web_url": f"https://app.example.com/reviews/{path.split('/')[-2]}",
            }
        if path.startswith("/api/agent/reviews/") and path.endswith("/findings"):
            return {
                "review_id": path.split("/")[-2],
                "findings": [
                    {
                        "id": "finding-1",
                        "severity": "high",
                        "title": "Missing authorization",
                    }
                ],
            }
        raise AssertionError(path)

    def post_json(self, path: str, payload: dict) -> dict:
        self.calls.append(("POST", path, payload))
        if path == "/api/reviews/intake/validate":
            return {
                "valid": True,
                "normalized_answers": payload["answers"],
                "missing_required": [],
                "errors": [],
            }
        if path == "/api/auth/login":
            return {"access_token": "login-token"}
        if path == "/api/reviews":
            return {
                "id": "review-123",
                "status": "created",
            }
        if path == "/api/threat-models":
            return {
                "id": "model-123",
                "system_name": payload["system_name"],
            }
        if path == "/api/reviews/review-123/bundles":
            return {
                "id": "bundle-123",
                "content_hash": "b" * 64,
                "file_count": len(payload["manifest"]),
            }
        if path == "/api/reviews/review-123/scanner-jobs":
            return {
                "review_id": "review-123",
                "bundle_id": payload["bundle_id"],
                "jobs": [{"id": "scan-1"}, {"id": "scan-2"}],
            }
        if path == "/api/agent/reviews/review-123/rerun":
            return {
                "review_id": "review-123",
                "indexed_entry_count": 0,
                "decision": {"decision": "pass"},
            }
        if path == "/api/agent/reviews/orchestrations":
            return {
                "contract_version": "threatgenix.agent.v1",
                "orchestration": {
                    "status": "completed",
                    "review": {"id": "review-123", "status": "completed"},
                    "web_url": "https://app.example.com/reviews/review-123",
                    "scanner_jobs": [{"id": "scan-1"}],
                    "decision": {"decision": "pass"},
                },
                "agent_tools": [{"name": "threatgenix.review.status"}],
            }
        raise AssertionError(path)


def _factory(server_url: str, token: str | None) -> FakeClient:
    return FakeClient(server_url, token)


def _answers() -> list[str]:
    return [
        "--answer",
        "business_purpose=Exports customer data for support operations.",
        "--answer",
        "data_classification=restricted",
        "--answer",
        "sensitive_data_types=pii",
        "--answer",
        "changed_security_surface=sensitive_data,authz",
        "--answer",
        "scanner_permissions=static_code,dependencies,secrets",
        "--answer",
        "upload_permission=true",
        "--answer",
        "out_of_scope=production database contents",
    ]


def test_init_writes_config(tmp_path: Path, capsys):
    config_path = tmp_path / ".threatgenix.yml"

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "init",
            "--server-url",
            "https://api.example.com",
            "--web-url",
            "https://app.example.com",
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    assert 'server_url: "https://api.example.com"' in config_path.read_text()
    assert 'web_url: "https://app.example.com"' in config_path.read_text()
    assert "Wrote" in capsys.readouterr().out


def test_init_detects_git_context_and_stores_answer_defaults(tmp_path: Path, capsys, monkeypatch):
    config_path = tmp_path / ".threatgenix.yml"
    monkeypatch.setattr(
        threatgenix,
        "detect_git_context",
        lambda _repo_path: {
            "git_remote": "git@github.com:example-org/example-app.git",
            "git_branch": "main",
            "git_commit": "abc123",
        },
    )

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "init",
            "--server-url",
            "https://api.example.com",
            "--app-name",
            "ExampleApp",
            "--answer",
            "business_purpose=Customer exports",
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    config_text = config_path.read_text(encoding="utf-8")
    assert 'app_name: "ExampleApp"' in config_text
    assert 'git_remote: "git@github.com:example-org/example-app.git"' in config_text
    assert 'answer.business_purpose: "Customer exports"' in config_text
    assert "token" not in config_text.casefold()
    assert "secrets_written=false" in capsys.readouterr().out


def test_login_stores_token_in_keyring_without_printing_secret(tmp_path: Path, capsys, monkeypatch):
    config_path = tmp_path / ".threatgenix.yml"
    stored: dict[tuple[str, str], str] = {}
    fake_keyring = SimpleNamespace(
        set_password=lambda service, account, token: stored.__setitem__((service, account), token),
        get_password=lambda service, account: stored.get((service, account)),
    )
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "login",
            "--server-url",
            "https://api.example.com",
            "--email",
            "user@example.com",
            "--password",
            "password-123",
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    assert stored[(threatgenix.KEYRING_SERVICE, "https://api.example.com")] == "login-token"
    output = capsys.readouterr().out
    assert "token_storage=keyring" in output
    assert "login-token" not in output


def test_login_fallback_token_file_uses_0600_and_warns(tmp_path: Path, capsys, monkeypatch):
    config_path = tmp_path / ".threatgenix.yml"
    token_path = tmp_path / "token"
    monkeypatch.setitem(sys.modules, "keyring", None)

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "login",
            "--server-url",
            "https://api.example.com",
            "--token",
            "manual-token",
            "--token-file",
            str(token_path),
            "--no-keyring",
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    assert token_path.read_text(encoding="utf-8").strip() == "manual-token"
    assert stat.S_IMODE(token_path.stat().st_mode) == 0o600
    output = capsys.readouterr().out
    assert "token_storage=file" in output
    assert "warning=keyring unavailable" in output
    assert "manual-token" not in output


def test_review_fetches_question_bank_validates_and_creates_review(tmp_path: Path, capsys):
    FakeClient.instances.clear()
    config_path = tmp_path / ".threatgenix.yml"
    threatgenix.write_config(
        config_path,
        server_url="https://api.example.com",
        web_url="https://app.example.com",
    )

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "review",
            "--token",
            "token-123",
            "--app-name",
            "ExampleApp",
            "--commit-sha",
            "abc123",
            "--tool",
            "semgrep",
            *_answers(),
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "review_id=review-123" in output
    assert "url=https://app.example.com/reviews/review-123" in output
    client = FakeClient.instances[0]
    assert client.server_url == "https://api.example.com"
    assert client.token == "token-123"
    assert client.calls[0] == ("GET", "/api/reviews/intake/questions", {"review_type": "diff"})
    assert client.calls[1][0:2] == ("POST", "/api/reviews/intake/validate")
    create_payload = client.calls[2][2]
    assert create_payload["app_name"] == "ExampleApp"
    assert create_payload["intake_answers"]["scanner_permissions"] == [
        "static_code",
        "dependencies",
        "secrets",
    ]


def test_review_wait_polls_until_terminal_status(tmp_path: Path, capsys):
    FakeClient.instances.clear()
    config_path = tmp_path / ".threatgenix.yml"
    threatgenix.write_config(
        config_path,
        server_url="https://api.example.com",
        web_url="https://app.example.com",
    )

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "review",
            "--token",
            "token-123",
            "--app-name",
            "ExampleApp",
            "--commit-sha",
            "abc123",
            "--wait",
            "--wait-timeout",
            "1",
            "--wait-interval",
            "0",
            *_answers(),
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "rerun_indexed_entries=0" in output
    assert "rerun_decision=pass" in output
    assert "wait_status=completed" in output
    assert "decision=pass" in output
    assert ("POST", "/api/agent/reviews/review-123/rerun", {}) in FakeClient.instances[0].calls
    assert ("GET", "/api/agent/reviews/review-123/status", {}) in FakeClient.instances[0].calls


def test_review_wait_times_out_with_last_status(tmp_path: Path, capsys):
    class SlowClient(FakeClient):
        def get_json(self, path: str, params: dict[str, str] | None = None) -> dict:
            if path.startswith("/api/agent/reviews/") and path.endswith("/status"):
                self.calls.append(("GET", path, params or {}))
                return {
                    "review": {
                        "id": path.split("/")[-2],
                        "status": "scanning",
                    }
                }
            return super().get_json(path, params)

    def factory(server_url: str, token: str | None) -> SlowClient:
        return SlowClient(server_url, token)

    config_path = tmp_path / ".threatgenix.yml"
    threatgenix.write_config(config_path, server_url="https://api.example.com")

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "review",
            "--token",
            "token-123",
            "--app-name",
            "ExampleApp",
            "--commit-sha",
            "abc123",
            "--wait",
            "--wait-timeout",
            "0",
            "--wait-interval",
            "0",
            *_answers(),
        ],
        client_factory=factory,
    )

    assert exit_code == 2
    error = capsys.readouterr().err
    assert "Timed out waiting for review review-123" in error
    assert "last_status=scanning" in error
    assert ("POST", "/api/agent/reviews/review-123/rerun", {}) in SlowClient.instances[0].calls


def test_review_uses_configured_app_answers_and_stored_file_token(tmp_path: Path, capsys):
    FakeClient.instances.clear()
    config_path = tmp_path / ".threatgenix.yml"
    token_path = tmp_path / "token"
    threatgenix.store_file_token("https://api.example.com", "stored-token", str(token_path))
    threatgenix.write_config(
        config_path,
        server_url="https://api.example.com",
        web_url="https://app.example.com",
        app_name="ExampleApp",
        default_review_type="metadata",
        token_file=str(token_path),
        intake_answers={
            "business_purpose": "Exports customer data for support operations.",
            "data_classification": "restricted",
            "sensitive_data_types": "pii",
            "changed_security_surface": "sensitive_data,authz",
            "scanner_permissions": "static_code,dependencies,secrets",
            "upload_permission": "true",
            "out_of_scope": "production database contents",
        },
    )

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "review",
            "--commit-sha",
            "abc123",
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    assert "review_id=review-123" in capsys.readouterr().out
    client = FakeClient.instances[0]
    assert client.token == "stored-token"
    assert client.calls[0] == ("GET", "/api/reviews/intake/questions", {"review_type": "metadata"})
    create_payload = client.calls[2][2]
    assert create_payload["app_name"] == "ExampleApp"
    assert create_payload["intake_answers"]["upload_permission"] is True
    assert create_payload["intake_answers"]["sensitive_data_types"] == ["pii"]


def test_review_can_create_model_upload_bundle_and_enqueue_scanners(tmp_path: Path, capsys):
    FakeClient.instances.clear()
    config_path = tmp_path / ".threatgenix.yml"
    source_dir = tmp_path / "repo"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (source_dir / "requirements.txt").write_text("fastapi==1.0.0\n", encoding="utf-8")
    threatgenix.write_config(
        config_path,
        server_url="https://api.example.com",
        web_url="https://app.example.com",
    )

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "review",
            "--token",
            "token-123",
            "--app-name",
            "ExampleApp",
            "--commit-sha",
            "abc123",
            "--tool",
            "semgrep",
            "--tool",
            "trivy",
            "--create-threat-model",
            "--upload-bundle",
            "--source-path",
            str(source_dir),
            "--enqueue-scanners",
            *_answers(),
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "threat_model_id=model-123" in output
    assert "review_id=review-123" in output
    assert "bundle_id=bundle-123" in output
    assert "scanner_jobs=2" in output
    client = FakeClient.instances[0]
    assert client.calls[2][0:2] == ("POST", "/api/threat-models")
    create_payload = client.calls[3][2]
    assert create_payload["threat_model_id"] == "model-123"
    bundle_payload = client.calls[4][2]
    manifest_paths = {item["path"] for item in bundle_payload["manifest"]}
    assert "app.py" in manifest_paths
    assert "requirements.txt" in manifest_paths
    assert {
        item["file_kind"] for item in bundle_payload["manifest"]
    } == {"source", "dependency_lock"}
    enqueue_payload = client.calls[5][2]
    assert enqueue_payload["bundle_id"] == "bundle-123"
    assert enqueue_payload["tools"] == ["semgrep", "trivy"]


def test_review_refuses_scanner_enqueue_without_linked_model(tmp_path: Path, capsys):
    config_path = tmp_path / ".threatgenix.yml"
    threatgenix.write_config(config_path, server_url="https://api.example.com")

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "review",
            "--token",
            "token-123",
            "--app-name",
            "ExampleApp",
            "--commit-sha",
            "abc123",
            "--upload-bundle",
            "--enqueue-scanners",
            *_answers(),
        ],
        client_factory=_factory,
    )

    assert exit_code == 2
    assert "--enqueue-scanners requires --threat-model-id or --create-threat-model" in capsys.readouterr().err


def test_build_manifest_skips_runtime_dirs_and_classifies_files(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "src").mkdir()
    (repo / "src" / "main.ts").write_text("export const ok = true\n", encoding="utf-8")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_main.py").write_text("def test_ok(): pass\n", encoding="utf-8")
    (repo / "terraform.tf").write_text("resource x\n", encoding="utf-8")
    (repo / "README.md").write_text("# docs\n", encoding="utf-8")
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "skip.js").write_text("bad\n", encoding="utf-8")

    manifest = threatgenix.build_manifest([str(repo)], max_files=5000)

    by_path = {item["path"]: item for item in manifest}
    assert "src/main.ts" in by_path
    assert by_path["src/main.ts"]["file_kind"] == "source"
    assert by_path["tests/test_main.py"]["file_kind"] == "test"
    assert by_path["terraform.tf"]["file_kind"] == "iac"
    assert by_path["README.md"]["file_kind"] == "doc"
    assert "skip.js" not in by_path


def test_review_refuses_missing_token(tmp_path: Path, capsys, monkeypatch):
    config_path = tmp_path / ".threatgenix.yml"
    threatgenix.write_config(config_path, server_url="https://api.example.com")
    monkeypatch.delenv("THREATGENIX_TOKEN", raising=False)

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "review",
            "--app-name",
            "ExampleApp",
            "--commit-sha",
            "abc123",
        ],
        client_factory=_factory,
    )

    assert exit_code == 2
    assert "Missing token" in capsys.readouterr().err


def test_review_rejects_unknown_answer_before_submit(tmp_path: Path, capsys):
    FakeClient.instances.clear()
    config_path = tmp_path / ".threatgenix.yml"
    threatgenix.write_config(config_path, server_url="https://api.example.com")

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "review",
            "--token",
            "token-123",
            "--app-name",
            "ExampleApp",
            "--commit-sha",
            "abc123",
            "--answer",
            "unknown=value",
        ],
        client_factory=_factory,
    )

    assert exit_code == 2
    assert "Unknown intake answer: unknown" in capsys.readouterr().err
    assert len(FakeClient.instances[0].calls) == 1


def test_status_prints_decision(capsys):
    FakeClient.instances.clear()

    exit_code = threatgenix.main(
        [
            "status",
            "--server-url",
            "https://api.example.com",
            "--token",
            "token-123",
            "review-123",
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "review_id=review-123" in output
    assert "status=completed" in output
    assert "decision=pass" in output
    assert "url=https://app.example.com/reviews/review-123" in output


def test_open_prints_configured_web_review_url_without_token(tmp_path: Path, capsys):
    config_path = tmp_path / ".threatgenix.yml"
    threatgenix.write_config(
        config_path,
        server_url="https://api.example.com",
        web_url="https://app.example.com",
    )

    exit_code = threatgenix.main(
        ["--config", str(config_path), "open", "review-123"],
        client_factory=_factory,
    )

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "https://app.example.com/reviews/review-123"


def test_open_prefers_agent_open_endpoint_when_token_is_available(tmp_path: Path, capsys):
    FakeClient.instances.clear()
    config_path = tmp_path / ".threatgenix.yml"
    threatgenix.write_config(
        config_path,
        server_url="https://api.example.com",
        web_url="https://configured.example.com",
    )

    exit_code = threatgenix.main(
        ["--config", str(config_path), "open", "--token", "token-123", "review-123"],
        client_factory=_factory,
    )

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "https://app.example.com/reviews/review-123"
    assert FakeClient.instances[0].calls == [
        ("GET", "/api/agent/reviews/review-123/open", {}),
    ]


def test_findings_prints_count_and_titles(capsys):
    FakeClient.instances.clear()

    exit_code = threatgenix.main(
        [
            "findings",
            "--server-url",
            "https://api.example.com",
            "--token",
            "token-123",
            "review-123",
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "review_id=review-123" in output
    assert "findings=1" in output
    assert "Missing authorization" in output
    assert FakeClient.instances[0].calls == [
        ("GET", "/api/agent/reviews/review-123/findings", {"limit": "20"}),
    ]


def test_mcp_config_prints_server_config_without_expanding_token(tmp_path: Path, capsys):
    config_path = tmp_path / ".threatgenix.yml"
    threatgenix.write_config(config_path, server_url="https://api.example.com")

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "mcp-config",
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    config = threatgenix.json.loads(capsys.readouterr().out)
    server = config["mcpServers"]["threatgenix"]
    assert server["command"] == "threatgenix-mcp"
    assert server["args"] == []
    assert server["env"]["THREATGENIX_API_URL"] == "https://api.example.com"
    assert server["env"]["THREATGENIX_TOKEN"] == "${THREATGENIX_TOKEN}"


def test_mcp_config_can_emit_source_tree_module_mode(tmp_path: Path, capsys):
    config_path = tmp_path / ".threatgenix.yml"
    threatgenix.write_config(config_path, server_url="https://api.example.com")

    exit_code = threatgenix.main(
        [
            "--config",
            str(config_path),
            "mcp-config",
            "--command",
            "/opt/threatgenix/python",
            "--module-mode",
        ],
        client_factory=_factory,
    )

    assert exit_code == 0
    config = threatgenix.json.loads(capsys.readouterr().out)
    server = config["mcpServers"]["threatgenix"]
    assert server["command"] == "/opt/threatgenix/python"
    assert server["args"] == ["-m", "app.cli.threatgenix_mcp"]

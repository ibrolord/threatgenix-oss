from __future__ import annotations

from io import BytesIO

from app.cli import threatgenix_mcp


class FakeClient:
    instances: list["FakeClient"] = []

    def __init__(self, server_url: str, token: str | None) -> None:
        self.server_url = server_url
        self.token = token
        self.calls: list[tuple[str, str, object]] = []
        FakeClient.instances.append(self)

    def get_json(self, path: str, params: dict[str, str] | None = None) -> dict:
        self.calls.append(("GET", path, params or {}))
        if path.endswith("/status"):
            return {
                "contract_version": "threatgenix.agent.v1",
                "review": {"id": "review-123", "status": "completed", "decision": "pass"},
                "web_url": "https://app.example.com/reviews/review-123",
                "access": {
                    "rate_limit": {
                        "window_seconds": 60,
                        "token_limit": 60,
                        "token_remaining": 59,
                        "tenant_limit": 120,
                        "tenant_remaining": 119,
                        "retry_after_seconds": 30,
                        "token_fingerprint": "abc123",
                    },
                    "quotas": {
                        "scan_minutes": {
                            "window_seconds": 60,
                            "limit": 30,
                            "used": 0,
                            "remaining": 30,
                        }
                    },
                },
            }
        if path.endswith("/findings"):
            return {
                "contract_version": "threatgenix.agent.v1",
                "review_id": "review-123",
                "findings": [],
            }
        if path.endswith("/open"):
            return {
                "contract_version": "threatgenix.agent.v1",
                "review_id": "review-123",
                "web_url": "https://app.example.com/reviews/review-123",
            }
        raise AssertionError(path)

    def post_json(self, path: str, payload: dict) -> dict:
        self.calls.append(("POST", path, payload))
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
        if path.endswith("/rerun"):
            return {
                "contract_version": "threatgenix.agent.v1",
                "review_id": "review-123",
                "indexed_entry_count": 2,
                "decision": {"decision": "pass"},
            }
        raise AssertionError(path)


def _factory(server_url: str, token: str | None) -> FakeClient:
    return FakeClient(server_url, token)


def test_mcp_lists_stable_threatgenix_tools():
    response = threatgenix_mcp.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    assert response is not None
    assert response["result"]["tools"][0]["name"] == "threatgenix.review.orchestrate"
    assert response["result"]["tools"][0]["annotations"]["threatgenix_rate_limit"]["scope"] == (
        "tenant_and_token"
    )
    assert "bundle_storage_bytes" in response["result"]["tools"][0]["annotations"]["threatgenix_quota_cost"]
    assert {tool["name"] for tool in response["result"]["tools"]} == {
        "threatgenix.review.orchestrate",
        "threatgenix.review.status",
        "threatgenix.review.findings",
        "threatgenix.review.rerun",
        "threatgenix.review.open",
    }


def test_mcp_orchestrate_calls_tenant_scoped_agent_api(monkeypatch):
    FakeClient.instances.clear()
    monkeypatch.setenv("THREATGENIX_API_URL", "https://api.example.com")
    monkeypatch.setenv("THREATGENIX_TOKEN", "tenant-token")

    response = threatgenix_mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "threatgenix.review.orchestrate",
                "arguments": {
                    "review": {
                        "app_name": "ExampleApp",
                        "invocation_surface": "mcp",
                        "input_kind": "diff",
                        "intake_answers": {"business_purpose": "Customer export."},
                    }
                },
            },
        },
        client_factory=_factory,
    )

    assert response is not None
    result = response["result"]["structuredContent"]
    assert result["contract_version"] == "threatgenix.agent.v1"
    assert result["orchestration"]["web_url"] == "https://app.example.com/reviews/review-123"
    client = FakeClient.instances[0]
    assert client.server_url == "https://api.example.com"
    assert client.token == "tenant-token"
    assert client.calls[0][0:2] == ("POST", "/api/agent/reviews/orchestrations")


def test_mcp_status_and_open_return_review_url(monkeypatch):
    monkeypatch.setenv("THREATGENIX_API_URL", "https://api.example.com")
    monkeypatch.setenv("THREATGENIX_TOKEN", "tenant-token")

    status = threatgenix_mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "threatgenix.review.status",
                "arguments": {"review_id": "review-123"},
            },
        },
        client_factory=_factory,
    )
    opened = threatgenix_mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "threatgenix.review.open",
                "arguments": {"review_id": "review-123"},
            },
        },
        client_factory=_factory,
    )

    assert status is not None
    assert opened is not None
    assert status["result"]["structuredContent"]["web_url"].endswith("/reviews/review-123")
    assert status["result"]["structuredContent"]["access"]["rate_limit"]["token_remaining"] == 59
    assert opened["result"]["structuredContent"]["web_url"].endswith("/reviews/review-123")


def test_mcp_missing_token_returns_json_rpc_error(monkeypatch):
    monkeypatch.delenv("THREATGENIX_TOKEN", raising=False)

    response = threatgenix_mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "threatgenix.review.status",
                "arguments": {"review_id": "review-123"},
            },
        },
        client_factory=_factory,
    )

    assert response is not None
    assert response["error"]["code"] == -32000
    assert "Missing THREATGENIX_TOKEN" in response["error"]["message"]


def test_mcp_content_length_framing_round_trips():
    message = {"jsonrpc": "2.0", "id": 6, "method": "tools/list"}
    stream = BytesIO()

    threatgenix_mcp.write_framed_message(stream, message)
    stream.seek(0)

    assert threatgenix_mcp.read_framed_message(stream) == message

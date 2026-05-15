from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.services import llm_client


def test_production_rejects_non_bedrock_provider(monkeypatch):
    monkeypatch.setattr(llm_client.settings, "app_env", "production")
    monkeypatch.setattr(llm_client.settings, "llm_provider", "anthropic")
    monkeypatch.setattr(llm_client.settings, "allow_external_ai_providers_in_production", False)
    monkeypatch.setattr(llm_client, "_cached_client", None)

    with pytest.raises(RuntimeError, match="restricted to AWS Bedrock"):
        llm_client.get_llm_client()


def test_production_rejects_non_canadian_bedrock_model_without_opt_in(monkeypatch):
    monkeypatch.setattr(llm_client.settings, "app_env", "production")
    monkeypatch.setattr(llm_client.settings, "allow_external_ai_providers_in_production", False)

    with pytest.raises(RuntimeError, match="Canadian Bedrock inference profile"):
        llm_client.set_provider_for_user(
            uuid.uuid4(),
            "bedrock",
            "us.anthropic.claude-opus-4-5-20251101-v1:0",
        )


def test_production_auto_only_attempts_bedrock(monkeypatch):
    attempted: list[str] = []

    def fake_try_provider(name: str):
        attempted.append(name)
        return None

    monkeypatch.setattr(llm_client.settings, "app_env", "production")
    monkeypatch.setattr(llm_client.settings, "llm_provider", "auto")
    monkeypatch.setattr(llm_client.settings, "allow_external_ai_providers_in_production", False)
    monkeypatch.setattr(llm_client, "_cached_client", None)
    monkeypatch.setattr(llm_client, "_try_provider", fake_try_provider)

    with pytest.raises(RuntimeError, match="No LLM provider available"):
        llm_client.get_llm_client()

    assert attempted == ["bedrock"]


def test_production_opt_in_allows_non_bedrock_provider(monkeypatch):
    class FakeAnthropicProvider:
        provider_name = "anthropic"
        model_name = "claude-opus-4-1"

    monkeypatch.setattr(llm_client.settings, "app_env", "production")
    monkeypatch.setattr(llm_client.settings, "llm_provider", "anthropic")
    monkeypatch.setattr(llm_client.settings, "allow_external_ai_providers_in_production", True)
    monkeypatch.setattr(llm_client, "_PROVIDER_MAP", {"anthropic": FakeAnthropicProvider})
    monkeypatch.setattr(llm_client, "_cached_client", None)

    client = llm_client.get_llm_client()

    assert client.provider_name == "anthropic"


def test_production_opt_in_allows_non_canadian_bedrock_model(monkeypatch):
    class FakeBedrockProvider:
        provider_name = "bedrock"
        model_name = "ca.amazon.nova-lite-v1:0"

    monkeypatch.setattr(llm_client.settings, "app_env", "production")
    monkeypatch.setattr(llm_client.settings, "allow_external_ai_providers_in_production", True)
    monkeypatch.setattr(llm_client, "_PROVIDER_MAP", {"bedrock": FakeBedrockProvider})

    client = llm_client.set_provider_for_user(
        uuid.uuid4(),
        "bedrock",
        "us.anthropic.claude-opus-4-5-20251101-v1:0",
    )

    assert client.provider_name == "bedrock"
    assert client.model_name == "us.anthropic.claude-opus-4-5-20251101-v1:0"


def test_production_opt_in_auto_attempts_all_providers(monkeypatch):
    attempted: list[str] = []

    def fake_try_provider(name: str):
        attempted.append(name)
        return None

    monkeypatch.setattr(llm_client.settings, "app_env", "production")
    monkeypatch.setattr(llm_client.settings, "llm_provider", "auto")
    monkeypatch.setattr(llm_client.settings, "allow_external_ai_providers_in_production", True)
    monkeypatch.setattr(llm_client, "_cached_client", None)
    monkeypatch.setattr(llm_client, "_try_provider", fake_try_provider)

    with pytest.raises(RuntimeError, match="No LLM provider available"):
        llm_client.get_llm_client()

    assert attempted == [name for name, _ in llm_client.PROVIDER_REGISTRY]


@pytest.mark.asyncio
async def test_byok_lookup_accepts_uuid_user_id_and_applies_model_override(monkeypatch):
    calls: list[tuple[str, str | None]] = []

    class FakeDB:
        async def execute(self, _stmt):
            class Result:
                @staticmethod
                def scalar_one_or_none():
                    return None

            return Result()

    class FakeClient:
        provider_name = "bedrock"
        model_name = "ca.anthropic.test-profile"

    def fake_build_provider_client(provider_name: str, model: str | None = None):
        calls.append((provider_name, model))
        return FakeClient()

    monkeypatch.setattr(llm_client, "_build_provider_client", fake_build_provider_client)

    client = await llm_client.get_llm_client_for_user_byok(
        uuid.uuid4(),
        "bedrock",
        FakeDB(),
        model="ca.anthropic.test-profile",
    )

    assert client.provider_name == "bedrock"
    assert calls == [("bedrock", "ca.anthropic.test-profile")]


@pytest.mark.asyncio
async def test_async_user_provider_preference_preserves_model_override(monkeypatch):
    user_id = uuid.uuid4()
    calls: list[tuple[uuid.UUID | str, str, str | None]] = []

    class FakeClient:
        provider_name = "bedrock"
        model_name = "ca.anthropic.test-profile"

    async def fake_user_byok(user_id_arg, provider_name, _db, model=None):
        calls.append((user_id_arg, provider_name, model))
        return FakeClient()

    monkeypatch.setattr(
        llm_client,
        "_user_provider_preferences",
        {str(user_id): ("bedrock", "ca.anthropic.test-profile")},
    )
    monkeypatch.setattr(llm_client, "get_llm_client_for_user_byok", fake_user_byok)

    client = await llm_client.get_llm_client_for_user_async(user_id, object())

    assert client.model_name == "ca.anthropic.test-profile"
    assert calls == [(user_id, "bedrock", "ca.anthropic.test-profile")]


def test_byok_client_construction_does_not_mutate_server_key(monkeypatch):
    calls: list[tuple[str | None, str | None, str | None]] = []

    class FakeOpenAIProvider:
        provider_name = "openai"

        def __init__(self, *, api_key: str | None = None, model: str | None = None):
            calls.append((api_key, model, llm_client.settings.openai_api_key))
            self.model_name = model or "default"

    monkeypatch.setattr(llm_client.settings, "openai_api_key", None)
    monkeypatch.setattr(llm_client, "_PROVIDER_MAP", {"openai": FakeOpenAIProvider})

    client = llm_client._build_provider_client_with_key("openai", "sk-user", "gpt-user")

    assert client.model_name == "gpt-user"
    assert calls == [("sk-user", "gpt-user", None)]
    assert llm_client.settings.openai_api_key is None


@pytest.mark.parametrize(
    ("model", "expected_token_limit_key"),
    [
        ("gpt-4o", "max_tokens"),
        ("gpt-5.4-mini", "max_completion_tokens"),
        ("o3", "max_completion_tokens"),
    ],
)
def test_openai_provider_uses_model_compatible_token_limit(
    monkeypatch,
    model: str,
    expected_token_limit_key: str,
):
    captured: dict[str, object] = {}

    class FakeResponse:
        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "arguments": '{"summary":"ok"}',
                                    }
                                }
                            ]
                        }
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }

    class FakeHTTPClient:
        def __init__(self, timeout):
            self.timeout = timeout

        def post(self, url, *, headers, json):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return FakeResponse()

    import httpx

    monkeypatch.setattr(httpx, "Client", FakeHTTPClient)

    client = llm_client.OpenAIProvider(api_key="sk-test", model=model)
    result = client.call_with_tools(
        system_message="system",
        user_message="user",
        tools=[
            {
                "name": "record_agent_reasoning",
                "description": "Record result",
                "inputSchema": {"json": {"type": "object"}},
            }
        ],
        max_tokens=32,
    )

    assert result == {"summary": "ok"}
    body = captured["json"]
    assert isinstance(body, dict)
    assert body[expected_token_limit_key] == 32
    other_key = "max_completion_tokens" if expected_token_limit_key == "max_tokens" else "max_tokens"
    assert other_key not in body


def test_gemini_provider_uses_header_auth_not_query_parameter(monkeypatch):
    captured: dict[str, object] = {}

    class FakeResponse:
        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {
                "candidates": [
                    {"content": {"parts": [{"functionCall": {"args": {"ok": True}}}]}}
                ],
                "usageMetadata": {},
            }

    class FakeHTTPClient:
        def __init__(self, timeout):
            self.timeout = timeout

        def post(self, url, *, headers, json):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return FakeResponse()

    import httpx

    monkeypatch.setattr(httpx, "Client", FakeHTTPClient)

    client = llm_client.GeminiProvider(
        api_key="gemini-secret-key",
        model="gemini-test",
    )
    result = client.call_with_tools(
        system_message="system",
        user_message="user",
        tools=[
            {
                "name": "record",
                "description": "Record result",
                "inputSchema": {"json": {"type": "object"}},
            }
        ],
    )

    assert result == {"ok": True}
    assert "gemini-secret-key" not in str(captured["url"])
    assert "?key=" not in str(captured["url"])
    assert captured["headers"] == {"x-goog-api-key": "gemini-secret-key"}


def test_gemini_provider_redacts_api_key_from_errors(monkeypatch, caplog):
    class FakeHTTPClient:
        def __init__(self, timeout):
            self.timeout = timeout

        def post(self, url, *, headers, json):
            del url, headers, json
            raise RuntimeError(
                "request failed for https://example.test?key=gemini-secret-key "
                "Authorization: Bearer bearer-secret"
            )

    import httpx

    monkeypatch.setattr(httpx, "Client", FakeHTTPClient)
    client = llm_client.GeminiProvider(
        api_key="gemini-secret-key",
        model="gemini-test",
    )

    with caplog.at_level("WARNING", logger="app.services.llm_client"):
        result = client.call_with_tools(
            system_message="system",
            user_message="user",
            tools=[
                {
                    "name": "record",
                    "description": "Record result",
                    "inputSchema": {"json": {"type": "object"}},
                }
            ],
        )

    assert result is None
    assert "gemini-secret-key" not in caplog.text
    assert "bearer-secret" not in caplog.text
    assert "key=[redacted]" in caplog.text


@pytest.mark.asyncio
async def test_byok_lookup_normalizes_provider_and_prefers_stored_model(monkeypatch):
    calls: list[tuple[str, str, str | None]] = []
    user_id = uuid.uuid4()

    class FakeDB:
        async def execute(self, _stmt):
            class Result:
                @staticmethod
                def scalar_one_or_none():
                    return SimpleNamespace(
                        encrypted_key="encrypted-user-key",
                        model_override="gpt-byok",
                    )

            return Result()

    class FakeClient:
        provider_name = "openai"
        model_name = "gpt-byok"

    def fake_build_provider_client_with_key(
        provider_name: str,
        api_key: str,
        model: str | None = None,
    ):
        calls.append((provider_name, api_key, model))
        return FakeClient()

    monkeypatch.setattr(llm_client, "_PROVIDER_MAP", {"openai": object})
    monkeypatch.setattr(
        "app.services.key_encryption.decrypt_key",
        lambda encrypted: f"decrypted:{encrypted}",
    )
    monkeypatch.setattr(
        llm_client,
        "_build_provider_client_with_key",
        fake_build_provider_client_with_key,
    )

    client = await llm_client.get_llm_client_for_user_byok(
        user_id,
        "OpenAI",
        FakeDB(),
        model="gpt-request",
    )

    assert client.model_name == "gpt-byok"
    assert calls == [("openai", "decrypted:encrypted-user-key", "gpt-byok")]

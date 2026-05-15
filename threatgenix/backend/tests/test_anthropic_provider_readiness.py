"""Deterministic and opt-in live readiness checks for direct Anthropic calls.

Default run:
    pytest tests/test_anthropic_provider_readiness.py -q

Opt-in live smoke:
    THREATGENIX_RUN_ANTHROPIC_LIVE_SMOKE=1 \
    ANTHROPIC_API_KEY=... \
    THREATGENIX_LIVE_ANTHROPIC_MODEL=...opus... \
    pytest tests/test_anthropic_provider_readiness.py::test_live_anthropic_opus_tool_call_smoke -q
"""

from __future__ import annotations

import logging
import os
from types import SimpleNamespace

import pytest

from app.services import llm_client


SYNTHETIC_SYSTEM_MESSAGE = (
    "You are validating a ThreatGenix Anthropic provider integration. "
    "Use the provided readiness tool exactly once. Do not include customer data. "
    "Return every required tool field exactly as requested."
)

SYNTHETIC_USER_MESSAGE = (
    "Synthetic non-sensitive readiness check. "
    "Call record_live_anthropic_readiness with status=ready, "
    "provider=anthropic, model_family=opus, and payload_sensitivity=synthetic. "
    "Do not omit payload_sensitivity."
)

READINESS_TOOLS = [
    {
        "name": "record_live_anthropic_readiness",
        "description": "Record the result of a synthetic Anthropic Opus readiness check.",
        "inputSchema": {
            "json": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["ready"],
                        "description": "Integration readiness status; must be ready.",
                    },
                    "provider": {
                        "type": "string",
                        "enum": ["anthropic"],
                        "description": "Provider exercised by the smoke test.",
                    },
                    "model_family": {
                        "type": "string",
                        "enum": ["opus"],
                        "description": "Model family exercised by the smoke test.",
                    },
                    "payload_sensitivity": {
                        "type": "string",
                        "enum": ["synthetic"],
                        "description": "Confirms the prompt contains only synthetic non-customer data.",
                    },
                },
                "required": [
                    "status",
                    "provider",
                    "model_family",
                    "payload_sensitivity",
                ],
            },
        },
    },
]


def test_anthropic_provider_builds_messages_tool_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify request shape without network or real credentials."""
    captured: dict[str, object] = {}
    create_calls = 0

    class FakeAnthropicClient:
        def __init__(self, *, api_key: str) -> None:
            captured["api_key"] = api_key
            self.messages = SimpleNamespace(create=self._create)

        def _create(self, **kwargs: object) -> SimpleNamespace:
            nonlocal create_calls
            create_calls += 1
            captured["request"] = kwargs
            return SimpleNamespace(
                usage=SimpleNamespace(input_tokens=11, output_tokens=7),
                content=[
                    SimpleNamespace(
                        type="tool_use",
                        input={
                            "status": "ready",
                            "provider": "anthropic",
                            "model_family": "opus",
                            "payload_sensitivity": "synthetic",
                        },
                    )
                ],
            )

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropicClient)

    client = llm_client.AnthropicProvider(
        api_key="test-anthropic-key-not-real",
        model="claude-opus-test-model",
    )
    result = client.call_with_tools(
        system_message=SYNTHETIC_SYSTEM_MESSAGE,
        user_message=SYNTHETIC_USER_MESSAGE,
        tools=READINESS_TOOLS,
        max_tokens=64,
        prompt_version="test_anthropic_provider_readiness",
    )

    assert result == {
        "status": "ready",
        "provider": "anthropic",
        "model_family": "opus",
        "payload_sensitivity": "synthetic",
    }
    assert create_calls == 1
    assert captured["api_key"] == "test-anthropic-key-not-real"

    request = captured["request"]
    assert isinstance(request, dict)
    assert request["model"] == "claude-opus-test-model"
    assert request["max_tokens"] == 64
    assert request["system"] == SYNTHETIC_SYSTEM_MESSAGE
    assert request["messages"] == [{"role": "user", "content": SYNTHETIC_USER_MESSAGE}]
    assert request["tool_choice"] == {
        "type": "tool",
        "name": "record_live_anthropic_readiness",
    }
    assert request["tools"] == [
        {
            "name": READINESS_TOOLS[0]["name"],
            "description": READINESS_TOOLS[0]["description"],
            "input_schema": READINESS_TOOLS[0]["inputSchema"]["json"],
        }
    ]


def test_anthropic_provider_caps_requested_tokens_to_configured_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeAnthropicClient:
        def __init__(self, *, api_key: str) -> None:
            self.messages = SimpleNamespace(create=self._create)

        @staticmethod
        def _create(**kwargs: object) -> SimpleNamespace:
            captured["request"] = kwargs
            return SimpleNamespace(
                usage=SimpleNamespace(input_tokens=3, output_tokens=2),
                content=[
                    SimpleNamespace(
                        type="tool_use",
                        input={
                            "status": "ready",
                            "provider": "anthropic",
                            "model_family": "opus",
                            "payload_sensitivity": "synthetic",
                        },
                    )
                ],
            )

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropicClient)
    monkeypatch.setattr(llm_client.settings, "anthropic_max_tokens", 32)

    client = llm_client.AnthropicProvider(
        api_key="test-anthropic-key-not-real",
        model="claude-opus-test-model",
    )
    result = client.call_with_tools(
        system_message=SYNTHETIC_SYSTEM_MESSAGE,
        user_message=SYNTHETIC_USER_MESSAGE,
        tools=READINESS_TOOLS,
        max_tokens=4096,
        prompt_version="test_anthropic_provider_budget",
    )

    assert result is not None
    request = captured["request"]
    assert isinstance(request, dict)
    assert request["max_tokens"] == 32


def test_anthropic_provider_redacts_quota_errors_without_prompt_or_secret_leak(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class FakeAnthropicClient:
        def __init__(self, *, api_key: str) -> None:
            self.messages = SimpleNamespace(create=self._create)

        @staticmethod
        def _create(**_kwargs: object) -> SimpleNamespace:
            raise RuntimeError(
                "quota exceeded for authorization: bearer test-anthropic-key-not-real "
                "x-api-key='test-anthropic-key-not-real' "
                f"while processing {SYNTHETIC_USER_MESSAGE}"
            )

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropicClient)

    client = llm_client.AnthropicProvider(
        api_key="test-anthropic-key-not-real",
        model="claude-opus-test-model",
    )
    with caplog.at_level(logging.WARNING, logger="app.services.llm_client"):
        result = client.call_with_tools(
            system_message=SYNTHETIC_SYSTEM_MESSAGE,
            user_message=SYNTHETIC_USER_MESSAGE,
            tools=READINESS_TOOLS,
            max_tokens=64,
            prompt_version="test_anthropic_provider_quota_error",
        )

    assert result is None
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert "quota exceeded" in log_text
    assert "test-anthropic-key-not-real" not in log_text
    assert SYNTHETIC_USER_MESSAGE not in log_text
    assert SYNTHETIC_SYSTEM_MESSAGE not in log_text


def test_anthropic_provider_requires_explicit_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(llm_client.settings, "anthropic_api_key", None)

    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY not set"):
        llm_client.AnthropicProvider(model="claude-opus-test-model")


@pytest.mark.skipif(
    os.getenv("THREATGENIX_RUN_ANTHROPIC_LIVE_SMOKE") != "1",
    reason="set THREATGENIX_RUN_ANTHROPIC_LIVE_SMOKE=1 to run the live Anthropic Opus smoke",
)
def test_live_anthropic_opus_tool_call_smoke() -> None:
    """Make one synthetic Opus Messages API call only when explicitly enabled."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    model = os.getenv("THREATGENIX_LIVE_ANTHROPIC_MODEL")

    if not api_key:
        pytest.skip("set ANTHROPIC_API_KEY from an approved secret source")
    if not model:
        pytest.skip("set THREATGENIX_LIVE_ANTHROPIC_MODEL to an approved Opus model id")
    if "opus" not in model.lower():
        pytest.fail("THREATGENIX_LIVE_ANTHROPIC_MODEL must be an explicit Opus model id")

    client = llm_client.AnthropicProvider(api_key=api_key, model=model)
    result = client.call_with_tools(
        system_message=SYNTHETIC_SYSTEM_MESSAGE,
        user_message=SYNTHETIC_USER_MESSAGE,
        tools=READINESS_TOOLS,
        max_tokens=128,
        prompt_version="live_anthropic_opus_readiness",
    )

    assert result is not None
    assert result["status"] == "ready"
    assert result["provider"] == "anthropic"
    assert result["model_family"] == "opus"
    assert result["payload_sensitivity"] == "synthetic"

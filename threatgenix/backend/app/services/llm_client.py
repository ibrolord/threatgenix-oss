"""Multi-provider LLM client with fallback chain.

Supports: AWS Bedrock, Anthropic API (direct), OpenAI, OpenRouter,
          Google Gemini, xAI (Grok), Perplexity, Ollama (local).
Provider is selected by LLM_PROVIDER env var or runtime switching.
"auto" tries each in order until one succeeds.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from typing import Any, Optional, Protocol
from uuid import UUID

from app.config import settings

logger = logging.getLogger(__name__)


class LLMClient(Protocol):
    """Interface that all LLM providers implement."""

    provider_name: str
    model_name: str

    def call_with_tools(
        self,
        system_message: str,
        user_message: str,
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
        prompt_version: str = "unknown",
    ) -> Optional[dict[str, Any]]:
        """Call the LLM with tool definitions. Returns tool_use input dict or None."""
        ...


# ─── Helpers ───────────────────────────────────────────────────────


def _bedrock_tools_to_openai(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert Bedrock tool format to OpenAI-compatible function calling format."""
    openai_tools = []
    for tool in tools:
        openai_tools.append({
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["inputSchema"]["json"],
            },
        })
    return openai_tools


def _extract_json_from_content(content: str) -> Optional[dict[str, Any]]:
    """Try to extract a JSON object from LLM text content (fallback for no tool_use)."""
    # Try the whole content as JSON first
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass

    # Try to find JSON block in markdown code fences
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group(1))
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass

    # Try to find first { ... } block
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass

    return None


def _prompt_hash(system_message: str, user_message: str) -> str:
    return hashlib.sha256((system_message + user_message).encode()).hexdigest()[:12]


def _redact_provider_exception(
    exc: Exception,
    *,
    sensitive_fragments: tuple[str, ...] = (),
) -> str:
    message = str(exc)
    message = re.sub(r"(?i)([?&]key=)[^&\s]+", r"\1[redacted]", message)
    message = re.sub(
        r"(?i)(authorization:\s*bearer\s+)[^\s,;]+",
        r"\1[redacted]",
        message,
    )
    message = re.sub(
        r"(?i)(x-api-key['\"]?\s*[:=]\s*['\"]?)[^'\"\s,;]+",
        r"\1[redacted]",
        message,
    )
    for fragment in sensitive_fragments:
        if fragment:
            message = message.replace(fragment, "[redacted]")
    return message


def _openai_uses_completion_token_limit(model: str) -> bool:
    normalized = model.lower()
    return normalized.startswith(("gpt-5", "o1", "o3", "o4"))


def _bounded_token_budget(requested: int, configured: int) -> int:
    configured_budget = configured if configured > 0 else 4096
    requested_budget = requested if requested > 0 else configured_budget
    return max(1, min(requested_budget, configured_budget))


# ─── Bedrock Provider ───────────────────────────────────────────────


class BedrockProvider:
    """AWS Bedrock Converse API provider."""

    provider_name = "bedrock"

    def __init__(self) -> None:
        import boto3
        from botocore.config import Config as BotoConfig

        region = settings.bedrock_region
        if region != "ca-central-1":
            message = f"Bedrock region is '{region}', NOT ca-central-1."
            if settings.app_env in {"production", "staging"}:
                raise RuntimeError(message)
            logger.warning(message)

        model_id = settings.bedrock_model_id
        _assert_bedrock_model_allowed(model_id)

        boto_config = BotoConfig(
            region_name=region,
            read_timeout=settings.bedrock_timeout_seconds,
            connect_timeout=10,
            retries={"max_attempts": 0},
        )
        self.client = boto3.client(
            "bedrock-runtime",
            region_name=region,
            config=boto_config,
        )
        self.model_id = model_id
        self.model_name = self.model_id

    def call_with_tools(
        self,
        system_message: str,
        user_message: str,
        tools: list[dict[str, Any]],
        max_tokens: int = settings.bedrock_max_tokens,
        prompt_version: str = "unknown",
    ) -> Optional[dict[str, Any]]:
        from botocore.exceptions import ClientError

        messages = [{"role": "user", "content": [{"text": user_message}]}]
        system = [{"text": system_message}]
        tool_config = {"tools": [{"toolSpec": t} for t in tools]}

        phash = _prompt_hash(system_message, user_message)
        logger.info(
            "bedrock_call_start prompt_version=%s model=%s prompt_hash=%s",
            prompt_version, self.model_id, phash,
        )

        start = time.monotonic()
        try:
            response = self.client.converse(
                modelId=self.model_id,
                messages=messages,
                system=system,
                toolConfig=tool_config,
                inferenceConfig={"maxTokens": max_tokens},
            )
        except (ClientError, Exception) as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "bedrock_call_error prompt_version=%s elapsed_ms=%d error=%s",
                prompt_version, elapsed_ms, str(exc),
            )
            return None

        elapsed_ms = int((time.monotonic() - start) * 1000)
        usage = response.get("usage", {})
        logger.info(
            "bedrock_call_complete prompt_version=%s elapsed_ms=%d "
            "input_tokens=%d output_tokens=%d",
            prompt_version, elapsed_ms,
            usage.get("inputTokens", 0), usage.get("outputTokens", 0),
        )

        try:
            for block in response["output"]["message"]["content"]:
                if "toolUse" in block:
                    return block["toolUse"]["input"]
        except (KeyError, TypeError) as exc:
            logger.warning("bedrock_parse_error: %s", exc)
        return None


# ─── Anthropic API Provider ─────────────────────────────────────────


class AnthropicProvider:
    """Direct Anthropic Messages API provider."""

    provider_name = "anthropic"

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        try:
            import anthropic
        except ImportError:
            raise RuntimeError("Install 'anthropic' package: pip install anthropic")

        selected_api_key = api_key or settings.anthropic_api_key
        if not selected_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")

        self.client = anthropic.Anthropic(api_key=selected_api_key)
        self.model_id = model or settings.anthropic_model_id
        self.model_name = self.model_id

    def call_with_tools(
        self,
        system_message: str,
        user_message: str,
        tools: list[dict[str, Any]],
        max_tokens: int = settings.anthropic_max_tokens,
        prompt_version: str = "unknown",
    ) -> Optional[dict[str, Any]]:
        anthropic_tools = []
        for tool in tools:
            anthropic_tools.append({
                "name": tool["name"],
                "description": tool["description"],
                "input_schema": tool["inputSchema"]["json"],
            })

        phash = _prompt_hash(system_message, user_message)
        logger.info(
            "anthropic_call_start prompt_version=%s model=%s prompt_hash=%s",
            prompt_version, self.model_id, phash,
        )

        start = time.monotonic()
        bounded_max_tokens = _bounded_token_budget(max_tokens, settings.anthropic_max_tokens)
        if bounded_max_tokens != max_tokens:
            logger.info(
                "anthropic_token_budget_capped prompt_version=%s requested=%d capped=%d",
                prompt_version,
                max_tokens,
                bounded_max_tokens,
            )

        request: dict[str, Any] = {
            "model": self.model_id,
            "max_tokens": bounded_max_tokens,
            "system": system_message,
            "messages": [{"role": "user", "content": user_message}],
            "tools": anthropic_tools,
        }
        if len(anthropic_tools) == 1:
            request["tool_choice"] = {
                "type": "tool",
                "name": anthropic_tools[0]["name"],
            }
        elif anthropic_tools:
            request["tool_choice"] = {"type": "any"}

        try:
            response = self.client.messages.create(
                **request,
            )
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "anthropic_call_error prompt_version=%s elapsed_ms=%d error=%s",
                prompt_version,
                elapsed_ms,
                _redact_provider_exception(
                    exc,
                    sensitive_fragments=(system_message, user_message),
                ),
            )
            return None

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "anthropic_call_complete prompt_version=%s elapsed_ms=%d "
            "input_tokens=%d output_tokens=%d",
            prompt_version, elapsed_ms,
            getattr(response.usage, "input_tokens", 0),
            getattr(response.usage, "output_tokens", 0),
        )

        for block in response.content:
            if block.type == "tool_use":
                return block.input
        return None


# ─── OpenAI-compatible base (httpx) ─────────────────────────────────


class _OpenAICompatibleProvider:
    """Base class for providers using an OpenAI-compatible chat completions API."""

    provider_name: str = "openai_compat"
    model_name: str = ""

    def __init__(self, *, api_key: str, base_url: str, model: str,
                 extra_headers: Optional[dict[str, str]] = None,
                 supports_tools: bool = True) -> None:
        import httpx

        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self.model_name = model
        self._extra_headers = extra_headers or {}
        self._supports_tools = supports_tools
        self._http = httpx.Client(timeout=120)

    def call_with_tools(
        self,
        system_message: str,
        user_message: str,
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
        prompt_version: str = "unknown",
    ) -> Optional[dict[str, Any]]:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            **self._extra_headers,
        }

        body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message},
            ],
        }
        token_limit_key = (
            "max_completion_tokens"
            if self.provider_name == "openai" and _openai_uses_completion_token_limit(self._model)
            else "max_tokens"
        )
        body[token_limit_key] = max_tokens

        if self._supports_tools:
            body["tools"] = _bedrock_tools_to_openai(tools)
            body["tool_choice"] = "auto"
        else:
            # For providers without tool support, instruct via system message
            tool_descriptions = json.dumps(
                [{"name": t["name"], "description": t["description"],
                  "parameters": t["inputSchema"]["json"]} for t in tools],
                indent=2,
            )
            body["messages"][0]["content"] += (
                "\n\nYou MUST respond with ONLY a valid JSON object matching one of "
                "these tool schemas (no markdown, no explanation):\n" + tool_descriptions
            )

        phash = _prompt_hash(system_message, user_message)
        logger.info(
            "%s_call_start prompt_version=%s model=%s prompt_hash=%s",
            self.provider_name, prompt_version, self._model, phash,
        )

        start = time.monotonic()
        try:
            resp = self._http.post(
                f"{self._base_url}/chat/completions",
                headers=headers,
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "%s_call_error prompt_version=%s elapsed_ms=%d error=%s",
                self.provider_name, prompt_version, elapsed_ms, str(exc),
            )
            return None

        elapsed_ms = int((time.monotonic() - start) * 1000)
        usage = data.get("usage", {})
        logger.info(
            "%s_call_complete prompt_version=%s elapsed_ms=%d "
            "input_tokens=%d output_tokens=%d",
            self.provider_name, prompt_version, elapsed_ms,
            usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0),
        )

        # Extract tool calls from response
        choices = data.get("choices", [])
        if not choices:
            return None

        message = choices[0].get("message", {})

        # Check for tool_calls first
        tool_calls = message.get("tool_calls")
        if tool_calls:
            fn = tool_calls[0].get("function", {})
            args = fn.get("arguments", "")
            if isinstance(args, str):
                try:
                    return json.loads(args)
                except json.JSONDecodeError:
                    logger.warning("%s_parse_error: cannot parse tool args", self.provider_name)
                    return None
            return args

        # Fallback: try to parse JSON from content
        content = message.get("content", "")
        if content:
            result = _extract_json_from_content(content)
            if result:
                return result

        return None


# ─── OpenAI Provider ────────────────────────────────────────────────


class OpenAIProvider(_OpenAICompatibleProvider):
    """OpenAI GPT provider via chat completions API."""

    provider_name = "openai"

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        selected_api_key = api_key or settings.openai_api_key
        if not selected_api_key:
            raise RuntimeError("OPENAI_API_KEY not set")
        super().__init__(
            api_key=selected_api_key,
            base_url="https://api.openai.com/v1",
            model=model or settings.openai_model,
        )


# ─── OpenRouter Provider ───────────────────────────────────────────


class OpenRouterProvider(_OpenAICompatibleProvider):
    """OpenRouter provider — OpenAI-compatible, routes to many models."""

    provider_name = "openrouter"

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        selected_api_key = api_key or settings.openrouter_api_key
        if not selected_api_key:
            raise RuntimeError("OPENROUTER_API_KEY not set")
        super().__init__(
            api_key=selected_api_key,
            base_url="https://openrouter.ai/api/v1",
            model=model or settings.openrouter_model,
            extra_headers={
                "HTTP-Referer": "https://threatgenix.app",
                "X-Title": "ThreatGenix",
            },
        )


# ─── xAI (Grok) Provider ──────────────────────────────────────────


class XAIProvider(_OpenAICompatibleProvider):
    """xAI Grok provider — OpenAI-compatible."""

    provider_name = "xai"

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        selected_api_key = api_key or settings.xai_api_key
        if not selected_api_key:
            raise RuntimeError("XAI_API_KEY not set")
        super().__init__(
            api_key=selected_api_key,
            base_url="https://api.x.ai/v1",
            model=model or settings.xai_model,
        )


# ─── Perplexity Provider ──────────────────────────────────────────


class PerplexityProvider(_OpenAICompatibleProvider):
    """Perplexity provider — OpenAI-compatible, limited/no tool support."""

    provider_name = "perplexity"

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        selected_api_key = api_key or settings.perplexity_api_key
        if not selected_api_key:
            raise RuntimeError("PERPLEXITY_API_KEY not set")
        super().__init__(
            api_key=selected_api_key,
            base_url="https://api.perplexity.ai",
            model=model or settings.perplexity_model,
            supports_tools=False,  # Perplexity doesn't reliably support tool_use
        )


# ─── Google Gemini Provider ────────────────────────────────────────


class GeminiProvider:
    """Google Gemini API provider with native function calling."""

    provider_name = "gemini"

    def __init__(self, *, api_key: str | None = None, model: str | None = None) -> None:
        import httpx

        selected_api_key = api_key or settings.gemini_api_key
        if not selected_api_key:
            raise RuntimeError("GEMINI_API_KEY not set")

        self._api_key = selected_api_key
        self._model = model or settings.gemini_model
        self.model_name = self._model
        self._http = httpx.Client(timeout=120)

    def _convert_tools_to_gemini(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert Bedrock tool format to Gemini functionDeclarations format."""
        declarations = []
        for tool in tools:
            schema = tool["inputSchema"]["json"].copy()
            # Gemini doesn't support additionalProperties at the top level the same way;
            # strip it to avoid validation errors.
            schema.pop("additionalProperties", None)
            declarations.append({
                "name": tool["name"],
                "description": tool["description"],
                "parameters": schema,
            })
        return [{"functionDeclarations": declarations}]

    def call_with_tools(
        self,
        system_message: str,
        user_message: str,
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
        prompt_version: str = "unknown",
    ) -> Optional[dict[str, Any]]:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self._model}:generateContent"
        )

        body: dict[str, Any] = {
            "contents": [
                {"role": "user", "parts": [{"text": user_message}]},
            ],
            "systemInstruction": {
                "parts": [{"text": system_message}],
            },
            "tools": self._convert_tools_to_gemini(tools),
            "generationConfig": {
                "maxOutputTokens": max_tokens,
            },
        }

        phash = _prompt_hash(system_message, user_message)
        logger.info(
            "gemini_call_start prompt_version=%s model=%s prompt_hash=%s",
            prompt_version, self._model, phash,
        )

        start = time.monotonic()
        try:
            resp = self._http.post(
                url,
                headers={"x-goog-api-key": self._api_key},
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "gemini_call_error prompt_version=%s elapsed_ms=%d error=%s",
                prompt_version, elapsed_ms, _redact_provider_exception(exc),
            )
            return None

        elapsed_ms = int((time.monotonic() - start) * 1000)
        usage_meta = data.get("usageMetadata", {})
        logger.info(
            "gemini_call_complete prompt_version=%s elapsed_ms=%d "
            "input_tokens=%d output_tokens=%d",
            prompt_version, elapsed_ms,
            usage_meta.get("promptTokenCount", 0),
            usage_meta.get("candidatesTokenCount", 0),
        )

        # Extract function call from Gemini response
        try:
            candidates = data.get("candidates", [])
            if not candidates:
                return None
            parts = candidates[0].get("content", {}).get("parts", [])
            for part in parts:
                fc = part.get("functionCall")
                if fc:
                    return fc.get("args", {})
                # Fallback: text content with JSON
                text = part.get("text")
                if text:
                    result = _extract_json_from_content(text)
                    if result:
                        return result
        except (KeyError, TypeError, IndexError) as exc:
            logger.warning("gemini_parse_error: %s", exc)

        return None


# ─── Ollama Provider ────────────────────────────────────────────────


class OllamaProvider:
    """Ollama local LLM provider via OpenAI-compatible API."""

    provider_name = "ollama"

    def __init__(self) -> None:
        import httpx

        self.base_url = settings.ollama_base_url
        self.model = settings.ollama_model
        self.model_name = self.model
        self.http = httpx.Client(timeout=120)

        # Verify Ollama is running
        try:
            resp = self.http.get(f"{self.base_url}/api/tags")
            resp.raise_for_status()
        except Exception as exc:
            raise RuntimeError(f"Ollama not available at {self.base_url}: {exc}")

    def call_with_tools(
        self,
        system_message: str,
        user_message: str,
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
        prompt_version: str = "unknown",
    ) -> Optional[dict[str, Any]]:
        openai_tools = _bedrock_tools_to_openai(tools)

        phash = _prompt_hash(system_message, user_message)
        logger.info(
            "ollama_call_start prompt_version=%s model=%s prompt_hash=%s",
            prompt_version, self.model, phash,
        )

        start = time.monotonic()
        try:
            resp = self.http.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_message},
                        {"role": "user", "content": user_message},
                    ],
                    "tools": openai_tools,
                    "stream": False,
                    "options": {"num_predict": max_tokens},
                },
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "ollama_call_error prompt_version=%s elapsed_ms=%d error=%s",
                prompt_version, elapsed_ms, str(exc),
            )
            return self._call_json_mode(
                system_message=system_message,
                user_message=user_message,
                tools=tools,
                max_tokens=max_tokens,
                prompt_version=prompt_version,
            )

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "ollama_call_complete prompt_version=%s elapsed_ms=%d model=%s",
            prompt_version, elapsed_ms, self.model,
        )

        message = data.get("message", {})
        tool_calls = message.get("tool_calls", [])
        if tool_calls:
            fn = tool_calls[0].get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                args = json.loads(args)
            return args

        content = message.get("content", "")
        if content:
            result = _extract_json_from_content(content)
            if result:
                return result

        return self._call_json_mode(
            system_message=system_message,
            user_message=user_message,
            tools=tools,
            max_tokens=max_tokens,
            prompt_version=prompt_version,
        )

    def _call_json_mode(
        self,
        *,
        system_message: str,
        user_message: str,
        tools: list[dict[str, Any]],
        max_tokens: int,
        prompt_version: str,
    ) -> Optional[dict[str, Any]]:
        schema = {}
        if tools:
            schema = (tools[0].get("inputSchema") or {}).get("json") or {}
        json_user_message = "\n\n".join(
            [
                user_message,
                "Return only one JSON object matching this schema. Do not wrap it in markdown.",
                json.dumps(schema, sort_keys=True, default=str),
            ]
        )
        start = time.monotonic()
        try:
            resp = self.http.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_message},
                        {"role": "user", "content": json_user_message},
                    ],
                    "stream": False,
                    "format": "json",
                    "options": {"num_predict": max_tokens},
                },
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "ollama_json_mode_error prompt_version=%s elapsed_ms=%d error=%s",
                prompt_version,
                elapsed_ms,
                str(exc),
            )
            return None

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "ollama_json_mode_complete prompt_version=%s elapsed_ms=%d model=%s",
            prompt_version,
            elapsed_ms,
            self.model,
        )
        return _extract_json_from_content((data.get("message") or {}).get("content", ""))


# ─── Provider Registry & Factory ───────────────────────────────────

# All known providers in auto-fallback order
PROVIDER_REGISTRY: list[tuple[str, type]] = [
    ("bedrock", BedrockProvider),
    ("anthropic", AnthropicProvider),
    ("openai", OpenAIProvider),
    ("openrouter", OpenRouterProvider),
    ("gemini", GeminiProvider),
    ("xai", XAIProvider),
    ("perplexity", PerplexityProvider),
    ("ollama", OllamaProvider),
]

# Map for quick lookup
_PROVIDER_MAP: dict[str, type] = {name: cls for name, cls in PROVIDER_REGISTRY}

_cached_client: Optional[LLMClient] = None
_active_provider_name: Optional[str] = None
_active_model_name: Optional[str] = None
_user_provider_preferences: dict[str, tuple[str, Optional[str]]] = {}


def _production_llm_boundary_enabled() -> bool:
    return (
        settings.app_env in {"production", "staging"}
        and not settings.allow_external_ai_providers_in_production
    )


def _is_canadian_bedrock_profile(model: str | None) -> bool:
    return bool(model and model.startswith("ca."))


def _assert_provider_allowed(provider_name: str) -> None:
    if _production_llm_boundary_enabled() and provider_name != "bedrock":
        raise RuntimeError(
            "Production AI processing is restricted to AWS Bedrock in ca-central-1."
        )


def _assert_bedrock_model_allowed(model: str | None) -> None:
    if _production_llm_boundary_enabled() and not _is_canadian_bedrock_profile(model):
        raise RuntimeError(
            "Production AI processing requires a Canadian Bedrock inference profile "
            "unless external AI provider opt-in is enabled."
        )


def _try_provider(name: str) -> Optional[LLMClient]:
    """Try to initialize a provider by name. Returns None on failure."""
    _assert_provider_allowed(name)
    cls = _PROVIDER_MAP.get(name)
    if cls is None:
        return None
    try:
        client = cls()
        logger.info(
            "llm_provider_ready provider=%s model=%s",
            name, getattr(client, "model_name", "unknown"),
        )
        return client
    except Exception as exc:
        logger.info("llm_provider_skip provider=%s reason=%s", name, exc)
        return None


def _apply_model_override(client: LLMClient, model: str) -> LLMClient:
    """Apply a runtime model override to a freshly constructed provider client."""
    if getattr(client, "provider_name", None) == "bedrock":
        _assert_bedrock_model_allowed(model)
    if hasattr(client, "model_id"):
        setattr(client, "model_id", model)
    if hasattr(client, "_model"):
        setattr(client, "_model", model)
    if hasattr(client, "model"):
        setattr(client, "model", model)
    client.model_name = model
    return client


def _build_provider_client(
    provider_name: str,
    model: Optional[str] = None,
) -> LLMClient:
    if provider_name == "bedrock":
        _assert_bedrock_model_allowed(model or settings.bedrock_model_id)
    client = _try_provider(provider_name)
    if client is None:
        raise RuntimeError(f"{provider_name} provider failed to initialize")
    if model:
        _apply_model_override(client, model)
    return client


def _user_key(user_id: UUID | str) -> str:
    return str(user_id)


def get_llm_client() -> LLMClient:
    """Get an LLM client based on LLM_PROVIDER setting.

    "auto" tries providers in order: bedrock -> anthropic -> openai -> openrouter
    -> gemini -> xai -> perplexity -> ollama.
    Result is cached until reset_llm_client() is called.
    """
    global _cached_client, _active_provider_name, _active_model_name
    if _cached_client is not None:
        return _cached_client

    provider = settings.llm_provider.lower()

    if provider == "auto":
        providers = [("bedrock", BedrockProvider)] if _production_llm_boundary_enabled() else PROVIDER_REGISTRY
        for name, _ in providers:
            client = _try_provider(name)
            if client:
                logger.info("llm_provider_selected provider=%s (auto)", name)
                _cached_client = client
                _active_provider_name = name
                _active_model_name = getattr(client, "model_name", "unknown")
                return _cached_client
        raise RuntimeError(
            "No LLM provider available. Configure at least one provider's API key, "
            "set up AWS credentials for Bedrock, or run Ollama locally."
        )

    # Specific provider requested
    _assert_provider_allowed(provider)
    if provider not in _PROVIDER_MAP:
        raise ValueError(
            f"Unknown LLM_PROVIDER: {provider}. "
            f"Valid options: {', '.join(_PROVIDER_MAP.keys())}, auto"
        )

    client = _try_provider(provider)
    if client:
        _cached_client = client
        _active_provider_name = provider
        _active_model_name = getattr(client, "model_name", "unknown")
        return _cached_client
    raise RuntimeError(f"{provider} provider failed to initialize")


def get_llm_client_for_user(user_id: UUID | str) -> LLMClient:
    """Get an LLM client using the current user's preferred provider when set."""
    preference = _user_provider_preferences.get(_user_key(user_id))
    if preference is None:
        return get_llm_client()

    provider_name, model = preference
    return _build_provider_client(provider_name, model)


async def get_llm_client_for_user_byok(
    user_id: UUID | str,
    provider_name: str,
    db: Any,
    model: str | None = None,
) -> LLMClient:
    """Get an LLM client using the user's BYOK key if stored, else server key.

    Resolution order:
      1. User BYOK key (from user_provider_keys table) -> decrypt and inject
      2. Server env key -> standard provider init
      3. Unavailable -> raise RuntimeError
    """
    from sqlalchemy import select
    from app.models.user_provider_key import UserProviderKey
    from app.services.key_encryption import decrypt_key

    provider_name = provider_name.lower()
    if provider_name not in _PROVIDER_MAP:
        raise ValueError(
            f"Unknown provider: {provider_name}. "
            f"Valid options: {', '.join(_PROVIDER_MAP.keys())}"
        )
    user_id_value = user_id if isinstance(user_id, UUID) else UUID(str(user_id))
    result = await db.execute(
        select(UserProviderKey).where(
            UserProviderKey.user_id == user_id_value,
            UserProviderKey.provider == provider_name,
        )
    )
    key_row = result.scalar_one_or_none()

    if key_row is not None:
        api_key = decrypt_key(key_row.encrypted_key)
        selected_model = key_row.model_override or model
        return _build_provider_client_with_key(provider_name, api_key, selected_model)

    # Fall back to server key
    return _build_provider_client(provider_name, model)


async def get_llm_client_for_user_async(user_id: UUID | str, db: Any) -> LLMClient:
    """Full BYOK-aware client resolution for async inference call sites.

    Resolution order:
      1. User's preferred provider (in-memory preference dict)
         → check DB for a BYOK key for that provider → use it if found
      2. Server-configured default provider → server key
    """
    preference = _user_provider_preferences.get(_user_key(user_id))
    if preference is not None:
        provider_name, model = preference
        return await get_llm_client_for_user_byok(
            user_id,
            provider_name,
            db,
            model=model,
        )

    # No per-user preference — use server default, still check BYOK
    server_provider = settings.llm_provider.lower()
    if server_provider not in ("auto", "bedrock"):
        # Try BYOK for the server-configured provider
        return await get_llm_client_for_user_byok(user_id, server_provider, db)

    # Bedrock or auto — no BYOK applicable, use sync path
    return get_llm_client_for_user(user_id)


def _build_provider_client_with_key(
    provider_name: str,
    api_key: str,
    model: str | None = None,
) -> LLMClient:
    """Build a provider client injecting a user-supplied API key."""
    provider_name = provider_name.lower()
    _assert_provider_allowed(provider_name)
    if provider_name not in _PROVIDER_MAP:
        raise ValueError(f"Unknown provider: {provider_name}")

    cls = _PROVIDER_MAP[provider_name]
    try:
        return cls(api_key=api_key, model=model)
    except TypeError as exc:
        raise RuntimeError(f"{provider_name} does not support BYOK client construction") from exc


def reset_llm_client() -> None:
    """Clear the cached client so the next call to get_llm_client() re-initializes."""
    global _cached_client, _active_provider_name, _active_model_name
    _cached_client = None
    _active_provider_name = None
    _active_model_name = None


def set_provider(provider_name: str, model: Optional[str] = None) -> LLMClient:
    """Switch the active provider (and optionally model) at runtime.

    Updates the settings, resets the cache, and returns the new client.
    """
    provider_name = provider_name.lower()
    if provider_name not in _PROVIDER_MAP:
        raise ValueError(
            f"Unknown provider: {provider_name}. "
            f"Valid options: {', '.join(_PROVIDER_MAP.keys())}"
        )

    # Update the model setting if provided
    if model:
        _set_model_for_provider(provider_name, model)

    # Update the active provider setting
    settings.llm_provider = provider_name

    reset_llm_client()
    return get_llm_client()


def set_provider_for_user(
    user_id: UUID | str,
    provider_name: str,
    model: Optional[str] = None,
) -> LLMClient:
    """Persist the active provider preference for a single authenticated user."""
    provider_name = provider_name.lower()
    if provider_name not in _PROVIDER_MAP:
        raise ValueError(
            f"Unknown provider: {provider_name}. "
            f"Valid options: {', '.join(_PROVIDER_MAP.keys())}"
        )

    client = _build_provider_client(provider_name, model)
    set_provider_preference_for_user(user_id, provider_name, model)
    return client


def set_provider_preference_for_user(
    user_id: UUID | str,
    provider_name: str,
    model: Optional[str] = None,
) -> None:
    """Record an authenticated user's provider preference after validation.

    This intentionally does not build a server-key client. BYOK-aware API
    paths validate with the user's stored key first, then remember the choice.
    """
    provider_name = provider_name.lower()
    if provider_name not in _PROVIDER_MAP:
        raise ValueError(
            f"Unknown provider: {provider_name}. "
            f"Valid options: {', '.join(_PROVIDER_MAP.keys())}"
        )
    _user_provider_preferences[_user_key(user_id)] = (provider_name, model)


def clear_provider_preference_for_user(
    user_id: UUID | str,
    provider_name: str | None = None,
) -> None:
    """Clear a user's active provider preference.

    When a specific provider is supplied, only clear the preference if it points
    at that provider. This prevents deleting one BYOK key from disturbing a
    deliberate selection of another provider.
    """
    key = _user_key(user_id)
    if provider_name is None:
        _user_provider_preferences.pop(key, None)
        return

    current = _user_provider_preferences.get(key)
    if current is not None and current[0] == provider_name.lower():
        _user_provider_preferences.pop(key, None)


def _set_model_for_provider(provider_name: str, model: str) -> None:
    """Update the settings model field for a given provider."""
    model_field_map = {
        "bedrock": "bedrock_model_id",
        "anthropic": "anthropic_model_id",
        "openai": "openai_model",
        "openrouter": "openrouter_model",
        "gemini": "gemini_model",
        "xai": "xai_model",
        "perplexity": "perplexity_model",
        "ollama": "ollama_model",
    }
    field = model_field_map.get(provider_name)
    if field:
        setattr(settings, field, model)


def get_active_provider_info() -> dict[str, str]:
    """Return info about the currently active provider."""
    if _cached_client is not None:
        return {
            "provider": _active_provider_name or "unknown",
            "model": _active_model_name or "unknown",
        }
    return {
        "provider": settings.llm_provider,
        "model": "not initialized",
    }


def get_active_provider_info_for_user(user_id: UUID | str) -> dict[str, str]:
    """Return provider info for the current user's selected provider."""
    preference = _user_provider_preferences.get(_user_key(user_id))
    if preference is None:
        return get_active_provider_info()

    provider_name, model = preference
    if model:
        return {"provider": provider_name, "model": model}

    try:
        client = _build_provider_client(provider_name)
        return {
            "provider": provider_name,
            "model": getattr(client, "model_name", "unknown"),
        }
    except RuntimeError:
        return {"provider": provider_name, "model": "unavailable"}


def get_available_providers() -> list[dict[str, Any]]:
    """Return a list of providers that have valid configuration (keys set)."""
    available = []

    # Check each provider's key requirement
    checks: list[tuple[str, str, bool, str]] = [
        ("bedrock", "AWS Bedrock", True, settings.bedrock_model_id),
        # Bedrock uses IAM, always "available" — init may still fail at runtime
        ("anthropic", "Anthropic", bool(settings.anthropic_api_key), settings.anthropic_model_id),
        ("openai", "OpenAI", bool(settings.openai_api_key), settings.openai_model),
        ("openrouter", "OpenRouter", bool(settings.openrouter_api_key), settings.openrouter_model),
        ("gemini", "Google Gemini", bool(settings.gemini_api_key), settings.gemini_model),
        ("xai", "xAI (Grok)", bool(settings.xai_api_key), settings.xai_model),
        ("perplexity", "Perplexity", bool(settings.perplexity_api_key), settings.perplexity_model),
        ("ollama", "Ollama (Local)", True, settings.ollama_model),
        # Ollama has no key — availability depends on the server running
    ]

    for name, display_name, configured, default_model in checks:
        if configured:
            available.append({
                "name": name,
                "display_name": display_name,
                "default_model": default_model,
            })

    return available

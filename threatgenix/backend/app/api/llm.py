"""LLM provider management endpoints."""

import logging
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.models.user_provider_key import UserProviderKey
from app.services.auth import get_current_user
from app.services.key_encryption import decrypt_key, encrypt_key, mask_key
from app.services.llm_client import (
    get_active_provider_info_for_user,
    get_available_providers,
    get_llm_client_for_user_byok,
    set_provider_preference_for_user,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/llm", tags=["llm"])

# The 6 non-Bedrock providers that support BYOK
BYOK_PROVIDERS = {"anthropic", "openai", "openrouter", "gemini", "xai", "perplexity"}

# Display names for UI
PROVIDER_DISPLAY_NAMES = {
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "openrouter": "OpenRouter",
    "gemini": "Google Gemini",
    "xai": "xAI (Grok)",
    "perplexity": "Perplexity",
}

# Base URLs for test calls
_PROVIDER_TEST_URLS: dict[str, str] = {
    "anthropic": "https://api.anthropic.com/v1/messages",
    "openai": "https://api.openai.com/v1/models",
    "openrouter": "https://openrouter.ai/api/v1/models",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/models",
    "xai": "https://api.x.ai/v1/models",
    "perplexity": "https://api.perplexity.ai/chat/completions",
}
_OPENAI_CHAT_MODEL_PREFIXES = ("gpt-", "o")
_OPENAI_NON_CHAT_MARKERS = (
    "audio",
    "dall-e",
    "embedding",
    "image",
    "moderation",
    "realtime",
    "sora",
    "transcribe",
    "tts",
    "whisper",
)


def _dedupe_models(*model_groups: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for group in model_groups:
        for model in group:
            normalized = str(model or "").strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                out.append(normalized)
    return out


def _is_openai_generation_model(model_id: str) -> bool:
    lowered = model_id.lower()
    if not lowered.startswith(_OPENAI_CHAT_MODEL_PREFIXES):
        return False
    return not any(marker in lowered for marker in _OPENAI_NON_CHAT_MARKERS)


def _default_models_for_provider(provider: str) -> list[str]:
    if provider == "bedrock":
        return _dedupe_models(
            [settings.bedrock_model_id, settings.bedrock_enhancement_model_id]
        )
    if provider == "anthropic":
        return [settings.anthropic_model_id]
    if provider == "openai":
        return [settings.openai_model]
    if provider == "openrouter":
        return [settings.openrouter_model]
    if provider == "gemini":
        return [settings.gemini_model]
    if provider == "xai":
        return [settings.xai_model]
    if provider == "perplexity":
        return [settings.perplexity_model]
    if provider == "ollama":
        return [settings.ollama_model]
    return []


async def _stored_user_provider_key(
    provider: str,
    current_user: User,
    db: AsyncSession,
) -> str | None:
    if provider not in BYOK_PROVIDERS:
        return None
    result = await db.execute(
        select(UserProviderKey).where(
            UserProviderKey.user_id == current_user.id,
            UserProviderKey.provider == provider,
        )
    )
    key_row = result.scalar_one_or_none()
    if key_row is None:
        return None
    return decrypt_key(key_row.encrypted_key)


async def _provider_model_ids(
    provider: str,
    *,
    current_user: User,
    db: AsyncSession,
) -> tuple[list[str], str]:
    """Return generation-capable model IDs visible to this user/provider."""
    provider = provider.lower()
    defaults = _default_models_for_provider(provider)
    try:
        api_key = await _stored_user_provider_key(provider, current_user, db)
    except Exception:
        api_key = None

    import httpx

    if provider == "openai":
        api_key = api_key or settings.openai_api_key
        if not api_key:
            return defaults, "default"
        async with httpx.AsyncClient(timeout=15) as http:
            resp = await http.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
        if resp.status_code != 200:
            logger.info("openai_model_list_failed status=%s", resp.status_code)
            return defaults, "default"
        data = resp.json()
        models = sorted(
            model_id
            for item in data.get("data", [])
            if isinstance(item, dict)
            for model_id in [str(item.get("id") or "")]
            if _is_openai_generation_model(model_id)
        )
        return _dedupe_models(defaults, models), "live"

    if provider == "anthropic":
        api_key = api_key or settings.anthropic_api_key
        if not api_key:
            return defaults, "default"
        async with httpx.AsyncClient(timeout=15) as http:
            resp = await http.get(
                "https://api.anthropic.com/v1/models",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
            )
        if resp.status_code != 200:
            logger.info("anthropic_model_list_failed status=%s", resp.status_code)
            return defaults, "default"
        data = resp.json()
        models = sorted(
            str(item.get("id") or "")
            for item in data.get("data", [])
            if isinstance(item, dict) and item.get("id")
        )
        return _dedupe_models(defaults, models), "live"

    return defaults, "default"


class ProviderSwitchRequest(BaseModel):
    provider: str
    model: Optional[str] = None


class ProviderInfo(BaseModel):
    provider: str
    model: str


class ProviderModelsResponse(BaseModel):
    provider: str
    models: list[str]
    source: Literal["default", "live"]


class BYOKKeyRequest(BaseModel):
    api_key: str
    model_override: Optional[str] = None


class BYOKKeyResponse(BaseModel):
    provider: str
    display_name: str
    masked_key: str
    model_override: Optional[str] = None
    created_at: str


class LLMProviderHealthResponse(BaseModel):
    status: Literal["ready", "degraded", "unconfigured"]
    active_provider: str
    active_model: str
    server_provider: str
    bedrock_region: str
    bedrock_model_id: str
    bedrock_enhancement_model_id: str
    canada_residency_enforced: bool
    external_ai_providers_enabled: bool
    data_residency_mode: Literal["canada_only", "external_opt_in"]
    configured_provider_count: int
    warnings: list[str]
    next_actions: list[str]


# ─── Existing provider endpoints ──────────────────────────────────


@router.get("/providers")
async def list_providers(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return available LLM providers and the currently active one."""
    available = list(get_available_providers())
    available_names = {item["name"] for item in available}
    result = await db.execute(
        select(UserProviderKey.provider).where(UserProviderKey.user_id == current_user.id)
    )
    for provider in result.scalars().all():
        if provider in BYOK_PROVIDERS and provider not in available_names:
            available.append(
                {
                    "name": provider,
                    "display_name": PROVIDER_DISPLAY_NAMES.get(provider, provider),
                    "default_model": (_default_models_for_provider(provider) or [""])[0],
                    "source": "byok",
                }
            )
            available_names.add(provider)
    active = get_active_provider_info_for_user(current_user.id)
    return {
        "available": available,
        "active": active,
    }


@router.get("/providers/{provider}/models", response_model=ProviderModelsResponse)
async def list_provider_models(
    provider: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ProviderModelsResponse:
    """Return generation model IDs available for the selected provider."""
    provider = provider.lower()
    available_names = {item["name"] for item in get_available_providers()}
    stored_key = await _stored_user_provider_key(provider, current_user, db)
    if provider not in available_names and stored_key is None:
        raise HTTPException(status_code=404, detail=f"Provider '{provider}' is not configured.")
    models, source = await _provider_model_ids(
        provider,
        current_user=current_user,
        db=db,
    )
    return ProviderModelsResponse(provider=provider, models=models, source=source)


@router.get("/health", response_model=LLMProviderHealthResponse)
async def provider_health(current_user: User = Depends(get_current_user)) -> LLMProviderHealthResponse:
    """Return non-secret provider readiness and Canadian Bedrock residency posture."""
    available = get_available_providers()
    active = get_active_provider_info_for_user(current_user.id)
    active_provider = active.get("provider", "unknown")
    active_model = active.get("model", "unknown")
    warnings: list[str] = []
    next_actions: list[str] = []

    region_ok = settings.bedrock_region == "ca-central-1"
    model_ok = settings.bedrock_model_id.startswith("ca.")
    enhancement_ok = settings.bedrock_enhancement_model_id.startswith("ca.")
    active_model_ready = active_model not in {"not initialized", "unavailable", "unknown"}
    active_provider_ok = active_provider in {"bedrock", "auto", "unknown"}
    active_bedrock_model_ok = True
    if active_provider == "bedrock" and active_model_ready:
        active_bedrock_model_ok = active_model.startswith("ca.")
    if active_provider not in {"bedrock", "auto", "unknown"}:
        active_provider_ok = False
    external_ai_enabled = settings.allow_external_ai_providers_in_production
    canada_residency_enforced = (
        not external_ai_enabled
        and region_ok
        and model_ok
        and enhancement_ok
        and active_provider_ok
        and active_bedrock_model_ok
    )
    if external_ai_enabled:
        warnings.append(
            "External AI providers are enabled by explicit opt-in; strict Canada-only AI residency is not enforced."
        )
        next_actions.append(
            "Confirm tenant disclosures, audit logging, retention terms, and provider approvals before production use."
        )
    if not region_ok:
        warnings.append("AWS Bedrock region is not ca-central-1.")
        next_actions.append("Set BEDROCK_REGION=ca-central-1 before pilot use.")
    if not model_ok:
        warnings.append("Primary Bedrock model is not a Canadian cross-region inference profile.")
        next_actions.append("Set BEDROCK_MODEL_ID to a ca.* Bedrock profile.")
    if not enhancement_ok:
        warnings.append("Enhancement Bedrock model is not a Canadian cross-region inference profile.")
        next_actions.append("Set BEDROCK_ENHANCEMENT_MODEL_ID to a ca.* Bedrock profile.")
    if not active_provider_ok and not external_ai_enabled:
        warnings.append("The active LLM provider is outside the AWS Bedrock Canada-only boundary.")
        next_actions.append("Enable explicit external AI opt-in or switch the active provider to Bedrock.")
    if not active_bedrock_model_ok:
        warnings.append("The active Bedrock model is outside the Canada-only inference profile family.")
        next_actions.append("Enable explicit external AI opt-in or switch to a ca.* Bedrock profile.")
    if active.get("model") in {"unavailable", "not initialized"}:
        warnings.append("The active LLM client has not completed a ready runtime check.")
        next_actions.append("Run a generation smoke test before relying on AI-assisted output.")

    status: Literal["ready", "degraded", "unconfigured"] = "ready"
    if not available:
        status = "unconfigured"
        next_actions.append("Configure at least one server provider or BYOK provider.")
    elif warnings:
        status = "degraded"

    return LLMProviderHealthResponse(
        status=status,
        active_provider=active_provider,
        active_model=active_model,
        server_provider=settings.llm_provider,
        bedrock_region=settings.bedrock_region,
        bedrock_model_id=settings.bedrock_model_id,
        bedrock_enhancement_model_id=settings.bedrock_enhancement_model_id,
        canada_residency_enforced=canada_residency_enforced,
        external_ai_providers_enabled=external_ai_enabled,
        data_residency_mode="external_opt_in" if external_ai_enabled else "canada_only",
        configured_provider_count=len(available),
        warnings=warnings,
        next_actions=next_actions,
    )


@router.post("/provider", response_model=ProviderInfo)
async def switch_provider(
    req: ProviderSwitchRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Switch the current user's active LLM provider (and optionally model)."""
    try:
        client = await get_llm_client_for_user_byok(
            current_user.id,
            req.provider,
            db,
            model=req.model,
        )
        selected_provider = getattr(client, "provider_name", req.provider)
        selected_model = getattr(client, "model_name", req.model or "unknown")
        set_provider_preference_for_user(
            current_user.id,
            selected_provider,
            selected_model,
        )
        return ProviderInfo(
            provider=selected_provider,
            model=selected_model,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


# ─── BYOK key management endpoints ───────────────────────────────


@router.get("/keys", response_model=list[BYOKKeyResponse])
async def list_user_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all BYOK provider keys for the current user (masked)."""
    result = await db.execute(
        select(UserProviderKey).where(UserProviderKey.user_id == current_user.id)
    )
    keys = result.scalars().all()
    out: list[BYOKKeyResponse] = []
    for k in keys:
        try:
            plaintext = decrypt_key(k.encrypted_key)
            masked = mask_key(plaintext)
        except Exception:
            masked = "****"
        out.append(
            BYOKKeyResponse(
                provider=k.provider,
                display_name=PROVIDER_DISPLAY_NAMES.get(k.provider, k.provider),
                masked_key=masked,
                model_override=k.model_override,
                created_at=k.created_at.isoformat() if k.created_at else "",
            )
        )
    return out


@router.put("/keys/{provider}", response_model=BYOKKeyResponse)
async def upsert_user_key(
    provider: str,
    body: BYOKKeyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Store or update a BYOK API key for a provider."""
    if provider not in BYOK_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider}' does not support BYOK. "
            f"Valid providers: {', '.join(sorted(BYOK_PROVIDERS))}",
        )

    if not body.api_key or not body.api_key.strip():
        raise HTTPException(status_code=400, detail="api_key must not be empty")

    encrypted = encrypt_key(body.api_key.strip())

    # Upsert: find existing or create new
    result = await db.execute(
        select(UserProviderKey).where(
            UserProviderKey.user_id == current_user.id,
            UserProviderKey.provider == provider,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.encrypted_key = encrypted
        existing.model_override = body.model_override
    else:
        existing = UserProviderKey(
            user_id=current_user.id,
            provider=provider,
            encrypted_key=encrypted,
            model_override=body.model_override,
        )
        db.add(existing)

    await db.commit()
    await db.refresh(existing)

    return BYOKKeyResponse(
        provider=existing.provider,
        display_name=PROVIDER_DISPLAY_NAMES.get(provider, provider),
        masked_key=mask_key(body.api_key.strip()),
        model_override=existing.model_override,
        created_at=existing.created_at.isoformat() if existing.created_at else "",
    )


@router.delete("/keys/{provider}", status_code=204)
async def delete_user_key(
    provider: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a stored BYOK key for a provider."""
    if provider not in BYOK_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Invalid BYOK provider: {provider}")

    await db.execute(
        delete(UserProviderKey).where(
            UserProviderKey.user_id == current_user.id,
            UserProviderKey.provider == provider,
        )
    )
    await db.commit()
    return None


@router.post("/keys/{provider}/test")
async def test_user_key(
    provider: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Test that a stored BYOK key works by making a minimal API call."""
    if provider not in BYOK_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Invalid BYOK provider: {provider}")

    result = await db.execute(
        select(UserProviderKey).where(
            UserProviderKey.user_id == current_user.id,
            UserProviderKey.provider == provider,
        )
    )
    key_row = result.scalar_one_or_none()
    if key_row is None:
        raise HTTPException(status_code=404, detail=f"No key stored for provider '{provider}'")

    try:
        api_key = decrypt_key(key_row.encrypted_key)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to decrypt stored key")

    try:
        import httpx

        async with httpx.AsyncClient(timeout=15) as http:
            if provider == "anthropic":
                resp = await http.post(
                    _PROVIDER_TEST_URLS["anthropic"],
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": key_row.model_override or "claude-sonnet-4-20250514",
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                )
            elif provider == "gemini":
                resp = await http.get(
                    _PROVIDER_TEST_URLS["gemini"],
                    headers={"x-goog-api-key": api_key},
                )
            elif provider == "perplexity":
                resp = await http.post(
                    _PROVIDER_TEST_URLS["perplexity"],
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": key_row.model_override or "sonar",
                        "messages": [{"role": "user", "content": "hi"}],
                        "max_tokens": 1,
                    },
                )
            else:
                # OpenAI-compatible: openai, openrouter, xai — list models
                resp = await http.get(
                    _PROVIDER_TEST_URLS[provider],
                    headers={"Authorization": f"Bearer {api_key}"},
                )

        if resp.status_code in (200, 201):
            return {"status": "ok", "provider": provider}
        elif resp.status_code == 401:
            return {"status": "error", "provider": provider, "detail": "Invalid API key (401 Unauthorized)"}
        elif resp.status_code == 403:
            return {"status": "error", "provider": provider, "detail": "Access forbidden (403) - check key permissions"}
        else:
            return {
                "status": "error",
                "provider": provider,
                "detail": f"Provider returned HTTP {resp.status_code}",
            }
    except Exception as exc:
        return {
            "status": "error",
            "provider": provider,
            "detail": f"Connection error: {str(exc)}",
        }

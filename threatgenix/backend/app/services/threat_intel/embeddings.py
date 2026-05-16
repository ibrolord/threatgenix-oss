"""Embedding service for threat-intel semantic retrieval.

Generates 1024-dimensional embeddings for threat intelligence entries
and stores them in pgvector for semantic search. AWS Bedrock Titan remains
the default, with OpenAI-compatible providers available for self-hosted
deployments that explicitly opt in.
"""

from __future__ import annotations

import json
import logging

import boto3

from app.config import settings

logger = logging.getLogger(__name__)

# Titan Embeddings v2 produces 1024-dim vectors.
DEFAULT_EMBEDDING_MODEL_ID = "amazon.titan-embed-text-v2:0"
DEFAULT_OPENAI_EMBEDDING_MODEL_ID = "text-embedding-3-large"
EMBEDDING_DIMENSION = 1024
OPENAI_COMPATIBLE_EMBEDDING_PROVIDERS = {
    "openai",
    "openrouter",
    "zai",
    "openai_compatible",
}


def _get_bedrock_client():
    return boto3.client("bedrock-runtime", region_name=settings.bedrock_region)


def _embedding_provider() -> str:
    return (settings.embedding_provider or "bedrock").strip().lower()


def _configured_embedding_dimension() -> int:
    dimension = int(settings.embedding_dimension or EMBEDDING_DIMENSION)
    if dimension != EMBEDDING_DIMENSION:
        raise RuntimeError(
            "Threat-intel pgvector columns are Vector(1024). "
            f"Configured EMBEDDING_DIMENSION={dimension} is not supported by this schema."
        )
    return dimension


def _bedrock_embedding_model_id() -> str:
    model_id = (settings.embedding_model or settings.bedrock_embedding_model_id or "").strip()
    return model_id or DEFAULT_EMBEDDING_MODEL_ID


def _openai_compatible_embedding_model_id(provider: str) -> str:
    configured = (settings.embedding_model or "").strip()
    if configured:
        return configured
    if provider == "openai":
        return DEFAULT_OPENAI_EMBEDDING_MODEL_ID
    raise RuntimeError(
        f"EMBEDDING_MODEL is required when EMBEDDING_PROVIDER={provider}"
    )


def _openai_compatible_base_url(provider: str) -> str:
    if provider == "openai":
        return "https://api.openai.com/v1"
    if provider == "openrouter":
        return "https://openrouter.ai/api/v1"
    if provider == "zai":
        return settings.zai_base_url.rstrip("/")
    if provider == "openai_compatible" and settings.embedding_base_url:
        return settings.embedding_base_url.rstrip("/")
    raise RuntimeError(
        f"EMBEDDING_BASE_URL is required when EMBEDDING_PROVIDER={provider}"
    )


def _openai_compatible_api_key(provider: str) -> str:
    configured = (settings.embedding_api_key or "").strip()
    if configured:
        return configured
    provider_key_map = {
        "openai": settings.openai_api_key,
        "openrouter": settings.openrouter_api_key,
        "zai": settings.zai_api_key,
    }
    api_key = (provider_key_map.get(provider) or "").strip()
    if api_key:
        return api_key
    raise RuntimeError(f"EMBEDDING_API_KEY or {provider.upper()}_API_KEY is required")


def _validate_embedding_dimension(
    embedding: list[float],
    *,
    provider: str,
    model_id: str,
) -> list[float]:
    if len(embedding) != EMBEDDING_DIMENSION:
        raise RuntimeError(
            f"{provider} embedding model {model_id} returned {len(embedding)} dimensions; "
            f"ThreatGenix stores {EMBEDDING_DIMENSION}-dimension pgvector rows."
        )
    return embedding


def _generate_bedrock_embedding(text: str) -> list[float]:
    client = _get_bedrock_client()
    truncated = text[:8000]
    dimension = _configured_embedding_dimension()
    model_id = _bedrock_embedding_model_id()
    response = client.invoke_model(
        modelId=model_id,
        contentType="application/json",
        accept="application/json",
        body=json.dumps({
            "inputText": truncated,
            "dimensions": dimension,
            "normalize": True,
        }),
    )

    result = json.loads(response["body"].read())
    return _validate_embedding_dimension(
        [float(value) for value in result["embedding"]],
        provider="bedrock",
        model_id=model_id,
    )


def _generate_openai_compatible_embedding(text: str, *, provider: str) -> list[float]:
    import httpx

    truncated = text[:8000]
    dimension = _configured_embedding_dimension()
    model_id = _openai_compatible_embedding_model_id(provider)
    base_url = _openai_compatible_base_url(provider)
    api_key = _openai_compatible_api_key(provider)

    headers: dict[str, str] = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if provider == "openrouter":
        headers.update({
            "HTTP-Referer": "https://threatgenix.app",
            "X-Title": "ThreatGenix",
        })

    response = httpx.post(
        f"{base_url}/embeddings",
        headers=headers,
        json={
            "model": model_id,
            "input": truncated,
            "dimensions": dimension,
        },
        timeout=60,
    )
    response.raise_for_status()
    data = response.json()
    embedding = data.get("data", [{}])[0].get("embedding")
    if not isinstance(embedding, list):
        raise RuntimeError(f"{provider} embedding response did not include data[0].embedding")
    return _validate_embedding_dimension(
        [float(value) for value in embedding],
        provider=provider,
        model_id=model_id,
    )


def generate_embedding(text: str) -> list[float]:
    """Generate a single embedding vector from text.

    Args:
        text: The text to embed.

    Returns:
        1024-dimensional float vector.
    """
    provider = _embedding_provider()
    if provider == "bedrock":
        return _generate_bedrock_embedding(text)
    if provider in OPENAI_COMPATIBLE_EMBEDDING_PROVIDERS:
        return _generate_openai_compatible_embedding(text, provider=provider)
    raise RuntimeError(
        "Unsupported EMBEDDING_PROVIDER. Use one of: "
        "bedrock, openai, openrouter, zai, openai_compatible."
    )


def generate_embeddings_batch(texts: list[str], batch_size: int = 20) -> list[list[float]]:
    """Generate embeddings for multiple texts.

    Providers do not all support native batching, so we call sequentially but
    log progress for large batches.

    Args:
        texts: List of text strings to embed.
        batch_size: Log progress every batch_size items.

    Returns:
        List of embedding vectors, same order as input.
    """
    embeddings: list[list[float]] = []
    total = len(texts)

    for i, text in enumerate(texts):
        try:
            embedding = generate_embedding(text)
            embeddings.append(embedding)
        except Exception as exc:
            logger.warning("Failed to embed text %d/%d: %s", i + 1, total, exc)
            # Zero vector as fallback — entry will have low similarity scores
            embeddings.append([0.0] * EMBEDDING_DIMENSION)

        if (i + 1) % batch_size == 0:
            logger.info("Embedded %d/%d texts", i + 1, total)

    if total > batch_size:
        logger.info("Embedding complete: %d/%d texts", total, total)

    return embeddings


def build_embedding_text_attack(technique_id: str, name: str, description: str, tactic: str) -> str:
    """Build the text to embed for an ATT&CK technique."""
    return f"ATT&CK {technique_id} ({tactic}): {name}. {description[:2000]}"


def build_embedding_text_capec(capec_id: str, name: str, description: str) -> str:
    """Build the text to embed for a CAPEC attack pattern."""
    return f"Attack Pattern {capec_id}: {name}. {description[:2000]}"


def build_embedding_text_cwe(cwe_id: str, name: str, description: str) -> str:
    """Build the text to embed for a CWE weakness."""
    return f"Weakness {cwe_id}: {name}. {description[:2000]}"


def build_embedding_text_advisory(advisory_id: str, title: str, summary: str) -> str:
    """Build the text to embed for a CCCS advisory."""
    return f"Advisory {advisory_id}: {title}. {summary[:2000]}"

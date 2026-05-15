"""Embedding service using AWS Bedrock Titan Embeddings v2.

Generates 1024-dimensional embeddings for threat intelligence entries
and stores them in pgvector for semantic search.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import boto3

from app.config import settings

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Titan Embeddings v2 produces 1024-dim vectors.
DEFAULT_EMBEDDING_MODEL_ID = "amazon.titan-embed-text-v2:0"
EMBEDDING_DIMENSION = 1024


def _get_bedrock_client():
    return boto3.client("bedrock-runtime", region_name=settings.bedrock_region)


def generate_embedding(text: str) -> list[float]:
    """Generate a single embedding vector from text via Bedrock Titan.

    Args:
        text: The text to embed (max ~8K tokens for Titan v2).

    Returns:
        1024-dimensional float vector.
    """
    import json

    client = _get_bedrock_client()
    # Truncate to ~8000 chars to stay within Titan's token limit
    truncated = text[:8000]

    model_id = settings.bedrock_embedding_model_id.strip() or DEFAULT_EMBEDDING_MODEL_ID
    response = client.invoke_model(
        modelId=model_id,
        contentType="application/json",
        accept="application/json",
        body=json.dumps({
            "inputText": truncated,
            "dimensions": EMBEDDING_DIMENSION,
            "normalize": True,
        }),
    )

    result = json.loads(response["body"].read())
    return result["embedding"]


def generate_embeddings_batch(texts: list[str], batch_size: int = 20) -> list[list[float]]:
    """Generate embeddings for multiple texts.

    Titan Embeddings doesn't support native batching, so we call sequentially
    but log progress for large batches.

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

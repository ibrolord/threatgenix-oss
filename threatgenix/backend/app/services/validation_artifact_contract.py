"""Compatibility contract for validation artifact bundle identifiers."""

from __future__ import annotations

from typing import Any

VALIDATION_MANIFEST_NAME = "threatgenix-validation-manifest.json"
LEGACY_VALIDATION_MANIFEST_NAME = VALIDATION_MANIFEST_NAME
SEMANTIC_REVIEW_VALIDATION_MANIFEST_NAME = (
    "semantic-security-review-validation-manifest.json"
)
SSR_VALIDATION_MANIFEST_NAME = "ssr-validation-manifest.json"
VALIDATION_MANIFEST_NAMES = (
    VALIDATION_MANIFEST_NAME,
    SEMANTIC_REVIEW_VALIDATION_MANIFEST_NAME,
    SSR_VALIDATION_MANIFEST_NAME,
    "validation-manifest.json",
    "manifest.json",
)

VALIDATION_METADATA_KEY = "threatgenix_validation"
LEGACY_VALIDATION_METADATA_KEY = VALIDATION_METADATA_KEY
SEMANTIC_REVIEW_VALIDATION_METADATA_KEY = "semantic_review_validation"
SSR_VALIDATION_METADATA_KEY = "ssr_validation"
VALIDATION_METADATA_KEYS = (
    VALIDATION_METADATA_KEY,
    SEMANTIC_REVIEW_VALIDATION_METADATA_KEY,
    SSR_VALIDATION_METADATA_KEY,
)


def validation_metadata_from_raw(raw_output: Any) -> dict[str, Any]:
    """Return validation metadata from any supported raw-output key."""
    if not isinstance(raw_output, dict):
        return {}
    for key in VALIDATION_METADATA_KEYS:
        value = raw_output.get(key)
        if isinstance(value, dict):
            return value
    return {}


def attach_validation_metadata(
    raw_output: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Attach metadata under legacy and ThreatGenix aliases."""
    for key in VALIDATION_METADATA_KEYS:
        raw_output[key] = dict(metadata)
    return raw_output

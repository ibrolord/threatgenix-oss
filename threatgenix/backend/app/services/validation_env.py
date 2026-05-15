"""Environment-variable compatibility helpers for validation runtime config."""

from __future__ import annotations

import os
from collections.abc import Mapping

THREATGENIX_VALIDATION_PREFIX = "THREATGENIX_VALIDATION_"
SEMANTIC_REVIEW_VALIDATION_PREFIX = "SEMANTIC_REVIEW_VALIDATION_"
SSR_VALIDATION_PREFIX = "SSR_VALIDATION_"
_TRUE_VALUES = {"1", "true", "yes", "on"}


def validation_env_aliases(name: str) -> tuple[str, ...]:
    """Return supported names for a validation env var in precedence order."""
    if not name.startswith(THREATGENIX_VALIDATION_PREFIX):
        return (name,)
    suffix = name.removeprefix(THREATGENIX_VALIDATION_PREFIX)
    return (
        name,
        f"{SEMANTIC_REVIEW_VALIDATION_PREFIX}{suffix}",
        f"{SSR_VALIDATION_PREFIX}{suffix}",
    )


def validation_env_value(
    name: str,
    default: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """Read a validation env var, preserving legacy-name precedence."""
    source = os.environ if environ is None else environ
    for alias in validation_env_aliases(name):
        raw = source.get(alias)
        if raw is not None and raw.strip():
            return raw
    return default


def validation_env_flag(
    name: str,
    *,
    default: bool = False,
    environ: Mapping[str, str] | None = None,
) -> bool:
    raw = validation_env_value(name, environ=environ)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE_VALUES

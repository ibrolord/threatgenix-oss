from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_UNKNOWN_TOKENS = {"unknown", "unset", "notset", "not_set", "na", "n/a", "notapplicable", "not_applicable"}
_PUBLIC_EXPOSURE_KEYWORDS = ("internet", "public", "external", "dmz", "edge")
_PRIVATE_EXPOSURE_KEYWORDS = ("internal", "private", "vpc", "isolated", "intranet")
_TRUSTED_KEYWORDS = ("trusted", "privileged", "firstparty", "internal")
_UNTRUSTED_KEYWORDS = ("untrusted", "semitrusted", "thirdparty", "partner", "vendor", "external")
_SENSITIVE_CLASSIFICATION_KEYWORDS = (
    "confidential",
    "restricted",
    "secret",
    "sensitive",
    "regulated",
    "pci",
    "pii",
    "phi",
    "financial",
)
_NO_TLS_TOKENS = {"none", "notls", "plaintext", "cleartext", "unencrypted"}
_DEPRECATED_TLS_TOKENS = {"tls10", "tls11"}


def _text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _token(value: object | None) -> str | None:
    text = _text(value)
    if text is None:
        return None
    return re.sub(r"[^a-z0-9]+", "", text.casefold())


def infer_select_presence(
    value: object | None,
    *,
    disabled_tokens: set[str] | None = None,
) -> bool | None:
    token = _token(value)
    if token is None:
        return None
    if token in _UNKNOWN_TOKENS:
        return None
    if token in (disabled_tokens or {"none"}):
        return False
    return True


def infer_internet_facing_exposure(value: object | None) -> bool | None:
    token = _token(value)
    if token is None or token in _UNKNOWN_TOKENS:
        return None
    if token in {"internet", "dmz"}:
        return True
    if token in {"internal", "vpcprivate"}:
        return False
    if any(keyword in token for keyword in _PUBLIC_EXPOSURE_KEYWORDS):
        return True
    if any(keyword in token for keyword in _PRIVATE_EXPOSURE_KEYWORDS):
        return False
    return None


def infer_trusted_boundary(value: object | None) -> bool | None:
    token = _token(value)
    if token is None or token in _UNKNOWN_TOKENS:
        return None
    if token in {"trusted", "privileged"}:
        return True
    if token in {"untrusted", "semitrusted"}:
        return False
    if any(keyword in token for keyword in _TRUSTED_KEYWORDS):
        return True
    if any(keyword in token for keyword in _UNTRUSTED_KEYWORDS):
        return False
    return None


def is_sensitive_classification(value: object | None) -> bool:
    token = _token(value)
    if token is None:
        return False
    if token in {"confidential", "restricted"}:
        return True
    return any(keyword in token for keyword in _SENSITIVE_CLASSIFICATION_KEYWORDS)


def infer_handles_sensitive_data(properties: Mapping[str, Any] | None) -> bool | None:
    properties = properties or {}
    if any(
        properties.get(flag) is True
        for flag in ("handles_pii", "handles_financial_data", "stores_credentials", "stores_secrets")
    ):
        return True
    if is_sensitive_classification(properties.get("data_classification")):
        return True
    return None


def is_no_tls_value(value: object | None) -> bool:
    token = _token(value)
    if token is None:
        return False
    return token in _NO_TLS_TOKENS


def is_deprecated_tls_value(value: object | None) -> bool:
    token = _token(value)
    if token is None:
        return False
    return token in _DEPRECATED_TLS_TOKENS


def is_tls_1_0_value(value: object | None) -> bool:
    return _token(value) == "tls10"


def is_tls_1_1_value(value: object | None) -> bool:
    return _token(value) == "tls11"

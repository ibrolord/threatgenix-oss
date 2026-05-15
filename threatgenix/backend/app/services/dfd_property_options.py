from __future__ import annotations

import re
from typing import Any, Iterable
from uuid import UUID, uuid4

from app.schemas.dfd import (
    DFDPropertyOptionCreate,
    DFDPropertyOptionDraft,
    DFDPropertyOptionResponse,
    DFDPropertyOptionSuggestResponse,
)
from app.services.llm_client import get_llm_client_for_user

PROPERTY_OPTION_PROMPT_VERSION = "v1.0"

PROPERTY_OPTION_FIELD_LABELS: dict[str, str] = {
    "data_classification": "Data Classification",
    "authentication_type": "Authentication",
    "authorization_model": "Authorization Model",
    "network_exposure": "Network Exposure",
    "privilege_level": "Privilege Level",
    "runtime_type": "Runtime Type",
    "isolation_boundary": "Isolation Boundary",
    "input_validation": "Input Validation",
    "logging_level": "Logging Level",
    "encryption_at_rest": "Encryption at Rest",
    "backup_strategy": "Backup Strategy",
    "entity_scope": "Entity Scope",
    "entity_kind": "Entity Kind",
    "trust_level": "Trust Level",
    "responsibility": "Responsibility",
}

BUILT_IN_PROPERTY_OPTIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "data_classification": (
        ("Public", "Public"),
        ("Internal", "Internal"),
        ("Confidential", "Confidential"),
        ("Restricted", "Restricted"),
    ),
    "authentication_type": (
        ("none", "None"),
        ("api_key", "API Key"),
        ("oauth2", "OAuth 2"),
        ("mtls", "mTLS"),
        ("saml", "SAML"),
        ("jwt", "JWT"),
    ),
    "authorization_model": (
        ("none", "None"),
        ("rbac", "RBAC"),
        ("abac", "ABAC"),
        ("acl", "ACL"),
        ("policy", "Policy"),
    ),
    "network_exposure": (
        ("internet", "Internet"),
        ("dmz", "DMZ"),
        ("internal", "Internal"),
        ("vpc_private", "VPC Private"),
    ),
    "privilege_level": (
        ("standard", "Standard"),
        ("elevated", "Elevated"),
        ("privileged", "Privileged"),
        ("admin", "Admin"),
        ("system", "System"),
    ),
    "runtime_type": (
        ("service", "Service"),
        ("worker", "Worker"),
        ("function", "Function"),
        ("job", "Job"),
        ("gateway", "Gateway"),
        ("container", "Container"),
    ),
    "isolation_boundary": (
        ("shared_host", "Shared Host"),
        ("container", "Container"),
        ("sandbox", "Sandbox"),
        ("dedicated_host", "Dedicated Host"),
        ("managed_service", "Managed Service"),
    ),
    "input_validation": (
        ("none", "None"),
        ("partial", "Partial"),
        ("strict", "Strict"),
    ),
    "logging_level": (
        ("none", "None"),
        ("errors_only", "Errors Only"),
        ("audit", "Audit"),
        ("full", "Full"),
    ),
    "encryption_at_rest": (
        ("none", "None"),
        ("application_level", "Application-Level"),
        ("transparent", "Transparent"),
        ("hsm", "HSM-backed"),
    ),
    "backup_strategy": (
        ("none", "None"),
        ("local", "Local"),
        ("geo_redundant", "Geo-Redundant"),
    ),
    "entity_scope": (
        ("internal", "Internal"),
        ("external", "External"),
    ),
    "entity_kind": (
        ("human", "Human"),
        ("device", "Device"),
        ("system", "System"),
        ("saas", "SaaS"),
        ("api", "API"),
        ("service", "Service"),
    ),
    "trust_level": (
        ("untrusted", "Untrusted"),
        ("semi_trusted", "Semi-Trusted"),
        ("trusted", "Trusted"),
        ("privileged", "Privileged"),
    ),
    "responsibility": (
        ("provider", "Provider-Managed"),
        ("customer", "Customer-Managed"),
        ("shared", "Shared"),
    ),
}

PROPERTY_OPTION_SYSTEM_MESSAGE = """\
You design ThreatGenix dropdown aliases for DFD metadata fields.

Rules:
- Prefer existing canonical values for the chosen field when they fit.
- Propose a user-facing label that helps teams reflect their environment vocabulary.
- Only invent a new canonical value if the user's wording clearly requires a custom entry that is not covered by the built-in list.
- Return one alias using the tool.
"""

PROPERTY_OPTION_TOOL: dict[str, Any] = {
    "name": "suggest_property_option",
    "description": "Return a DFD dropdown alias, preferring an existing canonical value but allowing a custom one when required.",
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "field": {
                    "type": "string",
                    "enum": list(BUILT_IN_PROPERTY_OPTIONS),
                },
                "label": {"type": "string"},
                "canonical_value": {"type": "string"},
                "description": {"type": "string"},
                "rationale": {"type": "string"},
            },
            "required": ["field", "label", "canonical_value"],
        }
    },
}


def _normalize_whitespace(value: str) -> str:
    return " ".join(value.split()).strip()


def _normalized_label_key(value: str) -> str:
    return _normalize_whitespace(value).casefold()


def _builtin_label_lookup(field: str) -> dict[str, str]:
    return dict(BUILT_IN_PROPERTY_OPTIONS.get(field, ()))


def _normalize_property_option_draft(
    draft: DFDPropertyOptionDraft | DFDPropertyOptionCreate,
) -> DFDPropertyOptionDraft:
    label = _normalize_whitespace(draft.label)
    canonical_value = _normalize_whitespace(draft.canonical_value)
    description = _normalize_whitespace(draft.description) if draft.description else None
    rationale = _normalize_whitespace(draft.rationale) if draft.rationale else None

    return DFDPropertyOptionDraft(
        field=draft.field,
        label=label,
        canonical_value=canonical_value,
        description=description,
        ai_generated=draft.ai_generated,
        rationale=rationale,
    )


def load_custom_property_options(
    raw_options: list[dict[str, Any]] | None,
) -> list[DFDPropertyOptionResponse]:
    normalized: list[DFDPropertyOptionResponse] = []
    for item in raw_options or []:
        try:
            candidate = DFDPropertyOptionResponse.model_validate(item)
            normalized_draft = _normalize_property_option_draft(candidate)
        except Exception:
            continue
        normalized.append(
            DFDPropertyOptionResponse(
                id=str(candidate.id),
                **normalized_draft.model_dump(mode="json"),
            )
        )
    return normalized


def list_property_options(
    raw_options: list[dict[str, Any]] | None,
    *,
    field: str | None = None,
) -> list[DFDPropertyOptionResponse]:
    options = load_custom_property_options(raw_options)
    if field is not None:
        options = [option for option in options if option.field == field]
    return sorted(
        options,
        key=lambda option: (
            option.field.casefold(),
            option.label.casefold(),
            option.canonical_value.casefold(),
        ),
    )


def create_property_option(
    raw_options: list[dict[str, Any]] | None,
    draft: DFDPropertyOptionCreate,
) -> tuple[DFDPropertyOptionResponse, list[dict[str, Any]]]:
    normalized_draft = _normalize_property_option_draft(draft)
    existing = list_property_options(raw_options, field=normalized_draft.field)
    builtin_labels = {
        _normalized_label_key(label)
        for label in _builtin_label_lookup(normalized_draft.field).values()
    }
    normalized_label = _normalized_label_key(normalized_draft.label)
    if normalized_label in builtin_labels:
        raise ValueError("This label already exists as a built-in dropdown option.")
    if any(_normalized_label_key(option.label) == normalized_label for option in existing):
        raise ValueError("A dropdown alias with this label already exists for the selected field.")

    response = DFDPropertyOptionResponse(
        id=str(uuid4()),
        **normalized_draft.model_dump(mode="json"),
    )
    next_options = [
        *[option.model_dump(mode="json") for option in load_custom_property_options(raw_options)],
        response.model_dump(mode="json"),
    ]
    return response, next_options


def delete_property_option(
    raw_options: list[dict[str, Any]] | None,
    option_id: str,
) -> tuple[bool, list[dict[str, Any]]]:
    current_options = load_custom_property_options(raw_options)
    remaining = [option for option in current_options if option.id != option_id]
    if len(remaining) == len(current_options):
        return False, [option.model_dump(mode="json") for option in current_options]
    return True, [option.model_dump(mode="json") for option in remaining]


def _extract_label_from_prompt(prompt: str) -> str:
    cleaned = _normalize_whitespace(
        re.sub(r"^(add|create|make|suggest|alias)\s+", "", prompt, flags=re.IGNORECASE)
    )
    cleaned = re.sub(r"^(a|an|the)\s+", "", cleaned, flags=re.IGNORECASE)
    if not cleaned:
        return "Custom Alias"
    words = cleaned.split()
    return " ".join(words[:5]).title()


def _dedupe_suggested_label(label: str, existing_options: Iterable[DFDPropertyOptionResponse]) -> str:
    existing_keys = {_normalized_label_key(option.label) for option in existing_options}
    if _normalized_label_key(label) not in existing_keys:
        return label
    suffix = 2
    while _normalized_label_key(f"{label} {suffix}") in existing_keys:
        suffix += 1
    return f"{label} {suffix}"


def _heuristic_canonical_value(field: str, prompt: str) -> str:
    prompt_lower = prompt.casefold()

    if field == "data_classification":
        if any(token in prompt_lower for token in ("restricted", "secret", "pci", "regulated")):
            return "Restricted"
        if any(token in prompt_lower for token in ("confidential", "sensitive")):
            return "Confidential"
        if "public" in prompt_lower:
            return "Public"
        return "Internal"

    if field == "authentication_type":
        if any(token in prompt_lower for token in ("oidc", "openid", "cognito", "auth0", "entra", "okta", "oauth")):
            return "oauth2"
        if any(token in prompt_lower for token in ("mutual tls", "mtls", "client cert")):
            return "mtls"
        if "saml" in prompt_lower:
            return "saml"
        if "jwt" in prompt_lower:
            return "jwt"
        if any(token in prompt_lower for token in ("api key", "token")):
            return "api_key"
        return "none"

    if field == "authorization_model":
        if any(token in prompt_lower for token in ("abac", "attribute", "claim-based")):
            return "abac"
        if any(token in prompt_lower for token in ("acl", "allow list", "deny list")):
            return "acl"
        if any(token in prompt_lower for token in ("policy", "opa", "iam policy")):
            return "policy"
        if any(token in prompt_lower for token in ("role", "rbac", "group-based")):
            return "rbac"
        return "none"

    if field == "network_exposure":
        if any(token in prompt_lower for token in ("dmz", "edge tier")):
            return "dmz"
        if any(token in prompt_lower for token in ("vpc", "private subnet", "private network")):
            return "vpc_private"
        if any(token in prompt_lower for token in ("public", "internet", "external", "edge")):
            return "internet"
        return "internal"

    if field == "privilege_level":
        if any(token in prompt_lower for token in ("system", "kernel", "root service")):
            return "system"
        if any(token in prompt_lower for token in ("admin", "administrator")):
            return "admin"
        if "privileged" in prompt_lower:
            return "privileged"
        if any(token in prompt_lower for token in ("elevated", "power user")):
            return "elevated"
        return "standard"

    if field == "runtime_type":
        if any(token in prompt_lower for token in ("worker", "consumer", "processor")):
            return "worker"
        if any(token in prompt_lower for token in ("function", "lambda")):
            return "function"
        if any(token in prompt_lower for token in ("job", "cron", "batch")):
            return "job"
        if any(token in prompt_lower for token in ("gateway", "proxy", "load balancer", "ingress")):
            return "gateway"
        if any(token in prompt_lower for token in ("container", "pod")):
            return "container"
        return "service"

    if field == "isolation_boundary":
        if any(token in prompt_lower for token in ("dedicated host", "dedicated node")):
            return "dedicated_host"
        if any(token in prompt_lower for token in ("managed service", "provider-managed")):
            return "managed_service"
        if any(token in prompt_lower for token in ("sandbox", "microvm")):
            return "sandbox"
        if any(token in prompt_lower for token in ("container", "pod")):
            return "container"
        return "shared_host"

    if field == "input_validation":
        if any(token in prompt_lower for token in ("strict", "schema", "allowlist")):
            return "strict"
        if "partial" in prompt_lower:
            return "partial"
        return "none"

    if field == "logging_level":
        if any(token in prompt_lower for token in ("full", "verbose", "debug")):
            return "full"
        if "audit" in prompt_lower:
            return "audit"
        if any(token in prompt_lower for token in ("errors", "error only")):
            return "errors_only"
        return "none"

    if field == "encryption_at_rest":
        if "hsm" in prompt_lower:
            return "hsm"
        if any(token in prompt_lower for token in ("application", "app-level")):
            return "application_level"
        if any(token in prompt_lower for token in ("transparent", "tde")):
            return "transparent"
        return "none"

    if field == "backup_strategy":
        if any(token in prompt_lower for token in ("geo", "cross-region", "multi-region")):
            return "geo_redundant"
        if any(token in prompt_lower for token in ("local", "snapshot")):
            return "local"
        return "none"

    if field == "entity_scope":
        return "external" if "external" in prompt_lower else "internal"

    if field == "entity_kind":
        if "human" in prompt_lower or "user" in prompt_lower:
            return "human"
        if "device" in prompt_lower:
            return "device"
        if any(token in prompt_lower for token in ("saas", "vendor", "third-party")):
            return "saas"
        if "api" in prompt_lower:
            return "api"
        if "service" in prompt_lower:
            return "service"
        return "system"

    if field == "trust_level":
        if "privileged" in prompt_lower:
            return "privileged"
        if any(token in prompt_lower for token in ("trusted", "first-party")):
            return "trusted"
        if any(token in prompt_lower for token in ("semi", "partner")):
            return "semi_trusted"
        return "untrusted"

    if field == "responsibility":
        if "provider" in prompt_lower:
            return "provider"
        if "shared" in prompt_lower:
            return "shared"
        return "customer"

    return next(iter(_builtin_label_lookup(field)))


def _heuristic_suggestion(
    field: str,
    prompt: str,
    existing_options: list[DFDPropertyOptionResponse],
) -> DFDPropertyOptionSuggestResponse:
    label = _dedupe_suggested_label(_extract_label_from_prompt(prompt), existing_options)
    canonical_value = _heuristic_canonical_value(field, prompt)
    draft = DFDPropertyOptionDraft(
        field=field,
        label=label,
        canonical_value=canonical_value,
        description=f"Custom dropdown alias suggested from: {prompt}",
        ai_generated=True,
        rationale="Fallback heuristic suggestion based on the field and prompt keywords.",
    )
    return DFDPropertyOptionSuggestResponse(
        option=_normalize_property_option_draft(draft),
        degraded_reason="AI suggestion fell back to deterministic heuristics.",
    )


def suggest_property_option(
    *,
    user_id: UUID,
    field: str,
    prompt: str,
    threat_model_name: str,
    threat_model_description: str,
    raw_options: list[dict[str, Any]] | None,
) -> DFDPropertyOptionSuggestResponse:
    existing_options = list_property_options(raw_options, field=field)
    cleaned_prompt = _normalize_whitespace(prompt)
    builtin_lookup = _builtin_label_lookup(field)

    try:
        client = get_llm_client_for_user(user_id)
        tool_output = client.call_with_tools(
            system_message=PROPERTY_OPTION_SYSTEM_MESSAGE,
            user_message=(
                f"Threat model: {threat_model_name}\n"
                f"Description: {threat_model_description or '(none)'}\n"
                f"Field: {PROPERTY_OPTION_FIELD_LABELS[field]}\n"
                f"Allowed canonical values: {', '.join(f'{value} ({label})' for value, label in builtin_lookup.items())}\n"
                f"Existing aliases: {', '.join(option.label for option in existing_options[:20]) or '(none)'}\n"
                f"User request: {cleaned_prompt}\n"
                "Suggest one dropdown alias."
            ),
            tools=[PROPERTY_OPTION_TOOL],
            max_tokens=1000,
            prompt_version=PROPERTY_OPTION_PROMPT_VERSION,
        )
        if not tool_output:
            raise RuntimeError("property_option_llm_empty_response")

        llm_draft = DFDPropertyOptionDraft.model_validate(
            {
                **tool_output,
                "field": field,
                "ai_generated": True,
            }
        )
        normalized = _normalize_property_option_draft(llm_draft)
        normalized = normalized.model_copy(
            update={
                "label": _dedupe_suggested_label(normalized.label, existing_options),
            }
        )
        return DFDPropertyOptionSuggestResponse(option=normalized)
    except Exception:
        return _heuristic_suggestion(field, cleaned_prompt, existing_options)

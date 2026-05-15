from __future__ import annotations

import re
from typing import Any, Iterable
from uuid import UUID, uuid4

from app.schemas.dfd import (
    ComponentShape,
    DFDComponentTemplateCreate,
    DFDComponentTemplateDraft,
    DFDComponentTemplateResponse,
    DFDComponentTemplateSuggestResponse,
    NodeProperties,
)
from app.services.llm_client import get_llm_client_for_user

COMPONENT_TEMPLATE_PROMPT_VERSION = "v1.0"

SEMANTIC_NODE_TYPES = [
    "process",
    "data_store",
    "external_entity",
    "human_actor",
    "iam_role",
    "managed_service",
    "api_gateway",
    "container",
    "serverless",
]

COMPONENT_SHAPES = [shape.value for shape in ComponentShape]

COMPONENT_TEMPLATE_SYSTEM_MESSAGE = """\
You design ThreatGenix DFD component templates.

Rules:
- Keep threat logic normalized to the existing semantic node types.
- Choose exactly one semantic_node_type from the allowed list.
- Use shape only for visual differentiation.
- Prefer concise, security-relevant defaults.
- Do not invent complicated defaults when the prompt is vague.
- Return a single template draft using the tool.
"""

COMPONENT_TEMPLATE_TOOL: dict[str, Any] = {
    "name": "suggest_component_template",
    "description": "Return a DFD component template draft grounded in the user's request.",
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "label": {"type": "string"},
                "description": {"type": "string"},
                "semantic_node_type": {
                    "type": "string",
                    "enum": SEMANTIC_NODE_TYPES,
                },
                "shape": {
                    "type": "string",
                    "enum": COMPONENT_SHAPES,
                },
                "group": {"type": "string"},
                "default_name": {"type": "string"},
                "default_properties": {
                    "type": "object",
                    "additionalProperties": True,
                },
                "rationale": {"type": "string"},
            },
            "required": ["label", "semantic_node_type", "shape"],
        }
    },
}


def _template_response(
    *,
    template_id: str,
    label: str,
    semantic_node_type: str,
    shape: ComponentShape,
    group: str,
    description: str | None = None,
    default_name: str | None = None,
    default_properties: NodeProperties | dict[str, Any] | None = None,
    built_in: bool = False,
    ai_generated: bool = False,
    rationale: str | None = None,
) -> DFDComponentTemplateResponse:
    return DFDComponentTemplateResponse(
        id=template_id,
        label=label,
        description=description,
        semantic_node_type=semantic_node_type,
        shape=shape,
        group=group,
        default_name=default_name,
        default_properties=NodeProperties.model_validate(default_properties or {}),
        built_in=built_in,
        ai_generated=ai_generated,
        rationale=rationale,
    )


BUILT_IN_COMPONENT_TEMPLATES: tuple[DFDComponentTemplateResponse, ...] = (
    _template_response(
        template_id="builtin-process",
        label="Process",
        semantic_node_type="process",
        shape=ComponentShape.rounded_rect,
        group="Standard",
        description="Generic application or service process.",
        default_name="New Process",
        default_properties={"runtime_type": "service"},
        built_in=True,
    ),
    _template_response(
        template_id="builtin-data-store",
        label="Data Store",
        semantic_node_type="data_store",
        shape=ComponentShape.cylinder,
        group="Standard",
        description="Persistent data storage component.",
        default_name="New Data Store",
        default_properties={"store_type": "database"},
        built_in=True,
    ),
    _template_response(
        template_id="builtin-external-entity",
        label="External System",
        semantic_node_type="external_entity",
        shape=ComponentShape.square,
        group="Standard",
        description="External system or third-party dependency.",
        default_name="External System",
        default_properties={"entity_scope": "external", "entity_kind": "system"},
        built_in=True,
    ),
    _template_response(
        template_id="builtin-human-actor",
        label="Human Actor",
        semantic_node_type="human_actor",
        shape=ComponentShape.pill,
        group="Standard",
        description="Human user or operator.",
        default_name="User",
        default_properties={"entity_scope": "external", "entity_kind": "human"},
        built_in=True,
    ),
    _template_response(
        template_id="builtin-iam-role",
        label="IAM Role / Identity",
        semantic_node_type="iam_role",
        shape=ComponentShape.hexagon,
        group="Cloud",
        description="Service identity, role, or workload principal.",
        default_name="Service Identity",
        default_properties={"privilege_level": "privileged"},
        built_in=True,
    ),
    _template_response(
        template_id="builtin-managed-service",
        label="Managed Cloud Service",
        semantic_node_type="managed_service",
        shape=ComponentShape.cloud,
        group="Cloud",
        description="Provider-managed service such as S3, RDS, or Pub/Sub.",
        default_name="Managed Service",
        default_properties={"responsibility": "provider"},
        built_in=True,
    ),
    _template_response(
        template_id="builtin-api-gateway",
        label="API Gateway / Load Balancer",
        semantic_node_type="api_gateway",
        shape=ComponentShape.gateway,
        group="Cloud",
        description="Ingress or traffic distribution component.",
        default_name="API Gateway",
        default_properties={"runtime_type": "gateway", "network_exposure": "internet"},
        built_in=True,
    ),
    _template_response(
        template_id="builtin-container",
        label="Container / Pod / Task",
        semantic_node_type="container",
        shape=ComponentShape.stacked,
        group="Cloud",
        description="Containerized workload boundary.",
        default_name="Workload",
        default_properties={"runtime_type": "container", "isolation_boundary": "container"},
        built_in=True,
    ),
    _template_response(
        template_id="builtin-serverless",
        label="Serverless Function",
        semantic_node_type="serverless",
        shape=ComponentShape.diamond,
        group="Cloud",
        description="Ephemeral function or lambda-style runtime.",
        default_name="Function",
        default_properties={"runtime_type": "function", "isolation_boundary": "sandbox"},
        built_in=True,
    ),
    _template_response(
        template_id="builtin-message-queue",
        label="Message Queue / Stream",
        semantic_node_type="data_store",
        shape=ComponentShape.queue,
        group="Messaging",
        description="Queue, topic, or event stream component.",
        default_name="Message Queue",
        default_properties={"store_type": "queue", "store_purpose": "asynchronous messaging"},
        built_in=True,
    ),
)


def _normalize_whitespace(value: str) -> str:
    return " ".join(value.split()).strip()


def _normalized_label_key(value: str) -> str:
    return _normalize_whitespace(value).casefold()


def _default_group_for_node_type(node_type: str) -> str:
    if node_type in {"iam_role", "managed_service", "api_gateway", "container", "serverless"}:
        return "Cloud"
    if node_type == "data_store":
        return "Data"
    if node_type in {"external_entity", "human_actor"}:
        return "External"
    return "Custom"


def _normalize_default_properties(raw_properties: NodeProperties | dict[str, Any] | None) -> NodeProperties:
    properties = NodeProperties.model_validate(raw_properties or {})
    return properties.model_copy(
        update={
            "component_template_id": None,
            "component_label": None,
            "component_shape": None,
            "component_description": None,
            "property_display_labels": None,
        }
    )


def _normalize_template_draft(
    draft: DFDComponentTemplateDraft | DFDComponentTemplateCreate,
) -> DFDComponentTemplateDraft:
    label = _normalize_whitespace(draft.label)
    description = _normalize_whitespace(draft.description) if draft.description else None
    default_name = _normalize_whitespace(draft.default_name) if draft.default_name else None
    semantic_type_label = _normalize_whitespace(draft.semantic_type_label) if draft.semantic_type_label else None
    group = _normalize_whitespace(draft.group) if draft.group else _default_group_for_node_type(draft.semantic_node_type)
    rationale = _normalize_whitespace(draft.rationale) if draft.rationale else None
    return DFDComponentTemplateDraft(
        label=label,
        description=description,
        semantic_node_type=draft.semantic_node_type,
        semantic_type_label=semantic_type_label,
        shape=draft.shape,
        group=group or _default_group_for_node_type(draft.semantic_node_type),
        default_name=default_name or label,
        default_properties=_normalize_default_properties(draft.default_properties),
        ai_generated=draft.ai_generated,
        rationale=rationale,
    )


def load_custom_component_templates(
    raw_templates: list[dict[str, Any]] | None,
) -> list[DFDComponentTemplateResponse]:
    normalized: list[DFDComponentTemplateResponse] = []
    for item in raw_templates or []:
        try:
            candidate = DFDComponentTemplateResponse.model_validate(item)
        except Exception:
            continue
        normalized.append(
            DFDComponentTemplateResponse(
                **_normalize_template_draft(candidate).model_dump(mode="json"),
                id=str(candidate.id),
                built_in=False,
            )
        )
    return normalized


def list_component_templates(raw_templates: list[dict[str, Any]] | None) -> list[DFDComponentTemplateResponse]:
    custom_templates = load_custom_component_templates(raw_templates)
    templates = [*BUILT_IN_COMPONENT_TEMPLATES, *custom_templates]
    return sorted(
        templates,
        key=lambda template: (
            0 if template.built_in else 1,
            template.group.casefold(),
            template.label.casefold(),
        ),
    )


def create_component_template(
    raw_templates: list[dict[str, Any]] | None,
    draft: DFDComponentTemplateCreate,
) -> tuple[DFDComponentTemplateResponse, list[dict[str, Any]]]:
    normalized_draft = _normalize_template_draft(draft)
    existing = list_component_templates(raw_templates)
    normalized_label = _normalized_label_key(normalized_draft.label)
    if any(_normalized_label_key(template.label) == normalized_label for template in existing):
        raise ValueError("A component template with this label already exists.")

    response = DFDComponentTemplateResponse(
        id=str(uuid4()),
        built_in=False,
        **normalized_draft.model_dump(mode="json"),
    )
    next_templates = [
        *[template.model_dump(mode="json") for template in load_custom_component_templates(raw_templates)],
        response.model_dump(mode="json"),
    ]
    return response, next_templates


def delete_component_template(
    raw_templates: list[dict[str, Any]] | None,
    template_id: str,
) -> tuple[bool, list[dict[str, Any]]]:
    if template_id.startswith("builtin-"):
        raise ValueError("Built-in component templates cannot be deleted.")

    current_templates = load_custom_component_templates(raw_templates)
    remaining = [template for template in current_templates if template.id != template_id]
    if len(remaining) == len(current_templates):
        return False, [template.model_dump(mode="json") for template in current_templates]
    return True, [template.model_dump(mode="json") for template in remaining]


def _extract_label_from_prompt(prompt: str) -> str:
    cleaned = _normalize_whitespace(re.sub(r"^(add|create|make|suggest)\s+", "", prompt, flags=re.IGNORECASE))
    cleaned = re.sub(r"^(a|an|the)\s+", "", cleaned, flags=re.IGNORECASE)
    if not cleaned:
        return "Custom Component"
    words = cleaned.split()
    label = " ".join(words[:5])
    return label.title()


def _dedupe_suggested_label(label: str, existing_templates: Iterable[DFDComponentTemplateResponse]) -> str:
    existing_keys = {_normalized_label_key(template.label) for template in existing_templates}
    if _normalized_label_key(label) not in existing_keys:
        return label
    suffix = 2
    while _normalized_label_key(f"{label} {suffix}") in existing_keys:
        suffix += 1
    return f"{label} {suffix}"


def _heuristic_suggestion(
    prompt: str,
    existing_templates: list[DFDComponentTemplateResponse],
) -> DFDComponentTemplateSuggestResponse:
    prompt_lower = prompt.casefold()
    label = _dedupe_suggested_label(_extract_label_from_prompt(prompt), existing_templates)

    draft = DFDComponentTemplateDraft(
        label=label,
        description=f"Custom stencil suggested from: {prompt}",
        semantic_node_type="process",
        shape=ComponentShape.rounded_rect,
        group="Custom",
        default_name=label,
        default_properties=NodeProperties(),
        ai_generated=True,
        rationale="Fallback heuristic suggestion based on the component name.",
    )

    if any(token in prompt_lower for token in ("lambda", "serverless", "cloud function", "function")):
        draft.semantic_node_type = "serverless"
        draft.shape = ComponentShape.diamond
        draft.group = "Cloud"
        draft.default_properties = NodeProperties(runtime_type="function", isolation_boundary="sandbox")
    elif any(token in prompt_lower for token in ("container", "pod", "ecs", "kubernetes", "k8s")):
        draft.semantic_node_type = "container"
        draft.shape = ComponentShape.stacked
        draft.group = "Cloud"
        draft.default_properties = NodeProperties(runtime_type="container", isolation_boundary="container")
    elif any(token in prompt_lower for token in ("api gateway", "load balancer", "ingress", "reverse proxy", "gateway", "waf")):
        draft.semantic_node_type = "api_gateway"
        draft.shape = ComponentShape.gateway
        draft.group = "Cloud"
        draft.default_properties = NodeProperties(runtime_type="gateway", network_exposure="internet")
    elif any(token in prompt_lower for token in ("queue", "topic", "kafka", "pubsub", "bus", "stream")):
        draft.semantic_node_type = "data_store"
        draft.shape = ComponentShape.queue
        draft.group = "Messaging"
        draft.default_properties = NodeProperties(store_type="queue", store_purpose="asynchronous messaging")
    elif any(token in prompt_lower for token in ("database", "postgres", "mysql", "mongodb", "redis", "cache", "bucket", "storage")):
        draft.semantic_node_type = "data_store"
        draft.shape = ComponentShape.cylinder
        draft.group = "Data"
        draft.default_properties = NodeProperties(store_type="database")
    elif any(token in prompt_lower for token in ("third-party", "saas", "vendor", "partner", "external")):
        draft.semantic_node_type = "external_entity"
        draft.shape = ComponentShape.square
        draft.group = "External"
        draft.default_properties = NodeProperties(entity_scope="external", entity_kind="saas")
    elif any(token in prompt_lower for token in ("iam", "role", "service account", "identity", "principal")):
        draft.semantic_node_type = "iam_role"
        draft.shape = ComponentShape.hexagon
        draft.group = "Cloud"
        draft.default_properties = NodeProperties(privilege_level="privileged")
    elif any(token in prompt_lower for token in ("managed service", "s3", "rds", "bigquery", "cloud sql", "dynamodb")):
        draft.semantic_node_type = "managed_service"
        draft.shape = ComponentShape.cloud
        draft.group = "Cloud"
        draft.default_properties = NodeProperties(responsibility="provider")

    return DFDComponentTemplateSuggestResponse(
        template=_normalize_template_draft(draft),
        degraded_reason="AI suggestion fell back to deterministic heuristics.",
    )


def suggest_component_template(
    *,
    user_id: UUID,
    prompt: str,
    threat_model_name: str,
    threat_model_description: str,
    raw_templates: list[dict[str, Any]] | None,
) -> DFDComponentTemplateSuggestResponse:
    existing_templates = list_component_templates(raw_templates)
    cleaned_prompt = _normalize_whitespace(prompt)

    try:
        client = get_llm_client_for_user(user_id)
        tool_output = client.call_with_tools(
            system_message=COMPONENT_TEMPLATE_SYSTEM_MESSAGE,
            user_message=(
                f"Threat model: {threat_model_name}\n"
                f"Description: {threat_model_description or '(none)'}\n"
                f"Existing templates: {', '.join(template.label for template in existing_templates[:20])}\n"
                f"User request: {cleaned_prompt}\n"
                "Suggest one reusable DFD component template."
            ),
            tools=[COMPONENT_TEMPLATE_TOOL],
            max_tokens=1200,
            prompt_version=COMPONENT_TEMPLATE_PROMPT_VERSION,
        )
        if not tool_output:
            raise RuntimeError("component_template_llm_empty_response")

        llm_draft = DFDComponentTemplateDraft.model_validate(
            {
                **tool_output,
                "ai_generated": True,
            }
        )
        normalized = _normalize_template_draft(llm_draft)
        normalized = normalized.model_copy(
            update={
                "label": _dedupe_suggested_label(normalized.label, existing_templates),
            }
        )
        return DFDComponentTemplateSuggestResponse(template=normalized)
    except Exception:
        return _heuristic_suggestion(cleaned_prompt, existing_templates)

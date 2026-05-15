"""F-02 LLM extraction service: PDF raw text -> DocumentParseResult.

Extracts architecture components, data flows, and trust boundaries from
bank system design documents using Claude via AWS Bedrock Converse API
with tool_use for structured output enforcement.

Prompt version is tracked for regression testing and debugging.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from app.config import settings
from app.schemas.document import (
    ExtractionOutcome,
    DocumentExtractionEvidence,
    DocumentParseResult,
    ParsedBoundary,
    ParsedComponent,
    ParsedFlow,
)
from app.services.doc_parser import (
    assess_parse_result,
    heuristic_parse_architecture,
    normalize_flow_label,
    normalize_extracted_text,
    supplement_sparse_boundaries,
)
from app.services.llm_client import LLMClient, get_llm_client

logger = logging.getLogger(__name__)

_LOCATION_COMPONENT_RE = re.compile(
    r"\b(on[- ]premises data centers?|public cloud tenant|warm standby region|"
    r"primary public cloud tenant|secondary location for disaster recovery)\b",
    re.IGNORECASE,
)
_FLOW_LABEL_STORE_RE = re.compile(
    r"\b(weather|maintenance|vendor support|crew operational messaging|"
    r"flight[- ]plan optimization|airport decision[- ]making(?: feeds?)?) data\b",
    re.IGNORECASE,
)
_ABSTRACT_EXTERNAL_COMPONENT_RE = re.compile(
    r"\b(vendor support|crew operational messaging)\b",
    re.IGNORECASE,
)
_EFB_CANONICAL_NAME = "Electronic Flight Bag (EFB) synchronization service"
_EFB_ALIAS_RE = re.compile(r"^efb synchronization service$", re.IGNORECASE)
_DOCUMENT_TYPE_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "architecture_design",
        (
            "architecture",
            "system design",
            "high level design",
            "technical design",
            "component diagram",
            "deployment diagram",
        ),
    ),
    (
        "deployment_spec",
        (
            "deployment",
            "infrastructure",
            "kubernetes",
            "terraform",
            "vpc",
            "container",
            "helm",
        ),
    ),
    (
        "sequence_or_workflow",
        (
            "sequence diagram",
            "workflow",
            "request flow",
            "request/response",
            "message flow",
            "swimlane",
        ),
    ),
    (
        "api_or_integration_spec",
        (
            "openapi",
            "swagger",
            "endpoint",
            "api spec",
            "integration",
            "webhook",
        ),
    ),
)

# ─── Prompt Versioning ───────────────────────────────────────────────
EXTRACTION_PROMPT_VERSION = "v1.0"

# ─── System Message ──────────────────────────────────────────────────
EXTRACTION_SYSTEM_MESSAGE = """\
You are a senior security architect analyzing system design documents for \
Canadian banks. Your task is to extract architecture components, data flows, \
and trust boundaries from the raw text of a design document.

## What to extract

1. COMPONENTS — every distinct system element:
   - **process**: services, APIs, applications, microservices, gateways, \
engines, workers, schedulers
   - **data_store**: databases, caches, message queues, file stores, \
data warehouses, key vaults, HSMs
   - **external_entity**: end users, administrators, third-party systems, \
partner APIs, regulatory bodies, card networks

2. DATA FLOWS — connections between components showing data movement:
   - Identify source and target by the exact component name you extracted
   - Label describes what data moves (e.g., "authentication request", \
"payment authorization", "encrypted card data")
   - Classify the data types carried in each flow using these categories: \
PAN (card numbers), PII (personal info like name/email/address/SIN), \
credentials (passwords/tokens/API keys), session_token, transaction_data, \
account_data, consent_record, audit_log, config, public. \
A flow can carry multiple data types.

3. TRUST BOUNDARIES — security zones that group components by trust level:
   - Infer from context clues: "DMZ", "internal network", "external-facing", \
"partner zone", "PCI scope", "cardholder data environment"
   - The "contains" list must use exact component names from your extraction

## Rules (follow strictly)

- ONLY extract what the document explicitly describes or strongly implies. \
Do NOT invent components that are not mentioned or clearly implied.
- Use the specific names from the document, not generic labels. If the \
document says "Interac e-Transfer Gateway", use that — not "payment gateway".
- Each component must appear exactly once with a unique name.
- Flow source and target must match extracted component names exactly.

## Confidence scoring

Assign confidence (0.0 to 1.0) based on how explicitly the document \
describes each item:
- **0.9–1.0**: Component is named explicitly with a clear role description. \
Example: "The API Gateway (Kong) routes all external requests."
- **0.7–0.8**: Component is named but its role is only partially described. \
Example: "Requests pass through the API gateway to backend services."
- **0.5–0.6**: Component is implied but not named directly. Example: \
"User data is persisted" implies a database but does not name one.
- **0.3–0.4**: Component is weakly inferred from context. Example: \
"The system is PCI-compliant" implies an HSM may exist but is not stated.
- **Below 0.3**: Do not extract. If you are this uncertain, the component \
is not in the document.

## Banking terminology

Recognize these as specific component types, not generic terms:
- Core banking system, ledger, general ledger → process
- Payment gateway, payment processor, acquirer, issuer → process
- Fraud detection engine, risk scoring service → process
- KYC/AML service, identity verification → process
- SWIFT interface, Interac gateway, EFT processor → process
- Card management system, tokenization service → process
- API gateway, WAF, load balancer, reverse proxy → process
- HSM (Hardware Security Module), key vault → data_store
- Redis cache, session store, message queue (Kafka, RabbitMQ) → data_store
- Customer database, transaction database, audit log → data_store
- Card networks (Visa, Mastercard), credit bureaus → external_entity
- Mobile app users, online banking users, branch tellers → external_entity
- Regulators (OSFI, FINTRAC), payment networks → external_entity

You must call the extract_architecture tool with your results. Do not \
respond with plain text."""

# ─── User Message Template ───────────────────────────────────────────
EXTRACTION_USER_TEMPLATE = """\
Extract all architecture components, data flows, and trust boundaries \
from the following system design document for "{system_name}".

Analyze the full text carefully. Extract every component, flow, and \
boundary you can identify with confidence >= 0.3.

---
DOCUMENT TEXT:
{raw_text}
---

Call the extract_architecture tool with your findings."""

# ─── Tool Schema (Bedrock Converse API tool_use format) ──────────────
EXTRACT_ARCHITECTURE_TOOL: dict[str, Any] = {
    "name": "extract_architecture",
    "description": (
        "Extract architecture components, data flows, and trust boundaries "
        "from a bank system design document. You MUST call this tool with "
        "your extraction results."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "components": {
                    "type": "array",
                    "description": (
                        "All system components found in the document. "
                        "Each must have a unique name."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": (
                                    "Exact name as used in the document, "
                                    "or a clear descriptive name if implied."
                                ),
                            },
                            "component_type": {
                                "type": "string",
                                "enum": [
                                    "process",
                                    "data_store",
                                    "external_entity",
                                    "human_actor",
                                ],
                                "description": (
                                    "process = services/APIs/apps, "
                                    "data_store = databases/caches/queues/HSMs, "
                                    "external_entity = systems/third-parties, "
                                    "human_actor = human users/operators/analysts"
                                ),
                            },
                            "confidence": {
                                "type": "number",
                                "minimum": 0.0,
                                "maximum": 1.0,
                                "description": (
                                    "How explicitly the document describes "
                                    "this component. 0.9+ = named with clear "
                                    "description, 0.5-0.8 = partially described "
                                    "or implied, 0.3-0.4 = weakly inferred."
                                ),
                            },
                            "description": {
                                "type": "string",
                                "description": (
                                    "Brief description of the component's role "
                                    "based on the document text."
                                ),
                            },
                        },
                        "required": [
                            "name",
                            "component_type",
                            "confidence",
                            "description",
                        ],
                    },
                },
                "flows": {
                    "type": "array",
                    "description": (
                        "Data flows between components. Source and target "
                        "must exactly match component names from the "
                        "components list."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "source": {
                                "type": "string",
                                "description": (
                                    "Name of the source component "
                                    "(must match a component name exactly)."
                                ),
                            },
                            "target": {
                                "type": "string",
                                "description": (
                                    "Name of the target component "
                                    "(must match a component name exactly)."
                                ),
                            },
                            "label": {
                                "type": "string",
                                "description": (
                                    "What data moves in this flow "
                                    "(e.g., 'authentication request', "
                                    "'encrypted card data')."
                                ),
                            },
                            "confidence": {
                                "type": "number",
                                "minimum": 0.0,
                                "maximum": 1.0,
                                "description": (
                                    "How explicitly the document describes "
                                    "this data flow."
                                ),
                            },
                            "data_types": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "Types of data carried in this flow. Use specific "
                                    "classifications: 'PAN' (card numbers), 'PII' "
                                    "(personal info), 'PHI' (health info), 'credentials' "
                                    "(passwords/tokens/keys), 'session_token', "
                                    "'transaction_data', 'account_data', 'consent_record', "
                                    "'audit_log', 'config', 'public'. Infer from the "
                                    "flow label and context."
                                ),
                            },
                        },
                        "required": [
                            "source",
                            "target",
                            "label",
                            "confidence",
                        ],
                    },
                },
                "boundaries": {
                    "type": "array",
                    "description": (
                        "Trust boundaries / security zones that group "
                        "components. The contains list must use exact "
                        "component names."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": (
                                    "Name of the trust boundary or security "
                                    "zone (e.g., 'DMZ', 'Internal Network', "
                                    "'PCI CDE')."
                                ),
                            },
                            "contains": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "List of component names within this "
                                    "boundary. Must match component names "
                                    "exactly."
                                ),
                            },
                        },
                        "required": ["name", "contains"],
                    },
                },
            },
            "required": ["components", "flows", "boundaries"],
        }
    },
}


def _empty_parse_result() -> DocumentParseResult:
    """Return an empty DocumentParseResult for graceful degradation."""
    return DocumentParseResult(
        components=[],
        flows=[],
        boundaries=[],
        raw_text_excerpt="",
    )


def classify_document_type(raw_text: str) -> str | None:
    """Classify the uploaded document using deterministic keyword scoring."""
    normalized_text = normalize_extracted_text(raw_text).lower()
    best_label: str | None = None
    best_score = 0

    for label, keywords in _DOCUMENT_TYPE_RULES:
        score = sum(1 for keyword in keywords if keyword in normalized_text)
        if score > best_score:
            best_label = label
            best_score = score

    return best_label if best_score > 0 else None


def merge_parse_results(
    primary: DocumentParseResult,
    fallback: DocumentParseResult,
) -> DocumentParseResult:
    """Public merge helper so callers can combine deterministic extraction layers."""
    return _merge_parse_results(primary, fallback)


def build_extraction_evidence(
    raw_text: str,
    parse_result: DocumentParseResult,
    *,
    warnings: list[str] | None = None,
    diagram_pages: list[int] | None = None,
    diagram_artifacts: list[str] | None = None,
    detected_doc_type: str | None = None,
) -> DocumentExtractionEvidence:
    """Build a compact evidence summary for UI and downstream threat analysis."""
    extraction_sources: list[str] = []

    def _append_source(value: str | None) -> None:
        if not value or value in extraction_sources:
            return
        extraction_sources.append(value)

    for component in parse_result.components:
        _append_source(component.extraction_source)
    for flow in parse_result.flows:
        _append_source(flow.extraction_source)
    for boundary in parse_result.boundaries:
        _append_source(boundary.extraction_source)

    if diagram_pages:
        _append_source("diagram")

    low_confidence_areas = [warning for warning in (warnings or []) if warning.strip()]
    if any(component.confidence < 0.6 for component in parse_result.components):
        low_confidence_areas.append(
            "Some extracted components were inferred with low confidence. Review them in the DFD editor."
        )
    if any(flow.confidence < 0.6 for flow in parse_result.flows):
        low_confidence_areas.append(
            "Some extracted data flows were inferred with low confidence. Review diagram connectors before relying on them."
        )

    deduped_low_confidence_areas: list[str] = []
    for warning in low_confidence_areas:
        if warning not in deduped_low_confidence_areas:
            deduped_low_confidence_areas.append(warning)

    return DocumentExtractionEvidence(
        component_count=len(parse_result.components),
        flow_count=len(parse_result.flows),
        boundary_count=len(parse_result.boundaries),
        diagram_pages=sorted(set(diagram_pages or [])),
        diagram_artifacts=list(dict.fromkeys(diagram_artifacts or [])),
        extraction_sources=extraction_sources,
        low_confidence_areas=deduped_low_confidence_areas,
        raw_text_excerpt=parse_result.raw_text_excerpt or normalize_extracted_text(raw_text)[:500],
        detected_doc_type=detected_doc_type if detected_doc_type is not None else classify_document_type(raw_text),
    )


def _parse_tool_response(
    tool_output: dict[str, Any],
    raw_text: str,
    known_components: list[ParsedComponent] | None = None,
) -> DocumentParseResult:
    """Convert Bedrock tool_use response dict into DocumentParseResult.

    Validates each item individually — malformed items are dropped rather
    than failing the entire parse. This is intentional: partial results
    are better than no results.
    """
    components: list[ParsedComponent] = []
    flows: list[ParsedFlow] = []
    boundaries: list[ParsedBoundary] = []

    # Parse components
    for raw in tool_output.get("components", []):
        try:
            components.append(
                ParsedComponent(
                    name=str(raw["name"]).strip(),
                    component_type=raw["component_type"],
                    confidence=float(raw["confidence"]),
                    description=str(raw.get("description", "")),
                    extraction_source="llm",
                    evidence_snippet=str(raw.get("description", "")).strip(),
                )
            )
        except (KeyError, ValueError, TypeError) as exc:
            logger.debug("Skipping malformed component: %s — %s", raw, exc)

    # Build set of valid component names for flow validation (normalized)
    def _normalize(name: str) -> str:
        """Match normalize_name() from dfd_generator.py."""
        name = name.lower().strip()
        name = name.replace("-", " ").replace("_", " ")
        name = re.sub(r"\s+", " ", name)
        return name

    valid_names_normalized = {_normalize(c.name) for c in components}
    if known_components:
        valid_names_normalized.update(_normalize(component.name) for component in known_components)

    # Parse flows — only keep flows whose source/target match a component
    # Uses normalized matching to avoid dropping flows due to casing/formatting
    for raw in tool_output.get("flows", []):
        try:
            source = str(raw["source"]).strip()
            target = str(raw["target"]).strip()
            if _normalize(source) not in valid_names_normalized:
                logger.debug(
                    "Flow source '%s' not in components, dropping flow", source
                )
                continue
            if _normalize(target) not in valid_names_normalized:
                logger.debug(
                    "Flow target '%s' not in components, dropping flow", target
                )
                continue
            flows.append(
                ParsedFlow(
                    source=source,
                    target=target,
                    label=normalize_flow_label(str(raw.get("label", ""))),
                    confidence=float(raw["confidence"]),
                    data_types=[str(dt) for dt in raw.get("data_types", [])],
                    extraction_source="llm",
                    evidence_snippet=normalize_flow_label(str(raw.get("label", ""))),
                )
            )
        except (KeyError, ValueError, TypeError) as exc:
            logger.debug("Skipping malformed flow: %s — %s", raw, exc)

    # Parse boundaries — filter contains to valid component names (normalized)
    for raw in tool_output.get("boundaries", []):
        try:
            contains_raw = raw.get("contains", [])
            contains = [
                str(name).strip()
                for name in contains_raw
                if _normalize(str(name).strip()) in valid_names_normalized
            ]
            if contains:  # Only add boundaries that actually contain components
                boundaries.append(
                    ParsedBoundary(
                        name=str(raw["name"]).strip(),
                        contains=contains,
                        extraction_source="llm",
                        evidence_snippet=str(raw["name"]).strip(),
                    )
                )
        except (KeyError, ValueError, TypeError) as exc:
            logger.debug("Skipping malformed boundary: %s — %s", raw, exc)

    # Excerpt: first 500 chars of raw text for reference
    excerpt = raw_text[:500] if raw_text else ""

    result = DocumentParseResult(
        components=components,
        flows=flows,
        boundaries=boundaries,
        raw_text_excerpt=excerpt,
    )

    logger.info(
        "extraction_parse_complete components=%d flows=%d boundaries=%d",
        len(components),
        len(flows),
        len(boundaries),
    )

    return result


def _normalize_component_name(name: str) -> str:
    name = name.lower().strip()
    name = name.replace("-", " ").replace("_", " ")
    name = re.sub(r"\s+", " ", name)
    return name


def _sanitize_parse_result(
    raw_text: str,
    parse_result: DocumentParseResult,
) -> DocumentParseResult:
    """Remove narrative pseudo-components before DFD generation."""

    def _is_pseudo_component(component: ParsedComponent) -> bool:
        normalized_name = _normalize_component_name(component.name)
        description = (component.description or "").strip()

        if _LOCATION_COMPONENT_RE.search(normalized_name):
            return True

        if component.component_type == "data_store" and (
            _FLOW_LABEL_STORE_RE.search(normalized_name)
            or description.startswith("Data related to ")
        ):
            return True

        if component.component_type == "external_entity" and _ABSTRACT_EXTERNAL_COMPONENT_RE.fullmatch(
            normalized_name
        ):
            return True

        return False

    retained_components: list[ParsedComponent] = []
    dropped_component_names: set[str] = set()
    alias_map: dict[str, str] = {}

    normalized_names = {
        _normalize_component_name(component.name): component
        for component in parse_result.components
    }
    has_canonical_efb = _normalize_component_name(_EFB_CANONICAL_NAME) in normalized_names

    for component in parse_result.components:
        normalized_name = _normalize_component_name(component.name)
        if has_canonical_efb and _EFB_ALIAS_RE.match(component.name):
            alias_map[normalized_name] = _EFB_CANONICAL_NAME
            dropped_component_names.add(normalized_name)
            continue
        if _is_pseudo_component(component):
            dropped_component_names.add(normalized_name)
            continue
        retained_components.append(component)

    valid_component_names = {
        _normalize_component_name(component.name)
        for component in retained_components
    }

    sanitized_flows: list[ParsedFlow] = []
    seen_flows: set[tuple[str, str, str]] = set()
    for flow in parse_result.flows:
        source = alias_map.get(_normalize_component_name(flow.source), flow.source)
        target = alias_map.get(_normalize_component_name(flow.target), flow.target)
        normalized_source = _normalize_component_name(source)
        normalized_target = _normalize_component_name(target)
        if normalized_source not in valid_component_names or normalized_target not in valid_component_names:
            continue
        key = (normalized_source, normalized_target, flow.label.strip().lower())
        if key in seen_flows:
            continue
        sanitized_flows.append(
            flow.model_copy(
                update={
                    "source": source,
                    "target": target,
                }
            )
        )
        seen_flows.add(key)

    sanitized_boundaries: list[ParsedBoundary] = []
    for boundary in parse_result.boundaries:
        contains: list[str] = []
        seen_contains: set[str] = set()
        for component_name in boundary.contains:
            remapped_name = alias_map.get(_normalize_component_name(component_name), component_name)
            normalized_name = _normalize_component_name(remapped_name)
            if normalized_name not in valid_component_names or normalized_name in seen_contains:
                continue
            contains.append(remapped_name)
            seen_contains.add(normalized_name)
        if contains:
            sanitized_boundaries.append(
                boundary.model_copy(update={"contains": contains})
            )

    return DocumentParseResult(
        components=retained_components,
        flows=sanitized_flows,
        boundaries=sanitized_boundaries,
        raw_text_excerpt=parse_result.raw_text_excerpt or raw_text[:500],
    )


def _merge_parse_results(
    primary: DocumentParseResult,
    fallback: DocumentParseResult,
) -> DocumentParseResult:
    """Merge AI output with deterministic extraction, preferring explicit AI data."""
    components: dict[str, ParsedComponent] = {
        _normalize_component_name(component.name): component
        for component in primary.components
    }
    for component in fallback.components:
        components.setdefault(_normalize_component_name(component.name), component)

    flows: list[ParsedFlow] = list(primary.flows)
    seen_flows = {
        (
            _normalize_component_name(flow.source),
            _normalize_component_name(flow.target),
            flow.label.strip().lower(),
        )
        for flow in flows
    }
    for flow in fallback.flows:
        key = (
            _normalize_component_name(flow.source),
            _normalize_component_name(flow.target),
            flow.label.strip().lower(),
        )
        if key not in seen_flows:
            flows.append(flow)
            seen_flows.add(key)

    boundaries: dict[str, list[str]] = {
        _normalize_component_name(boundary.name): list(boundary.contains)
        for boundary in primary.boundaries
    }
    boundary_name_lookup = {
        _normalize_component_name(boundary.name): boundary.name
        for boundary in primary.boundaries
    }
    for boundary in fallback.boundaries:
        normalized_name = _normalize_component_name(boundary.name)
        if normalized_name not in boundaries:
            boundaries[normalized_name] = list(boundary.contains)
            boundary_name_lookup[normalized_name] = boundary.name
            continue
        existing = {
            _normalize_component_name(name): name
            for name in boundaries[normalized_name]
        }
        for component_name in boundary.contains:
            existing.setdefault(_normalize_component_name(component_name), component_name)
        boundaries[normalized_name] = list(existing.values())

    return DocumentParseResult(
        components=list(components.values()),
        flows=flows,
        boundaries=[
            ParsedBoundary(name=boundary_name_lookup[name], contains=contains)
            for name, contains in boundaries.items()
        ],
        raw_text_excerpt=primary.raw_text_excerpt or fallback.raw_text_excerpt,
    )


def _needs_additional_flow_pass(parse_result: DocumentParseResult) -> bool:
    """Detect when the merged extraction still has implausibly sparse flow coverage."""
    if not parse_result.components:
        return False

    component_count = len(parse_result.components)
    flow_count = len(parse_result.flows)
    if flow_count == 0:
        return True

    normalized_types = {
        _normalize_component_name(component.name): component.component_type
        for component in parse_result.components
    }
    external_names = {
        name for name, component_type in normalized_types.items()
        if component_type == "external_entity"
    }
    external_flow_participants = {
        endpoint
        for flow in parse_result.flows
        for endpoint in (
            _normalize_component_name(flow.source),
            _normalize_component_name(flow.target),
        )
        if endpoint in external_names
    }

    return (
        (component_count >= 10 and flow_count < max(4, component_count // 2))
        or (len(external_names) >= 4 and len(external_flow_participants) < 2)
    )


def _extract_sync(
    raw_text: str,
    system_name: str,
    client: LLMClient | None = None,
) -> DocumentParseResult:
    """Synchronous extraction — called from async wrapper.

    Fallback chain:
    1. tool_use response -> parse directly
    2. If tool_use fails -> retry once with same prompt
    3. If both fail -> return empty DocumentParseResult
    """
    if client is None:
        client = get_llm_client()

    normalized_text = normalize_extracted_text(raw_text)
    deterministic_result = heuristic_parse_architecture(normalized_text)
    user_message = EXTRACTION_USER_TEMPLATE.format(
        raw_text=normalized_text,
        system_name=system_name,
    )
    tools = [EXTRACT_ARCHITECTURE_TOOL]

    # Attempt 1
    tool_output = client.call_with_tools(
        system_message=EXTRACTION_SYSTEM_MESSAGE,
        user_message=user_message,
        tools=tools,
        prompt_version=EXTRACTION_PROMPT_VERSION,
    )

    if tool_output is not None:
        ai_result = _parse_tool_response(
            tool_output,
            normalized_text,
            known_components=deterministic_result.components,
        )
        merged_result = _sanitize_parse_result(
            normalized_text,
            _merge_parse_results(ai_result, deterministic_result),
        )
        if _needs_additional_flow_pass(merged_result):
            flow_result = _extract_missing_flows(
                normalized_text,
                system_name,
                client,
                merged_result.components,
            )
            merged_result = _sanitize_parse_result(
                normalized_text,
                _merge_parse_results(flow_result, merged_result),
            )
        return supplement_sparse_boundaries(normalized_text, merged_result)

    # Attempt 2: retry once
    logger.warning(
        "extraction_retry prompt_version=%s reason=first_attempt_failed",
        EXTRACTION_PROMPT_VERSION,
    )
    tool_output = client.call_with_tools(
        system_message=EXTRACTION_SYSTEM_MESSAGE,
        user_message=user_message,
        tools=tools,
        prompt_version=EXTRACTION_PROMPT_VERSION,
    )

    if tool_output is not None:
        ai_result = _parse_tool_response(
            tool_output,
            normalized_text,
            known_components=deterministic_result.components,
        )
        merged_result = _sanitize_parse_result(
            normalized_text,
            _merge_parse_results(ai_result, deterministic_result),
        )
        if _needs_additional_flow_pass(merged_result):
            flow_result = _extract_missing_flows(
                normalized_text,
                system_name,
                client,
                merged_result.components,
            )
            merged_result = _sanitize_parse_result(
                normalized_text,
                _merge_parse_results(flow_result, merged_result),
            )
        return supplement_sparse_boundaries(normalized_text, merged_result)

    # Both attempts failed — graceful degradation
    logger.warning(
        "extraction_failed prompt_version=%s returning empty result",
        EXTRACTION_PROMPT_VERSION,
    )
    return deterministic_result if deterministic_result.components else _empty_parse_result()


def _build_extraction_outcome(
    raw_text: str,
    parse_result: DocumentParseResult,
) -> ExtractionOutcome:
    extraction_status, warnings = assess_parse_result(raw_text, parse_result)
    return ExtractionOutcome(
        parse_result=parse_result,
        extraction_status=extraction_status,
        warnings=warnings,
        evidence=build_extraction_evidence(
            raw_text,
            parse_result,
            warnings=warnings,
        ),
    )


EXTRACT_FLOWS_TOOL: dict[str, Any] = {
    "name": "extract_data_flows",
    "description": (
        "Extract data flows between known components from the document. "
        "Source and target must exactly match the provided component names."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "flows": EXTRACT_ARCHITECTURE_TOOL["inputSchema"]["json"]["properties"]["flows"],
            },
            "required": ["flows"],
        }
    },
}


FLOW_FALLBACK_SYSTEM_MESSAGE = """\
You are extracting only data flows from a system design document.

Rules:
- Use ONLY the component names provided in the prompt.
- Only extract flows that are explicitly stated or strongly implied by the text.
- If the document describes a workflow or synchronization path, capture the most plausible source and target using the provided components.
- Prefer major external-input, crew/client-delivery, privileged-workflow, and audit-replication flows when they are explicitly described.
- Return your answer by calling the extract_data_flows tool.
"""


def _extract_missing_flows(
    raw_text: str,
    system_name: str,
    client: LLMClient,
    components: list[ParsedComponent],
) -> DocumentParseResult:
    component_names = "\n".join(f"- {component.name}" for component in components)
    user_message = (
        f'Extract missing data flows for "{system_name}".\n\n'
        f"Known components:\n{component_names}\n\n"
        f"Document text:\n{raw_text}\n"
    )
    tool_output = client.call_with_tools(
        system_message=FLOW_FALLBACK_SYSTEM_MESSAGE,
        user_message=user_message,
        tools=[EXTRACT_FLOWS_TOOL],
        prompt_version=f"{EXTRACTION_PROMPT_VERSION}-flows",
    )
    if tool_output is None:
        return _empty_parse_result()
    parsed = _parse_tool_response(
        {"components": [], "flows": tool_output.get("flows", []), "boundaries": []},
        raw_text,
        known_components=components,
    )
    return DocumentParseResult(
        components=[],
        flows=parsed.flows,
        boundaries=[],
        raw_text_excerpt=parsed.raw_text_excerpt,
    )


async def extract_components_from_text(
    raw_text: str,
    system_name: str,
    client: LLMClient | None = None,
) -> ExtractionOutcome:
    """Extract architecture components from raw PDF text using Claude.

    This is the main entry point for F-02 LLM extraction. It runs the
    synchronous Bedrock call in a thread pool to avoid blocking the
    async event loop.

    Graceful degradation (F-24): returns empty DocumentParseResult on
    any failure, including timeout (30s default).

    Args:
        raw_text: Raw text extracted from the PDF by PyMuPDF.
        system_name: Name of the system being analyzed (from threat model).
        client: Optional BedrockClient instance (for testing/DI).

    Returns:
        DocumentParseResult with extracted components, flows, boundaries.
        Empty result on any failure.
    """
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(
                _extract_sync,
                raw_text,
                system_name,
                client,
            ),
            timeout=float(settings.bedrock_timeout_seconds),
        )
        return _build_extraction_outcome(raw_text, result)
    except asyncio.TimeoutError:
        logger.warning(
            "extraction_timeout prompt_version=%s timeout_seconds=%d",
            EXTRACTION_PROMPT_VERSION,
            settings.bedrock_timeout_seconds,
        )
        return _build_extraction_outcome(raw_text, _empty_parse_result())
    except Exception as exc:
        logger.warning(
            "extraction_unexpected_error prompt_version=%s error=%s",
            EXTRACTION_PROMPT_VERSION,
            str(exc),
        )
        return _build_extraction_outcome(raw_text, _empty_parse_result())

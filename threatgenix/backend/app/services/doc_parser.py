"""PDF validation and heuristic architecture extraction helpers."""

import logging
import re
from collections import OrderedDict
from typing import Iterable

import fitz  # PyMuPDF
from fastapi import HTTPException, UploadFile

from app.config import settings
from app.schemas.document import (
    DocumentParseResult,
    ParsedBoundary,
    ParsedComponent,
    ParsedFlow,
)

logger = logging.getLogger(__name__)
_BOUNDARY_HEADER_RE = re.compile(r"^Trust Boundary:\s*(?P<name>.+?)\s*$", re.IGNORECASE)
_CONTAINS_HEADER_RE = re.compile(r"^Contains:\s*$", re.IGNORECASE)
_DATA_FLOWS_HEADER_RE = re.compile(r"^Data Flows?:\s*$", re.IGNORECASE)
_SECURITY_PROPERTIES_HEADER_RE = re.compile(r"^Security Properties:\s*$", re.IGNORECASE)
_SECTION_HEADER_RE = re.compile(r"^[A-Z][A-Za-z0-9 /&()'_-]{2,}:\s*$")
_STRUCTURED_COMPONENT_RE = re.compile(
    r"^-\s+(?P<name>.+?)\s+\[(?P<component_type>[A-Za-z _-]+)\]\s*$"
)
_FLOW_RE = re.compile(
    r"^-\s+(?P<source>.+?)\s*(?:->|→)\s*(?P<target>.+?)\s*:\s*(?P<label>.+?)\s*$"
)
_SECURITY_PROPERTIES_RE = re.compile(
    r"^-\s+(?P<name>.+?)\s*:\s*(?P<properties>.+?)\s*$"
)
_PROPERTY_PAIR_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^,\s]+)")
_NARRATIVE_COMPONENT_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9&/+().-]*(?: (?:[A-Za-z0-9&/+().-]+|\([A-Z0-9]+\))){0,8} "
    r"(?:(?i:gateway|orchestrator|engine|service|connector|ledger|vault|store|repository|archive|"
    r"broker|bus|historian|bastion|host|console|app|user|partner|vendor|technician|operator|analyst|"
    r"platform|database|portal|provider|interface|exchange|forest|client|workspace|pipeline|"
    r"adapter|feed|package|enclave|lake|mirror)))\b"
)
_STRICT_COMPONENT_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9&/+().-]*(?: [A-Z][A-Za-z0-9&/+().-]*){1,6} "
    r"(?:(?i:gateway|orchestrator|engine|service|connector|ledger|vault|store|repository|archive|"
    r"broker|bus|historian|bastion|host|console|app|user|partner|vendor|technician|operator|analyst|"
    r"platform|database|portal|provider|interface|exchange|forest|client|workspace|pipeline|"
    r"adapter|feed|package|enclave|lake|mirror)))\b"
)
_FLOW_HINT_RE = re.compile(
    r"\b(route|routes|through|into|to|from|via|invoke|invokes|send|sends|deliver|delivers|"
    r"receive|receives|upload|uploads|replicate|replicated|replicates|sync|synchronization|"
    r"reaches|reach|pass|passes|handoff|approval|callback)\b",
    re.IGNORECASE,
)
_STRUCTURED_TYPE_RE = re.compile(r"\[(?:[A-Za-z _-]+)\]")
_WORKFLOW_MARKER_RE = re.compile(r"\b(workflow|approval|release|override|repair|callback)\b", re.IGNORECASE)
_SEGMENT_SKIP_MARKER_RE = re.compile(
    r"\b(Trust Boundary:|Contains:|Critical Assets:|Privileged Workflows:|"
    r"Security Properties:|Abuse Cases To Consider:|System Name:|Primary Objective:)\b",
    re.IGNORECASE,
)
_PROCESS_SUFFIXES = {
    "gateway", "orchestrator", "engine", "service", "connector", "broker",
    "bus", "bastion", "host", "console", "platform", "portal", "interface",
    "workspace", "pipeline", "adapter", "exchange",
}
_DATA_STORE_SUFFIXES = {
    "ledger", "vault", "store", "repository", "archive", "database", "db",
    "cache", "queue", "historian", "lake", "mirror",
}
_EXTERNAL_SUFFIXES = {
    "app", "user", "partner", "vendor", "technician", "operator", "analyst",
    "provider", "client", "feed",
}
_HUMAN_ACTOR_SUFFIXES = {"user", "technician", "operator", "analyst"}
_WORKFLOW_SERVICE_NAME_RE = re.compile(r"\b(workflow service|rules and policy engine)\b", re.IGNORECASE)
_CREW_RECOVERY_NAME_RE = re.compile(r"\bcrew recovery\b", re.IGNORECASE)
_MESSAGING_SERVICE_NAME_RE = re.compile(r"\boperational messaging service\b", re.IGNORECASE)
_MESSAGING_PROVIDER_NAME_RE = re.compile(r"\b(acars|satcom messaging)\b", re.IGNORECASE)
_EFB_SYNC_NAME_RE = re.compile(r"\befb sync\b", re.IGNORECASE)
_EFB_CLIENT_NAME_RE = re.compile(r"\b(electronic flight bag|efb client)\b", re.IGNORECASE)
_VENDOR_SUPPORT_NAME_RE = re.compile(r"\b(vendor support|support enclave)\b", re.IGNORECASE)
_MAINTENANCE_CONTROL_NAME_RE = re.compile(r"\bmaintenance control\b", re.IGNORECASE)
_WEATHER_PROVIDER_NAME_RE = re.compile(r"\bweather intelligence provider\b", re.IGNORECASE)
_DISPATCH_RELEASE_NAME_RE = re.compile(r"\bdispatch release service\b", re.IGNORECASE)
_AIRCRAFT_HEALTH_NAME_RE = re.compile(r"\baircraft health feed\b", re.IGNORECASE)
_MRO_VENDOR_NAME_RE = re.compile(r"\bmro vendor system\b", re.IGNORECASE)
_AIRPORT_CDM_NAME_RE = re.compile(r"\bairport cdm feed\b", re.IGNORECASE)
_TURNAROUND_SERVICE_NAME_RE = re.compile(r"\bturnaround coordination service\b", re.IGNORECASE)
_RECORDS_RETENTION_SIGNAL_RE = re.compile(
    r"\b(records retention|retention vault|immutable operational records)\b",
    re.IGNORECASE,
)
_ANALYTICS_WORKLOAD_SIGNAL_RE = re.compile(
    r"\banalytics workloads?\b",
    re.IGNORECASE,
)
_SAFETY_INVESTIGATION_SIGNAL_RE = re.compile(
    r"\b(safety investigation|safety investigators?)\b",
    re.IGNORECASE,
)
_VENDOR_SUPPORT_DIAGNOSTIC_SIGNAL_RE = re.compile(
    r"("
    r"\b(vendor[- ]support|support enclave|vendor support providers?)\b"
    r".{0,120}\b(diagnostic|time-boxed|airline approval|approved|break[- ]glass|urgent issues?)\b"
    r"|"
    r"\b(diagnostic|time-boxed|airline approval|approved|break[- ]glass|urgent issues?)\b"
    r".{0,120}\b(vendor[- ]support|support enclave|vendor support providers?)\b"
    r")",
    re.IGNORECASE | re.DOTALL,
)
_AVIATION_BOUNDARY_SIGNAL_RE = re.compile(
    r"\b(dispatch|maintenance|crew|aircraft|airport|turnaround|efb|acars|flight operations)\b",
    re.IGNORECASE,
)
_SPECIALIZED_BOUNDARY_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "Corporate Identity and Core Records Boundary",
        re.compile(
            r"\b(active directory|federated identity|identity service|privileged access|"
            r"retention vault|records retention|mirror database|safety investigation)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Vendor Support and Security Boundary",
        re.compile(
            r"\b(vendor[- ]support|support enclave|soc|siem|telemetry|monitoring|diagnostic)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Airport and Station Operations Boundary",
        re.compile(
            r"\b(station|ground handlers?|fueling|de-icing|gate|pushback|turnaround|partner apis?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Aircraft and Crew Edge Boundary",
        re.compile(
            r"\b(aircraft|crew|electronic flight bag|efb|acars|satcom|pilot)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "External Aviation Services Boundary",
        re.compile(
            r"\b(weather providers?|flight-plan optimization providers?|airport decision-making "
            r"feed providers?|maintenance data providers?|crew operational messaging providers?|"
            r"airport cdm|civil aviation|border|clearance|mro vendor|regulatory exchange|"
            r"aircraft health feed|weather intelligence provider|flight plan optimization vendor|"
            r"airport cdm feed|civil aviation regulatory exchange|border / crew clearance "
            r"interface|mro vendor system)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "Cloud Operations Platform Boundary",
        re.compile(
            r"\b(api gateway|workflow|dispatch release|crew recovery|maintenance control|"
            r"turnaround coordination|efb sync|operational messaging|audit and decision log|"
            r"operations data lake|analytics workloads?|rules and policy engine|flight operations and maintenance "
            r"control platform)\b",
            re.IGNORECASE,
        ),
    ),
)


def normalize_extracted_text(raw_text: str) -> str:
    """Normalize PyMuPDF output while preserving document structure."""
    text = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("•", "- ").replace("\u2022", "- ")
    text = text.replace("?", "'")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def detect_structure_signals(raw_text: str) -> dict[str, bool]:
    """Detect whether the document contains explicit architecture structure."""
    normalized_text = normalize_extracted_text(raw_text)
    lowered = normalized_text.lower()
    return {
        "has_trust_boundaries": "trust boundary:" in lowered,
        "has_data_flows": "data flow:" in lowered or "data flows:" in lowered,
        "has_security_properties": "security properties:" in lowered,
        "has_workflow_markers": bool(_WORKFLOW_MARKER_RE.search(normalized_text)),
        "has_typed_components": bool(_STRUCTURED_TYPE_RE.search(normalized_text)),
    }


def assess_parse_result(
    raw_text: str,
    parse_result: DocumentParseResult,
) -> tuple[str, list[str]]:
    """Classify extraction quality and emit user-facing warnings."""
    signals = detect_structure_signals(raw_text)
    warnings: list[str] = []

    if signals["has_trust_boundaries"] and not parse_result.boundaries:
        warnings.append(
            "The document describes trust boundaries, but none were extracted."
        )
    if (
        signals["has_data_flows"]
        or signals["has_workflow_markers"]
        or signals["has_typed_components"]
    ) and not parse_result.flows:
        warnings.append(
            "No data flows were extracted; threat coverage will be limited until the DFD is repaired."
        )
    if len(parse_result.components) >= 4 and not parse_result.boundaries:
        warnings.append(
            "No trust boundaries were modeled; boundary-crossing threats may be under-reported."
        )
    if len(parse_result.components) >= 8 and len(parse_result.flows) <= 1:
        warnings.append(
            "Very few data flows were extracted relative to the number of components; the DFD is likely incomplete."
        )
    if len(parse_result.components) >= 12 and len(parse_result.boundaries) <= 1:
        warnings.append(
            "Very few trust boundaries were extracted relative to the number of components; trust-zone coverage is likely incomplete."
        )

    return ("partial" if warnings else "complete"), warnings


def _canonical_component_type(raw_type: str) -> str | None:
    normalized = raw_type.strip().lower()
    normalized = normalized.replace("-", " ").replace("_", " ")
    normalized = re.sub(r"\s+", " ", normalized)
    if normalized in {"process", "service", "application"}:
        return "process"
    if normalized in {"data store", "datastore", "database", "storage"}:
        return "data_store"
    if normalized in {"human actor", "human", "actor"}:
        return "human_actor"
    if normalized in {"external entity", "external", "entity"}:
        return "external_entity"
    if normalized == "user":
        return "human_actor"
    return None


def _normalize_component_name(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip().lower())


def normalize_flow_label(label: str) -> str:
    """Strip PDF and bullet artifacts from a flow label."""
    cleaned = label.replace("\n", " ").strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    cleaned = re.sub(r"^[>\-:;|/\\\s]+", "", cleaned)
    cleaned = cleaned.strip(" .,:;|-")
    return cleaned or "inferred workflow"


def _infer_component_type(name: str) -> str:
    last_token = name.split()[-1].lower()
    if last_token in _DATA_STORE_SUFFIXES:
        return "data_store"
    if last_token in _HUMAN_ACTOR_SUFFIXES:
        return "human_actor"
    if last_token in _EXTERNAL_SUFFIXES:
        return "external_entity"
    if last_token in _PROCESS_SUFFIXES:
        return "process"
    return "process"


def _iter_candidate_segments(normalized_text: str) -> Iterable[str]:
    seen: set[str] = set()
    for raw_line in normalized_text.splitlines():
        line = raw_line.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        yield line

    for paragraph in normalized_text.split("\n\n"):
        paragraph_text = re.sub(r"\s+", " ", paragraph).strip()
        if len(paragraph_text) < 12:
            continue
        for segment in re.split(r"(?<=[.!?])\s+", paragraph_text):
            candidate = segment.strip()
            if len(candidate) < 12 or candidate in seen:
                continue
            seen.add(candidate)
            yield candidate


def _find_component_mentions(
    text: str,
    component_names: list[str],
) -> list[str]:
    matches: list[tuple[int, int, str]] = []
    occupied: list[tuple[int, int]] = []
    lowered = text.lower()

    for name in sorted(component_names, key=len, reverse=True):
        pattern = re.compile(re.escape(name), re.IGNORECASE)
        match = pattern.search(lowered)
        if not match:
            continue
        start, end = match.span()
        if any(not (end <= occ_start or start >= occ_end) for occ_start, occ_end in occupied):
            continue
        matches.append((start, end, name))
        occupied.append((start, end))

    matches.sort(key=lambda item: item[0])
    ordered: list[str] = []
    seen_names: set[str] = set()
    for _, _, name in matches:
        if name not in seen_names:
            ordered.append(name)
            seen_names.add(name)
    return ordered


def _looks_like_component_name(name: str) -> bool:
    cleaned = name.strip().strip(".,:;")
    cleaned = re.sub(r"^(The|A|An)\s+", "", cleaned)
    tokens = cleaned.split()
    if len(tokens) < 2:
        return False
    uppercase_tokens = sum(
        1
        for token in tokens
        if (token[:1].isupper() and any(char.isalpha() for char in token))
        or (token.startswith("(") and token.endswith(")") and token[1:-1].isupper())
    )
    lowercase_tokens = sum(
        1
        for token in tokens
        if token.islower() and token not in {"and", "of", "for", "the"}
    )
    return uppercase_tokens >= 2 and lowercase_tokens <= 2


def _component_name_uppercase_score(name: str) -> int:
    tokens = name.split()
    return sum(
        1
        for token in tokens
        if (token[:1].isupper() and any(char.isalpha() for char in token))
        or (token.startswith("(") and token.endswith(")") and token[1:-1].isupper())
    )


def _sanitize_component_candidate(name: str) -> str | None:
    cleaned = re.sub(r"\s+", " ", name.strip().strip(".,:;"))
    tokens = cleaned.split()
    candidates: list[str] = []
    for start in range(len(tokens)):
        candidate = " ".join(tokens[start:]).strip(".,:;")
        candidate = re.sub(r"^(The|A|An)\s+", "", candidate)
        if any(marker in candidate for marker in [".", ";", ":"]):
            continue
        if _looks_like_component_name(candidate):
            candidates.append(candidate)
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda candidate: (
            _component_name_uppercase_score(candidate),
            -len(candidate.split()),
        ),
    )


def _derive_flow_label(segment: str, component_names: list[str]) -> str:
    label = segment
    for component_name in component_names:
        label = re.sub(re.escape(component_name), "", label, flags=re.IGNORECASE)
    label = normalize_flow_label(label)
    if len(label) > 120:
        label = label[:117].rstrip() + "..."
    return label or "inferred workflow"


def _find_component_name(
    components: "OrderedDict[str, ParsedComponent]",
    pattern: re.Pattern[str],
) -> str | None:
    for component in components.values():
        if pattern.search(component.name):
            return component.name
    return None


def _ensure_narrative_anchor_components(
    normalized_text: str,
    components: "OrderedDict[str, ParsedComponent]",
) -> None:
    """Recover domain anchors that often appear in narrative form without capitalization."""
    lowered_text = normalized_text.lower()

    def _ensure_component(
        name: str,
        component_type: str,
        *,
        confidence: float,
        description: str,
    ) -> None:
        normalized_name = _normalize_component_name(name)
        if normalized_name in components:
            return
        components[normalized_name] = ParsedComponent(
            name=name,
            component_type=component_type,
            confidence=confidence,
            description=description,
        )

    if _RECORDS_RETENTION_SIGNAL_RE.search(normalized_text):
        _ensure_component(
            "Records Retention Vault",
            "data_store",
            confidence=0.74,
            description="Recovered from narrative references to records retention and immutable operational records.",
        )

    if _SAFETY_INVESTIGATION_SIGNAL_RE.search(normalized_text):
        _ensure_component(
            "Safety Investigation Workspace",
            "process",
            confidence=0.7,
            description="Recovered from narrative references to safety investigation workflows.",
        )

    if (
        _AVIATION_BOUNDARY_SIGNAL_RE.search(normalized_text)
        and _VENDOR_SUPPORT_DIAGNOSTIC_SIGNAL_RE.search(normalized_text)
    ):
        _ensure_component(
            "Vendor Support Enclave",
            "external_entity",
            confidence=0.69,
            description="Recovered from narrative references to vendor support joining time-boxed or diagnostic aviation workflows.",
        )

    if _ANALYTICS_WORKLOAD_SIGNAL_RE.search(normalized_text) and (
        "system-of-record" in lowered_text
        or "operational" in lowered_text
        or _AVIATION_BOUNDARY_SIGNAL_RE.search(normalized_text)
    ):
        _ensure_component(
            "Analytics Workloads",
            "process",
            confidence=0.68,
            description="Recovered from narrative references to analytics workloads attached to the operational control platform.",
        )


def _infer_structured_operational_flows(
    normalized_text: str,
    components: "OrderedDict[str, ParsedComponent]",
) -> list[ParsedFlow]:
    """Recover strongly implied operational flows from structured sections."""
    lowered = normalized_text.lower()
    flows: list[ParsedFlow] = []
    seen: set[tuple[str, str, str]] = set()

    def _append(source: str | None, target: str | None, label: str, confidence: float) -> None:
        if not source or not target:
            return
        normalized_label = normalize_flow_label(label)
        key = (
            _normalize_component_name(source),
            _normalize_component_name(target),
            normalized_label.lower(),
        )
        if key in seen:
            return
        flows.append(
            ParsedFlow(
                source=source,
                target=target,
                label=normalized_label,
                confidence=confidence,
                data_types=[],
            )
        )
        seen.add(key)

    workflow_service = _find_component_name(components, _WORKFLOW_SERVICE_NAME_RE)
    crew_recovery = _find_component_name(components, _CREW_RECOVERY_NAME_RE)
    if crew_recovery and (
        "crew recovery manager reassigns pairings" in lowered
        or ("crew legality" in lowered and "disruption" in lowered)
    ):
        _append(workflow_service, crew_recovery, "disruption recovery action", 0.72)

    messaging_service = _find_component_name(components, _MESSAGING_SERVICE_NAME_RE)
    messaging_provider = _find_component_name(components, _MESSAGING_PROVIDER_NAME_RE)
    if messaging_service and messaging_provider and (
        "provider handoff acknowledgements" in lowered
        or ("acars" in lowered and "messaging" in lowered)
    ):
        _append(
            messaging_service,
            messaging_provider,
            "provider handoff acknowledgement",
            0.74,
        )

    efb_sync = _find_component_name(components, _EFB_SYNC_NAME_RE)
    efb_client = _find_component_name(components, _EFB_CLIENT_NAME_RE)
    if efb_sync and efb_client and "signed package manifest required before client synchronization" in lowered:
        _append(efb_sync, efb_client, "signed package manifest", 0.72)

    vendor_support = _find_component_name(components, _VENDOR_SUPPORT_NAME_RE)
    maintenance_control = _find_component_name(components, _MAINTENANCE_CONTROL_NAME_RE)
    if vendor_support and maintenance_control and "diagnostic access" in lowered:
        _append(vendor_support, maintenance_control, "diagnostic access request", 0.73)

    weather_provider = _find_component_name(components, _WEATHER_PROVIDER_NAME_RE)
    dispatch_release = _find_component_name(components, _DISPATCH_RELEASE_NAME_RE)
    if weather_provider and dispatch_release and "weather" in lowered:
        _append(weather_provider, dispatch_release, "weather and NOTAM package", 0.7)

    aircraft_health = _find_component_name(components, _AIRCRAFT_HEALTH_NAME_RE)
    if aircraft_health and maintenance_control and (
        "health-feed" in lowered
        or "aircraft status" in lowered
        or "health monitoring" in lowered
        or "health feed" in lowered
    ):
        _append(aircraft_health, maintenance_control, "aircraft health alert", 0.71)

    mro_vendor = _find_component_name(components, _MRO_VENDOR_NAME_RE)
    if mro_vendor and maintenance_control and ("mro" in lowered or "maintenance vendor" in lowered):
        _append(mro_vendor, maintenance_control, "maintenance recommendation upload", 0.71)

    airport_cdm = _find_component_name(components, _AIRPORT_CDM_NAME_RE)
    turnaround_service = _find_component_name(components, _TURNAROUND_SERVICE_NAME_RE)
    if airport_cdm and turnaround_service and (
        "turnaround readiness" in lowered
        or "airport milestone" in lowered
        or "cdm" in lowered
    ):
        _append(airport_cdm, turnaround_service, "airport milestone update", 0.69)

    return flows


def _infer_flows_from_text(
    normalized_text: str,
    components: "OrderedDict[str, ParsedComponent]",
) -> list[ParsedFlow]:
    component_names = [component.name for component in components.values()]
    if len(component_names) < 2:
        return []

    flows: list[ParsedFlow] = []
    seen: set[tuple[str, str, str]] = set()

    for segment in _iter_candidate_segments(normalized_text):
        lowered_segment = segment.lower()
        if (
            _SEGMENT_SKIP_MARKER_RE.search(segment)
            or _STRUCTURED_TYPE_RE.search(segment)
            or "security properties" in lowered_segment
            or "privileged workflows" in lowered_segment
            or "critical assets" in lowered_segment
        ):
            continue
        if "->" in segment or "→" in segment:
            continue
        if segment.startswith("- ") and "->" not in segment and "replicated to" not in segment.lower():
            continue
        if not _FLOW_HINT_RE.search(segment):
            continue
        mentions = _find_component_mentions(segment, component_names)
        if len(mentions) < 2:
            continue
        if len(mentions) > 4 and "->" not in segment and "replicated to" not in segment.lower():
            continue
        label = _derive_flow_label(segment, mentions)
        for source_name, target_name in zip(mentions, mentions[1:]):
            key = (
                _normalize_component_name(source_name),
                _normalize_component_name(target_name),
                label.lower(),
            )
            if key in seen:
                continue
            flows.append(
                ParsedFlow(
                    source=source_name,
                    target=target_name,
                    label=label,
                    confidence=0.58,
                    data_types=[],
                )
            )
            seen.add(key)
    return flows


def _infer_boundaries_from_components(
    components: "OrderedDict[str, ParsedComponent]",
) -> list[ParsedBoundary]:
    if not components:
        return []

    external_names = [
        component.name
        for component in components.values()
        if component.component_type == "external_entity"
    ]
    process_names = [
        component.name
        for component in components.values()
        if component.component_type == "process"
    ]
    store_names = [
        component.name
        for component in components.values()
        if component.component_type == "data_store"
    ]

    boundaries: list[ParsedBoundary] = []
    if external_names:
        boundaries.append(
            ParsedBoundary(name="External Edge", contains=external_names)
        )
    if process_names:
        boundaries.append(
            ParsedBoundary(name="Application Control Plane", contains=process_names)
        )
    if store_names:
        boundaries.append(
            ParsedBoundary(name="Restricted Data Zone", contains=store_names)
        )
    return boundaries


def _boundary_component_names(boundaries: list[ParsedBoundary]) -> set[str]:
    return {
        _normalize_component_name(component_name)
        for boundary in boundaries
        for component_name in boundary.contains
    }


def _should_supplement_boundaries(
    components: list[ParsedComponent],
    boundaries: list[ParsedBoundary],
) -> bool:
    if not components:
        return False
    if not boundaries:
        return True

    component_count = len(components)
    if component_count < 6:
        return False

    covered_component_count = len(
        _boundary_component_names(boundaries)
        & {_normalize_component_name(component.name) for component in components}
    )
    coverage_ratio = covered_component_count / component_count if component_count else 1.0
    if coverage_ratio < 0.75:
        return True
    if component_count >= 12 and len(boundaries) <= 1:
        return True
    return False


def _append_boundary_members(
    boundary_members: "OrderedDict[str, list[str]]",
    boundary_name: str,
    component_names: list[str],
    covered_components: set[str],
) -> None:
    is_new_boundary = boundary_name not in boundary_members
    existing_members = boundary_members.setdefault(boundary_name, [])
    existing_lookup = {
        _normalize_component_name(component_name): component_name
        for component_name in existing_members
    }

    additions: list[str] = []
    for component_name in component_names:
        normalized_name = _normalize_component_name(component_name)
        if normalized_name in covered_components or normalized_name in existing_lookup:
            continue
        additions.append(component_name)
        existing_lookup[normalized_name] = component_name

    if is_new_boundary and len(additions) < 2:
        return

    if additions:
        existing_members.extend(additions)
        covered_components.update(
            _normalize_component_name(component_name) for component_name in additions
        )


def supplement_sparse_boundaries(
    raw_text: str,
    parse_result: DocumentParseResult,
) -> DocumentParseResult:
    """Add inferred trust boundaries when component coverage is obviously sparse."""
    if not _should_supplement_boundaries(
        parse_result.components,
        parse_result.boundaries,
    ):
        return parse_result

    boundary_members: "OrderedDict[str, list[str]]" = OrderedDict(
        (
            boundary.name,
            list(
                OrderedDict.fromkeys(
                    component_name for component_name in boundary.contains if component_name
                )
            ),
        )
        for boundary in parse_result.boundaries
        if boundary.contains
    )
    covered_components = _boundary_component_names(parse_result.boundaries)
    normalized_text = normalize_extracted_text(raw_text)

    if _AVIATION_BOUNDARY_SIGNAL_RE.search(normalized_text):
        for boundary_name, pattern in _SPECIALIZED_BOUNDARY_RULES:
            matched_components = [
                component.name
                for component in parse_result.components
                if pattern.search(component.name)
            ]
            _append_boundary_members(
                boundary_members,
                boundary_name,
                matched_components,
                covered_components,
            )

    remaining_components: "OrderedDict[str, ParsedComponent]" = OrderedDict(
        (
            _normalize_component_name(component.name),
            component,
        )
        for component in parse_result.components
        if _normalize_component_name(component.name) not in covered_components
    )
    for inferred_boundary in _infer_boundaries_from_components(remaining_components):
        _append_boundary_members(
            boundary_members,
            inferred_boundary.name,
            inferred_boundary.contains,
            covered_components,
        )

    return parse_result.model_copy(
        update={
            "boundaries": [
                ParsedBoundary(name=boundary_name, contains=contains)
                for boundary_name, contains in boundary_members.items()
                if contains
            ]
        }
    )


def heuristic_parse_architecture(raw_text: str) -> DocumentParseResult:
    """Deterministically extract architecture hints from structured text."""
    normalized_text = normalize_extracted_text(raw_text)
    lines = [line.strip() for line in normalized_text.splitlines()]

    components: "OrderedDict[str, ParsedComponent]" = OrderedDict()
    boundaries: "OrderedDict[str, list[str]]" = OrderedDict()
    flows: list[ParsedFlow] = []
    component_properties: dict[str, list[str]] = {}

    current_boundary: str | None = None
    in_contains_block = False
    in_flow_block = False
    in_properties_block = False

    def _ensure_component(
        name: str,
        component_type: str,
        *,
        confidence: float,
        description: str,
    ) -> None:
        normalized_name = _normalize_component_name(name)
        if normalized_name in components:
            return
        components[normalized_name] = ParsedComponent(
            name=name,
            component_type=component_type,
            confidence=confidence,
            description=description,
        )

    for line in lines:
        if not line:
            in_contains_block = False
            continue

        boundary_match = _BOUNDARY_HEADER_RE.match(line)
        if boundary_match:
            current_boundary = boundary_match.group("name").strip()
            boundaries.setdefault(current_boundary, [])
            in_contains_block = False
            in_flow_block = False
            in_properties_block = False
            continue

        if _CONTAINS_HEADER_RE.match(line) and current_boundary is not None:
            in_contains_block = True
            in_flow_block = False
            in_properties_block = False
            continue

        if _DATA_FLOWS_HEADER_RE.match(line):
            in_flow_block = True
            in_contains_block = False
            in_properties_block = False
            current_boundary = None
            continue

        if _SECURITY_PROPERTIES_HEADER_RE.match(line):
            in_properties_block = True
            in_flow_block = False
            in_contains_block = False
            current_boundary = None
            continue

        if _SECTION_HEADER_RE.match(line):
            in_contains_block = False
            in_flow_block = False
            in_properties_block = False

        component_match = _STRUCTURED_COMPONENT_RE.match(line)
        if in_contains_block and component_match:
            name = component_match.group("name").strip()
            raw_type = component_match.group("component_type")
            component_type = _canonical_component_type(raw_type) or _infer_component_type(name)
            _ensure_component(
                name,
                component_type,
                confidence=0.98,
                description="Extracted from structured trust boundary section.",
            )
            if current_boundary is not None:
                boundaries.setdefault(current_boundary, [])
                if name not in boundaries[current_boundary]:
                    boundaries[current_boundary].append(name)
            continue

        if component_match and not in_properties_block:
            name = component_match.group("name").strip()
            raw_type = component_match.group("component_type")
            component_type = _canonical_component_type(raw_type) or _infer_component_type(name)
            _ensure_component(
                name,
                component_type,
                confidence=0.95,
                description="Extracted from structured architecture section.",
            )
            continue

        if in_contains_block:
            component_match = _STRUCTURED_COMPONENT_RE.match(line)
            if component_match and current_boundary is not None:
                name = component_match.group("name").strip()
                component_type = _canonical_component_type(
                    component_match.group("component_type")
                ) or _infer_component_type(name)
                _ensure_component(
                    name,
                    component_type,
                    confidence=0.98,
                    description="Extracted from structured trust boundary section.",
                )
                if name not in boundaries[current_boundary]:
                    boundaries[current_boundary].append(name)
            continue

        if in_flow_block:
            flow_match = _FLOW_RE.match(line)
            if flow_match:
                flows.append(
                    ParsedFlow(
                        source=flow_match.group("source").strip(),
                        target=flow_match.group("target").strip(),
                        label=normalize_flow_label(flow_match.group("label")),
                        confidence=0.97,
                        data_types=[],
                    )
                )
            continue

        if in_properties_block:
            prop_match = _SECURITY_PROPERTIES_RE.match(line)
            if prop_match:
                name = prop_match.group("name").strip()
                properties = [
                    f"{key}={value}"
                    for key, value in _PROPERTY_PAIR_RE.findall(prop_match.group("properties"))
                ]
                if properties:
                    component_properties.setdefault(name, []).extend(properties)
            continue

    for flow in flows:
        for endpoint in (flow.source, flow.target):
            _ensure_component(
                endpoint,
                _infer_component_type(endpoint),
                confidence=0.9,
                description="Inferred from structured data flow section.",
            )

    for segment in _iter_candidate_segments(normalized_text):
        lowered_segment = segment.lower()
        if (
            _SEGMENT_SKIP_MARKER_RE.search(segment)
            or _STRUCTURED_TYPE_RE.search(segment)
            or "security properties" in lowered_segment
        ):
            continue
        for pattern in (_STRICT_COMPONENT_RE, _NARRATIVE_COMPONENT_RE):
            for match in pattern.finditer(segment):
                name = _sanitize_component_candidate(match.group(1))
                if name is None:
                    continue
                _ensure_component(
                    name,
                    _infer_component_type(name),
                    confidence=0.62,
                    description="Heuristically inferred from narrative document text.",
                )

    _ensure_narrative_anchor_components(normalized_text, components)

    inferred_flows = _infer_flows_from_text(normalized_text, components)
    seen_flow_keys = {
        (
            _normalize_component_name(flow.source),
            _normalize_component_name(flow.target),
            flow.label.lower(),
        )
        for flow in flows
    }
    for flow in inferred_flows:
        key = (
            _normalize_component_name(flow.source),
            _normalize_component_name(flow.target),
            flow.label.lower(),
        )
        if key not in seen_flow_keys:
            flows.append(flow)
            seen_flow_keys.add(key)

    structured_inferred_flows = _infer_structured_operational_flows(
        normalized_text,
        components,
    )
    for flow in structured_inferred_flows:
        key = (
            _normalize_component_name(flow.source),
            _normalize_component_name(flow.target),
            flow.label.lower(),
        )
        if key not in seen_flow_keys:
            flows.append(flow)
            seen_flow_keys.add(key)

    for normalized_name, component in list(components.items()):
        properties = component_properties.get(component.name)
        if properties:
            components[normalized_name] = component.model_copy(
                update={"description": f"{component.description} Properties: {', '.join(properties)}"}
            )

    parsed_boundaries = [
        ParsedBoundary(name=boundary_name, contains=contains)
        for boundary_name, contains in boundaries.items()
        if contains
    ]
    if not parsed_boundaries:
        parsed_boundaries = _infer_boundaries_from_components(components)

    return supplement_sparse_boundaries(
        normalized_text,
        DocumentParseResult(
            components=list(components.values()),
            flows=flows,
            boundaries=parsed_boundaries,
            raw_text_excerpt=normalized_text[:500],
        ),
    )


async def validate_pdf(file: UploadFile) -> tuple[bytes, int]:
    """Validate uploaded file is a PDF with 1..pdf_max_pages pages.

    Returns:
        Tuple of (file_bytes, page_count).

    Raises:
        HTTPException(400) if file is not a valid PDF, has 0 pages,
        or exceeds the configured page limit.
    """
    pdf_bytes = await file.read()

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception:
        raise HTTPException(status_code=400, detail="File is not a valid PDF.")

    page_count = doc.page_count
    doc.close()

    if page_count == 0:
        raise HTTPException(status_code=400, detail="PDF has no pages.")

    if page_count > settings.pdf_max_pages:
        raise HTTPException(
            status_code=400,
            detail=f"PDF exceeds maximum of {settings.pdf_max_pages} pages (got {page_count}).",
        )

    logger.info("pdf_validated filename=%s pages=%d", file.filename, page_count)
    return pdf_bytes, page_count


def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    """Extract text from all pages of a PDF.

    Returns:
        Concatenated text from all pages, separated by newlines.
    """
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    pages_text = []
    for page in doc:
        pages_text.append(page.get_text())
    doc.close()
    return "\n".join(pages_text)

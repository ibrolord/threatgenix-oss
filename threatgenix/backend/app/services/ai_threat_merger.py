"""B22 AI Threat Merger: Merges AI enhancement output with rule-based threats.

Takes the AI enhancement output (new threats + enrichments) and merges it with
existing rule-based threats to produce a single unified threat list.

The AI pass is ADDITIVE only -- it cannot remove or override rules engine threats.
Enrichments annotate existing threats with AI insights but do not change severity.
"""

from __future__ import annotations

import logging
import re

from app.schemas.ai_pass import AIPassOutput, AIThreatRaw
from app.schemas.dfd import DFDNodeResponse
from app.schemas.rules import GeneratedThreat, RuleEngineOutput

logger = logging.getLogger(__name__)
_WHITESPACE_RE = re.compile(r"\s+")
_FREEFORM_CONTROL_CITATION_RE = re.compile(
    r"\s*\((?:Req(?:uirement)?\s*[\d.]+|§\s*[\d.]+|Principle\s+\d+)[^)]*\)"
)
_INLINE_CONTROL_CITATION_RE = re.compile(
    r"\b(?:Req(?:uirement)?\s*[\d.]+|§\s*[\d.]+|Principle\s+\d+)\b"
)


def build_node_name_map(dfd_nodes: list[DFDNodeResponse]) -> dict[str, str]:
    """Build name->id map for resolving AI node references.

    Uses normalized matching (lowercase, stripped) since the AI may use
    slightly different casing than the original DFD node names.
    """
    return {node.name.lower().strip(): str(node.id) for node in dfd_nodes}


def _resolve_node_ids(
    ai_threat: AIThreatRaw,
    node_name_to_id: dict[str, str],
) -> list[str]:
    """Extract node IDs from a description by checking for known node names.

    Prefer the structured affected_node_names returned by the model. If those
    are absent or incomplete, fall back to scanning the description text.
    """
    found: list[str] = []
    for name in ai_threat.affected_node_names:
        node_id = node_name_to_id.get(name.lower().strip())
        if node_id and node_id not in found:
            found.append(node_id)

    description_lower = ai_threat.description.lower()
    for name_lower, node_id in node_name_to_id.items():
        if name_lower in description_lower and node_id not in found:
            found.append(node_id)
    return found


def _referenced_boundaries(text: str, boundary_names: set[str] | None) -> set[str]:
    if not boundary_names:
        return set()
    text_lower = text.lower()
    return {
        boundary_name
        for boundary_name in boundary_names
        if boundary_name.lower() in text_lower
    }


def _referenced_node_ids_in_text(
    text: str,
    node_name_to_id: dict[str, str],
) -> set[str]:
    text_lower = text.lower()
    return {
        node_id
        for name_lower, node_id in node_name_to_id.items()
        if name_lower in text_lower
    }


def _normalize_ai_insight(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text.strip()).casefold()


def _strip_unstructured_control_citations(text: str) -> str:
    cleaned = _FREEFORM_CONTROL_CITATION_RE.sub("", text)
    cleaned = _INLINE_CONTROL_CITATION_RE.sub("", cleaned)
    return _WHITESPACE_RE.sub(" ", cleaned).strip(" ,.;:")


def _append_ai_insight(
    existing_rationale: str | None,
    ai_insight: str,
) -> str | None:
    current = (existing_rationale or "").strip()
    candidate = ai_insight.strip()

    if not current:
        return f"[AI Insight] {candidate}" if candidate else None
    if not candidate:
        return current

    normalized_candidate = _normalize_ai_insight(candidate)
    existing_insights = [
        _normalize_ai_insight(part)
        for part in current.split("[AI Insight]")[1:]
        if part.strip()
    ]
    if normalized_candidate in existing_insights:
        return current

    return f"{current}\n\n[AI Insight] {candidate}"


def _is_duplicate(
    ai_threat: AIThreatRaw,
    existing_threats: list[GeneratedThreat],
    ai_node_ids: list[str],
) -> bool:
    """Check if an AI threat duplicates an existing rule threat.

    Heuristic: same stride_category AND at least one overlapping
    affected_node_id -> likely duplicate -> skip.
    """
    for existing in existing_threats:
        if existing.stride_category != ai_threat.stride_category:
            continue
        existing_node_set = set(existing.affected_node_ids)
        if existing_node_set & set(ai_node_ids):
            return True
    return False


def merge_ai_threats(
    rules_output: RuleEngineOutput,
    ai_output: AIPassOutput,
    node_name_to_id: dict[str, str],
    boundary_names: set[str] | None = None,
    node_id_to_provider_managed: dict[str, bool] | None = None,
) -> list[GeneratedThreat]:
    """Merge AI-discovered threats with existing rule threats.

    Returns the full list: original rule threats + new AI threats.
    AI threats get new display_ids continuing from where rules left off.

    Args:
        rules_output: Output from the deterministic rules engine.
        ai_output: Output from the AI enhancement pass.
        node_name_to_id: Mapping of normalized (lowercase, stripped) node
            names to node IDs for resolving affected_node_ids.
        node_id_to_provider_managed: Mapping of node ID to whether that node
            is provider-managed. Used to propagate the flag to AI-discovered
            threats.
    """
    _pm_lookup: dict[str, bool] = node_id_to_provider_managed or {}
    # Start with copies of all rule threats so we can mutate enriched ones
    merged: list[GeneratedThreat] = [t.model_copy() for t in rules_output.threats]

    if not ai_output.threats:
        return merged

    # Separate new threats from enrichments
    new_threats: list[AIThreatRaw] = []
    enrichments: list[AIThreatRaw] = []
    for t in ai_output.threats:
        if t.enhances_rule_threat_id is not None:
            enrichments.append(t)
        else:
            new_threats.append(t)

    # --- Process enrichments ---
    # Build a lookup by display_id for O(1) access
    display_id_to_idx: dict[str, int] = {
        t.display_id: i for i, t in enumerate(merged)
    }

    for enrichment in enrichments:
        idx = display_id_to_idx.get(enrichment.enhances_rule_threat_id)  # type: ignore[arg-type]
        if idx is None:
            # No matching rule threat -- skip gracefully
            continue
        target = merged[idx]
        target_boundaries = _referenced_boundaries(target.description, boundary_names)
        enrichment_boundaries = _referenced_boundaries(
            f"{enrichment.description} {enrichment.reasoning}",
            boundary_names,
        )
        if (
            enrichment_boundaries
            and enrichment_boundaries != target_boundaries
        ):
            logger.warning(
                "ai_enrichment_boundary_mismatch: skipping enrichment %s due to boundary mismatch %s vs %s",
                enrichment.enhances_rule_threat_id,
                sorted(target_boundaries),
                sorted(enrichment_boundaries),
            )
            continue
        referenced_node_ids = _referenced_node_ids_in_text(
            f"{enrichment.description} {enrichment.reasoning}",
            node_name_to_id,
        )
        if referenced_node_ids and not referenced_node_ids.issubset(set(target.affected_node_ids)):
            logger.warning(
                "ai_enrichment_node_mismatch: skipping enrichment %s due to unrelated nodes %s",
                enrichment.enhances_rule_threat_id,
                sorted(referenced_node_ids - set(target.affected_node_ids)),
            )
            continue

        existing_rationale = (target.relevance_rationale or "").strip()
        ai_insight_parts = [
            _strip_unstructured_control_citations(part)
            for part in [enrichment.description, enrichment.reasoning]
            if part and part.strip()
        ]
        ai_insight = " ".join(ai_insight_parts)
        updated_rationale = _append_ai_insight(existing_rationale, ai_insight)
        merged[idx] = target.model_copy(
            update={
                "source": "AI+Rules",
                "relevance_rationale": updated_rationale,
            }
        )

    # --- Process new AI threats ---
    # Determine starting display_id number
    existing_display_nums: list[int] = []
    for t in merged:
        # Parse "T-NNN" format
        try:
            num = int(t.display_id.split("-", 1)[1])
            existing_display_nums.append(num)
        except (IndexError, ValueError):
            pass
    next_display_num = max(existing_display_nums, default=0) + 1

    ai_counter = 1
    for ai_threat in new_threats:
        node_ids = _resolve_node_ids(ai_threat, node_name_to_id)

        if not node_ids:
            logger.warning(
                "ai_threat_no_matching_nodes: AI threat '%s' does not reference "
                "any known DFD node names. Available nodes: %s",
                ai_threat.description[:80],
                ", ".join(node_name_to_id.keys()),
            )

        if _is_duplicate(ai_threat, rules_output.threats, node_ids):
            continue

        # Extract title from description if it follows the "Title: rest" format
        # produced by _parse_enhancement_response
        if ": " in ai_threat.description:
            threat_subtype = ai_threat.description.split(": ", 1)[0]
        else:
            threat_subtype = ai_threat.description[:80]

        merged.append(
            GeneratedThreat(
                rule_id=f"AI-{ai_counter:03d}",
                display_id=f"T-{next_display_num:03d}",
                stride_category=ai_threat.stride_category,
                threat_subtype=threat_subtype,
                severity=ai_threat.severity,
                description=ai_threat.description,
                affected_node_ids=node_ids,
                affected_edge_ids=[],
                relevance_rationale=ai_threat.relevance_rationale,
                source="AI",
                provider_managed=any(_pm_lookup.get(nid, False) for nid in node_ids),
            )
        )
        ai_counter += 1
        next_display_num += 1

    return merged

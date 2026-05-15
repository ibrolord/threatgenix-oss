"""DFD generation service (Blocks 8 + 9).

Converts a DocumentParseResult into DFD database records:
DFDNode, DFDEdge, TrustBoundary. Includes name normalization
for robust node resolution (WORRY-1).
"""

import logging
import re
from typing import Optional
from uuid import UUID

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.schemas.document import DocumentParseResult
from app.services.dfd_layout import compute_layout

logger = logging.getLogger(__name__)


# ─── Block 8: Name Normalization ────────────────────────────────────


def normalize_name(name: str) -> str:
    """Lowercase, strip, remove hyphens/underscores, collapse whitespace."""
    name = name.lower().strip()
    name = name.replace("-", " ").replace("_", " ")
    name = re.sub(r"\s+", " ", name)
    return name


def resolve_node_by_name(name: str, nodes: dict[str, UUID]) -> Optional[UUID]:
    """Find node UUID by normalized name. Returns None if no match."""
    normalized = normalize_name(name)
    return nodes.get(normalized)


# ─── Block 9: DFD Generation ────────────────────────────────────────


async def generate_dfd_from_parse_result(
    db: AsyncSession,
    threat_model_id: UUID,
    parse_result: DocumentParseResult,
) -> DFDResponse:
    """Generate DFD records from a DocumentParseResult.

    Idempotent: deletes any existing DFD data for this threat_model_id
    before creating new records.

    Args:
        db: Async database session.
        threat_model_id: The threat model to generate DFD for.
        parse_result: Parsed components, flows, and boundaries from AI extraction.

    Returns:
        DFDResponse with created nodes, edges, and trust boundaries.
    """
    # Delete existing DFD data (idempotent re-generation)
    await db.execute(delete(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id))
    await db.execute(delete(DFDNode).where(DFDNode.threat_model_id == threat_model_id))
    await db.execute(delete(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id))

    # Create DFDNode for each ParsedComponent
    db_nodes: list[DFDNode] = []
    name_to_uuid: dict[str, UUID] = {}  # normalized_name -> node UUID

    for component in parse_result.components:
        node_properties: dict[str, object] = {}
        if component.description:
            node_properties["description"] = component.description
        if component.extraction_source:
            node_properties["extraction_source"] = component.extraction_source
        if component.evidence_page is not None:
            node_properties["evidence_page"] = component.evidence_page
        if component.evidence_snippet:
            node_properties["evidence_snippet"] = component.evidence_snippet

        node = DFDNode(
            threat_model_id=threat_model_id,
            node_type=component.component_type,
            name=component.name,
            confidence=component.confidence,
            properties=node_properties,
        )
        db.add(node)
        db_nodes.append(node)
        name_to_uuid[normalize_name(component.name)] = node.id

    # Flush to ensure node IDs are assigned
    await db.flush()

    # Refresh name_to_uuid with flushed IDs
    name_to_uuid = {}
    for node in db_nodes:
        name_to_uuid[normalize_name(node.name)] = node.id

    # Compute layout positions
    node_dicts = [{"id": str(n.id), "node_type": n.node_type} for n in db_nodes]
    positions = compute_layout(node_dicts, [])

    # Apply positions to nodes
    for node in db_nodes:
        pos = positions.get(str(node.id))
        if pos:
            node.position_x, node.position_y = pos

    # Create DFDEdge for each ParsedFlow
    db_edges: list[DFDEdge] = []
    for flow in parse_result.flows:
        source_id = resolve_node_by_name(flow.source, name_to_uuid)
        target_id = resolve_node_by_name(flow.target, name_to_uuid)

        if source_id is None or target_id is None:
            logger.debug(
                "Skipping flow '%s' -> '%s': unresolved node(s)",
                flow.source,
                flow.target,
            )
            continue

        edge_props = {}
        if flow.data_types:
            edge_props["data_types"] = flow.data_types
        if flow.extraction_source:
            edge_props["extraction_source"] = flow.extraction_source
        if flow.evidence_page is not None:
            edge_props["evidence_page"] = flow.evidence_page
        if flow.evidence_snippet:
            edge_props["evidence_snippet"] = flow.evidence_snippet

        edge = DFDEdge(
            threat_model_id=threat_model_id,
            source_node_id=source_id,
            target_node_id=target_id,
            label=flow.label,
            properties=edge_props,
        )
        db.add(edge)
        db_edges.append(edge)

    # Create TrustBoundary for each ParsedBoundary
    db_boundaries: list[TrustBoundary] = []
    for boundary in parse_result.boundaries:
        resolved_ids = []
        for component_name in boundary.contains:
            node_id = resolve_node_by_name(component_name, name_to_uuid)
            if node_id is not None:
                resolved_ids.append(node_id)

        tb = TrustBoundary(
            threat_model_id=threat_model_id,
            name=boundary.name,
            node_ids=resolved_ids,
        )
        db.add(tb)
        db_boundaries.append(tb)

    await db.flush()

    logger.info(
        "dfd_generated threat_model_id=%s nodes=%d edges=%d boundaries=%d",
        threat_model_id,
        len(db_nodes),
        len(db_edges),
        len(db_boundaries),
    )

    # Build response
    return DFDResponse(
        nodes=[DFDNodeResponse.model_validate(n) for n in db_nodes],
        edges=[DFDEdgeResponse.model_validate(e) for e in db_edges],
        trust_boundaries=[TrustBoundaryResponse.model_validate(tb) for tb in db_boundaries],
    )

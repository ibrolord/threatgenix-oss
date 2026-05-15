from __future__ import annotations

from app.schemas.dfd import TrustBoundaryResponse


def _find_boundary_for_node(
    node_id: str,
    boundaries: list[TrustBoundaryResponse],
) -> TrustBoundaryResponse | None:
    for boundary in boundaries:
        if node_id in [str(nid) for nid in boundary.node_ids]:
            return boundary
    return None


def crosses_trust_boundary(
    source_id: str,
    target_id: str,
    boundaries: list[TrustBoundaryResponse],
) -> tuple[bool, str | None]:
    """
    Returns (crosses: bool, boundary_name: str | None).
    boundary_name is the name of the boundary being crossed INTO (target's boundary),
    or None if no crossing.
    """
    source_boundary = _find_boundary_for_node(source_id, boundaries)
    target_boundary = _find_boundary_for_node(target_id, boundaries)

    # Case 4: Both outside any boundary
    if source_boundary is None and target_boundary is None:
        return (False, None)

    # Case 1: Same boundary
    if (
        source_boundary is not None
        and target_boundary is not None
        and source_boundary.id == target_boundary.id
    ):
        return (False, None)

    # Case 2: Different boundaries
    if source_boundary is not None and target_boundary is not None:
        return (True, target_boundary.name)

    # Case 3: One inside, one outside
    if target_boundary is not None:
        return (True, target_boundary.name)
    # source_boundary is not None, target is outside
    return (True, source_boundary.name)

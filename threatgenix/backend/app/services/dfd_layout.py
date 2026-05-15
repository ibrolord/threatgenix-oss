"""Simple rank-based DFD layout (Block 10).

Groups nodes by type into columns (external_entity/human_actor | process | data_store)
and spaces them evenly. Frontend dagre will re-layout, so this just needs
to produce reasonable initial positions.
"""


def compute_layout(
    nodes: list[dict],
    edges: list[dict],
    rankdir: str = "LR",
    nodesep: int = 80,
    ranksep: int = 120,
) -> dict[str, tuple[float, float]]:
    """Compute simple rank-based positions for DFD nodes.

    Args:
        nodes: List of dicts with at least "id" and "node_type" keys.
        edges: List of dicts (unused for now; reserved for smarter layout).
        rankdir: Layout direction. "LR" = left-to-right (default).
        nodesep: Vertical spacing between nodes in the same rank.
        ranksep: Horizontal spacing between ranks.

    Returns:
        Dict mapping node id (str) -> (x, y) position tuple.
    """
    # Group nodes into ranks by type
    rank_order = ["external_entity", "process", "data_store"]
    ranks: dict[str, list[str]] = {r: [] for r in rank_order}

    for node in nodes:
        node_type = node.get("node_type", "process")
        node_id = str(node["id"])
        if node_type == "human_actor":
            ranks["external_entity"].append(node_id)
        elif node_type in ranks:
            ranks[node_type].append(node_id)
        else:
            ranks["process"].append(node_id)

    positions: dict[str, tuple[float, float]] = {}

    for rank_index, rank_key in enumerate(rank_order):
        node_ids = ranks[rank_key]
        x = float(rank_index * ranksep)
        # Center nodes vertically within the rank
        total_height = (len(node_ids) - 1) * nodesep if node_ids else 0
        start_y = -total_height / 2.0

        for i, node_id in enumerate(node_ids):
            y = start_y + i * nodesep
            positions[node_id] = (x, y)

    return positions

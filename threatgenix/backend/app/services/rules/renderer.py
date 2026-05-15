from __future__ import annotations

from collections import defaultdict

from app.schemas.dfd import DFDEdgeResponse, DFDNodeResponse


def build_context(
    source: DFDNodeResponse | None = None,
    edge: DFDEdgeResponse | None = None,
    target: DFDNodeResponse | None = None,
    boundary_name: str | None = None,
    node: DFDNodeResponse | None = None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build template variable dict from DFD elements."""
    ctx: dict[str, str] = {
        "source_name": source.name if source else "",
        "source_type": source.node_type if source else "",
        "target_name": target.name if target else "",
        "target_type": target.node_type if target else "",
        "edge_label": edge.label if edge else "data",
        "node_name": node.name if node else "",
        "node_type": node.node_type if node else "",
        "boundary_name": boundary_name or "",
    }
    if extra:
        ctx.update(extra)
    return ctx


def render_description(template: str, context: dict[str, str]) -> str:
    """Render a description template with context variables.

    Uses format_map with defaultdict fallback so missing keys
    produce '{key}' instead of raising KeyError.
    """
    safe_context = defaultdict(lambda: "{unknown}", context)
    return template.format_map(safe_context)

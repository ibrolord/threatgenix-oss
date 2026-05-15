from __future__ import annotations

from uuid import uuid4

from app.schemas.dfd import DFDEdgeResponse, DFDNodeResponse
from app.services.rules.renderer import build_context, render_description


def _make_node(name: str = "WebApp", node_type: str = "process") -> DFDNodeResponse:
    return DFDNodeResponse(
        id=uuid4(),
        node_type=node_type,
        name=name,
        position_x=0,
        position_y=0,
        trust_boundary_id=None,
        properties={},
    )


def _make_edge(label: str = "HTTP request") -> DFDEdgeResponse:
    return DFDEdgeResponse(
        id=uuid4(),
        source_node_id=uuid4(),
        target_node_id=uuid4(),
        label=label,
        properties={},
    )


class TestBuildContext:
    def test_full_tuple(self):
        source = _make_node("Browser", "external_entity")
        edge = _make_edge("HTTP request")
        target = _make_node("API Server", "process")
        ctx = build_context(
            source=source,
            edge=edge,
            target=target,
            boundary_name="Internet",
        )
        assert ctx["source_name"] == "Browser"
        assert ctx["source_type"] == "external_entity"
        assert ctx["target_name"] == "API Server"
        assert ctx["target_type"] == "process"
        assert ctx["edge_label"] == "HTTP request"
        assert ctx["boundary_name"] == "Internet"

    def test_standalone_node_only(self):
        node = _make_node("Database", "data_store")
        ctx = build_context(node=node)
        assert ctx["node_name"] == "Database"
        assert ctx["node_type"] == "data_store"
        assert ctx["source_name"] == ""
        assert ctx["source_type"] == ""
        assert ctx["target_name"] == ""
        assert ctx["target_type"] == ""
        assert ctx["edge_label"] == "data"
        assert ctx["boundary_name"] == ""

    def test_extra_dict_merging(self):
        ctx = build_context(extra={"severity": "HIGH", "category": "Spoofing"})
        assert ctx["severity"] == "HIGH"
        assert ctx["category"] == "Spoofing"
        # built-in keys still present
        assert ctx["source_name"] == ""


class TestRenderDescription:
    def test_all_variables_present(self):
        ctx = {
            "source_name": "Browser",
            "target_name": "API",
            "edge_label": "HTTP",
        }
        template = "{source_name} sends {edge_label} to {target_name}"
        result = render_description(template, ctx)
        assert result == "Browser sends HTTP to API"

    def test_missing_variables(self):
        ctx = {"source_name": "Browser"}
        template = "{source_name} sends {edge_label} to {target_name}"
        result = render_description(template, ctx)
        assert result == "Browser sends {unknown} to {unknown}"

    def test_empty_template(self):
        result = render_description("", {"source_name": "Browser"})
        assert result == ""

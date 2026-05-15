from __future__ import annotations

import pytest

from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.services.rules.engine import evaluate_rules

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_STRIDE = {
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
}


def _make_node(
    node_id: str,
    node_type: str,
    name: str,
    trust_boundary_id: str | None = None,
    properties: dict | None = None,
) -> DFDNodeResponse:
    return DFDNodeResponse(
        id=node_id,
        node_type=node_type,
        name=name,
        position_x=0.0,
        position_y=0.0,
        trust_boundary_id=trust_boundary_id,
        properties=properties or {},
    )


# ---------------------------------------------------------------------------
# Deterministic IDs so tests are reproducible
# ---------------------------------------------------------------------------
NODE_EE1 = "00000000-0000-0000-0000-000000000001"
NODE_EE2 = "00000000-0000-0000-0000-000000000002"
NODE_P1 = "00000000-0000-0000-0000-000000000003"
NODE_P2 = "00000000-0000-0000-0000-000000000004"
NODE_DS1 = "00000000-0000-0000-0000-000000000005"

EDGE1 = "00000000-0000-0000-0000-0000000000e1"
EDGE2 = "00000000-0000-0000-0000-0000000000e2"
EDGE3 = "00000000-0000-0000-0000-0000000000e3"
EDGE4 = "00000000-0000-0000-0000-0000000000e4"
EDGE5 = "00000000-0000-0000-0000-0000000000e5"
EDGE6 = "00000000-0000-0000-0000-0000000000e6"

BOUNDARY1 = "00000000-0000-0000-0000-0000000000b1"
BOUNDARY2 = "00000000-0000-0000-0000-0000000000b2"


@pytest.fixture()
def reference_dfd() -> DFDResponse:
    """Reference DFD with 5 nodes, 6 edges, 2 trust boundaries.

    Layout:
      EE1 (external, outside boundaries)
      EE2 (external, outside boundaries)
      P1  (process, in boundary 1 "Internal Network")
      P2  (process, in boundary 2 "DMZ")
      DS1 (data_store, in boundary 1 "Internal Network")

    Edges:
      EE1 -> P2  (crosses into DMZ)
      EE2 -> P2  (crosses into DMZ)
      P2  -> P1  (crosses DMZ -> Internal Network)
      P1  -> DS1 (same boundary)
      DS1 -> P1  (same boundary)
      P1  -> EE1 (crosses out of Internal Network)
    """
    nodes = [
        _make_node(NODE_EE1, "external_entity", "Web Browser"),
        _make_node(NODE_EE2, "external_entity", "Mobile App"),
        _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1),
        _make_node(NODE_P2, "process", "API Gateway", trust_boundary_id=BOUNDARY2),
        _make_node(NODE_DS1, "data_store", "User DB", trust_boundary_id=BOUNDARY1),
    ]

    edges = [
        DFDEdgeResponse(id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P2, label="HTTP request", properties={}),
        DFDEdgeResponse(id=EDGE2, source_node_id=NODE_EE2, target_node_id=NODE_P2, label="API call", properties={}),
        DFDEdgeResponse(id=EDGE3, source_node_id=NODE_P2, target_node_id=NODE_P1, label="internal RPC", properties={}),
        DFDEdgeResponse(id=EDGE4, source_node_id=NODE_P1, target_node_id=NODE_DS1, label="SQL query", properties={}),
        DFDEdgeResponse(id=EDGE5, source_node_id=NODE_DS1, target_node_id=NODE_P1, label="query results", properties={}),
        DFDEdgeResponse(id=EDGE6, source_node_id=NODE_P1, target_node_id=NODE_EE1, label="HTTP response", properties={}),
    ]

    boundaries = [
        TrustBoundaryResponse(id=BOUNDARY1, name="Internal Network", node_ids=[NODE_P1, NODE_DS1]),
        TrustBoundaryResponse(id=BOUNDARY2, name="DMZ", node_ids=[NODE_P2]),
    ]

    return DFDResponse(nodes=nodes, edges=edges, trust_boundaries=boundaries)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEvaluateRulesBasic:
    def test_returns_non_empty_threats(self, reference_dfd: DFDResponse) -> None:
        result = evaluate_rules(reference_dfd)
        assert len(result.threats) > 0

    def test_display_ids_sequential(self, reference_dfd: DFDResponse) -> None:
        result = evaluate_rules(reference_dfd)
        for idx, threat in enumerate(result.threats, start=1):
            assert threat.display_id == f"T-{idx:03d}", (
                f"Expected T-{idx:03d}, got {threat.display_id}"
            )

    def test_valid_stride_categories(self, reference_dfd: DFDResponse) -> None:
        result = evaluate_rules(reference_dfd)
        for threat in result.threats:
            assert threat.stride_category in VALID_STRIDE, (
                f"Invalid STRIDE category: {threat.stride_category}"
            )

    def test_all_threats_have_source_rules_engine(self, reference_dfd: DFDResponse) -> None:
        result = evaluate_rules(reference_dfd)
        for threat in result.threats:
            assert threat.source == "Rules"

    def test_malformed_edges_are_reported_as_warnings(self) -> None:
        valid_node = _make_node(
            NODE_P1,
            "process",
            "Payments API",
            properties={"network_exposure": "internet", "authentication_type": "none"},
        )
        missing_node_id = "00000000-0000-0000-0000-000000000099"
        dfd = DFDResponse(
            nodes=[valid_node],
            edges=[
                DFDEdgeResponse(
                    id=EDGE1,
                    source_node_id=NODE_P1,
                    target_node_id=missing_node_id,
                    label="credential-bearing request",
                    properties={},
                )
            ],
            trust_boundaries=[],
        )

        result = evaluate_rules(dfd)

        assert result.warnings == [
            f"Skipped edge {EDGE1}: missing target node {missing_node_id}."
        ]
        assert all(EDGE1 not in threat.affected_edge_ids for threat in result.threats)


class TestDeterminism:
    def test_same_output_twice(self, reference_dfd: DFDResponse) -> None:
        result1 = evaluate_rules(reference_dfd)
        result2 = evaluate_rules(reference_dfd)
        # Compare everything except execution_time_ms
        assert len(result1.threats) == len(result2.threats)
        for t1, t2 in zip(result1.threats, result2.threats):
            assert t1.rule_id == t2.rule_id
            assert t1.display_id == t2.display_id
            assert t1.stride_category == t2.stride_category
            assert t1.threat_subtype == t2.threat_subtype
            assert t1.severity == t2.severity
            assert t1.description == t2.description
            assert t1.affected_node_ids == t2.affected_node_ids
            assert t1.affected_edge_ids == t2.affected_edge_ids


class TestDeduplication:
    def test_duplicate_rule_same_nodes_produces_one_threat(self) -> None:
        """If an edge is duplicated (same src/tgt) the rule should fire only once
        per unique (rule_id, affected_node_ids) pair."""
        nodes = [
            _make_node(NODE_EE1, "external_entity", "Browser"),
            _make_node(NODE_P1, "process", "Server", trust_boundary_id=BOUNDARY1),
        ]
        # Two edges between same pair of nodes
        edges = [
            DFDEdgeResponse(id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1, label="req1", properties={}),
            DFDEdgeResponse(id=EDGE2, source_node_id=NODE_EE1, target_node_id=NODE_P1, label="req2", properties={}),
        ]
        boundaries = [
            TrustBoundaryResponse(id=BOUNDARY1, name="Internal", node_ids=[NODE_P1]),
        ]
        dfd = DFDResponse(nodes=nodes, edges=edges, trust_boundaries=boundaries)
        result = evaluate_rules(dfd)

        # Check that for any given rule_id, the same node pair appears at most once
        seen: set[tuple[str, tuple[str, ...]]] = set()
        for threat in result.threats:
            key = (threat.rule_id, tuple(sorted(threat.affected_node_ids)))
            assert key not in seen, f"Duplicate threat: {key}"
            seen.add(key)

    def test_same_rule_distinct_node_pairs_remain_separate(self) -> None:
        """Distinct source/target pairs should stay distinct even for one rule."""
        nodes = [
            _make_node(NODE_EE1, "external_entity", "Consumer Mobile App"),
            _make_node(NODE_EE2, "external_entity", "Treasury Portal User"),
            _make_node(
                NODE_P1,
                "process",
                "API Gateway",
                trust_boundary_id=BOUNDARY1,
                properties={"uses_auth": False},
            ),
        ]
        edges = [
            DFDEdgeResponse(
                id=EDGE1,
                source_node_id=NODE_EE1,
                target_node_id=NODE_P1,
                label="payment initiation",
                properties={},
            ),
            DFDEdgeResponse(
                id=EDGE2,
                source_node_id=NODE_EE2,
                target_node_id=NODE_P1,
                label="privileged batch approval",
                properties={},
            ),
        ]
        boundaries = [
            TrustBoundaryResponse(id=BOUNDARY1, name="Customer Edge", node_ids=[NODE_P1]),
        ]
        dfd = DFDResponse(nodes=nodes, edges=edges, trust_boundaries=boundaries)

        result = evaluate_rules(dfd)
        s01_threats = [t for t in result.threats if t.rule_id == "S-01"]

        assert len(s01_threats) == 2
        assert {
            tuple(sorted(t.affected_node_ids))
            for t in s01_threats
        } == {
            tuple(sorted([NODE_EE1, NODE_P1])),
            tuple(sorted([NODE_EE2, NODE_P1])),
        }


class TestCounts:
    def test_rules_evaluated_and_fired(self, reference_dfd: DFDResponse) -> None:
        result = evaluate_rules(reference_dfd)
        assert result.rules_evaluated > 0
        assert result.rules_fired > 0
        # rules_fired <= unique rule IDs in threats
        fired_ids = {t.rule_id for t in result.threats}
        assert result.rules_fired == len(fired_ids)

    def test_execution_time_positive(self, reference_dfd: DFDResponse) -> None:
        result = evaluate_rules(reference_dfd)
        assert result.execution_time_ms > 0


class TestPropertySuppression:
    """F-06: Setting security properties on nodes reduces threat count."""

    def test_properties_reduce_threat_count(self, reference_dfd: DFDResponse) -> None:
        """Same DFD with properties set should produce fewer threats."""
        baseline = evaluate_rules(reference_dfd)
        baseline_count = len(baseline.threats)

        # Build same DFD but with properties set on nodes
        secured_nodes = [
            _make_node(NODE_EE1, "external_entity", "Web Browser", properties={"authenticated": True}),
            _make_node(NODE_EE2, "external_entity", "Mobile App", properties={"authenticated": True}),
            _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1,
                       properties={"uses_auth": True, "validates_input": True, "uses_encryption": True}),
            _make_node(NODE_P2, "process", "API Gateway", trust_boundary_id=BOUNDARY2,
                       properties={"uses_auth": True, "validates_input": True}),
            _make_node(NODE_DS1, "data_store", "User DB", trust_boundary_id=BOUNDARY1,
                       properties={"encrypted_at_rest": True}),
        ]

        secured_dfd = DFDResponse(
            nodes=secured_nodes,
            edges=reference_dfd.edges,
            trust_boundaries=reference_dfd.trust_boundaries,
        )

        secured_result = evaluate_rules(secured_dfd)
        secured_count = len(secured_result.threats)

        assert secured_count < baseline_count, (
            f"Properties should reduce threats: {baseline_count} (baseline) vs {secured_count} (secured)"
        )

    def test_single_property_suppresses_specific_rules(self) -> None:
        """Setting uses_auth on target suppresses S-02 for that edge."""
        nodes = [
            _make_node(NODE_EE1, "external_entity", "Browser"),
            _make_node(NODE_P1, "process", "Server", trust_boundary_id=BOUNDARY1,
                       properties={"uses_auth": True}),
        ]
        edges = [
            DFDEdgeResponse(id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                            label="request", properties={}),
        ]
        boundaries = [
            TrustBoundaryResponse(id=BOUNDARY1, name="Internal", node_ids=[NODE_P1]),
        ]
        dfd = DFDResponse(nodes=nodes, edges=edges, trust_boundaries=boundaries)
        result = evaluate_rules(dfd)

        rule_ids = {t.rule_id for t in result.threats}
        assert "S-02" not in rule_ids, "S-02 should be suppressed when target uses_auth=True"

    def test_authenticated_suppresses_s01_s03(self) -> None:
        """Setting authenticated on external entity suppresses S-01 and S-03."""
        nodes = [
            _make_node(NODE_EE1, "external_entity", "Browser",
                       properties={"authenticated": True}),
            _make_node(NODE_P1, "process", "Server", trust_boundary_id=BOUNDARY1),
        ]
        edges = [
            DFDEdgeResponse(id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                            label="request", properties={}),
        ]
        boundaries = [
            TrustBoundaryResponse(id=BOUNDARY1, name="Internal", node_ids=[NODE_P1]),
        ]
        dfd = DFDResponse(nodes=nodes, edges=edges, trust_boundaries=boundaries)
        result = evaluate_rules(dfd)

        rule_ids = {t.rule_id for t in result.threats}
        assert "S-01" not in rule_ids, "S-01 should be suppressed when source authenticated=True"
        assert "S-03" not in rule_ids, "S-03 should be suppressed when external entity authenticated=True"

    def test_properties_are_deterministic(self, reference_dfd: DFDResponse) -> None:
        """Property suppression must be deterministic."""
        secured_nodes = [
            _make_node(NODE_EE1, "external_entity", "Web Browser", properties={"authenticated": True}),
            _make_node(NODE_EE2, "external_entity", "Mobile App"),
            _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1,
                       properties={"uses_auth": True}),
            _make_node(NODE_P2, "process", "API Gateway", trust_boundary_id=BOUNDARY2),
            _make_node(NODE_DS1, "data_store", "User DB", trust_boundary_id=BOUNDARY1),
        ]
        secured_dfd = DFDResponse(
            nodes=secured_nodes,
            edges=reference_dfd.edges,
            trust_boundaries=reference_dfd.trust_boundaries,
        )
        r1 = evaluate_rules(secured_dfd)
        r2 = evaluate_rules(secured_dfd)
        assert len(r1.threats) == len(r2.threats)
        for t1, t2 in zip(r1.threats, r2.threats):
            assert t1.rule_id == t2.rule_id

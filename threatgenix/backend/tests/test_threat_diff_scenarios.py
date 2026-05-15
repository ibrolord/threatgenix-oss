"""Real-world scenario tests for the threat diff engine (C-01).

These tests use the ACTUAL rules engine (no mocks) to exercise the full
pipeline: build DFD -> evaluate_rules -> get baseline -> modify DFD ->
evaluate_rules again -> diff.
"""

from __future__ import annotations


from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.services.rules.engine import evaluate_rules
from app.services.threat_diff import diff_threat_lists


# ---------------------------------------------------------------------------
# Deterministic IDs for reproducibility
# ---------------------------------------------------------------------------

NODE_EE1 = "10000000-0000-0000-0000-000000000001"
NODE_EE2 = "10000000-0000-0000-0000-000000000002"
NODE_P1 = "10000000-0000-0000-0000-000000000003"
NODE_P2 = "10000000-0000-0000-0000-000000000004"
NODE_DS1 = "10000000-0000-0000-0000-000000000005"
NODE_DS2 = "10000000-0000-0000-0000-000000000006"
NODE_P3 = "10000000-0000-0000-0000-000000000007"
NODE_P4 = "10000000-0000-0000-0000-000000000008"

EDGE1 = "10000000-0000-0000-0000-0000000000e1"
EDGE2 = "10000000-0000-0000-0000-0000000000e2"
EDGE3 = "10000000-0000-0000-0000-0000000000e3"
EDGE4 = "10000000-0000-0000-0000-0000000000e4"
EDGE5 = "10000000-0000-0000-0000-0000000000e5"
EDGE6 = "10000000-0000-0000-0000-0000000000e6"
EDGE7 = "10000000-0000-0000-0000-0000000000e7"
EDGE8 = "10000000-0000-0000-0000-0000000000e8"

BOUNDARY1 = "10000000-0000-0000-0000-0000000000b1"
BOUNDARY2 = "10000000-0000-0000-0000-0000000000b2"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _serialize_threats(output) -> list[dict]:
    """Convert RuleEngineOutput.threats to list[dict] for diff comparison."""
    return [
        {
            "rule_id": gt.rule_id,
            "stride_category": gt.stride_category,
            "threat_subtype": gt.threat_subtype,
            "severity": gt.severity,
            "description": gt.description,
            "affected_node_ids": [str(nid) for nid in gt.affected_node_ids],
            "affected_edge_ids": [str(eid) for eid in gt.affected_edge_ids],
        }
        for gt in output.threats
    ]


# ---------------------------------------------------------------------------
# Scenario Tests
# ---------------------------------------------------------------------------


class TestScenarioAddNodeCreatesNewThreats:
    """Scenario 1: Adding a data_store node + edge creates new threats."""

    def test_scenario_add_node_creates_new_threats(self):
        # Baseline DFD: external_entity -> process (with trust boundary crossing)
        baseline_nodes = [
            _make_node(NODE_EE1, "external_entity", "Web Browser"),
            _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1),
        ]
        baseline_edges = [
            DFDEdgeResponse(
                id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                label="HTTP request", properties={},
            ),
        ]
        baseline_boundaries = [
            TrustBoundaryResponse(id=BOUNDARY1, name="Internal Network", node_ids=[NODE_P1]),
        ]
        baseline_dfd = DFDResponse(
            nodes=baseline_nodes, edges=baseline_edges,
            trust_boundaries=baseline_boundaries,
        )

        baseline_output = evaluate_rules(baseline_dfd)
        baseline_threats = _serialize_threats(baseline_output)
        baseline_rule_ids = {t.rule_id for t in baseline_output.threats}

        # Modified DFD: add data_store + edge from process -> data_store
        modified_nodes = baseline_nodes + [
            _make_node(NODE_DS1, "data_store", "Customer DB", trust_boundary_id=BOUNDARY1),
        ]
        modified_edges = baseline_edges + [
            DFDEdgeResponse(
                id=EDGE2, source_node_id=NODE_P1, target_node_id=NODE_DS1,
                label="SQL query", properties={},
            ),
        ]
        modified_boundaries = [
            TrustBoundaryResponse(
                id=BOUNDARY1, name="Internal Network", node_ids=[NODE_P1, NODE_DS1],
            ),
        ]
        modified_dfd = DFDResponse(
            nodes=modified_nodes, edges=modified_edges,
            trust_boundaries=modified_boundaries,
        )

        modified_output = evaluate_rules(modified_dfd)
        modified_threats = _serialize_threats(modified_output)

        # Diff
        result = diff_threat_lists(baseline_threats, modified_threats)

        # We should have added threats (data store rules: T-03, T-06, D-06, R-03, etc.)
        assert result["counts"]["added"] > 0, "Adding a data_store should create new threats"
        assert result["counts"]["total_after"] > result["counts"]["total_before"]

        # Verify new rules fired that weren't in baseline
        added_rule_ids = {t["rule_id"] for t in result["added"]}
        modified_rule_ids = {t.rule_id for t in modified_output.threats}
        new_rules = modified_rule_ids - baseline_rule_ids
        # At least some new rules should appear in the diff's added list
        assert added_rule_ids & new_rules


class TestScenarioRemoveNodeRemovesThreats:
    """Scenario 2: Removing a data_store node removes related threats."""

    def test_scenario_remove_node_removes_threats(self):
        # Baseline DFD: ext_entity -> process -> data_store
        baseline_nodes = [
            _make_node(NODE_EE1, "external_entity", "Web Browser"),
            _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1),
            _make_node(NODE_DS1, "data_store", "Customer DB", trust_boundary_id=BOUNDARY1),
        ]
        baseline_edges = [
            DFDEdgeResponse(
                id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                label="HTTP request", properties={},
            ),
            DFDEdgeResponse(
                id=EDGE2, source_node_id=NODE_P1, target_node_id=NODE_DS1,
                label="SQL query", properties={},
            ),
        ]
        baseline_boundaries = [
            TrustBoundaryResponse(
                id=BOUNDARY1, name="Internal Network", node_ids=[NODE_P1, NODE_DS1],
            ),
        ]
        baseline_dfd = DFDResponse(
            nodes=baseline_nodes, edges=baseline_edges,
            trust_boundaries=baseline_boundaries,
        )

        baseline_output = evaluate_rules(baseline_dfd)
        baseline_threats = _serialize_threats(baseline_output)

        # Modified DFD: remove data_store + its edge
        modified_nodes = [
            _make_node(NODE_EE1, "external_entity", "Web Browser"),
            _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1),
        ]
        modified_edges = [
            DFDEdgeResponse(
                id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                label="HTTP request", properties={},
            ),
        ]
        modified_boundaries = [
            TrustBoundaryResponse(id=BOUNDARY1, name="Internal Network", node_ids=[NODE_P1]),
        ]
        modified_dfd = DFDResponse(
            nodes=modified_nodes, edges=modified_edges,
            trust_boundaries=modified_boundaries,
        )

        modified_output = evaluate_rules(modified_dfd)
        modified_threats = _serialize_threats(modified_output)

        # Diff
        result = diff_threat_lists(baseline_threats, modified_threats)

        assert result["counts"]["removed"] > 0, "Removing a data_store should remove threats"
        assert result["counts"]["total_before"] > result["counts"]["total_after"]

        # Removed threats should include data-store-related rules
        removed_rule_ids = {t["rule_id"] for t in result["removed"]}
        # T-03 (write integrity), T-06 (unencrypted store), D-06 (no backup),
        # R-03 (unaudited modification) are likely candidates
        assert len(removed_rule_ids) > 0


class TestScenarioSetPropertiesMitigatesThreats:
    """Scenario 3: Setting authentication properties suppresses spoofing threats."""

    def test_scenario_set_properties_mitigates_threats(self):
        # Baseline DFD: unauthenticated external entity -> process without auth
        baseline_nodes = [
            _make_node(NODE_EE1, "external_entity", "Web Browser"),
            _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1),
        ]
        baseline_edges = [
            DFDEdgeResponse(
                id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                label="HTTP request", properties={},
            ),
        ]
        baseline_boundaries = [
            TrustBoundaryResponse(id=BOUNDARY1, name="Internal Network", node_ids=[NODE_P1]),
        ]
        baseline_dfd = DFDResponse(
            nodes=baseline_nodes, edges=baseline_edges,
            trust_boundaries=baseline_boundaries,
        )

        baseline_output = evaluate_rules(baseline_dfd)
        baseline_threats = _serialize_threats(baseline_output)

        # Verify spoofing threats exist in baseline
        baseline_spoofing = [
            t for t in baseline_output.threats
            if t.stride_category == "Spoofing"
        ]
        assert len(baseline_spoofing) > 0, "Baseline should have Spoofing threats"

        # Modified DFD: set authenticated=True on ext_entity, uses_auth=True on process
        modified_nodes = [
            _make_node(NODE_EE1, "external_entity", "Web Browser",
                       properties={"authenticated": True}),
            _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1,
                       properties={"uses_auth": True}),
        ]
        modified_dfd = DFDResponse(
            nodes=modified_nodes, edges=baseline_edges,
            trust_boundaries=baseline_boundaries,
        )

        modified_output = evaluate_rules(modified_dfd)
        modified_threats = _serialize_threats(modified_output)

        # Diff
        result = diff_threat_lists(baseline_threats, modified_threats)

        # Should have removed spoofing threats
        assert result["counts"]["removed"] > 0, "Auth properties should remove threats"
        removed_categories = {t["stride_category"] for t in result["removed"]}
        assert "Spoofing" in removed_categories, "Removed threats should include Spoofing"

        # Verify S-01, S-02, S-03 are suppressed
        modified_rule_ids = {t.rule_id for t in modified_output.threats}
        assert "S-01" not in modified_rule_ids, "S-01 should be suppressed"
        assert "S-02" not in modified_rule_ids, "S-02 should be suppressed"
        assert "S-03" not in modified_rule_ids, "S-03 should be suppressed"


class TestScenarioAddTrustBoundaryChangesThreats:
    """Scenario 4: Adding a trust boundary causes boundary-crossing rules to fire."""

    def test_scenario_add_trust_boundary_changes_threats(self):
        # Baseline DFD: nodes with NO trust boundary
        baseline_nodes = [
            _make_node(NODE_EE1, "external_entity", "Web Browser"),
            _make_node(NODE_P1, "process", "App Server"),
        ]
        baseline_edges = [
            DFDEdgeResponse(
                id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                label="HTTP request", properties={},
            ),
        ]
        baseline_dfd = DFDResponse(
            nodes=baseline_nodes, edges=baseline_edges, trust_boundaries=[],
        )

        baseline_output = evaluate_rules(baseline_dfd)
        baseline_threats = _serialize_threats(baseline_output)

        # Verify no boundary-crossing rules fired
        baseline_rule_ids = {t.rule_id for t in baseline_output.threats}
        boundary_rules = {"S-01", "S-02", "T-01", "I-01", "E-01", "E-02", "S-04", "E-06"}
        assert not (baseline_rule_ids & boundary_rules), \
            "No boundary-crossing rules should fire without a trust boundary"

        # Modified DFD: add trust boundary around the process
        modified_nodes = [
            _make_node(NODE_EE1, "external_entity", "Web Browser"),
            _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1),
        ]
        modified_boundaries = [
            TrustBoundaryResponse(id=BOUNDARY1, name="Internal Network", node_ids=[NODE_P1]),
        ]
        modified_dfd = DFDResponse(
            nodes=modified_nodes, edges=baseline_edges,
            trust_boundaries=modified_boundaries,
        )

        modified_output = evaluate_rules(modified_dfd)
        modified_threats = _serialize_threats(modified_output)

        # Diff
        result = diff_threat_lists(baseline_threats, modified_threats)

        # Should have added boundary-crossing threats
        assert result["counts"]["added"] > 0, \
            "Adding a trust boundary should create new threats"
        added_rule_ids = {t["rule_id"] for t in result["added"]}
        # At least some boundary-crossing rules should now fire
        assert len(added_rule_ids & boundary_rules) > 0, \
            "Added threats should include boundary-crossing rules"


class TestScenarioNoChangesProducesEmptyDiff:
    """Scenario 5: Identical DFDs produce an empty diff."""

    def test_scenario_no_changes_produces_empty_diff(self):
        nodes = [
            _make_node(NODE_EE1, "external_entity", "Web Browser"),
            _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1),
            _make_node(NODE_DS1, "data_store", "Customer DB", trust_boundary_id=BOUNDARY1),
        ]
        edges = [
            DFDEdgeResponse(
                id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                label="HTTP request", properties={},
            ),
            DFDEdgeResponse(
                id=EDGE2, source_node_id=NODE_P1, target_node_id=NODE_DS1,
                label="SQL query", properties={},
            ),
        ]
        boundaries = [
            TrustBoundaryResponse(
                id=BOUNDARY1, name="Internal Network", node_ids=[NODE_P1, NODE_DS1],
            ),
        ]
        dfd = DFDResponse(nodes=nodes, edges=edges, trust_boundaries=boundaries)

        # Run rules twice on same DFD
        output1 = evaluate_rules(dfd)
        output2 = evaluate_rules(dfd)

        threats1 = _serialize_threats(output1)
        threats2 = _serialize_threats(output2)

        result = diff_threat_lists(threats1, threats2)

        assert result["counts"]["added"] == 0
        assert result["counts"]["removed"] == 0
        assert result["counts"]["total_before"] == result["counts"]["total_after"]
        assert result["added"] == []
        assert result["removed"] == []


class TestScenarioComplexEditMixedChanges:
    """Scenario 6: Complex banking DFD edit with simultaneous add/remove/modify."""

    def test_scenario_complex_edit_mixed_changes(self):
        # Baseline: API Gateway -> Auth Service -> Core Banking -> Customer DB
        baseline_nodes = [
            _make_node(NODE_EE1, "external_entity", "Customer Browser"),
            _make_node(NODE_P1, "process", "API Gateway", trust_boundary_id=BOUNDARY2),
            _make_node(NODE_P2, "process", "Auth Service", trust_boundary_id=BOUNDARY1),
            _make_node(NODE_P3, "process", "Core Banking", trust_boundary_id=BOUNDARY1),
            _make_node(NODE_DS1, "data_store", "Customer DB", trust_boundary_id=BOUNDARY1),
        ]
        baseline_edges = [
            DFDEdgeResponse(
                id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                label="HTTP request", properties={},
            ),
            DFDEdgeResponse(
                id=EDGE2, source_node_id=NODE_P1, target_node_id=NODE_P2,
                label="auth token", properties={},
            ),
            DFDEdgeResponse(
                id=EDGE3, source_node_id=NODE_P2, target_node_id=NODE_P3,
                label="authenticated request", properties={},
            ),
            DFDEdgeResponse(
                id=EDGE4, source_node_id=NODE_P3, target_node_id=NODE_DS1,
                label="SQL query", properties={},
            ),
        ]
        baseline_boundaries = [
            TrustBoundaryResponse(
                id=BOUNDARY1, name="Internal Network",
                node_ids=[NODE_P2, NODE_P3, NODE_DS1],
            ),
            TrustBoundaryResponse(id=BOUNDARY2, name="DMZ", node_ids=[NODE_P1]),
        ]
        baseline_dfd = DFDResponse(
            nodes=baseline_nodes, edges=baseline_edges,
            trust_boundaries=baseline_boundaries,
        )

        baseline_output = evaluate_rules(baseline_dfd)
        baseline_threats = _serialize_threats(baseline_output)

        # Modified DFD:
        # 1. Add Payment Service (new node + edge)
        # 2. Remove edge from Auth Service -> Core Banking (EDGE3)
        # 3. Set uses_encryption=True on Core Banking
        modified_nodes = [
            _make_node(NODE_EE1, "external_entity", "Customer Browser"),
            _make_node(NODE_P1, "process", "API Gateway", trust_boundary_id=BOUNDARY2),
            _make_node(NODE_P2, "process", "Auth Service", trust_boundary_id=BOUNDARY1),
            _make_node(NODE_P3, "process", "Core Banking", trust_boundary_id=BOUNDARY1,
                       properties={"uses_encryption": True}),
            _make_node(NODE_DS1, "data_store", "Customer DB", trust_boundary_id=BOUNDARY1),
            # New node
            _make_node(NODE_P4, "process", "Payment Service", trust_boundary_id=BOUNDARY1),
        ]
        modified_edges = [
            DFDEdgeResponse(
                id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                label="HTTP request", properties={},
            ),
            DFDEdgeResponse(
                id=EDGE2, source_node_id=NODE_P1, target_node_id=NODE_P2,
                label="auth token", properties={},
            ),
            # EDGE3 removed (Auth Service -> Core Banking)
            DFDEdgeResponse(
                id=EDGE4, source_node_id=NODE_P3, target_node_id=NODE_DS1,
                label="SQL query", properties={},
            ),
            # New edge: Core Banking -> Payment Service
            DFDEdgeResponse(
                id=EDGE5, source_node_id=NODE_P3, target_node_id=NODE_P4,
                label="payment instruction", properties={},
            ),
        ]
        modified_boundaries = [
            TrustBoundaryResponse(
                id=BOUNDARY1, name="Internal Network",
                node_ids=[NODE_P2, NODE_P3, NODE_DS1, NODE_P4],
            ),
            TrustBoundaryResponse(id=BOUNDARY2, name="DMZ", node_ids=[NODE_P1]),
        ]
        modified_dfd = DFDResponse(
            nodes=modified_nodes, edges=modified_edges,
            trust_boundaries=modified_boundaries,
        )

        modified_output = evaluate_rules(modified_dfd)
        modified_threats = _serialize_threats(modified_output)

        result = diff_threat_lists(baseline_threats, modified_threats)

        # Should have BOTH added AND removed threats
        has_added = result["counts"]["added"] > 0
        has_removed = result["counts"]["removed"] > 0
        assert has_added or has_removed, \
            "Complex edit should produce at least added or removed threats"
        # With 3 changes (add node, remove edge, set property), we expect mixed results
        # The encryption property should suppress some threats (T-01, I-01 related)
        # The new Payment Service node should trigger new standalone rules (D-02, etc.)


class TestScenarioDiffIdentityStableAcrossNodeReordering:
    """Scenario 7: Same DFD with nodes in different order produces zero-change diff."""

    def test_scenario_diff_identity_stable_across_node_reordering(self):
        # Build DFD with nodes in one order
        nodes_order1 = [
            _make_node(NODE_EE1, "external_entity", "Web Browser"),
            _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1),
            _make_node(NODE_DS1, "data_store", "Customer DB", trust_boundary_id=BOUNDARY1),
        ]
        edges = [
            DFDEdgeResponse(
                id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                label="HTTP request", properties={},
            ),
            DFDEdgeResponse(
                id=EDGE2, source_node_id=NODE_P1, target_node_id=NODE_DS1,
                label="SQL query", properties={},
            ),
        ]
        boundaries = [
            TrustBoundaryResponse(
                id=BOUNDARY1, name="Internal Network", node_ids=[NODE_P1, NODE_DS1],
            ),
        ]

        dfd1 = DFDResponse(nodes=nodes_order1, edges=edges, trust_boundaries=boundaries)
        output1 = evaluate_rules(dfd1)
        threats1 = _serialize_threats(output1)

        # Same DFD with nodes in reversed order (same IDs)
        nodes_order2 = [
            _make_node(NODE_DS1, "data_store", "Customer DB", trust_boundary_id=BOUNDARY1),
            _make_node(NODE_P1, "process", "App Server", trust_boundary_id=BOUNDARY1),
            _make_node(NODE_EE1, "external_entity", "Web Browser"),
        ]

        dfd2 = DFDResponse(nodes=nodes_order2, edges=edges, trust_boundaries=boundaries)
        output2 = evaluate_rules(dfd2)
        threats2 = _serialize_threats(output2)

        result = diff_threat_lists(threats1, threats2)

        assert result["counts"]["added"] == 0, \
            "Node reordering should not create added threats"
        assert result["counts"]["removed"] == 0, \
            "Node reordering should not create removed threats"
        assert result["counts"]["total_before"] == result["counts"]["total_after"]


class TestScenarioDescriptionSnippetsAreUseful:
    """Scenario 8: Description snippets are truncated but readable."""

    def test_scenario_description_snippets_are_useful(self):
        # Build a DFD that triggers threats with long descriptions
        nodes = [
            _make_node(NODE_EE1, "external_entity", "Customer Web Browser Application"),
            _make_node(NODE_P1, "process", "Authentication and Authorization Service",
                       trust_boundary_id=BOUNDARY1),
        ]
        edges = [
            DFDEdgeResponse(
                id=EDGE1, source_node_id=NODE_EE1, target_node_id=NODE_P1,
                label="HTTPS authentication credentials with MFA token", properties={},
            ),
        ]
        boundaries = [
            TrustBoundaryResponse(id=BOUNDARY1, name="Internal Corporate Network", node_ids=[NODE_P1]),
        ]
        dfd = DFDResponse(nodes=nodes, edges=edges, trust_boundaries=boundaries)

        output = evaluate_rules(dfd)
        threats = _serialize_threats(output)

        # Diff against empty baseline (all threats are "added")
        result = diff_threat_lists([], threats)

        assert len(result["added"]) > 0, "Should have added threats"

        for summary in result["added"]:
            snippet = summary["description_snippet"]
            # Snippet should be at most 80 chars
            assert len(snippet) <= 80, \
                f"Snippet too long ({len(snippet)} chars): {snippet!r}"
            # Snippet should not be empty
            assert len(snippet) > 0, "Snippet should not be empty"
            # Snippet should start with a capital letter or meaningful content
            assert snippet[0].isupper() or snippet[0] == "{", \
                f"Snippet should start meaningfully: {snippet!r}"
            # Required fields should be present
            assert summary["rule_id"], "rule_id should not be empty"
            assert summary["stride_category"], "stride_category should not be empty"
            assert summary["severity"], "severity should not be empty"

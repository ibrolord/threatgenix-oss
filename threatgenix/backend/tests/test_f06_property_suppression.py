"""F-06 Integration Test: Element Property Panel — property suppression.

Proves that setting security properties on DFD nodes suppresses the
expected STRIDE threats produced by the rules engine:
  - S-01: authenticated=True on external_entity suppresses spoofing
  - S-02: uses_auth=True on process target suppresses general spoofing
  - S-03: authenticated=True on external_entity suppresses identity spoofing
  - D-01: validates_input=True on process suppresses DoS flood threats
  - T-01: uses_encryption=True on either endpoint suppresses tampering in transit
  - I-01: uses_encryption=True on either endpoint suppresses info disclosure in transit
"""
from __future__ import annotations


from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.services.rules.engine import evaluate_rules

# ---------------------------------------------------------------------------
# Deterministic IDs
# ---------------------------------------------------------------------------
NODE_EE = "00000000-0000-0000-0000-f06000000001"
NODE_P1 = "00000000-0000-0000-0000-f06000000002"
NODE_DS = "00000000-0000-0000-0000-f06000000003"

EDGE1 = "00000000-0000-0000-0000-f060000000e1"
EDGE2 = "00000000-0000-0000-0000-f060000000e2"
EDGE3 = "00000000-0000-0000-0000-f060000000e3"

BOUNDARY = "00000000-0000-0000-0000-f060000000b1"


def _node(nid: str, ntype: str, name: str, *, boundary: str | None = None, props: dict | None = None) -> DFDNodeResponse:
    return DFDNodeResponse(
        id=nid, node_type=ntype, name=name,
        position_x=0, position_y=0,
        trust_boundary_id=boundary,
        properties=props or {},
    )


def _build_dfd(
    node_props: dict[str, dict],
    *,
    external_name: str = "Browser",
    process_name: str = "App Server",
    inbound_label: str = "payment request",
) -> DFDResponse:
    """Build a 3-node DFD (EE -> P1 -> DS) with the given per-node properties."""
    nodes = [
        _node(NODE_EE, "external_entity", external_name, props=node_props.get(NODE_EE, {})),
        _node(NODE_P1, "process", process_name, boundary=BOUNDARY, props=node_props.get(NODE_P1, {})),
        _node(NODE_DS, "data_store", "Database", boundary=BOUNDARY, props=node_props.get(NODE_DS, {})),
    ]
    edges = [
        DFDEdgeResponse(id=EDGE1, source_node_id=NODE_EE, target_node_id=NODE_P1, label=inbound_label, properties={}),
        DFDEdgeResponse(id=EDGE2, source_node_id=NODE_P1, target_node_id=NODE_DS, label="SQL query with password", properties={}),
        DFDEdgeResponse(id=EDGE3, source_node_id=NODE_DS, target_node_id=NODE_P1, label="query results", properties={}),
    ]
    boundaries = [
        TrustBoundaryResponse(id=BOUNDARY, name="Internal", node_ids=[NODE_P1, NODE_DS]),
    ]
    return DFDResponse(nodes=nodes, edges=edges, trust_boundaries=boundaries)


class TestF06EndToEndSuppression:
    """Verify the full suppression chain: empty props -> baseline threats, set props -> fewer threats."""

    def test_baseline_has_threats(self) -> None:
        """Step 1-2: Empty properties produce a non-trivial baseline."""
        dfd = _build_dfd({})
        result = evaluate_rules(dfd)
        assert len(result.threats) > 0, "Baseline DFD should produce threats"

    def test_secured_has_fewer_threats(self) -> None:
        """Steps 3-5: Setting properties reduces total threat count."""
        baseline_result = evaluate_rules(_build_dfd({}))
        baseline_count = len(baseline_result.threats)

        secured_props = {
            NODE_EE: {"authenticated": True},
            NODE_P1: {"uses_auth": True, "validates_input": True, "uses_encryption": True},
            NODE_DS: {"encrypted_at_rest": True},
        }
        secured_result = evaluate_rules(_build_dfd(secured_props))
        secured_count = len(secured_result.threats)

        assert secured_count < baseline_count, (
            f"Expected fewer threats after setting properties: baseline={baseline_count}, secured={secured_count}"
        )

    def test_s01_suppressed_by_authenticated(self) -> None:
        """Step 6: S-01 should be suppressed when external entity is authenticated."""
        baseline_rules = {t.rule_id for t in evaluate_rules(_build_dfd({})).threats}
        assert "S-01" in baseline_rules, "S-01 should fire for unauthenticated external entity"

        secured_props = {NODE_EE: {"authenticated": True}}
        secured_rules = {t.rule_id for t in evaluate_rules(_build_dfd(secured_props)).threats}
        assert "S-01" not in secured_rules, "S-01 should be suppressed when authenticated=True"

    def test_s02_suppressed_by_uses_auth(self) -> None:
        """Step 6: S-02 should be suppressed when target uses_auth."""
        baseline_rules = {t.rule_id for t in evaluate_rules(_build_dfd({})).threats}
        assert "S-02" in baseline_rules, "S-02 should fire when target lacks uses_auth"

        secured_props = {NODE_P1: {"uses_auth": True}}
        secured_rules = {t.rule_id for t in evaluate_rules(_build_dfd(secured_props)).threats}
        assert "S-02" not in secured_rules, "S-02 should be suppressed when uses_auth=True"

    def test_s03_suppressed_by_authenticated(self) -> None:
        """Step 6: S-03 should be suppressed for authenticated partner actors."""
        high_value_partner_dfd = _build_dfd(
            {},
            external_name="Partner Network",
            process_name="Token Gateway",
            inbound_label="token callback",
        )
        baseline_rules = {t.rule_id for t in evaluate_rules(high_value_partner_dfd).threats}
        assert "S-03" in baseline_rules, "S-03 should fire for an unauthenticated partner actor"

        secured_props = {NODE_EE: {"authenticated": True}}
        secured_rules = {
            t.rule_id
            for t in evaluate_rules(
                _build_dfd(
                    secured_props,
                    external_name="Partner Network",
                    process_name="Token Gateway",
                    inbound_label="token callback",
                )
            ).threats
        }
        assert "S-03" not in secured_rules, "S-03 should be suppressed when the partner actor is authenticated"

    def test_d01_suppressed_by_validates_input(self) -> None:
        """Step 6: D-01 should be suppressed when process validates_input=True."""
        baseline_rules = {t.rule_id for t in evaluate_rules(_build_dfd({})).threats}
        assert "D-01" in baseline_rules, "D-01 should fire when process lacks validates_input"

        secured_props = {NODE_P1: {"validates_input": True}}
        secured_rules = {t.rule_id for t in evaluate_rules(_build_dfd(secured_props)).threats}
        assert "D-01" not in secured_rules, "D-01 should be suppressed when validates_input=True"

    def test_t01_suppressed_by_uses_encryption(self) -> None:
        """Step 6: T-01 should be suppressed when either endpoint uses_encryption=True."""
        baseline_rules = {t.rule_id for t in evaluate_rules(_build_dfd({})).threats}
        assert "T-01" in baseline_rules, "T-01 should fire without encryption on cross-boundary flow"

        # Suppress via source encryption
        secured_props = {NODE_EE: {"uses_encryption": True}}
        secured_rules = {t.rule_id for t in evaluate_rules(_build_dfd(secured_props)).threats}
        assert "T-01" not in secured_rules, "T-01 should be suppressed when source uses_encryption=True"

    def test_t01_suppressed_by_target_encryption(self) -> None:
        """T-01 also suppressed when target has uses_encryption=True."""
        secured_props = {NODE_P1: {"uses_encryption": True}}
        secured_rules = {t.rule_id for t in evaluate_rules(_build_dfd(secured_props)).threats}
        assert "T-01" not in secured_rules, "T-01 should be suppressed when target uses_encryption=True"

    def test_i01_suppressed_by_uses_encryption(self) -> None:
        """Step 6: I-01 should be suppressed when either endpoint uses_encryption=True."""
        baseline_rules = {t.rule_id for t in evaluate_rules(_build_dfd({})).threats}
        assert "I-01" in baseline_rules, "I-01 should fire without encryption on cross-boundary flow"

        secured_props = {NODE_P1: {"uses_encryption": True}}
        secured_rules = {t.rule_id for t in evaluate_rules(_build_dfd(secured_props)).threats}
        assert "I-01" not in secured_rules, "I-01 should be suppressed when uses_encryption=True"

    def test_incremental_properties_reduce_threats(self) -> None:
        """Each additional property should reduce (or maintain) the threat count."""
        baseline_count = len(evaluate_rules(_build_dfd({})).threats)

        one_prop = {NODE_EE: {"authenticated": True}}
        one_count = len(evaluate_rules(_build_dfd(one_prop)).threats)
        assert one_count < baseline_count, (
            f"One property should reduce threats: {baseline_count} -> {one_count}"
        )

        two_props = {
            NODE_EE: {"authenticated": True},
            NODE_P1: {"uses_auth": True},
        }
        two_count = len(evaluate_rules(_build_dfd(two_props)).threats)
        assert two_count <= one_count, (
            f"Two properties should not increase threats: {one_count} -> {two_count}"
        )

        three_props = {
            NODE_EE: {"authenticated": True},
            NODE_P1: {"uses_auth": True, "validates_input": True},
        }
        three_count = len(evaluate_rules(_build_dfd(three_props)).threats)
        assert three_count <= two_count, (
            f"Three properties should not increase threats: {two_count} -> {three_count}"
        )

    def test_suppression_is_deterministic(self) -> None:
        """Property suppression must produce identical results on repeated evaluation."""
        props = {
            NODE_EE: {"authenticated": True},
            NODE_P1: {"uses_auth": True, "uses_encryption": True},
        }
        dfd = _build_dfd(props)
        r1 = evaluate_rules(dfd)
        r2 = evaluate_rules(dfd)
        assert len(r1.threats) == len(r2.threats)
        assert [t.rule_id for t in r1.threats] == [t.rule_id for t in r2.threats]

    def test_secured_still_has_structural_threats(self) -> None:
        """Even a fully secured DFD retains structural threats that cannot be suppressed."""
        all_props = {
            NODE_EE: {"authenticated": True, "trusted": True, "uses_encryption": True},
            NODE_P1: {"uses_auth": True, "validates_input": True, "uses_encryption": True},
            NODE_DS: {"encrypted_at_rest": True, "has_backup": True},
        }
        result = evaluate_rules(_build_dfd(all_props))
        assert len(result.threats) > 0, (
            "Structural workflow threats should persist even with all explicit control properties set"
        )

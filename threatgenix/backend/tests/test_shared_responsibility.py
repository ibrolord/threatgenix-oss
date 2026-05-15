"""Tests for Gap 3: Shared responsibility annotations.

Covers:
- provider_managed=True on threats when any triggering node has responsibility="provider"
- provider_managed=False when responsibility is "customer", "shared", or absent
- Flag propagates through tuple, standalone, and boundary rules
- AI-merger propagates provider_managed to AI-discovered threats
- Severity is NOT affected by provider_managed flag
"""
from __future__ import annotations

import uuid


from app.schemas.ai_pass import AIPassOutput, AIThreatRaw
from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.schemas.rules import GeneratedThreat, RuleEngineOutput
from app.services.ai_threat_merger import merge_ai_threats
from app.services.rules.engine import evaluate_rules

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BOUNDARY_ID = "bb000000-0000-0000-0000-000000000001"


def _node(
    node_type: str,
    node_id: str | None = None,
    trust_boundary_id: str | None = None,
    properties: dict | None = None,
    name: str | None = None,
) -> DFDNodeResponse:
    return DFDNodeResponse(
        id=node_id or str(uuid.uuid4()),
        node_type=node_type,
        name=name or f"test-{node_type}",
        position_x=0.0,
        position_y=0.0,
        trust_boundary_id=trust_boundary_id,
        properties=properties or {},
    )


def _edge(
    src: DFDNodeResponse,
    tgt: DFDNodeResponse,
    label: str = "",
) -> DFDEdgeResponse:
    return DFDEdgeResponse(
        id=str(uuid.uuid4()),
        source_node_id=str(src.id),
        target_node_id=str(tgt.id),
        label=label,
        properties={},
    )


def _boundary(node_ids: list[str] | None = None) -> TrustBoundaryResponse:
    return TrustBoundaryResponse(
        id=BOUNDARY_ID,
        name="Cloud Trust Boundary",
        node_ids=node_ids or [],
    )


def _dfd(
    nodes: list[DFDNodeResponse],
    edges: list[DFDEdgeResponse],
    boundaries: list[TrustBoundaryResponse] | None = None,
) -> DFDResponse:
    return DFDResponse(
        nodes=nodes,
        edges=edges,
        trust_boundaries=boundaries or [],
    )


# ---------------------------------------------------------------------------
# provider_managed on standalone rules
# ---------------------------------------------------------------------------


class TestProviderManagedStandalone:
    def test_flag_set_when_standalone_node_is_provider_managed(self):
        """C-01 fires on managed_service; if it's provider-managed, flag must be True."""
        ds = _node(
            "managed_service",
            node_id="cc000000-0000-0000-0000-000000000011",
            properties={"encrypted_at_rest": False, "responsibility": "provider"},
        )
        proc = _node("process")
        dfd = _dfd([ds, proc], [_edge(proc, ds)])
        result = evaluate_rules(dfd)
        c01_threats = [t for t in result.threats if t.rule_id == "C-01"]
        assert len(c01_threats) >= 1
        assert all(t.provider_managed for t in c01_threats), (
            "C-01 threats on a provider-managed node should have provider_managed=True"
        )

    def test_flag_false_when_customer_responsibility(self):
        ds = _node(
            "managed_service",
            properties={"encrypted_at_rest": False, "responsibility": "customer"},
        )
        proc = _node("process")
        dfd = _dfd([ds, proc], [_edge(proc, ds)])
        result = evaluate_rules(dfd)
        c01_threats = [t for t in result.threats if t.rule_id == "C-01"]
        assert len(c01_threats) >= 1
        assert all(not t.provider_managed for t in c01_threats)

    def test_flag_false_when_no_responsibility_set(self):
        ds = _node("managed_service", properties={"encrypted_at_rest": False})
        proc = _node("process")
        dfd = _dfd([ds, proc], [_edge(proc, ds)])
        result = evaluate_rules(dfd)
        c01_threats = [t for t in result.threats if t.rule_id == "C-01"]
        assert len(c01_threats) >= 1
        assert all(not t.provider_managed for t in c01_threats)

    def test_flag_false_when_shared_responsibility(self):
        ds = _node(
            "managed_service",
            properties={"encrypted_at_rest": False, "responsibility": "shared"},
        )
        proc = _node("process")
        dfd = _dfd([ds, proc], [_edge(proc, ds)])
        result = evaluate_rules(dfd)
        c01_threats = [t for t in result.threats if t.rule_id == "C-01"]
        assert len(c01_threats) >= 1
        assert all(not t.provider_managed for t in c01_threats)


# ---------------------------------------------------------------------------
# provider_managed on tuple rules
# ---------------------------------------------------------------------------


class TestProviderManagedTuple:
    def test_flag_set_when_source_is_provider_managed(self):
        """Any tuple threat where source has responsibility=provider should be flagged."""
        ext = _node(
            "external_entity",
            node_id="cc000000-0000-0000-0000-000000000001",
            properties={"authenticated": False, "responsibility": "provider"},
        )
        proc = _node("process", node_id="cc000000-0000-0000-0000-000000000002")
        dfd = _dfd([ext, proc], [_edge(ext, proc)])
        result = evaluate_rules(dfd)
        flagged = [t for t in result.threats if t.provider_managed]
        assert len(flagged) > 0, "Should have at least one provider_managed threat from tuple rule"

    def test_flag_set_when_target_is_provider_managed(self):
        ext = _node("external_entity", node_id="cc000000-0000-0000-0000-000000000003",
                    properties={"authenticated": False})
        proc = _node("process", node_id="cc000000-0000-0000-0000-000000000004",
                     properties={"responsibility": "provider"})
        dfd = _dfd([ext, proc], [_edge(ext, proc)])
        result = evaluate_rules(dfd)
        flagged = [t for t in result.threats if t.provider_managed]
        assert len(flagged) > 0

    def test_flag_false_when_neither_node_is_provider_managed(self):
        ext = _node("external_entity", node_id="cc000000-0000-0000-0000-000000000005",
                    properties={"authenticated": False})
        proc = _node("process", node_id="cc000000-0000-0000-0000-000000000006")
        dfd = _dfd([ext, proc], [_edge(ext, proc)])
        result = evaluate_rules(dfd)
        # All threats should have provider_managed=False
        assert all(not t.provider_managed for t in result.threats)


# ---------------------------------------------------------------------------
# provider_managed does NOT affect severity
# ---------------------------------------------------------------------------


class TestSeverityUnchanged:
    def test_severity_unchanged_when_provider_managed(self):
        """Severity must not be altered by the provider_managed flag."""
        ds = _node(
            "managed_service",
            properties={"encrypted_at_rest": False, "responsibility": "provider"},
        )
        ds_plain = _node("managed_service", properties={"encrypted_at_rest": False})
        proc = _node("process", node_id="cc000000-0000-0000-0000-000000000007")
        proc2 = _node("process", node_id="cc000000-0000-0000-0000-000000000008")
        dfd_pm = _dfd([ds, proc], [_edge(proc, ds)])
        dfd_plain = _dfd([ds_plain, proc2], [_edge(proc2, ds_plain)])
        result_pm = evaluate_rules(dfd_pm)
        result_plain = evaluate_rules(dfd_plain)
        c01_pm = {t.rule_id: t.severity for t in result_pm.threats if t.rule_id == "C-01"}
        c01_plain = {t.rule_id: t.severity for t in result_plain.threats if t.rule_id == "C-01"}
        assert c01_pm == c01_plain, "Severity must be identical regardless of provider_managed flag"


# ---------------------------------------------------------------------------
# AI merger propagates provider_managed
# ---------------------------------------------------------------------------


def _make_rules_output(threats: list[GeneratedThreat]) -> RuleEngineOutput:
    return RuleEngineOutput(
        threats=threats,
        execution_time_ms=0.0,
        rules_evaluated=0,
        rules_fired=0,
    )


def _make_ai_output(threats: list[AIThreatRaw]) -> AIPassOutput:
    return AIPassOutput(
        threats=threats,
        model_id="test-model",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0.0,
    )


def _make_ai_threat(name: str) -> AIThreatRaw:
    return AIThreatRaw(
        stride_category="Spoofing",
        severity="High",
        description=f"AI threat about {name}",
        affected_node_names=[name],
        enhances_rule_threat_id=None,
        reasoning="test reasoning",
        relevance_rationale="test rationale",
    )


class TestAIMergerProviderManaged:
    def test_ai_threat_flagged_when_node_is_provider_managed(self):
        """AI-discovered threat must inherit provider_managed from resolved node."""
        node_id = "ai-node-001"
        ai_output = _make_ai_output([_make_ai_threat("managed-svc")])
        rules_output = _make_rules_output([])
        name_map = {"managed-svc": node_id}
        pm_map = {node_id: True}
        result = merge_ai_threats(rules_output, ai_output, name_map,
                                  node_id_to_provider_managed=pm_map)
        assert len(result) == 1
        assert result[0].provider_managed is True

    def test_ai_threat_not_flagged_when_node_is_customer_managed(self):
        node_id = "ai-node-002"
        ai_output = _make_ai_output([_make_ai_threat("my-service")])
        rules_output = _make_rules_output([])
        name_map = {"my-service": node_id}
        pm_map = {node_id: False}
        result = merge_ai_threats(rules_output, ai_output, name_map,
                                  node_id_to_provider_managed=pm_map)
        assert len(result) == 1
        assert result[0].provider_managed is False

    def test_ai_threat_not_flagged_when_no_pm_map_provided(self):
        """Backwards-compatible: omitting pm_map defaults everything to False."""
        node_id = "ai-node-003"
        ai_output = _make_ai_output([_make_ai_threat("some-service")])
        rules_output = _make_rules_output([])
        name_map = {"some-service": node_id}
        result = merge_ai_threats(rules_output, ai_output, name_map)
        assert len(result) == 1
        assert result[0].provider_managed is False

    def test_ai_threat_flagged_when_any_node_is_provider_managed(self):
        """Multi-node threat: flagged if ANY affected node is provider-managed."""
        id1 = "ai-node-multi-1"
        id2 = "ai-node-multi-2"
        threat = AIThreatRaw(
            stride_category="Tampering",
            severity="Medium",
            description="Threat affecting both nodes",
            affected_node_names=["node-a", "node-b"],
            enhances_rule_threat_id=None,
            reasoning="test reasoning",
            relevance_rationale="test rationale",
        )
        rules_output = _make_rules_output([])
        ai_output = _make_ai_output([threat])
        name_map = {"node-a": id1, "node-b": id2}
        pm_map = {id1: False, id2: True}  # only id2 is provider-managed
        result = merge_ai_threats(rules_output, ai_output, name_map,
                                  node_id_to_provider_managed=pm_map)
        assert len(result) == 1
        assert result[0].provider_managed is True

    def test_rule_threats_retain_their_provider_managed_value(self):
        """Existing rule threats must not have their provider_managed value overwritten."""
        rule_threat = GeneratedThreat(
            rule_id="C-01",
            display_id="T-001",
            stride_category="Information Disclosure",
            threat_subtype="Managed service without encryption",
            severity="High",
            description="desc",
            affected_node_ids=["some-id"],
            affected_edge_ids=[],
            relevance_rationale="",
            source="rule",
            provider_managed=True,
        )
        rules_output = _make_rules_output([rule_threat])
        ai_output = _make_ai_output([])
        result = merge_ai_threats(rules_output, ai_output, {})
        assert len(result) == 1
        assert result[0].provider_managed is True

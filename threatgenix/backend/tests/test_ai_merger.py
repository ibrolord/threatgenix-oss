"""Tests for B22 AI Threat Merger."""

from __future__ import annotations

from uuid import uuid4


from app.schemas.ai_pass import AIPassOutput, AIThreatRaw
from app.schemas.dfd import DFDNodeResponse
from app.schemas.rules import GeneratedThreat, RuleEngineOutput
from app.services.ai_threat_merger import (
    build_node_name_map,
    merge_ai_threats,
)


# ─── Fixtures ────────────────────────────────────────────────────────


def _make_node(name: str) -> DFDNodeResponse:
    return DFDNodeResponse(
        id=uuid4(),
        node_type="process",
        name=name,
        position_x=0,
        position_y=0,
        trust_boundary_id=None,
        properties={},
    )


def _make_rule_threat(
    display_id: str,
    stride_category: str = "Tampering",
    severity: str = "High",
    node_ids: list[str] | None = None,
) -> GeneratedThreat:
    return GeneratedThreat(
        rule_id="STRIDE-T-001",
        display_id=display_id,
        stride_category=stride_category,
        threat_subtype="Data modification",
        severity=severity,
        description=f"Rule-based threat {display_id}",
        affected_node_ids=node_ids or [],
        affected_edge_ids=[],
        source="Rules",
    )


def _make_rules_output(threats: list[GeneratedThreat]) -> RuleEngineOutput:
    return RuleEngineOutput(
        threats=threats,
        execution_time_ms=10.0,
        rules_evaluated=5,
        rules_fired=len(threats),
    )


def _make_empty_ai_output() -> AIPassOutput:
    return AIPassOutput(
        threats=[],
        model_id="test-model",
        input_tokens=0,
        output_tokens=0,
        latency_ms=0.0,
    )


def _make_ai_output(threats: list[AIThreatRaw]) -> AIPassOutput:
    return AIPassOutput(
        threats=threats,
        model_id="test-model",
        input_tokens=100,
        output_tokens=50,
        latency_ms=500.0,
    )


# ─── Tests: Empty AI output ─────────────────────────────────────────


class TestMergeEmptyAIOutput:
    def test_returns_rule_threats_unchanged(self):
        rule_threats = [
            _make_rule_threat("T-001"),
            _make_rule_threat("T-002", stride_category="Spoofing"),
        ]
        rules_output = _make_rules_output(rule_threats)
        ai_output = _make_empty_ai_output()

        result = merge_ai_threats(rules_output, ai_output, {})

        assert len(result) == 2
        assert result[0].display_id == "T-001"
        assert result[1].display_id == "T-002"
        assert result[0].source == "Rules"
        assert result[1].source == "Rules"

    def test_empty_rules_and_empty_ai(self):
        rules_output = _make_rules_output([])
        ai_output = _make_empty_ai_output()

        result = merge_ai_threats(rules_output, ai_output, {})

        assert result == []


# ─── Tests: New AI threats ───────────────────────────────────────────


class TestMergeNewAIThreats:
    def test_adds_new_ai_threats_with_correct_display_ids(self):
        rule_threats = [
            _make_rule_threat("T-001"),
            _make_rule_threat("T-002"),
        ]
        rules_output = _make_rules_output(rule_threats)
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="API Abuse: Attacker exploits unauthenticated endpoint",
                stride_category="Elevation of Privilege",
                severity="Critical",
                enhances_rule_threat_id=None,
                reasoning="The endpoint lacks auth checks",
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, {})

        assert len(result) == 3
        new_threat = result[2]
        assert new_threat.display_id == "T-003"
        assert new_threat.rule_id == "AI-001"
        assert new_threat.stride_category == "Elevation of Privilege"
        assert new_threat.severity == "Critical"
        assert new_threat.source == "AI"
        assert new_threat.threat_subtype == "API Abuse"
        assert new_threat.affected_edge_ids == []

    def test_display_id_sequencing_from_t005(self):
        """Rules T-001 to T-005, AI starts at T-006."""
        rule_threats = [_make_rule_threat(f"T-{i:03d}") for i in range(1, 6)]
        rules_output = _make_rules_output(rule_threats)
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Session Hijack: Weak token generation",
                stride_category="Spoofing",
                severity="High",
                enhances_rule_threat_id=None,
                reasoning="Tokens lack entropy",
            ),
            AIThreatRaw(
                description="Log Injection: Attacker poisons audit logs",
                stride_category="Repudiation",
                severity="Medium",
                enhances_rule_threat_id=None,
                reasoning="Unsanitized log input",
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, {})

        assert len(result) == 7
        assert result[5].display_id == "T-006"
        assert result[5].rule_id == "AI-001"
        assert result[6].display_id == "T-007"
        assert result[6].rule_id == "AI-002"

    def test_skips_duplicate_ai_threats(self):
        """Same STRIDE category + overlapping node IDs -> duplicate -> skip."""
        node_id = str(uuid4())
        rule_threats = [
            _make_rule_threat(
                "T-001",
                stride_category="Tampering",
                node_ids=[node_id],
            ),
        ]
        rules_output = _make_rules_output(rule_threats)

        node_name = "Payment Service"
        node_name_to_id = {node_name.lower().strip(): node_id}

        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Data Tampering: Attacker modifies data in payment service",
                stride_category="Tampering",
                severity="High",
                enhances_rule_threat_id=None,
                reasoning="Payment data at risk",
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, node_name_to_id)

        # AI threat should be skipped as duplicate
        assert len(result) == 1
        assert result[0].display_id == "T-001"

    def test_does_not_skip_different_stride_category(self):
        """Different STRIDE category -> not a duplicate."""
        node_id = str(uuid4())
        rule_threats = [
            _make_rule_threat(
                "T-001",
                stride_category="Tampering",
                node_ids=[node_id],
            ),
        ]
        rules_output = _make_rules_output(rule_threats)

        node_name = "Payment Service"
        node_name_to_id = {node_name.lower().strip(): node_id}

        ai_output = _make_ai_output([
            AIThreatRaw(
                description="DoS: Attacker floods payment service",
                stride_category="Denial of Service",
                severity="High",
                enhances_rule_threat_id=None,
                reasoning="No rate limiting",
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, node_name_to_id)

        assert len(result) == 2
        assert result[1].stride_category == "Denial of Service"


# ─── Tests: Enrichments ─────────────────────────────────────────────


class TestMergeEnrichments:
    def test_enrichment_appends_ai_insight(self):
        rule_threats = [
            _make_rule_threat("T-001", severity="High"),
        ]
        rules_output = _make_rules_output(rule_threats)
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="In a PCI context this is Critical due to cardholder data exposure",
                stride_category="",
                severity="Critical",
                enhances_rule_threat_id="T-001",
                reasoning="PCI DSS 3.4 requires encryption",
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, {})

        assert len(result) == 1
        assert result[0].description == "Rule-based threat T-001"
        assert result[0].relevance_rationale is not None
        assert "[AI Insight]" in result[0].relevance_rationale
        assert "PCI context" in result[0].relevance_rationale

    def test_enrichment_sets_source_to_ai_rules(self):
        rule_threats = [_make_rule_threat("T-001")]
        rules_output = _make_rules_output(rule_threats)
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Enhanced description with banking context",
                stride_category="",
                severity="",
                enhances_rule_threat_id="T-001",
                reasoning="Relevant to OSFI B-13",
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, {})

        assert result[0].source == "AI+Rules"

    def test_enrichment_does_not_change_severity(self):
        rule_threats = [_make_rule_threat("T-001", severity="Medium")]
        rules_output = _make_rules_output(rule_threats)
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Should be Critical",
                stride_category="",
                severity="Critical",
                enhances_rule_threat_id="T-001",
                reasoning="Higher risk than assessed",
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, {})

        # Severity stays at original value -- enrichments are advisory
        assert result[0].severity == "Medium"

    def test_enrichment_with_nonmatching_display_id_is_skipped(self):
        rule_threats = [_make_rule_threat("T-001")]
        rules_output = _make_rules_output(rule_threats)
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Enhancement for nonexistent threat",
                stride_category="",
                severity="High",
                enhances_rule_threat_id="T-999",
                reasoning="This threat doesn't exist",
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, {})

        assert len(result) == 1
        # Description should be unchanged -- enrichment was skipped
        assert "[AI Insight]" not in result[0].description
        assert not result[0].relevance_rationale
        assert result[0].source == "Rules"

    def test_enrichment_with_conflicting_boundary_name_is_skipped(self):
        rule_threats = [_make_rule_threat("T-001")]
        rule_threats[0] = rule_threats[0].model_copy(
            update={
                "description": (
                    "Rule-based threat T-001 across the Corporate Identity and Core Records Boundary"
                ),
            }
        )
        rules_output = _make_rules_output(rule_threats)
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Enhanced description across the Cloud Operations Platform Boundary",
                stride_category="",
                severity="",
                enhances_rule_threat_id="T-001",
                reasoning="Mismatched boundary context",
            ),
        ])

        result = merge_ai_threats(
            rules_output,
            ai_output,
            {},
            {
                "Corporate Identity and Core Records Boundary",
                "Cloud Operations Platform Boundary",
            },
        )

        assert result[0].description == rule_threats[0].description
        assert result[0].source == "Rules"

    def test_duplicate_enrichment_payload_is_appended_once(self):
        rule_threats = [_make_rule_threat("T-001")]
        rules_output = _make_rules_output(rule_threats)
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Privileged payment flow is high impact",
                stride_category="",
                severity="Critical",
                enhances_rule_threat_id="T-001",
                reasoning="Tampering could trigger unauthorized settlement",
            ),
            AIThreatRaw(
                description="Privileged payment flow is high impact",
                stride_category="",
                severity="Critical",
                enhances_rule_threat_id="T-001",
                reasoning="Tampering could trigger unauthorized settlement",
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, {})

        assert result[0].relevance_rationale is not None
        assert result[0].relevance_rationale.count("[AI Insight]") == 1

    def test_existing_identical_ai_insight_is_not_reappended(self):
        rule_threat = _make_rule_threat("T-001").model_copy(
            update={
                "relevance_rationale": (
                    "Base rationale.\n\n"
                    "[AI Insight] Privileged payment flow is high impact "
                    "Tampering could trigger unauthorized settlement"
                ),
            }
        )
        rules_output = _make_rules_output([rule_threat])
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Privileged payment flow is high impact",
                stride_category="",
                severity="Critical",
                enhances_rule_threat_id="T-001",
                reasoning="Tampering could trigger unauthorized settlement",
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, {})

        assert result[0].relevance_rationale is not None
        assert result[0].relevance_rationale.count("[AI Insight]") == 1

    def test_enrichment_strips_freeform_control_citations(self):
        rule_threats = [_make_rule_threat("T-001")]
        rules_output = _make_rules_output(rule_threats)
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Privileged payment path is high impact",
                stride_category="",
                severity="Critical",
                enhances_rule_threat_id="T-001",
                reasoning=(
                    "This could violate PCI DSS requirements for secure transaction "
                    "handling (Req 3.4) and OSFI B-13 governance (§4.1)."
                ),
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, {})

        assert result[0].relevance_rationale is not None
        assert "Req 3.4" not in result[0].relevance_rationale
        assert "§4.1" not in result[0].relevance_rationale


# ─── Tests: Node name resolution ────────────────────────────────────


class TestNodeNameResolution:
    def test_build_node_name_map(self):
        nodes = [_make_node("Web Server"), _make_node("Database")]
        name_map = build_node_name_map(nodes)

        assert "web server" in name_map
        assert "database" in name_map
        assert name_map["web server"] == str(nodes[0].id)
        assert name_map["database"] == str(nodes[1].id)

    def test_case_insensitive_resolution(self):
        node = _make_node("Payment Gateway")
        node_id = str(node.id)
        name_map = build_node_name_map([node])

        # AI might refer to it in different casing
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Bypass: Attacker bypasses PAYMENT GATEWAY validation",
                stride_category="Elevation of Privilege",
                severity="High",
                enhances_rule_threat_id=None,
                reasoning="Missing input validation",
            ),
        ])
        rules_output = _make_rules_output([])

        result = merge_ai_threats(rules_output, ai_output, name_map)

        assert len(result) == 1
        assert node_id in result[0].affected_node_ids

    def test_unknown_node_names_are_skipped(self):
        """AI references a node name not in the DFD -- no node IDs resolved."""
        name_map = {"web server": str(uuid4())}
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Attack on Unknown Service that doesn't exist",
                stride_category="Spoofing",
                severity="Medium",
                enhances_rule_threat_id=None,
                reasoning="Hypothetical",
            ),
        ])
        rules_output = _make_rules_output([])

        result = merge_ai_threats(rules_output, ai_output, name_map)

        assert len(result) == 1
        assert result[0].affected_node_ids == []

    def test_structured_affected_node_names_are_used_before_description_scanning(self):
        node = _make_node("Privileged Access Broker")
        node_id = str(node.id)
        name_map = build_node_name_map([node])
        ai_output = _make_ai_output([
            AIThreatRaw(
                description="Operational control abuse without exact node mention",
                stride_category="Elevation of Privilege",
                severity="High",
                enhances_rule_threat_id=None,
                reasoning="Privilege escalation path",
                affected_node_names=["Privileged Access Broker"],
            ),
        ])

        result = merge_ai_threats(_make_rules_output([]), ai_output, name_map)

        assert len(result) == 1
        assert result[0].affected_node_ids == [node_id]


# ─── Tests: Combined scenarios ───────────────────────────────────────


class TestMergeCombined:
    def test_new_threats_and_enrichments_together(self):
        node = _make_node("Auth Service")
        node_id = str(node.id)
        name_map = build_node_name_map([node])

        rule_threats = [
            _make_rule_threat("T-001", stride_category="Spoofing", node_ids=[node_id]),
            _make_rule_threat("T-002", stride_category="Tampering"),
        ]
        rules_output = _make_rules_output(rule_threats)

        ai_output = _make_ai_output([
            # Enrichment for T-001
            AIThreatRaw(
                description="Banking-specific credential stuffing risk",
                stride_category="",
                severity="Critical",
                enhances_rule_threat_id="T-001",
                reasoning="High-value target",
            ),
            # New threat (different STRIDE from existing)
            AIThreatRaw(
                description="Log Forgery: Attacker modifies auth service logs",
                stride_category="Repudiation",
                severity="Medium",
                enhances_rule_threat_id=None,
                reasoning="Audit trail compromise",
            ),
        ])

        result = merge_ai_threats(rules_output, ai_output, name_map)

        # 2 original + 1 new = 3
        assert len(result) == 3

        # T-001 enriched
        assert result[0].source == "AI+Rules"
        assert result[0].description == "Rule-based threat T-001"
        assert result[0].relevance_rationale is not None
        assert "[AI Insight]" in result[0].relevance_rationale

        # T-002 unchanged
        assert result[1].source == "Rules"

        # New AI threat
        assert result[2].display_id == "T-003"
        assert result[2].source == "AI"
        assert result[2].stride_category == "Repudiation"
        assert node_id in result[2].affected_node_ids

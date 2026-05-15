"""Tests for B21 AI Enhancement Service."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4


from app.schemas.ai_pass import AIPassOutput, AIThreatRaw
from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.schemas.rules import GeneratedThreat, RuleEngineOutput
from app.services.ai_enhancement import (
    VALID_STRIDE_CATEGORIES,
    _build_regulatory_context,
    _enhance_sync,
    _filter_ai_threats_by_regulatory_scope,
    _parse_enhancement_response,
    _summarize_nodes,
    build_ai_pass_input,
    enhance_threats,
)


# ─── Fixtures ────────────────────────────────────────────────────────


def _make_dfd() -> DFDResponse:
    """Create a minimal DFD for testing."""
    node1_id = uuid4()
    node2_id = uuid4()
    node3_id = uuid4()
    return DFDResponse(
        nodes=[
            DFDNodeResponse(
                id=node1_id,
                node_type="process",
                name="API Gateway",
                position_x=0,
                position_y=0,
                trust_boundary_id=None,
                properties={},
            ),
            DFDNodeResponse(
                id=node2_id,
                node_type="data_store",
                name="Customer Database",
                position_x=100,
                position_y=0,
                trust_boundary_id=None,
                properties={},
            ),
            DFDNodeResponse(
                id=node3_id,
                node_type="external_entity",
                name="Mobile App User",
                position_x=200,
                position_y=0,
                trust_boundary_id=None,
                properties={},
            ),
        ],
        edges=[
            DFDEdgeResponse(
                id=uuid4(),
                source_node_id=node1_id,
                target_node_id=node2_id,
                label="query customer data",
                properties={},
            ),
        ],
        trust_boundaries=[
            TrustBoundaryResponse(
                id=uuid4(),
                name="PCI CDE",
                node_ids=[node1_id, node2_id],
            ),
        ],
    )


def _make_rules_output() -> RuleEngineOutput:
    """Create a minimal RuleEngineOutput for testing."""
    node_id = str(uuid4())
    edge_id = str(uuid4())
    return RuleEngineOutput(
        threats=[
            GeneratedThreat(
                rule_id="S-01",
                display_id="T-001",
                stride_category="Spoofing",
                threat_subtype="Identity Spoofing",
                severity="High",
                description="An attacker could spoof the API Gateway identity",
                affected_node_ids=[node_id],
                affected_edge_ids=[edge_id],
                source="Rules",
            ),
        ],
        execution_time_ms=15.0,
        rules_evaluated=20,
        rules_fired=1,
    )


def _make_bedrock_tool_response() -> dict:
    """Simulate a successful Bedrock tool_use response."""
    return {
        "new_threats": [
            {
                "title": "Race Condition in Balance Update",
                "stride_category": "Tampering",
                "severity": "Critical",
                "description": (
                    "Concurrent transactions could exploit a race condition "
                    "in the Customer Database balance update path"
                ),
                "affected_node_names": ["Customer Database", "API Gateway"],
                "rationale": (
                    "The DFD shows direct data flow from API Gateway to "
                    "Customer Database without explicit transaction isolation"
                ),
            },
            {
                "title": "Missing Audit Trail for Data Access",
                "stride_category": "Repudiation",
                "severity": "High",
                "description": (
                    "No evidence of audit logging for customer data queries "
                    "through the API Gateway"
                ),
                "affected_node_names": ["API Gateway"],
                "rationale": (
                    "Privileged and sensitive data access should be "
                    "reconstructable during investigations"
                ),
            },
        ],
        "enrichments": [
            {
                "original_display_id": "T-001",
                "enhanced_description": (
                    "An attacker could spoof the API Gateway identity by "
                    "exploiting missing mutual TLS between Mobile App User "
                    "and API Gateway, potentially accessing protected "
                    "customer data resources"
                ),
                "suggested_severity": "Critical",
                "rationale": (
                    "Severity elevated to Critical because the API Gateway "
                    "sits on a high-impact path to sensitive customer data"
                ),
            },
        ],
    }


# ─── Tests ───────────────────────────────────────────────────────────


class TestBuildAIPassInput:
    """Tests for build_ai_pass_input."""

    def test_produces_correct_structure(self):
        dfd = _make_dfd()
        rules_output = _make_rules_output()
        doc_excerpt = "This is a sample banking system design document."

        result = build_ai_pass_input(dfd, rules_output, doc_excerpt)

        assert result.dfd is dfd
        assert len(result.rules_threats) == 1
        assert result.rules_threats[0].display_id == "T-001"
        assert result.rules_threats[0].stride_category == "Spoofing"
        assert result.doc_excerpt == doc_excerpt
        # Falls back to DFD inference when no system_name provided
        assert result.system_name == "API Gateway"

    def test_uses_threat_model_fields_when_provided(self):
        """ThreatModel context overrides DFD-based inference."""
        dfd = _make_dfd()
        rules_output = _make_rules_output()

        result = build_ai_pass_input(
            dfd,
            rules_output,
            "test",
            system_name="Open Banking API",
            description="Customer-facing open banking platform",
            data_classification="Restricted",
            regulatory_scope=["OSFI B-13", "PCI DSS", "PIPEDA"],
            deployment_model="cloud",
        )

        assert result.system_name == "Open Banking API"
        assert result.description == "Customer-facing open banking platform"
        assert result.data_classification == "Restricted"
        assert result.regulatory_scope == ["OSFI B-13", "PCI DSS", "PIPEDA"]
        assert result.deployment_model == "cloud"

    def test_carries_environment_context_summary(self):
        dfd = _make_dfd()
        rules_output = _make_rules_output()

        result = build_ai_pass_input(
            dfd,
            rules_output,
            "test",
            environment_context_summary="## Repository Evidence\n- Frameworks: FastAPI, React",
        )

        assert "Repository Evidence" in result.environment_context_summary
        assert "FastAPI" in result.environment_context_summary

    def test_truncates_doc_excerpt_at_4000(self):
        dfd = _make_dfd()
        rules_output = _make_rules_output()
        long_excerpt = "x" * 5000

        result = build_ai_pass_input(dfd, rules_output, long_excerpt)

        assert len(result.doc_excerpt) == 4000

    def test_default_system_name_when_no_processes(self):
        dfd = DFDResponse(
            nodes=[
                DFDNodeResponse(
                    id=uuid4(),
                    node_type="data_store",
                    name="Some DB",
                    position_x=0,
                    position_y=0,
                    trust_boundary_id=None,
                    properties={},
                ),
            ],
            edges=[],
            trust_boundaries=[],
        )
        rules_output = RuleEngineOutput(
            threats=[], execution_time_ms=1.0, rules_evaluated=0, rules_fired=0
        )

        result = build_ai_pass_input(dfd, rules_output, "")

        assert result.system_name == "Unknown System"

    def test_default_data_classification(self):
        """Default classification is Confidential when not provided."""
        dfd = DFDResponse(
            nodes=[
                DFDNodeResponse(
                    id=uuid4(),
                    node_type="process",
                    name="Service A",
                    position_x=0,
                    position_y=0,
                    trust_boundary_id=None,
                    properties={},
                ),
            ],
            edges=[],
            trust_boundaries=[],
        )
        rules_output = RuleEngineOutput(
            threats=[], execution_time_ms=1.0, rules_evaluated=0, rules_fired=0
        )

        result = build_ai_pass_input(dfd, rules_output, "")

        assert result.data_classification == "Confidential"


class TestSummarizeNodes:
    def test_missing_properties_are_not_rendered_as_gaps(self):
        dfd = _make_dfd()

        summary = _summarize_nodes(dfd)

        assert "NO auth" not in summary
        assert "NO input validation" not in summary
        assert "NO encryption" not in summary
        assert "NOT encrypted at rest" not in summary
        assert "NO backup" not in summary
        assert "UNTRUSTED" not in summary
        assert "UNAUTHENTICATED" not in summary

    def test_explicit_false_properties_are_rendered_as_gaps(self):
        dfd = DFDResponse(
            nodes=[
                DFDNodeResponse(
                    id=uuid4(),
                    node_type="process",
                    name="AML Screening Service",
                    position_x=0,
                    position_y=0,
                    trust_boundary_id=None,
                    properties={
                        "uses_auth": False,
                        "validates_input": False,
                        "uses_encryption": False,
                    },
                ),
            ],
            edges=[],
            trust_boundaries=[],
        )

        summary = _summarize_nodes(dfd)

        assert "NO auth" in summary
        assert "NO input validation" in summary
        assert "NO encryption" in summary


class TestParseEnhancementResponse:
    """Tests for _parse_enhancement_response."""

    def test_parses_valid_response(self):
        tool_output = _make_bedrock_tool_response()
        threats = _parse_enhancement_response(tool_output)

        # 2 new threats + 1 enrichment = 3 total
        assert len(threats) == 3

        # First new threat
        assert "Race Condition" in threats[0].description
        assert threats[0].stride_category == "Tampering"
        assert threats[0].severity == "Critical"
        assert threats[0].enhances_rule_threat_id is None

        # Enrichment
        enrichment = threats[2]
        assert enrichment.enhances_rule_threat_id == "T-001"
        assert "mutual TLS" in enrichment.description
        assert threats[0].affected_node_names == ["Customer Database", "API Gateway"]

    def test_filters_citations_when_not_grounded_by_intel_context(self):
        tool_output = {
            "new_threats": [
                {
                    "title": "Ungrounded Citation Threat",
                    "stride_category": "Tampering",
                    "severity": "High",
                    "description": "Attacker tampers with workflow state",
                    "affected_node_names": ["API Gateway"],
                    "rationale": "reason",
                    "relevance_rationale": "relevance",
                    "attack_technique_ids": ["T1078"],
                    "capec_ids": ["CAPEC-151"],
                    "cwe_ids": ["CWE-287"],
                },
            ],
            "enrichments": [],
        }

        threats = _parse_enhancement_response(
            tool_output,
            allowed_reference_ids=set(),
        )

        assert len(threats) == 1
        assert "[References:" not in threats[0].description

    def test_skips_invalid_stride_category(self):
        tool_output = {
            "new_threats": [
                {
                    "title": "Bad Threat",
                    "stride_category": "InvalidCategory",
                    "severity": "High",
                    "description": "test",
                    "affected_node_names": ["X"],
                    "rationale": "test",
                },
            ],
            "enrichments": [],
        }
        threats = _parse_enhancement_response(tool_output)
        assert len(threats) == 0

    def test_skips_invalid_severity(self):
        tool_output = {
            "new_threats": [
                {
                    "title": "Bad Threat",
                    "stride_category": "Spoofing",
                    "severity": "Ultra",
                    "description": "test",
                    "affected_node_names": ["X"],
                    "rationale": "test",
                },
            ],
            "enrichments": [],
        }
        threats = _parse_enhancement_response(tool_output)
        assert len(threats) == 0

    def test_skips_malformed_items(self):
        tool_output = {
            "new_threats": [
                {"title": "Missing required fields"},
            ],
            "enrichments": [
                {"not_a_valid_field": "value"},
            ],
        }
        threats = _parse_enhancement_response(tool_output)
        assert len(threats) == 0

    def test_empty_response(self):
        threats = _parse_enhancement_response({"new_threats": [], "enrichments": []})
        assert threats == []

    def test_dedupes_identical_enrichments(self):
        tool_output = {
            "new_threats": [],
            "enrichments": [
                {
                    "original_display_id": "T-001",
                    "enhanced_description": "Privileged payment flow is high impact",
                    "suggested_severity": "Critical",
                    "rationale": "Tampering could trigger unauthorized settlement",
                },
                {
                    "original_display_id": " T-001 ",
                    "enhanced_description": "Privileged   payment flow is high impact",
                    "suggested_severity": "Critical",
                    "rationale": "Tampering could trigger unauthorized   settlement",
                },
            ],
        }

        threats = _parse_enhancement_response(tool_output)

        assert len(threats) == 1
        assert threats[0].enhances_rule_threat_id == "T-001"

    def test_new_threats_have_valid_stride_categories(self):
        tool_output = _make_bedrock_tool_response()
        threats = _parse_enhancement_response(tool_output)

        for t in threats:
            if t.enhances_rule_threat_id is None:
                # New threat -- must have a valid STRIDE category
                assert t.stride_category in VALID_STRIDE_CATEGORIES, (
                    f"Invalid STRIDE category: {t.stride_category}"
                )


class TestRegulatoryScopeFiltering:
    def test_drops_new_ai_threats_with_out_of_scope_frameworks(self):
        threats = [
            AIThreatRaw(
                description="PCI DSS Data Minimization Non-Compliance: PCI DSS data minimization non-compliance",
                stride_category="Information Disclosure",
                severity="Critical",
                reasoning="PCI DSS Requirement 3.2 applies here.",
                relevance_rationale="PCI DSS penalties could apply.",
                affected_node_names=["Customer Database"],
            ),
            AIThreatRaw(
                description="NIST logging gap on privileged workflow",
                stride_category="Repudiation",
                severity="High",
                reasoning="NIST monitoring expectations apply.",
                relevance_rationale="NIST-aligned logging would improve accountability.",
                affected_node_names=["API Gateway"],
            ),
        ]

        filtered = _filter_ai_threats_by_regulatory_scope(
            threats,
            ["NIST", "ISO 27001"],
        )

        assert len(filtered) == 1
        assert filtered[0].description == "NIST logging gap on privileged workflow"

    def test_drops_named_framework_threats_when_no_scope_is_selected(self):
        threats = [
            AIThreatRaw(
                description="PCI DSS network segmentation gap",
                stride_category="Tampering",
                severity="High",
                reasoning="PCI DSS segmentation evidence is missing.",
                relevance_rationale="The named PCI scope is unsupported here.",
                affected_node_names=["API Gateway"],
            ),
        ]

        filtered = _filter_ai_threats_by_regulatory_scope(threats, [])

        assert filtered == []


class TestEnhanceSync:
    """Tests for _enhance_sync with mocked BedrockClient."""

    def test_returns_parsed_output_on_success(self):
        mock_client = MagicMock()
        mock_client.model_name = "anthropic.claude-3-sonnet-test"
        mock_client.call_with_tools.return_value = _make_bedrock_tool_response()

        dfd = _make_dfd()
        rules_output = _make_rules_output()
        ai_input = build_ai_pass_input(dfd, rules_output, "test excerpt")

        result = _enhance_sync(ai_input, client=mock_client)

        assert isinstance(result.output, AIPassOutput)
        assert len(result.output.threats) == 3  # 2 new + 1 enrichment
        assert result.output.model_id == "anthropic.claude-3-sonnet-test"
        assert result.output.latency_ms > 0
        assert result.warning is None
        mock_client.call_with_tools.assert_called_once()

    def test_includes_environment_context_block_when_present(self):
        mock_client = MagicMock()
        mock_client.model_name = "anthropic.claude-3-sonnet-test"
        mock_client.call_with_tools.return_value = _make_bedrock_tool_response()

        ai_input = build_ai_pass_input(
            _make_dfd(),
            _make_rules_output(),
            "test excerpt",
            environment_context_summary="## Repository Evidence\n- Frameworks: FastAPI",
        )

        _enhance_sync(ai_input, client=mock_client)

        system_message = mock_client.call_with_tools.call_args.kwargs["system_message"]
        user_message = mock_client.call_with_tools.call_args.kwargs["user_message"]
        assert "explicitly name the concrete signal" in system_message
        assert "## Environment Evidence" in user_message
        assert "Frameworks: FastAPI" in user_message

    def test_omits_environment_context_block_when_empty(self):
        mock_client = MagicMock()
        mock_client.model_name = "anthropic.claude-3-sonnet-test"
        mock_client.call_with_tools.return_value = _make_bedrock_tool_response()

        ai_input = build_ai_pass_input(
            _make_dfd(),
            _make_rules_output(),
            "test excerpt",
        )

        _enhance_sync(ai_input, client=mock_client)

        user_message = mock_client.call_with_tools.call_args.kwargs["user_message"]
        assert "## Environment Evidence" not in user_message

    def test_retries_once_on_first_failure(self):
        mock_client = MagicMock()
        mock_client.model_name = "test-model"
        mock_client.call_with_tools.side_effect = [
            None,  # first attempt fails
            _make_bedrock_tool_response(),  # retry succeeds
        ]

        dfd = _make_dfd()
        rules_output = _make_rules_output()
        ai_input = build_ai_pass_input(dfd, rules_output, "test")

        result = _enhance_sync(ai_input, client=mock_client)

        assert len(result.output.threats) == 3
        assert result.warning is not None
        assert mock_client.call_with_tools.call_count == 2

    def test_returns_empty_on_both_failures(self):
        mock_client = MagicMock()
        mock_client.model_name = "test-model"
        mock_client.call_with_tools.return_value = None

        dfd = _make_dfd()
        rules_output = _make_rules_output()
        ai_input = build_ai_pass_input(dfd, rules_output, "test")

        result = _enhance_sync(ai_input, client=mock_client)

        assert isinstance(result.output, AIPassOutput)
        assert len(result.output.threats) == 0
        assert result.warning is not None
        assert mock_client.call_with_tools.call_count == 2


class TestEnhanceThreatsAsync:
    """Tests for the async enhance_threats entry point."""

    def test_returns_empty_on_timeout(self):
        """enhance_threats returns empty AIPassOutput on timeout."""
        mock_client = MagicMock()
        mock_client.model_name = "test-model"

        # Make call_with_tools block long enough to trigger timeout
        import time

        def slow_call(**kwargs):
            time.sleep(5)
            return _make_bedrock_tool_response()

        mock_client.call_with_tools.side_effect = slow_call

        dfd = _make_dfd()
        rules_output = _make_rules_output()

        with patch("app.services.ai_enhancement.settings") as mock_settings:
            mock_settings.bedrock_timeout_seconds = 0.1
            mock_settings.bedrock_model_id = "test-model"
            result, skip_reason = asyncio.get_event_loop().run_until_complete(
                enhance_threats(dfd, rules_output, "test", client=mock_client)
            )

        assert isinstance(result, AIPassOutput)
        assert len(result.threats) == 0
        assert skip_reason is not None

    def test_returns_empty_on_bedrock_failure(self):
        """enhance_threats returns empty AIPassOutput when Bedrock fails."""
        mock_client = MagicMock()
        mock_client.model_name = "test-model"
        mock_client.call_with_tools.return_value = None

        dfd = _make_dfd()
        rules_output = _make_rules_output()

        result, skip_reason = asyncio.get_event_loop().run_until_complete(
            enhance_threats(dfd, rules_output, "test", client=mock_client)
        )

        assert isinstance(result, AIPassOutput)
        assert len(result.threats) == 0
        assert skip_reason is not None

    def test_returns_empty_on_unexpected_exception(self):
        """enhance_threats returns empty AIPassOutput on unexpected errors."""
        mock_client = MagicMock()
        mock_client.model_name = "test-model"
        mock_client.call_with_tools.side_effect = RuntimeError("boom")

        dfd = _make_dfd()
        rules_output = _make_rules_output()

        result, skip_reason = asyncio.get_event_loop().run_until_complete(
            enhance_threats(dfd, rules_output, "test", client=mock_client)
        )

        assert isinstance(result, AIPassOutput)
        assert len(result.threats) == 0
        assert skip_reason is not None

    def test_success_path(self):
        """enhance_threats returns parsed threats on success."""
        mock_client = MagicMock()
        mock_client.model_name = "test-model"
        mock_client.call_with_tools.return_value = _make_bedrock_tool_response()

        dfd = _make_dfd()
        rules_output = _make_rules_output()

        result, skip_reason = asyncio.get_event_loop().run_until_complete(
            enhance_threats(dfd, rules_output, "test doc", client=mock_client)
        )

        assert isinstance(result, AIPassOutput)
        assert len(result.threats) == 3
        assert skip_reason is None

    def test_success_path_with_retry_returns_warning(self):
        """enhance_threats should keep AI threats and expose retry degradation."""
        mock_client = MagicMock()
        mock_client.model_name = "test-model"
        mock_client.call_with_tools.side_effect = [
            None,
            _make_bedrock_tool_response(),
        ]

        dfd = _make_dfd()
        rules_output = _make_rules_output()

        result, skip_reason = asyncio.get_event_loop().run_until_complete(
            enhance_threats(dfd, rules_output, "test doc", client=mock_client)
        )

        assert len(result.threats) == 3
        assert skip_reason is not None
        assert "retrying a failed model response" in skip_reason

    def test_success_path_with_threat_intel_warning_returns_warning(self):
        """Threat-intel degradation should surface even when AI still succeeds."""
        mock_client = MagicMock()
        mock_client.model_name = "test-model"
        mock_client.call_with_tools.return_value = _make_bedrock_tool_response()

        fake_intel_ctx = MagicMock()
        fake_intel_ctx.to_prompt_context.return_value = ""
        fake_intel_ctx.unavailable_reason = "pgvector type unavailable"
        fake_intel_ctx.attack_techniques = []
        fake_intel_ctx.attack_patterns = []
        fake_intel_ctx.weaknesses = []
        fake_intel_ctx.advisories = []
        fake_intel_ctx.kev_matches = []
        fake_intel_ctx.cri_controls = []

        dfd = _make_dfd()
        rules_output = _make_rules_output()

        with patch(
            "app.services.threat_intel.retrieval.retrieve_threat_intel",
            new_callable=AsyncMock,
            return_value=fake_intel_ctx,
        ):
            result, skip_reason = asyncio.get_event_loop().run_until_complete(
                enhance_threats(
                    dfd, rules_output, "test doc", client=mock_client, db=MagicMock()
                )
            )

        assert len(result.threats) == 3
        assert skip_reason is not None
        assert "Threat intelligence unavailable" in skip_reason


class TestBuildRegulatoryContext:
    """Tests for _build_regulatory_context."""

    def test_empty_when_no_scope(self):
        result = _build_regulatory_context([], None)
        assert result == ""

    def test_includes_osfi_catalog(self):
        result = _build_regulatory_context(["OSFI B-13"], None)
        assert "OSFI B-13" in result
        assert "B-13 §4.1" in result

    def test_includes_multiple_frameworks(self):
        result = _build_regulatory_context(["OSFI B-13", "PCI DSS", "PIPEDA"], None)
        assert "OSFI B-13" in result
        assert "PCI DSS" in result
        assert "PIPEDA" in result
        assert "Req 1.3" in result  # PCI specific
        assert "Principle 3" in result  # PIPEDA specific

    def test_includes_deployment_model(self):
        result = _build_regulatory_context([], "cloud")
        assert "Cloud Deployment Threats" in result
        assert "IAM policies" in result

    def test_combined_regulatory_and_deployment(self):
        result = _build_regulatory_context(["FINTRAC"], "hybrid")
        assert "FINTRAC" in result
        assert "Hybrid Deployment Threats" in result

    def test_unknown_framework_gets_generic_entry(self):
        result = _build_regulatory_context(["SOC 2"], None)
        assert "SOC 2" in result
        assert "Identify threats relevant to SOC 2 compliance" in result

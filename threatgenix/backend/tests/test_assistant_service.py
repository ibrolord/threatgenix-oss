from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

from app.schemas.assistant import AssistantRequest
from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.schemas.security_review import (
    SecurityReviewApplicationSummary,
    SecurityReviewCoverageSummary,
    SecurityReviewDeltaSummary,
    SecurityReviewFinding,
    SecurityReviewFindingListResponse,
)
from app.schemas.threat import ThreatResponse
from app.services.assistant import respond_to_assistant_request


def _build_review_dfd() -> tuple[DFDResponse, str, str]:
    external_id = uuid4()
    api_id = uuid4()
    db_id = uuid4()
    orphan_id = uuid4()
    edge_ingress_id = uuid4()
    edge_db_id = uuid4()

    dfd = DFDResponse(
        nodes=[
            DFDNodeResponse(
                id=external_id,
                node_type="external_entity",
                name="End User",
                position_x=0,
                position_y=0,
                trust_boundary_id=None,
                properties={},
            ),
            DFDNodeResponse(
                id=api_id,
                node_type="process",
                name="API Gateway",
                position_x=160,
                position_y=0,
                trust_boundary_id=None,
                properties={"uses_auth": False, "validates_input": False},
            ),
            DFDNodeResponse(
                id=db_id,
                node_type="data_store",
                name="Customer DB",
                position_x=320,
                position_y=0,
                trust_boundary_id=None,
                properties={},
            ),
            DFDNodeResponse(
                id=orphan_id,
                node_type="process",
                name="Report Worker",
                position_x=320,
                position_y=160,
                trust_boundary_id=None,
                properties={},
            ),
        ],
        edges=[
            DFDEdgeResponse(
                id=edge_ingress_id,
                source_node_id=external_id,
                target_node_id=api_id,
                label="",
                properties={},
            ),
            DFDEdgeResponse(
                id=edge_db_id,
                source_node_id=api_id,
                target_node_id=db_id,
                label="query customer data",
                properties={},
            ),
        ],
        trust_boundaries=[],
    )
    return dfd, str(api_id), str(edge_ingress_id)


def _build_threat(node_id: str, edge_id: str) -> ThreatResponse:
    return ThreatResponse(
        id=uuid4(),
        display_id="T-001",
        description="Spoofing risk at the API gateway ingress.",
        stride_category="Spoofing",
        threat_subtype="Identity spoofing across trust boundary",
        severity="High",
        source="Rules",
        status="Open",
        dismiss_reason=None,
        rule_id="S-04",
        ai_enhanced=False,
        provider_managed=False,
        original_rule_threat_id=None,
        affected_node_ids=[node_id],
        affected_edge_ids=[edge_id],
        relevance_rationale="The ingress edge reaches API Gateway without authentication enabled.",
        mitigation_plan=None,
        mitigation_owner=None,
        due_date=None,
        mitigation_notes=None,
        closed_at=None,
        compliance_controls=[],
        created_at=datetime.now(timezone.utc),
    )


def _build_review_summary() -> SecurityReviewApplicationSummary:
    return SecurityReviewApplicationSummary(
        generated_at="2026-04-22T00:00:00Z",
        system_name="Northstar Bank",
        overall_priority="p1_now",
        overall_action_bucket="engineer_now",
        focus_statement="Fix the externally reachable identity path before treating hardening or evidence follow-up as the next move.",
        rationale=["Externally reachable trust-boundary crossing reaches a privileged asset."],
        next_steps=["Require authentication at the API ingress and verify the control in evidence."],
        coverage=SecurityReviewCoverageSummary(
            total_findings=1,
            threat_findings=1,
            systemic_findings=0,
            open_threats=1,
            public_entry_points=1,
            privileged_surfaces=1,
            restricted_assets=1,
            attack_paths=1,
            attached_evidence_sources=2,
            missing_evidence_sources=1,
        ),
        review_delta_summary=SecurityReviewDeltaSummary(new_findings=1),
    )


def _build_review_findings(threat_id: str, display_id: str) -> SecurityReviewFindingListResponse:
    finding = SecurityReviewFinding(
        id=f"threat:{threat_id}",
        source_object_type="threat",
        source_object_id=threat_id,
        threat_id=threat_id,
        display_id=display_id,
        wire_kind="threat",
        display_kind="threat",
        source_provenance="rules_engine",
        title="Spoofed caller identity",
        priority="p1_now",
        numeric_score=92,
        wire_action_bucket="engineer_now",
        queue_bucket="fix_now",
        computed_queue_bucket="fix_now",
        truth_status="validated",
        exploitability="high",
        urgency="immediate",
        business_impact="high",
        regulatory_pressure="high",
        confidence="high",
        is_real=True,
        is_urgent=True,
        is_exploitable_in_context=True,
        is_regulatory_or_control_relevant=True,
        needs_engineering_change=True,
        needs_evidence=False,
        why_now="The boundary-crossing ingress reaches the API without authentication.",
        impacted_assets=["API Gateway"],
        entry_point="End User",
        evidence_refs=["dfd", "cloud"],
        linked_threat_ids=[threat_id],
        linked_change_ids=[],
        linked_control_ids=[],
        owner=None,
        due_at=None,
        note=None,
        review_status="open",
        last_non_terminal_bucket=None,
        primary_mode="findings",
        noise_disposition="focus",
        computed_recommendation_changed=False,
        systemic=False,
        next_best_action="Require authentication at the API ingress and capture the verification evidence.",
        next_step="Require authentication at the API ingress and capture the verification evidence.",
        rationale_excerpt="Validated by the current DFD and evidence set.",
    )
    return SecurityReviewFindingListResponse(
        generated_at="2026-04-22T00:00:00Z",
        system_name="Northstar Bank",
        default_finding_id=finding.id,
        findings=[finding],
    )


def test_review_returns_grounded_findings():
    dfd, _, _ = _build_review_dfd()

    response = respond_to_assistant_request(
        request=AssistantRequest(message="/review review this DFD"),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[],
        environment_context_summary=None,
    )

    assert response.mode == "review"
    assert response.findings
    assert any("trust boundar" in finding.title.lower() for finding in response.findings)
    assert any("orphan" in finding.title.lower() for finding in response.findings)


def test_review_prefers_deterministic_security_review_queue_when_available() -> None:
    dfd, api_node_id, edge_id = _build_review_dfd()
    threat = _build_threat(api_node_id, edge_id)
    review_summary = _build_review_summary()
    review_findings = _build_review_findings(str(threat.id), threat.display_id)

    response = respond_to_assistant_request(
        request=AssistantRequest(message="/review what matters now?"),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[threat],
        environment_context_summary=None,
        review_summary=review_summary,
        review_findings=review_findings,
    )

    assert response.mode == "review"
    assert "Fix Now" in response.answer
    assert "Spoofed caller identity" in response.answer
    assert response.findings
    assert response.findings[0].title == "Spoofed caller identity"


def test_review_truncates_long_queue_finding_titles_for_assistant_schema() -> None:
    dfd, api_node_id, edge_id = _build_review_dfd()
    threat = _build_threat(api_node_id, edge_id)
    review_summary = _build_review_summary()
    review_findings = _build_review_findings(str(threat.id), threat.display_id)
    long_title = (
        "T-026: The HTTPS request flow from a third-party integration crosses the "
        "external network trust boundary as a privileged control plane action that "
        "could grant elevated access."
    )
    review_findings.findings[0] = review_findings.findings[0].model_copy(
        update={"title": long_title}
    )

    response = respond_to_assistant_request(
        request=AssistantRequest(message="/review summarize the top review risk"),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[threat],
        environment_context_summary=None,
        review_summary=review_summary,
        review_findings=review_findings,
    )

    assert response.mode == "review"
    assert response.findings
    assert len(response.findings[0].title) <= 160
    assert response.findings[0].title.endswith("...")


def test_review_truncates_long_queue_copy_for_assistant_schema() -> None:
    dfd, api_node_id, edge_id = _build_review_dfd()
    threat = _build_threat(api_node_id, edge_id)
    review_summary = _build_review_summary()
    review_findings = _build_review_findings(str(threat.id), threat.display_id)
    review_findings.findings[0] = review_findings.findings[0].model_copy(
        update={
            "why_now": " ".join(
                [
                    "The finding remains in Fix Now because the externally reachable payment callback "
                    "can reach privileged ledger operations without a current verification record."
                ]
                * 40
            ),
            "next_best_action": " ".join(
                ["Add an enforced authentication control and attach runtime proof."] * 30
            ),
        }
    )

    response = respond_to_assistant_request(
        request=AssistantRequest(message="/review summarize the top review risk"),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[threat],
        environment_context_summary=None,
        review_summary=review_summary,
        review_findings=review_findings,
    )

    assert response.mode == "review"
    assert response.findings
    assert len(response.findings[0].description) <= 1200
    assert response.findings[0].description.endswith("...")


def test_review_can_focus_on_selected_review_finding() -> None:
    dfd, api_node_id, edge_id = _build_review_dfd()
    threat = _build_threat(api_node_id, edge_id)
    review_summary = _build_review_summary()
    review_findings = _build_review_findings(str(threat.id), threat.display_id)
    selected_finding = review_findings.findings[0]

    response = respond_to_assistant_request(
        request=AssistantRequest(
            message="/review explain this finding",
            review_finding_id=selected_finding.id,
        ),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[threat],
        environment_context_summary=None,
        review_summary=review_summary,
        review_findings=review_findings,
    )

    assert response.mode == "review"
    assert "Spoofed caller identity" in response.answer
    assert "real" in response.answer
    assert "Next best action" in response.answer


def test_review_can_draft_structured_artifact_for_selected_finding() -> None:
    dfd, api_node_id, edge_id = _build_review_dfd()
    threat = _build_threat(api_node_id, edge_id)
    review_summary = _build_review_summary()
    review_findings = _build_review_findings(str(threat.id), threat.display_id)
    selected_finding = review_findings.findings[0]

    response = respond_to_assistant_request(
        request=AssistantRequest(
            message="/review draft the next step note for this finding",
            review_finding_id=selected_finding.id,
        ),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[threat],
        environment_context_summary=None,
        review_summary=review_summary,
        review_findings=review_findings,
    )

    assert response.mode == "review"
    assert len(response.action_artifacts) == 1
    artifact = response.action_artifacts[0]
    assert artifact.kind == "remediation_note"
    assert artifact.review_finding_id == selected_finding.id
    assert artifact.source_object_type == "threat"
    assert "Why now" in artifact.body
    assert artifact.references


def test_explain_threat_returns_rule_and_suggestions():
    dfd, api_node_id, edge_id = _build_review_dfd()
    threat = _build_threat(api_node_id, edge_id)

    response = respond_to_assistant_request(
        request=AssistantRequest(
            message="/explain why did this threat fire?",
            anchor={"kind": "threat", "id": threat.id},
        ),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[threat],
        environment_context_summary=None,
    )

    assert response.mode == "explain"
    assert "T-001" in response.answer
    assert "S-04" in response.answer
    assert any(reference.kind == "threat" for reference in response.references)
    assert "uses_auth" in response.answer


def test_build_uses_llm_and_filters_invalid_references():
    dfd, api_node_id, _ = _build_review_dfd()
    fake_client = MagicMock()
    fake_client.call_with_tools.return_value = {
        "mode": "build",
        "answer": "Add a customer database behind the API gateway.",
        "references": [
            {"kind": "node", "id": api_node_id, "label": "API Gateway"},
            {"kind": "node", "id": str(uuid4()), "label": "Ghost Node"},
        ],
        "proposal": {
            "proposal_type": "create_connected_node",
            "title": "Add Customer Database",
            "summary": "Create a data store behind the API Gateway.",
            "anchor_node_id": api_node_id,
            "anchor_handle": "source",
            "node_type": "data_store",
            "node_name": "Customer Database",
            "edge_label": "persist customer records",
        },
    }

    with patch("app.services.assistant.get_llm_client_for_user", return_value=fake_client):
        response = respond_to_assistant_request(
            request=AssistantRequest(
                message="model a persistence tier behind API Gateway",
                mode_hint="build",
            ),
            user_id=uuid4(),
            threat_model_name="Northstar Bank",
            description="Retail banking",
            data_classification="Restricted",
            regulatory_scope=["OSFI B-13"],
            deployment_model="cloud",
            dfd=dfd,
            threats=[],
            environment_context_summary=None,
        )

    assert response.mode == "build"
    assert response.proposal is not None
    assert response.proposal.proposal_type == "create_connected_node"
    assert len(response.references) == 1
    assert response.references[0].label == "API Gateway"


def test_ask_llm_accepts_nullable_optional_structured_fields():
    dfd, _, _ = _build_review_dfd()
    fake_client = MagicMock()
    fake_client.call_with_tools.return_value = {
        "mode": "ask",
        "answer": "Prioritize validating the public API Gateway trust boundary.",
        "references": None,
        "proposal": None,
        "findings": None,
        "action_artifacts": [{"kind": "remediation_note"}],
        "guided_steps": ["not-a-step"],
    }

    with patch("app.services.assistant.get_llm_client_for_user", return_value=fake_client):
        response = respond_to_assistant_request(
            request=AssistantRequest(
                message="give one concise threat-modeling observation",
                mode_hint="ask",
            ),
            user_id=uuid4(),
            threat_model_name="Northstar Bank",
            description="Retail banking",
            data_classification="Restricted",
            regulatory_scope=["OSFI B-13"],
            deployment_model="cloud",
            dfd=dfd,
            threats=[],
            environment_context_summary=None,
        )

    assert response.mode == "ask"
    assert response.degraded_reason is None
    assert response.answer.startswith("Prioritize")
    assert response.references == []
    assert response.action_artifacts == []
    assert response.guided_steps == []


def test_build_malformed_llm_tool_payload_falls_back_without_schema_details():
    dfd, _, _ = _build_review_dfd()
    fake_client = MagicMock()
    fake_client.call_with_tools.return_value = {
        "mode": "build",
        "references": [],
        "proposal": {
            "proposal_type": "update_node",
            "title": "Malformed update",
            "summary": "Missing required answer field should fail schema validation.",
        },
    }

    with patch("app.services.assistant.get_llm_client_for_user", return_value=fake_client):
        response = respond_to_assistant_request(
            request=AssistantRequest(
                message="help me build the next part of this model",
                mode_hint="build",
            ),
            user_id=uuid4(),
            threat_model_name="Northstar Bank",
            description="Retail banking",
            data_classification="Restricted",
            regulatory_scope=["OSFI B-13"],
            deployment_model="cloud",
            dfd=dfd,
            threats=[],
            environment_context_summary=None,
        )

    assert response.mode == "build"
    assert response.guided_steps
    assert "deterministic mode" in (response.degraded_reason or "")
    assert "Missing required answer field" not in (response.degraded_reason or "")
    assert "Field required" not in (response.degraded_reason or "")


def test_build_skips_noop_property_update():
    dfd, api_node_id, _ = _build_review_dfd()
    for node in dfd.nodes:
        if str(node.id) == api_node_id:
            node.properties["uses_auth"] = True

    response = respond_to_assistant_request(
        request=AssistantRequest(
            message="/build set uses_auth true on API Gateway",
            anchor={"kind": "node", "id": api_node_id},
        ),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[],
        environment_context_summary=None,
    )

    assert response.mode == "build"
    assert response.proposal is None
    assert "already has `uses_auth=True`" in response.answer


def test_build_add_service_behind_anchor_defaults_to_process():
    dfd, api_node_id, _ = _build_review_dfd()

    response = respond_to_assistant_request(
        request=AssistantRequest(
            message='/build add a service named "Fraud Scoring Service" behind API Gateway',
            anchor={"kind": "node", "id": api_node_id},
        ),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[],
        environment_context_summary=None,
    )

    assert response.mode == "build"
    assert response.proposal is not None
    assert response.proposal.proposal_type == "create_connected_node"
    assert response.proposal.node_type == "process"


def test_build_can_capture_assumption_on_anchor_node():
    dfd, api_node_id, _ = _build_review_dfd()

    response = respond_to_assistant_request(
        request=AssistantRequest(
            message="/build create an assumption on API Gateway that authentication is enforced before business logic",
            anchor={"kind": "node", "id": api_node_id},
        ),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[],
        environment_context_summary=None,
    )

    assert response.mode == "build"
    assert response.proposal is not None
    assert response.proposal.proposal_type == "create_assumption"
    assert response.proposal.assumption_anchor_kind == "node"
    assert str(response.proposal.assumption_anchor_id) == api_node_id
    assert response.guided_steps


def test_build_fallback_returns_guided_steps_when_llm_unavailable():
    dfd, _, _ = _build_review_dfd()

    with patch("app.services.assistant.get_llm_client_for_user", side_effect=RuntimeError("offline")):
        response = respond_to_assistant_request(
            request=AssistantRequest(
                message="/build guide me through building this threat model",
                mode_hint="build",
            ),
            user_id=uuid4(),
            threat_model_name="Northstar Bank",
            description="Retail banking",
            data_classification="Restricted",
            regulatory_scope=["OSFI B-13"],
            deployment_model="cloud",
            dfd=dfd,
            threats=[],
            environment_context_summary="Repository evidence shows an API and background worker.",
            assumption_count=0,
        )

    assert response.mode == "build"
    assert response.guided_steps
    assert any(step.status == "current" for step in response.guided_steps)
    current_step = next(step for step in response.guided_steps if step.status == "current")
    assert current_step.provenance
    assert current_step.proposal_bundle is not None
    assert current_step.proposal_bundle.proposals
    assert "deterministic mode" in (response.degraded_reason or "")


def test_guided_build_boundary_step_can_stage_a_small_modeling_pass():
    dfd, _, _ = _build_review_dfd()

    with patch("app.services.assistant.get_llm_client_for_user", side_effect=RuntimeError("offline")):
        response = respond_to_assistant_request(
            request=AssistantRequest(
                message="/build guide me through building this threat model",
                mode_hint="build",
            ),
            user_id=uuid4(),
            threat_model_name="Northstar Bank",
            description="Retail banking",
            data_classification="Restricted",
            regulatory_scope=["OSFI B-13"],
            deployment_model="cloud",
            dfd=dfd,
            threats=[],
            environment_context_summary=None,
            assumption_count=0,
        )

    boundary_step = next(step for step in response.guided_steps if step.id == "trust-boundaries")
    assert boundary_step.proposal_bundle is not None
    assert boundary_step.provenance
    assert [proposal.proposal_type for proposal in boundary_step.proposal_bundle.proposals] == [
        "create_boundary",
        "create_assumption",
    ]


def test_review_flags_missing_boundary_crossing_protocol_and_classification():
    dfd, api_node_id, edge_id = _build_review_dfd()
    boundary_id = uuid4()

    for node in dfd.nodes:
        if str(node.id) in {api_node_id, str(dfd.nodes[2].id)}:
            node.trust_boundary_id = boundary_id

    dfd.trust_boundaries = [
        TrustBoundaryResponse(
            id=boundary_id,
            name="Application Zone",
            node_ids=[dfd.nodes[1].id, dfd.nodes[2].id],
            position_x=120,
            position_y=-40,
            width=320,
            height=220,
        )
    ]

    response = respond_to_assistant_request(
        request=AssistantRequest(message="/review check crossing flows"),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[_build_threat(api_node_id, edge_id)],
        environment_context_summary=None,
    )

    assert response.mode == "review"
    assert response.findings
    assert any("protocol" in finding.title.lower() for finding in response.findings)
    assert any("classification" in finding.title.lower() for finding in response.findings)


def test_ask_edge_summary_includes_flow_semantics():
    dfd, _, edge_id = _build_review_dfd()
    dfd.edges[1].label = "Customer profile lookup"
    dfd.edges[1].properties = {
        "protocol": "SQL",
        "data_payload": "customer profile row",
        "data_classification": "Restricted",
        "auth_mechanism": "mTLS",
        "encryption_in_transit": True,
    }

    response = respond_to_assistant_request(
        request=AssistantRequest(
            message="What is this flow?",
            anchor={"kind": "edge", "id": dfd.edges[1].id},
        ),
        user_id=uuid4(),
        threat_model_name="Northstar Bank",
        description="Retail banking",
        data_classification="Restricted",
        regulatory_scope=["OSFI B-13"],
        deployment_model="cloud",
        dfd=dfd,
        threats=[],
        environment_context_summary=None,
    )

    assert response.mode == "ask"
    assert "protocol `SQL`" in response.answer
    assert "classification `Restricted`" in response.answer

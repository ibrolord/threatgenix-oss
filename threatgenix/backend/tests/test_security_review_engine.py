from __future__ import annotations

import pytest

from app.schemas.security_review import (
    SecurityReviewContext,
    SecurityReviewRiskAcceptance,
)
from app.services.security_review_engine import (
    evaluate_security_review_context,
    evaluate_security_review_contexts,
)
from tests.evals.security_review_engine_cases import SECURITY_REVIEW_ENGINE_CASES


@pytest.mark.parametrize(
    "case", SECURITY_REVIEW_ENGINE_CASES, ids=lambda case: case.name
)
def test_security_review_engine_regression_cases(case) -> None:
    decision = evaluate_security_review_context(case.context)

    assert decision.priority == case.expected.priority
    assert decision.action_bucket == case.expected.action_bucket
    assert decision.truth_status == case.expected.truth_status
    assert decision.urgency == case.expected.urgency
    assert decision.exploitability == case.expected.exploitability
    assert decision.business_impact == case.expected.business_impact
    assert decision.regulatory_pressure == case.expected.regulatory_pressure
    assert decision.noise_disposition == case.expected.noise_disposition
    assert 0 <= decision.numeric_score <= 100
    assert decision.score_breakdown.total == decision.numeric_score
    assert decision.rationale
    assert decision.next_steps


def test_security_review_engine_keeps_confirmed_exposure_above_hardening() -> None:
    confirmed = SecurityReviewContext(
        finding_kind="vulnerability",
        title="Confirmed internet-facing exploit path",
        scan_status="confirmed",
        has_known_exploited_vulnerability=True,
        has_exact_threat_intel=True,
        threat_severity="Critical",
        residual_risk_level="Critical",
        control_effectiveness="none",
        internet_facing=True,
        public_exposure=True,
        data_classification="Restricted",
        regulatory_scope=["PCI DSS"],
        business_criticality="mission_critical",
        evidence_strength="strong",
    )
    hardening = SecurityReviewContext(
        finding_kind="hardening",
        title="Optional future hardening idea",
        threat_severity="Medium",
        control_effectiveness="partial",
        data_classification="Internal",
        business_criticality="low",
        evidence_strength="weak",
    )

    confirmed_decision = evaluate_security_review_context(confirmed)
    hardening_decision = evaluate_security_review_context(hardening)

    assert confirmed_decision.numeric_score > hardening_decision.numeric_score
    assert confirmed_decision.priority == "p0_blocker"
    assert hardening_decision.priority == "p3_backlog"


def test_security_review_engine_routes_missing_regulatory_evidence_to_evidence_bucket() -> (
    None
):
    context = SecurityReviewContext(
        finding_kind="evidence_gap",
        title="Missing proof of production encryption control",
        finding_sources=["compliance", "cloud"],
        regulatory_scope=["SOC 2", "ISO 27001"],
        data_classification="Confidential",
        business_criticality="high",
        evidence_strength="missing",
        control_effectiveness="partial",
        change_surface="deployment",
        active_change_window=True,
    )

    decision = evaluate_security_review_context(context)

    assert decision.action_bucket == "fill_evidence_gap"
    assert decision.truth_status == "contextual"
    assert decision.regulatory_pressure in {"high", "red_line"}
    assert any(
        "missing cloud" in step.lower() or "missing" in step.lower()
        for step in decision.next_steps
    )


def test_security_review_engine_does_not_suppress_mitigated_findings_without_verification() -> (
    None
):
    context = SecurityReviewContext(
        finding_kind="threat",
        title="Mitigated privileged admin threat still needs proof",
        finding_sources=["dfd", "scan"],
        threat_severity="High",
        residual_risk_level="Low",
        control_effectiveness="substantial",
        scan_status="mitigated",
        privileged_access=True,
        data_classification="Confidential",
        regulatory_scope=["SOC 2"],
        business_criticality="moderate",
        evidence_strength="strong",
        compensating_controls_present=True,
    )

    decision = evaluate_security_review_context(context)

    assert decision.action_bucket == "verify_control"
    assert decision.noise_disposition == "queue"
    assert decision.priority in {"p2_sprint", "p4_monitor"}
    assert any("control" in step.lower() for step in decision.next_steps)


def test_security_review_engine_emits_explicit_evidence_adjustments() -> None:
    context = SecurityReviewContext(
        finding_kind="threat",
        title="Compensated admin path",
        finding_sources=["scan", "cloud", "compliance"],
        threat_severity="High",
        residual_risk_level="Medium",
        control_effectiveness="full",
        scan_status="mitigated",
        internet_facing=True,
        public_exposure=True,
        data_classification="Confidential",
        regulatory_scope=["SOC 2"],
        business_criticality="high",
        evidence_strength="strong",
        compensating_controls_present=True,
    )

    decision = evaluate_security_review_context(context)

    assert decision.evidence_adjustments
    assert any(
        item.evidence_type == "scan" and item.field_affected == "exploitability"
        for item in decision.evidence_adjustments
    )
    assert any(
        item.field_affected in {"priority", "action_bucket", "noise_disposition"}
        for item in decision.evidence_adjustments
    )


def test_security_review_engine_reopens_risk_acceptance_when_context_escalates() -> (
    None
):
    context = SecurityReviewContext(
        finding_kind="vulnerability",
        title="Accepted API risk now confirmed",
        finding_sources=["scan", "threat_intel"],
        threat_severity="Critical",
        residual_risk_level="Critical",
        control_effectiveness="none",
        scan_status="confirmed",
        has_known_exploited_vulnerability=True,
        internet_facing=True,
        public_exposure=True,
        data_classification="Restricted",
        regulatory_scope=["PCI DSS"],
        business_criticality="mission_critical",
        evidence_strength="strong",
        existing_risk_acceptance=SecurityReviewRiskAcceptance(
            finding_title="Accepted API risk now confirmed",
            status="active",
            accepted_by="priya",
            accepted_at="2026-01-10T00:00:00Z",
            expires_at="2026-12-31T00:00:00Z",
            acceptance_rationale="Accepted until compensating control rollout",
            reopen_triggers=["new KEV entry"],
        ),
        previous_priority="p3_backlog",
        days_since_last_review=45,
    )

    decision = evaluate_security_review_context(context)

    assert decision.risk_acceptance is not None
    assert decision.risk_acceptance.status == "reopened"
    assert decision.review_delta is not None
    assert decision.review_delta.disposition == "reopened"
    assert decision.review_delta.reopened_count == 1


def test_security_review_engine_groups_related_findings_into_attack_paths() -> None:
    contexts = [
        SecurityReviewContext(
            finding_key="f-1",
            finding_kind="threat",
            title="Public API auth bypass",
            finding_sources=["dfd"],
            affected_node_ids=["node-api"],
            entry_point="Public API",
            threat_severity="High",
            control_effectiveness="none",
            internet_facing=True,
            public_exposure=True,
            data_classification="Internal",
            business_criticality="high",
            evidence_strength="partial",
        ),
        SecurityReviewContext(
            finding_key="f-2",
            finding_kind="control_gap",
            title="Token vault access escalation",
            finding_sources=["dfd", "compliance"],
            affected_node_ids=["node-api", "node-vault"],
            target_asset="Token Vault",
            threat_severity="High",
            residual_risk_level="High",
            control_effectiveness="none",
            privileged_access=True,
            data_classification="Restricted",
            regulatory_scope=["PCI DSS"],
            business_criticality="mission_critical",
            evidence_strength="strong",
        ),
    ]

    decisions = evaluate_security_review_contexts(contexts)

    assert len(decisions) == 2
    assert len(decisions[0].related_attack_paths) == 1
    assert len(decisions[1].related_attack_paths) == 1
    path = decisions[0].related_attack_paths[0]
    assert path.entry_point == "Public API"
    assert path.target_asset == "Token Vault"
    assert path.hop_count >= 1
    assert path.composite_priority in {"p0_blocker", "p1_now", "p2_sprint"}
    assert path.path_nodes[0] == "Public API"
    assert path.path_nodes[-1] == "Token Vault"
    assert "dfd" in path.evidence_sources
    assert path.relationship_reasons
    assert any("Token Vault" in step for step in path.verification_steps)


def test_security_review_engine_splits_shared_entry_paths_by_target() -> None:
    contexts = [
        SecurityReviewContext(
            finding_key="f-entry",
            finding_kind="threat",
            title="Public API auth bypass",
            finding_sources=["dfd"],
            affected_node_ids=["node-api"],
            entry_point="Public API",
            threat_severity="High",
            control_effectiveness="none",
            internet_facing=True,
            public_exposure=True,
            data_classification="Internal",
            business_criticality="high",
            evidence_strength="partial",
        ),
        SecurityReviewContext(
            finding_key="f-vault",
            finding_kind="control_gap",
            title="Token vault access escalation",
            finding_sources=["dfd", "compliance"],
            affected_node_ids=["node-api", "node-vault"],
            target_asset="Token Vault",
            threat_severity="High",
            residual_risk_level="High",
            control_effectiveness="none",
            privileged_access=True,
            data_classification="Restricted",
            business_criticality="mission_critical",
            evidence_strength="strong",
        ),
        SecurityReviewContext(
            finding_key="f-ledger",
            finding_kind="control_gap",
            title="Ledger write path lacks scoped authorization",
            finding_sources=["dfd", "repository"],
            affected_node_ids=["node-api", "node-ledger"],
            target_asset="Payment Ledger",
            threat_severity="High",
            residual_risk_level="High",
            control_effectiveness="none",
            privileged_access=True,
            data_classification="Confidential",
            business_criticality="mission_critical",
            evidence_strength="strong",
        ),
    ]

    decisions = evaluate_security_review_contexts(contexts)

    entry_paths = decisions[0].related_attack_paths
    target_assets = {path.target_asset for path in entry_paths}
    assert {"Token Vault", "Payment Ledger"} <= target_assets
    assert all(path.entry_point == "Public API" for path in entry_paths)
    assert all(path.target_asset != path.entry_point for path in entry_paths)
    assert all(len(path.finding_titles) <= 4 for path in entry_paths)
    assert all(path.relationship_reasons for path in entry_paths)
    assert all(path.verification_steps for path in entry_paths)


def test_security_review_engine_does_not_group_unconnected_business_contexts() -> None:
    contexts = [
        SecurityReviewContext(
            finding_key="f-entry",
            finding_kind="threat",
            title="Public API auth bypass",
            finding_sources=["dfd"],
            affected_node_ids=["node-api"],
            entry_point="Public API",
            threat_severity="High",
            control_effectiveness="none",
            internet_facing=True,
            public_exposure=True,
            data_classification="Internal",
            business_criticality="high",
            business_capability="Payments",
            evidence_strength="partial",
        ),
        SecurityReviewContext(
            finding_key="f-vault",
            finding_kind="control_gap",
            title="Unrelated vault control gap",
            finding_sources=["compliance"],
            affected_node_ids=["node-vault"],
            target_asset="Token Vault",
            threat_severity="High",
            control_effectiveness="none",
            privileged_access=True,
            data_classification="Restricted",
            business_criticality="mission_critical",
            business_capability="Payments",
            evidence_strength="strong",
        ),
    ]

    decisions = evaluate_security_review_contexts(contexts)

    assert decisions[0].related_attack_paths == []
    assert decisions[1].related_attack_paths == []


def test_security_review_engine_groups_tight_business_entry_to_sensitive_target() -> (
    None
):
    contexts = [
        SecurityReviewContext(
            finding_key="f-entry",
            finding_kind="threat",
            title="Payments API auth bypass",
            finding_sources=["dfd"],
            entry_point="Payments API",
            threat_severity="High",
            control_effectiveness="none",
            internet_facing=True,
            public_exposure=True,
            data_classification="Internal",
            business_criticality="high",
            business_capability="Payments",
            evidence_strength="partial",
        ),
        SecurityReviewContext(
            finding_key="f-ledger",
            finding_kind="control_gap",
            title="Payment ledger accepts broad service role writes",
            finding_sources=["repository"],
            entry_point="Payments API",
            target_asset="Payment Ledger",
            threat_severity="High",
            control_effectiveness="none",
            privileged_access=True,
            data_classification="Restricted",
            business_criticality="mission_critical",
            business_capability="Payments",
            evidence_strength="strong",
        ),
    ]

    decisions = evaluate_security_review_contexts(contexts)

    assert len(decisions[0].related_attack_paths) == 1
    path = decisions[0].related_attack_paths[0]
    assert path.entry_point == "Payments API"
    assert path.target_asset == "Payment Ledger"
    assert path.support_count == 2


def test_security_review_engine_weights_boundary_crossing_control_plane_paths() -> None:
    control_plane_path = SecurityReviewContext(
        finding_kind="threat",
        title="Boundary-crossing control-plane path",
        finding_sources=["dfd", "cloud"],
        threat_severity="High",
        residual_risk_level="High",
        control_effectiveness="none",
        internet_facing=True,
        public_exposure=True,
        privileged_access=True,
        crosses_trust_boundary=True,
        control_plane_asset=True,
        crown_jewel=True,
        data_classification="Restricted",
        regulatory_scope=["PCI DSS"],
        business_criticality="mission_critical",
        evidence_strength="strong",
    )
    background_hardening = SecurityReviewContext(
        finding_kind="hardening",
        title="Internal hygiene improvement",
        finding_sources=["dfd"],
        threat_severity="Low",
        control_effectiveness="partial",
        data_classification="Internal",
        business_criticality="low",
        evidence_strength="weak",
    )

    lead_decision = evaluate_security_review_context(control_plane_path)
    background_decision = evaluate_security_review_context(background_hardening)

    assert lead_decision.numeric_score > background_decision.numeric_score
    assert lead_decision.numeric_score >= 2 * background_decision.numeric_score
    assert lead_decision.noise_disposition in {"focus", "queue"}
    assert any("trust boundary" in line.lower() for line in lead_decision.rationale)
    assert any(
        "control-plane" in line.lower() or "identity-bearing" in line.lower()
        for line in lead_decision.rationale
    )

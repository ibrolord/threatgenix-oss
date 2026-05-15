"""Regression cases for the Security Review Engineer decision layer."""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.security_review import SecurityReviewContext


@dataclass(frozen=True)
class ExpectedDecision:
    priority: str
    action_bucket: str
    truth_status: str
    urgency: str
    exploitability: str
    business_impact: str
    regulatory_pressure: str
    noise_disposition: str


@dataclass(frozen=True)
class SecurityReviewCase:
    name: str
    context: SecurityReviewContext
    expected: ExpectedDecision


SECURITY_REVIEW_ENGINE_CASES: list[SecurityReviewCase] = [
    SecurityReviewCase(
        name="internet_facing_payment_api_confirmed_exploit",
        context=SecurityReviewContext(
            finding_kind="vulnerability",
            title="Internet-facing payment API vulnerable to confirmed exploit path",
            finding_sources=["scan", "threat_intel", "cloud"],
            threat_severity="Critical",
            residual_risk_level="Critical",
            control_effectiveness="none",
            scan_status="confirmed",
            has_known_exploited_vulnerability=True,
            has_exact_threat_intel=True,
            internet_facing=True,
            public_exposure=True,
            data_classification="Restricted",
            regulatory_scope=["PCI DSS", "SOC 2"],
            business_criticality="mission_critical",
            business_capability="payments",
            evidence_strength="strong",
            change_surface="runtime",
            owner_known=False,
        ),
        expected=ExpectedDecision(
            priority="p0_blocker",
            action_bucket="bright_red_line",
            truth_status="validated",
            urgency="immediate",
            exploitability="proven",
            business_impact="severe",
            regulatory_pressure="red_line",
            noise_disposition="focus",
        ),
    ),
    SecurityReviewCase(
        name="mitigated_internal_admin_path_with_full_controls",
        context=SecurityReviewContext(
            finding_kind="threat",
            title="Internal admin workflow already mitigated by production controls",
            finding_sources=["dfd", "scan"],
            threat_severity="High",
            residual_risk_level="Low",
            control_effectiveness="full",
            scan_status="mitigated",
            has_exact_threat_intel=False,
            has_semantic_threat_intel=True,
            internet_facing=False,
            public_exposure=False,
            privileged_access=True,
            data_classification="Confidential",
            regulatory_scope=["SOC 2"],
            business_criticality="moderate",
            evidence_strength="strong",
            compensating_controls_present=True,
            owner_known=True,
            remediation_exists=True,
        ),
        expected=ExpectedDecision(
            priority="p4_monitor",
            action_bucket="verify_control",
            truth_status="strongly_indicated",
            urgency="defer",
            exploitability="low",
            business_impact="high",
            regulatory_pressure="moderate",
            noise_disposition="queue",
        ),
    ),
    SecurityReviewCase(
        name="soc2_logging_evidence_gap",
        context=SecurityReviewContext(
            finding_kind="evidence_gap",
            title="Missing attestation evidence for production audit logging",
            finding_sources=["compliance", "cloud"],
            control_effectiveness="partial",
            data_classification="Confidential",
            regulatory_scope=["SOC 2"],
            business_criticality="high",
            evidence_strength="missing",
            change_surface="deployment",
            active_change_window=True,
            owner_known=False,
        ),
        expected=ExpectedDecision(
            priority="p1_now",
            action_bucket="fill_evidence_gap",
            truth_status="contextual",
            urgency="current_cycle",
            exploitability="low",
            business_impact="high",
            regulatory_pressure="high",
            noise_disposition="queue",
        ),
    ),
    SecurityReviewCase(
        name="public_storage_drift_on_restricted_data",
        context=SecurityReviewContext(
            finding_kind="drift",
            title="Cloud drift exposed a restricted data store publicly",
            finding_sources=["cloud", "iac"],
            threat_severity="High",
            residual_risk_level="High",
            control_effectiveness="none",
            internet_facing=True,
            public_exposure=True,
            data_classification="Restricted",
            regulatory_scope=["HIPAA", "SOC 2"],
            business_criticality="high",
            evidence_strength="strong",
            change_surface="deployment",
            active_change_window=True,
        ),
        expected=ExpectedDecision(
            priority="p1_now",
            action_bucket="engineer_now",
            truth_status="contextual",
            urgency="current_cycle",
            exploitability="high",
            business_impact="severe",
            regulatory_pressure="red_line",
            noise_disposition="focus",
        ),
    ),
    SecurityReviewCase(
        name="theoretical_internal_service_hardening_item",
        context=SecurityReviewContext(
            finding_kind="hardening",
            title="Optional request-signing improvement for internal worker channel",
            finding_sources=["dfd", "manual"],
            threat_severity="Medium",
            control_effectiveness="partial",
            data_classification="Internal",
            business_criticality="low",
            evidence_strength="weak",
            change_surface="design",
        ),
        expected=ExpectedDecision(
            priority="p3_backlog",
            action_bucket="planned_hardening",
            truth_status="theoretical",
            urgency="planned",
            exploitability="low",
            business_impact="moderate",
            regulatory_pressure="low",
            noise_disposition="background",
        ),
    ),
    SecurityReviewCase(
        name="pci_token_store_missing_encryption_control",
        context=SecurityReviewContext(
            finding_kind="control_gap",
            title="PCI token store lacks attestable encryption-at-rest control",
            finding_sources=["dfd", "compliance", "repository"],
            threat_severity="High",
            residual_risk_level="High",
            control_effectiveness="none",
            data_classification="Restricted",
            regulatory_scope=["PCI DSS"],
            business_criticality="mission_critical",
            business_capability="token vault",
            evidence_strength="strong",
            privileged_access=True,
            change_surface="code",
            active_change_window=True,
        ),
        expected=ExpectedDecision(
            priority="p2_sprint",
            action_bucket="engineer_now",
            truth_status="contextual",
            urgency="current_cycle",
            exploitability="medium",
            business_impact="severe",
            regulatory_pressure="red_line",
            noise_disposition="focus",
        ),
    ),
]

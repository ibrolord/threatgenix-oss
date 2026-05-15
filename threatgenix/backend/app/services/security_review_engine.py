"""Deterministic decision layer for the Security Review Engineer feature.

This module turns heterogeneous security-review signals into explainable
recommendations. It also provides the first cross-finding synthesis primitives
that Claude Opus explicitly called out as missing:

- attack-path grouping across related findings
- evidence-adjustment tracking so verdict changes are inspectable
- risk-acceptance / review-delta handling so reviews are not stateless
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.schemas.security_review import (
    ActionBucket,
    BusinessCriticality,
    ExploitabilityRating,
    ImpactRating,
    NoiseDisposition,
    PriorityBand,
    RegulatoryPressure,
    SecurityReviewAttackPath,
    SecurityReviewContext,
    SecurityReviewDecision,
    SecurityReviewDelta,
    SecurityReviewEvidenceAdjustment,
    SecurityReviewRiskAcceptance,
    SecurityReviewScoreBreakdown,
    TruthStatus,
    UrgencyRating,
)

_SEVERITY_POINTS = {
    "Critical": 18,
    "High": 14,
    "Medium": 9,
    "Low": 4,
    None: 0,
}
_RESIDUAL_POINTS = {
    "Critical": 20,
    "High": 15,
    "Medium": 10,
    "Low": 5,
    "Negligible": 0,
    None: 0,
}
_DATA_CLASS_POINTS = {
    "Restricted": 14,
    "Confidential": 10,
    "Internal": 5,
    "Public": 0,
}
_BUSINESS_POINTS: dict[BusinessCriticality, int] = {
    "mission_critical": 14,
    "high": 10,
    "moderate": 5,
    "low": 0,
}
_CONTROL_POINTS = {
    "none": 10,
    "partial": 5,
    "substantial": -2,
    "full": -8,
}
_PRIORITY_RANK: dict[PriorityBand, int] = {
    "p0_blocker": 0,
    "p1_now": 1,
    "p2_sprint": 2,
    "p3_backlog": 3,
    "p4_monitor": 4,
}
_EXPLOITABILITY_RANK: dict[ExploitabilityRating, int] = {
    "proven": 3,
    "high": 2,
    "medium": 1,
    "low": 0,
}
_EVIDENCE_SOURCE_ORDER = [
    "scan",
    "repository",
    "threat_intel",
    "dfd",
    "cloud",
    "iac",
    "compliance",
    "sdlc",
    "manual",
]


def _clamp(value: int, lower: int = 0, upper: int = 100) -> int:
    return min(upper, max(lower, value))


def _parse_optional_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _pick_evidence_source(context: SecurityReviewContext) -> str:
    preferred_order = (
        "scan",
        "cloud",
        "iac",
        "repository",
        "compliance",
        "threat_intel",
        "sdlc",
        "dfd",
        "manual",
    )
    for item in preferred_order:
        if item in context.finding_sources:
            return item
    return "manual"


def _evidence_value_for_context(context: SecurityReviewContext) -> str:
    if context.scan_status == "mitigated":
        return "latest validation scan marked the path mitigated"
    if context.control_effectiveness in {"substantial", "full"}:
        return f"control effectiveness: {context.control_effectiveness}"
    if context.compensating_controls_present:
        return "compensating controls were identified for this finding"
    if context.evidence_strength == "strong":
        return "strong environment evidence is attached"
    return "review context evidence"


def _score_reality(context: SecurityReviewContext) -> int:
    score = 0
    if (
        context.finding_kind == "evidence_gap"
        and context.regulatory_scope
        and context.evidence_strength == "missing"
    ):
        score += 45
    if context.finding_kind == "compliance_gap" and context.regulatory_scope:
        score += 40
    if context.finding_kind == "control_gap" and context.regulatory_scope:
        score += 18
    if context.scan_status == "confirmed":
        score += 45
    elif context.scan_status == "mitigated":
        score += 25
    elif context.scan_status == "unverifiable":
        score += 8
    elif context.scan_status == "not_found":
        score -= 8
    if context.has_known_exploited_vulnerability:
        score += 18
    if context.has_exact_threat_intel:
        score += 12
    elif context.has_semantic_threat_intel:
        score += 6
    if context.finding_kind == "drift":
        score += 15
    if context.finding_kind == "threat" and context.evidence_strength in {
        "strong",
        "partial",
    }:
        if context.crosses_trust_boundary:
            score += 8
        if context.control_plane_asset:
            score += 8
        if context.crown_jewel:
            score += 6
        if context.public_exposure or context.internet_facing:
            score += 6
    evidence_adjustment = {
        "strong": 12,
        "partial": 7,
        "weak": 2,
        "missing": -6,
    }[context.evidence_strength]
    score += evidence_adjustment
    if context.finding_kind == "hardening":
        score -= 10
    return _clamp(score)


def _score_exploitability(context: SecurityReviewContext) -> int:
    score = 0
    if context.scan_status == "confirmed":
        score += 35
    if context.has_known_exploited_vulnerability:
        score += 25
    if context.has_exact_threat_intel:
        score += 12
    elif context.has_semantic_threat_intel:
        score += 6
    if context.internet_facing:
        score += 12
    if context.public_exposure:
        score += 12
    if context.privileged_access:
        score += 8
    if context.crosses_trust_boundary:
        score += 8
    if context.control_plane_asset:
        score += 8
    if context.crown_jewel:
        score += 6
    if context.active_change_window:
        score += 4
    score += _CONTROL_POINTS[context.control_effectiveness]
    if context.compensating_controls_present:
        score -= 8
    if context.scan_status == "mitigated":
        score -= 18
    if context.finding_kind in {"compliance_gap", "evidence_gap"}:
        score -= 8
    if context.finding_kind == "hardening":
        score -= 12
    return _clamp(score)


def _score_business_impact(context: SecurityReviewContext) -> int:
    score = 0
    score += _SEVERITY_POINTS[context.threat_severity]
    score += _RESIDUAL_POINTS[context.residual_risk_level]
    score += _DATA_CLASS_POINTS[context.data_classification]
    score += _BUSINESS_POINTS[context.business_criticality]
    if context.privileged_access:
        score += 6
    if context.control_plane_asset:
        score += 8
    if context.crown_jewel:
        score += 10
    if context.crosses_trust_boundary and context.public_exposure:
        score += 6
    if context.public_exposure and context.business_criticality in {
        "mission_critical",
        "high",
    }:
        score += 5
    if context.finding_kind == "evidence_gap" and context.regulatory_scope:
        score += 4
    return _clamp(score)


def _score_regulatory_pressure(context: SecurityReviewContext) -> int:
    score = 0
    score += min(len(context.regulatory_scope) * 6, 24)
    if context.data_classification == "Restricted":
        score += 20
    elif context.data_classification == "Confidential":
        score += 12
    if context.finding_kind in {"compliance_gap", "evidence_gap"}:
        score += 18
    if context.finding_kind == "control_gap" and context.regulatory_scope:
        score += 10
    if context.privileged_access:
        score += 4
    if context.control_plane_asset:
        score += 4
    if context.internet_facing or context.public_exposure:
        score += 8
    return _clamp(score)


def _score_noise_penalty(context: SecurityReviewContext) -> int:
    penalty = 0
    if context.finding_kind == "hardening":
        penalty += 18
    if context.scan_status == "mitigated":
        penalty += 14
    if context.control_effectiveness in {"substantial", "full"}:
        penalty += 10
    if context.compensating_controls_present:
        penalty += 8
    if context.evidence_strength in {
        "weak",
        "missing",
    } and context.finding_kind not in {"evidence_gap", "compliance_gap"}:
        penalty += 8
    if (
        not context.internet_facing
        and not context.public_exposure
        and not context.crosses_trust_boundary
        and context.business_criticality == "low"
    ):
        penalty += 5
    return _clamp(penalty)


def _classify_truth_status(
    context: SecurityReviewContext, reality_score: int
) -> TruthStatus:
    if (
        context.finding_kind == "evidence_gap"
        and context.regulatory_scope
        and context.evidence_strength == "missing"
    ):
        return "contextual"
    if context.finding_kind == "compliance_gap" and context.regulatory_scope:
        return "validated"
    if context.scan_status == "confirmed":
        return "validated"
    if context.scan_status == "mitigated":
        return "strongly_indicated"
    if context.finding_kind in {
        "control_gap",
        "drift",
    } and context.evidence_strength in {
        "strong",
        "partial",
    }:
        return "contextual"
    if reality_score >= 55:
        return "strongly_indicated"
    if reality_score >= 25:
        return "contextual"
    return "theoretical"


def _classify_exploitability(score: int) -> ExploitabilityRating:
    if score >= 65:
        return "proven"
    if score >= 35:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def _classify_business_impact(score: int) -> ImpactRating:
    if score >= 45:
        return "severe"
    if score >= 24:
        return "high"
    if score >= 12:
        return "moderate"
    return "low"


def _classify_regulatory_pressure(score: int) -> RegulatoryPressure:
    if score >= 40:
        return "red_line"
    if score >= 24:
        return "high"
    if score >= 10:
        return "moderate"
    return "low"


def _classify_action_bucket(
    context: SecurityReviewContext,
    truth_status: TruthStatus,
    exploitability: ExploitabilityRating,
    business_impact: ImpactRating,
    regulatory_pressure: RegulatoryPressure,
    total_score: int,
) -> ActionBucket:
    if (
        context.scan_status == "confirmed"
        and (
            context.internet_facing
            or context.public_exposure
            or regulatory_pressure == "red_line"
        )
        and business_impact in {"severe", "high"}
    ):
        return "bright_red_line"
    if context.finding_kind == "evidence_gap" and regulatory_pressure in {
        "red_line",
        "high",
    }:
        return "fill_evidence_gap"
    if context.finding_kind == "compliance_gap" and regulatory_pressure in {
        "red_line",
        "high",
    }:
        return "engineer_now"
    if context.scan_status == "mitigated" or (
        context.control_effectiveness in {"substantial", "full"} and total_score < 60
    ):
        return "verify_control"
    if truth_status in {"validated", "strongly_indicated"} and exploitability in {
        "proven",
        "high",
    }:
        return "engineer_now"
    if (
        context.finding_kind == "threat"
        and truth_status in {"contextual", "strongly_indicated"}
        and exploitability in {"proven", "high"}
        and business_impact in {"severe", "high"}
        and (
            context.crosses_trust_boundary
            or context.control_plane_asset
            or context.crown_jewel
        )
    ):
        return "engineer_now"
    if context.finding_kind == "hardening" or truth_status == "theoretical":
        return "planned_hardening"
    if total_score < 20:
        return "monitor"
    return "engineer_now"


def _classify_priority(
    context: SecurityReviewContext,
    action_bucket: ActionBucket,
    regulatory_pressure: RegulatoryPressure,
    total_score: int,
) -> PriorityBand:
    if action_bucket == "bright_red_line":
        return "p0_blocker"
    if action_bucket == "fill_evidence_gap":
        if (
            regulatory_pressure in {"red_line", "high"}
            and context.evidence_strength == "missing"
        ):
            return "p1_now"
        return "p2_sprint"
    if action_bucket == "engineer_now":
        if context.finding_kind == "drift" and context.public_exposure:
            return "p1_now"
        if (
            regulatory_pressure == "red_line"
            and context.business_criticality in {"mission_critical", "high"}
            and (context.public_exposure or context.internet_facing)
        ):
            return "p1_now"
        return "p1_now" if total_score >= 70 else "p2_sprint"
    if action_bucket == "verify_control":
        return "p2_sprint" if total_score >= 35 else "p4_monitor"
    if action_bucket == "planned_hardening":
        return "p3_backlog"
    return "p4_monitor"


def _classify_urgency(
    priority: PriorityBand, action_bucket: ActionBucket
) -> UrgencyRating:
    if priority == "p0_blocker":
        return "immediate"
    if priority == "p1_now":
        return "immediate" if action_bucket == "bright_red_line" else "current_cycle"
    if priority == "p2_sprint":
        return "current_cycle"
    if priority == "p3_backlog":
        return "planned"
    return "defer"


def _classify_noise_disposition(
    action_bucket: ActionBucket, total_score: int
) -> NoiseDisposition:
    if action_bucket in {"bright_red_line", "engineer_now"}:
        return "focus"
    if action_bucket in {"verify_control", "fill_evidence_gap"}:
        return "queue"
    if action_bucket == "planned_hardening":
        return "background"
    return "suppress" if total_score < 20 else "background"


def _build_rationale(
    context: SecurityReviewContext,
    truth_status: TruthStatus,
    exploitability: ExploitabilityRating,
    business_impact: ImpactRating,
    regulatory_pressure: RegulatoryPressure,
    action_bucket: ActionBucket,
) -> list[str]:
    reasons: list[str] = []

    if context.scan_status == "confirmed":
        reasons.append(
            "A validation scan confirmed this condition, so the issue is no longer theoretical."
        )
    elif context.scan_status == "mitigated":
        reasons.append(
            "A validation scan saw the path but current controls kept it mitigated, so closure still needs proof rather than assumption."
        )

    if context.has_known_exploited_vulnerability:
        reasons.append(
            "Threat intelligence shows active exploitation pressure, which elevates both urgency and exploitability."
        )
    elif context.has_exact_threat_intel:
        reasons.append(
            "The finding aligns with exact threat-intel references rather than only loose semantic similarity."
        )
    elif context.has_semantic_threat_intel:
        reasons.append(
            "Threat-intel support is semantic rather than exact, so the signal should guide prioritization but not overrule evidence."
        )

    if context.internet_facing or context.public_exposure:
        reasons.append(
            "The affected surface is externally reachable, which meaningfully raises exploitability and business exposure."
        )

    if context.crosses_trust_boundary:
        reasons.append(
            "The path crosses a trust boundary, so the review should treat it as a real change in trust and not just another internal edge."
        )

    if context.control_plane_asset:
        reasons.append(
            "The finding touches a control-plane or identity-bearing asset, which raises blast radius even when the surface is not customer-facing."
        )

    if context.crown_jewel or context.business_criticality == "mission_critical":
        reasons.append(
            "The affected capability behaves like a crown-jewel path, so the queue should bias toward concrete action over generic backlog treatment."
        )

    if context.data_classification in {"Restricted", "Confidential"}:
        reasons.append(
            f"The path touches {context.data_classification.lower()} data, so business and regulatory impact are materially higher."
        )

    if context.regulatory_scope:
        reasons.append(
            f"The model is in scope for {', '.join(context.regulatory_scope)}, so this should be judged as review evidence, not only engineering debt."
        )

    if (
        context.control_effectiveness in {"substantial", "full"}
        or context.compensating_controls_present
    ):
        reasons.append(
            "Compensating or implemented controls lower the noise floor, but they still need evidence before a reviewer should close the item."
        )
    elif context.control_effectiveness in {"none", "partial"}:
        reasons.append(
            "Control coverage is weak or incomplete, so the finding is less likely to be safely deferred."
        )

    if action_bucket == "fill_evidence_gap":
        reasons.append(
            "The critical gap is missing attestable evidence, which becomes a compliance problem even if exploitation is not yet proven."
        )
    elif action_bucket == "planned_hardening":
        reasons.append(
            "This reads more like forward hardening than immediate exposure, so it belongs in planned engineering work."
        )

    if truth_status == "theoretical" and exploitability == "low":
        reasons.append(
            "Current signals do not justify interrupting the team, which is exactly where noise filtering should de-prioritize the issue."
        )

    if not context.owner_known:
        reasons.append(
            "Ownership is unclear, which increases coordination risk and should be corrected immediately."
        )

    if not reasons:
        reasons.append(
            f"This is classified as {business_impact} impact with {regulatory_pressure} regulatory pressure and a {truth_status} truth state."
        )

    return reasons


def _build_next_steps(
    context: SecurityReviewContext, action_bucket: ActionBucket
) -> list[str]:
    steps: list[str] = []

    if not context.owner_known:
        steps.append(
            "Assign a concrete engineering owner before the review exits triage."
        )

    if action_bucket == "bright_red_line":
        steps.extend(
            [
                "Open an immediate engineering fix item and treat it as a release blocker until evidence changes.",
                "Contain or reduce external exposure before the next deploy where possible.",
                "Re-run validation scanning or environment checks after the fix and attach the evidence to the review record.",
            ]
        )
    elif action_bucket == "engineer_now":
        steps.extend(
            [
                "Create a current-cycle engineering task with the affected asset, control gap, and required evidence of closure.",
                "Define the minimum acceptable remediation or compensating control before closing the finding.",
            ]
        )
    elif action_bucket == "verify_control":
        steps.extend(
            [
                "Capture proof that the compensating control is active in production, not only described in design notes.",
                "Only close the finding after the control is demonstrated through scan or environment evidence.",
            ]
        )
    elif action_bucket == "fill_evidence_gap":
        steps.extend(
            [
                "Collect the missing cloud, IaC, repository, or runtime evidence needed to support the in-scope control assertion.",
                "Decide pass or fail after evidence is attached; do not let this linger as an undefined audit risk.",
            ]
        )
    elif action_bucket == "planned_hardening":
        steps.extend(
            [
                "Record the hardening change in backlog with the specific abuse case it reduces.",
                "Revisit if the surface becomes internet facing, compliance scoped, or otherwise higher impact.",
            ]
        )
    else:
        steps.append(
            "Keep the item visible for trend tracking, but do not interrupt active engineering work unless the signal strengthens."
        )

    if context.active_change_window and action_bucket in {
        "bright_red_line",
        "engineer_now",
    }:
        steps.append(
            "Because the surface is changing now, attach the review finding directly to the active PR or release work."
        )
    elif context.change_surface in {"code", "deployment"} and action_bucket in {
        "engineer_now",
        "fill_evidence_gap",
    }:
        steps.append(
            "Bake the required validation into the engineering workflow so the same issue does not quietly reappear on the next change."
        )

    return steps


def _evaluate_core_context(context: SecurityReviewContext) -> SecurityReviewDecision:
    reality_score = _score_reality(context)
    exploitability_score = _score_exploitability(context)
    business_score = _score_business_impact(context)
    regulatory_score = _score_regulatory_pressure(context)
    noise_penalty = _score_noise_penalty(context)

    total_score = _clamp(
        round(
            reality_score * 0.30
            + exploitability_score * 0.30
            + business_score * 0.20
            + regulatory_score * 0.20
            - noise_penalty
        )
    )

    truth_status = _classify_truth_status(context, reality_score)
    exploitability = _classify_exploitability(exploitability_score)
    business_impact = _classify_business_impact(business_score)
    regulatory_pressure = _classify_regulatory_pressure(regulatory_score)
    action_bucket = _classify_action_bucket(
        context,
        truth_status,
        exploitability,
        business_impact,
        regulatory_pressure,
        total_score,
    )
    priority = _classify_priority(
        context, action_bucket, regulatory_pressure, total_score
    )
    urgency = _classify_urgency(priority, action_bucket)
    noise_disposition = _classify_noise_disposition(action_bucket, total_score)

    breakdown = SecurityReviewScoreBreakdown(
        reality=reality_score,
        exploitability=exploitability_score,
        business_impact=business_score,
        regulatory_pressure=regulatory_score,
        noise_penalty=noise_penalty,
        total=total_score,
    )

    return SecurityReviewDecision(
        priority=priority,
        action_bucket=action_bucket,
        truth_status=truth_status,
        urgency=urgency,
        exploitability=exploitability,
        business_impact=business_impact,
        regulatory_pressure=regulatory_pressure,
        noise_disposition=noise_disposition,
        numeric_score=total_score,
        score_breakdown=breakdown,
        rationale=_build_rationale(
            context,
            truth_status,
            exploitability,
            business_impact,
            regulatory_pressure,
            action_bucket,
        ),
        next_steps=_build_next_steps(context, action_bucket),
    )


def _build_baseline_context(context: SecurityReviewContext) -> SecurityReviewContext:
    baseline = context.model_copy(deep=True)
    baseline.control_effectiveness = "none"
    baseline.compensating_controls_present = False
    if baseline.scan_status == "mitigated":
        baseline.scan_status = "unverifiable"
    if baseline.evidence_strength == "strong":
        baseline.evidence_strength = "partial"
    return baseline


def _append_adjustment_if_changed(
    adjustments: list[SecurityReviewEvidenceAdjustment],
    *,
    evidence_type: str,
    evidence_value: str,
    field_affected: str,
    original_value: str,
    adjusted_value: str,
    justification: str,
) -> None:
    if original_value == adjusted_value:
        return
    adjustments.append(
        SecurityReviewEvidenceAdjustment(
            evidence_type=evidence_type,  # type: ignore[arg-type]
            evidence_value=evidence_value,
            field_affected=field_affected,  # type: ignore[arg-type]
            original_value=original_value,
            adjusted_value=adjusted_value,
            justification=justification,
        )
    )


def _build_evidence_adjustments(
    context: SecurityReviewContext,
    baseline_decision: SecurityReviewDecision,
    final_decision: SecurityReviewDecision,
) -> list[SecurityReviewEvidenceAdjustment]:
    adjustments: list[SecurityReviewEvidenceAdjustment] = []
    evidence_type = _pick_evidence_source(context)

    if context.scan_status == "mitigated":
        _append_adjustment_if_changed(
            adjustments,
            evidence_type="scan",
            evidence_value="latest validation scan marked the path mitigated",
            field_affected="exploitability",
            original_value=baseline_decision.exploitability,
            adjusted_value=final_decision.exploitability,
            justification="Mitigated scan evidence should lower practical exploitability until the control is disproven or removed.",
        )
        _append_adjustment_if_changed(
            adjustments,
            evidence_type="scan",
            evidence_value="latest validation scan marked the path mitigated",
            field_affected="noise_disposition",
            original_value=baseline_decision.noise_disposition,
            adjusted_value=final_decision.noise_disposition,
            justification="A mitigated scan result changes the handling mode from direct interrupt toward verification work.",
        )

    if context.control_effectiveness in {"substantial", "full"}:
        _append_adjustment_if_changed(
            adjustments,
            evidence_type=evidence_type,
            evidence_value=f"control effectiveness: {context.control_effectiveness}",
            field_affected="priority",
            original_value=baseline_decision.priority,
            adjusted_value=final_decision.priority,
            justification="Verified control strength should reduce the default escalation level when the finding is not otherwise proven active.",
        )
        _append_adjustment_if_changed(
            adjustments,
            evidence_type=evidence_type,
            evidence_value=f"control effectiveness: {context.control_effectiveness}",
            field_affected="action_bucket",
            original_value=baseline_decision.action_bucket,
            adjusted_value=final_decision.action_bucket,
            justification="Strong controls can move the work from raw engineering remediation into verification of those controls.",
        )

    if context.compensating_controls_present:
        _append_adjustment_if_changed(
            adjustments,
            evidence_type=evidence_type,
            evidence_value="compensating controls were identified",
            field_affected="noise_disposition",
            original_value=baseline_decision.noise_disposition,
            adjusted_value=final_decision.noise_disposition,
            justification="Compensating controls should explicitly lower interruption pressure instead of disappearing into a hidden score tweak.",
        )

    if context.evidence_strength == "strong":
        _append_adjustment_if_changed(
            adjustments,
            evidence_type=evidence_type,
            evidence_value="strong environment evidence is attached",
            field_affected="truth_status",
            original_value=baseline_decision.truth_status,
            adjusted_value=final_decision.truth_status,
            justification="Strong evidence should upgrade the finding from loose context toward a better-grounded truth state.",
        )

    return adjustments


def _priority_delta(previous: PriorityBand | None, current: PriorityBand) -> str:
    if previous is None:
        return "new"
    previous_rank = _PRIORITY_RANK[previous]
    current_rank = _PRIORITY_RANK[current]
    if current_rank < previous_rank:
        return "escalated"
    if current_rank > previous_rank:
        return "deescalated"
    return "unchanged"


def _build_risk_acceptance_and_delta(
    context: SecurityReviewContext,
    decision: SecurityReviewDecision,
) -> tuple[SecurityReviewRiskAcceptance | None, SecurityReviewDelta | None]:
    acceptance = (
        context.existing_risk_acceptance.model_copy(deep=True)
        if context.existing_risk_acceptance is not None
        else None
    )
    delta = SecurityReviewDelta(
        days_since_last_review=context.days_since_last_review,
        disposition=_priority_delta(context.previous_priority, decision.priority),  # type: ignore[arg-type]
    )

    if delta.disposition == "new":
        delta.new_findings_count = 1
    elif delta.disposition == "escalated":
        delta.escalated_count = 1

    if acceptance is None:
        return None, delta if (
            context.previous_priority is not None
            or context.days_since_last_review is not None
        ) else delta

    now = datetime.now(UTC)
    expires_at = _parse_optional_iso_datetime(acceptance.expires_at)
    expired = expires_at is not None and expires_at <= now
    reopen_reasons: list[str] = []

    if expired:
        acceptance.status = "expired"
        delta.disposition = "reopened"
        delta.reopened_count = 1
        reopen_reasons.append("risk acceptance expired")

    if acceptance.status == "active":
        if context.has_known_exploited_vulnerability:
            reopen_reasons.append("new KEV or active exploitation pressure exists")
        if context.scan_status == "confirmed":
            reopen_reasons.append("validation scan confirmed the condition")
        if (
            context.previous_priority is not None
            and _PRIORITY_RANK[decision.priority]
            < _PRIORITY_RANK[context.previous_priority]
        ):
            reopen_reasons.append(
                "the finding escalated above the previously accepted priority"
            )

    if reopen_reasons:
        acceptance.status = "reopened"
        acceptance.reopen_triggers = sorted(
            set([*acceptance.reopen_triggers, *reopen_reasons])
        )
        delta.disposition = "reopened"
        delta.reopened_count = 1

    return acceptance, delta


def _contexts_are_attack_path_related(
    left: SecurityReviewContext, right: SecurityReviewContext
) -> bool:
    left_nodes = set(left.affected_node_ids)
    right_nodes = set(right.affected_node_ids)
    left_edges = set(left.affected_edge_ids)
    right_edges = set(right.affected_edge_ids)

    if left_nodes & right_nodes:
        return True
    if left_edges & right_edges:
        return True
    if (
        left.target_asset
        and right.entry_point
        and left.target_asset == right.entry_point
    ):
        return True
    if (
        right.target_asset
        and left.entry_point
        and right.target_asset == left.entry_point
    ):
        return True
    if _contexts_have_tight_business_path_bridge(left, right):
        return True
    return False


def _normalized_context_label(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().casefold()
    return candidate or None


def _context_labels(context: SecurityReviewContext) -> set[str]:
    return {
        label
        for label in (
            _normalized_context_label(context.title),
            _normalized_context_label(context.entry_point),
            _normalized_context_label(context.target_asset),
        )
        if label is not None
    }


def _contexts_have_tight_business_path_bridge(
    left: SecurityReviewContext, right: SecurityReviewContext
) -> bool:
    left_capability = _normalized_context_label(left.business_capability)
    right_capability = _normalized_context_label(right.business_capability)
    if not left_capability or left_capability != right_capability:
        return False

    left_exposed = left.internet_facing or left.public_exposure
    right_exposed = right.internet_facing or right.public_exposure
    if not (
        (left_exposed and _is_high_value_attack_target(right))
        or (right_exposed and _is_high_value_attack_target(left))
    ):
        return False

    left_labels = _context_labels(left)
    right_labels = _context_labels(right)
    left_entry = _normalized_context_label(left.entry_point)
    right_entry = _normalized_context_label(right.entry_point)
    if left_entry and left_entry == right_entry:
        return True
    left_target = _normalized_context_label(left.target_asset)
    right_target = _normalized_context_label(right.target_asset)
    return bool(
        (left_target and left_target in right_labels)
        or (right_target and right_target in left_labels)
    )


def _max_priority(priorities: list[PriorityBand]) -> PriorityBand:
    return min(priorities, key=lambda item: _PRIORITY_RANK[item])


def _max_exploitability(values: list[ExploitabilityRating]) -> ExploitabilityRating:
    return max(values, key=lambda item: _EXPLOITABILITY_RANK[item])


def _is_high_value_attack_target(context: SecurityReviewContext) -> bool:
    return (
        context.data_classification in {"Restricted", "Confidential"}
        or context.privileged_access
        or context.control_plane_asset
        or context.crown_jewel
        or context.business_criticality in {"mission_critical", "high"}
    )


def _select_attack_path_entry_point(
    contexts: list[SecurityReviewContext],
) -> str | None:
    public_entries = [
        context.entry_point or context.title
        for context in contexts
        if context.internet_facing or context.public_exposure
    ]
    if public_entries:
        return public_entries[0]
    return contexts[0].entry_point or contexts[0].title if contexts else None


def _attack_path_target_for_context(
    context: SecurityReviewContext,
    entry_point: str | None,
) -> str | None:
    if context.target_asset and context.target_asset != entry_point:
        return context.target_asset
    if (
        _is_high_value_attack_target(context)
        and not context.internet_facing
        and not context.public_exposure
        and context.title != entry_point
    ):
        return context.title
    return None


def _stable_unique_indexes(indexes: list[int]) -> list[int]:
    seen: set[int] = set()
    unique: list[int] = []
    for index in indexes:
        if index in seen:
            continue
        seen.add(index)
        unique.append(index)
    return unique


def _stable_unique_strings(values: list[str | None]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value is None:
            continue
        candidate = value.strip()
        if not candidate:
            continue
        key = candidate.casefold()
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _select_attack_path_entry_indexes(
    component: list[int],
    contexts: list[SecurityReviewContext],
    entry_point: str | None,
) -> list[int]:
    direct_entry_indexes = [
        index
        for index in component
        if contexts[index].entry_point == entry_point
        and (
            not contexts[index].target_asset
            or contexts[index].target_asset == entry_point
        )
    ]
    if direct_entry_indexes:
        return direct_entry_indexes

    exposed_same_entry_indexes = [
        index
        for index in component
        if contexts[index].entry_point == entry_point
        and (contexts[index].internet_facing or contexts[index].public_exposure)
    ]
    if exposed_same_entry_indexes:
        return exposed_same_entry_indexes

    exposed_indexes = [
        index
        for index in component
        if contexts[index].internet_facing or contexts[index].public_exposure
    ]
    if exposed_indexes:
        return exposed_indexes

    return [component[0]]


def _build_attack_path_nodes(
    entry_point: str | None,
    target_asset: str,
    contexts: list[SecurityReviewContext],
) -> list[str]:
    labels: list[str | None] = [entry_point]
    for context in contexts:
        if context.entry_point and context.entry_point != entry_point:
            labels.append(context.entry_point)
        if context.target_asset:
            labels.append(context.target_asset)
    labels.append(target_asset)
    return _stable_unique_strings(labels)[:5]


def _build_attack_path_evidence_sources(
    contexts: list[SecurityReviewContext],
) -> list[str]:
    sources = {source for context in contexts for source in context.finding_sources}
    return sorted(
        sources,
        key=lambda source: (
            _EVIDENCE_SOURCE_ORDER.index(source)
            if source in _EVIDENCE_SOURCE_ORDER
            else len(_EVIDENCE_SOURCE_ORDER),
            source,
        ),
    )


def _build_attack_path_relationship_reasons(
    entry_point: str | None,
    target_asset: str,
    contexts: list[SecurityReviewContext],
) -> list[str]:
    reasons: list[str] = []
    if entry_point:
        reasons.append(
            f"Starts from exposed or review-relevant entry point {entry_point}."
        )
    if any(context.internet_facing or context.public_exposure for context in contexts):
        reasons.append("At least one supporting finding is externally reachable.")
    if any(context.crosses_trust_boundary for context in contexts):
        reasons.append("The supporting findings include a trust-boundary crossing.")
    if any(
        context.data_classification in {"Restricted", "Confidential"}
        for context in contexts
    ):
        reasons.append(f"{target_asset} is on a restricted or confidential data path.")
    if any(
        context.privileged_access or context.control_plane_asset or context.crown_jewel
        for context in contexts
    ):
        reasons.append(
            "The route includes privileged, control-plane, or crown-jewel access."
        )
    if any(context.scan_status == "confirmed" for context in contexts):
        reasons.append(
            "Validation scan evidence confirms at least one supporting condition."
        )
    if any(context.has_semantic_threat_intel for context in contexts):
        reasons.append(
            "Semantic threat-intel signals line up with the modeled behavior."
        )
    if len(_build_attack_path_evidence_sources(contexts)) > 1:
        reasons.append("Multiple evidence sources converge on the same route.")
    return _stable_unique_strings(reasons)[:4]


def _build_attack_path_verification_steps(
    entry_point: str | None,
    target_asset: str,
    contexts: list[SecurityReviewContext],
) -> list[str]:
    source = entry_point or "the entry point"
    steps = [
        f"Trace runtime telemetry from {source} to {target_asset} and confirm the expected intermediates only.",
    ]
    if any(context.internet_facing or context.public_exposure for context in contexts):
        steps.append(
            f"Verify {source} enforces authentication, authorization, input validation, and rate limits before downstream calls."
        )
    if any(
        context.data_classification in {"Restricted", "Confidential"}
        or context.privileged_access
        for context in contexts
    ):
        steps.append(
            f"Confirm {target_asset} denies direct or over-broad access and requires a scoped service identity."
        )
    if any(context.crosses_trust_boundary for context in contexts):
        steps.append(
            "Check mTLS, network policy, segmentation, and egress allowlists at each trust-boundary crossing."
        )
    if any(context.scan_status == "confirmed" for context in contexts):
        steps.append(
            "Attach fresh validation evidence showing the confirmed condition is fixed or still exploitable."
        )
    if any(context.scan_status == "unverifiable" for context in contexts):
        steps.append(
            "Resolve unverifiable scan evidence with a targeted probe, log sample, or manual reproduction note."
        )
    if any(context.code_links for context in contexts):
        steps.append(
            "Review linked repository evidence for the exact route, guard condition, and test coverage."
        )
    return _stable_unique_strings(steps)[:4]


def _build_attack_path(
    *,
    path_id: str,
    entry_point: str | None,
    target_asset: str,
    contexts: list[SecurityReviewContext],
    decisions: list[SecurityReviewDecision],
    support_indexes: list[int],
    attachment_indexes: list[int],
) -> SecurityReviewAttackPath:
    support_indexes = _stable_unique_indexes(support_indexes)
    attachment_indexes = _stable_unique_indexes([*support_indexes, *attachment_indexes])
    support_contexts = [contexts[index] for index in support_indexes]
    attachment_contexts = [contexts[index] for index in attachment_indexes]
    support_decisions = [decisions[index] for index in support_indexes]
    path_nodes = _build_attack_path_nodes(entry_point, target_asset, support_contexts)
    support_count = len(support_contexts)
    finding_label = "finding" if support_count == 1 else "findings"

    return SecurityReviewAttackPath(
        path_id=path_id,
        finding_keys=[
            context.finding_key or context.title for context in attachment_contexts
        ],
        finding_titles=[context.title for context in support_contexts[:4]],
        chain_description=(
            f"{entry_point or 'Unknown entry'} -> {target_asset} "
            f"across {support_count} related {finding_label}"
        ),
        entry_point=entry_point,
        target_asset=target_asset,
        hop_count=max(len(path_nodes) - 1, 1),
        support_count=support_count,
        composite_exploitability=_max_exploitability(
            [decision.exploitability for decision in support_decisions]
        ),
        composite_priority=_max_priority(
            [decision.priority for decision in support_decisions]
        ),
        path_nodes=path_nodes,
        evidence_sources=_build_attack_path_evidence_sources(support_contexts),
        relationship_reasons=_build_attack_path_relationship_reasons(
            entry_point,
            target_asset,
            support_contexts,
        ),
        verification_steps=_build_attack_path_verification_steps(
            entry_point,
            target_asset,
            support_contexts,
        ),
    )


def synthesize_attack_paths(
    contexts: list[SecurityReviewContext],
    decisions: list[SecurityReviewDecision] | None = None,
) -> list[SecurityReviewAttackPath]:
    """Group related findings into path-level risks."""

    if len(contexts) < 2:
        return []

    if decisions is None:
        decisions = [evaluate_security_review_context(context) for context in contexts]

    visited: set[int] = set()
    paths: list[SecurityReviewAttackPath] = []

    for start_index in range(len(contexts)):
        if start_index in visited:
            continue
        queue = [start_index]
        component: list[int] = []
        while queue:
            index = queue.pop()
            if index in visited:
                continue
            visited.add(index)
            component.append(index)
            for candidate_index in range(len(contexts)):
                if candidate_index in visited or candidate_index == index:
                    continue
                if _contexts_are_attack_path_related(
                    contexts[index], contexts[candidate_index]
                ):
                    queue.append(candidate_index)

        if len(component) < 2:
            continue

        component_contexts = [contexts[index] for index in component]
        entry_point = _select_attack_path_entry_point(component_contexts)
        entry_indexes = _select_attack_path_entry_indexes(
            component, contexts, entry_point
        )

        target_groups: dict[str, list[int]] = {}
        for index in component:
            target = _attack_path_target_for_context(contexts[index], entry_point)
            if target is None:
                continue
            target_groups.setdefault(target, []).append(index)

        if not target_groups:
            fallback_target = next(
                (
                    candidate
                    for context in component_contexts
                    for candidate in (context.target_asset, context.title)
                    if candidate and candidate != entry_point
                ),
                None,
            )
            if fallback_target is not None:
                target_groups[fallback_target] = component

        for target_asset, target_indexes in target_groups.items():
            support_indexes = _stable_unique_indexes(
                [*entry_indexes[:1], *target_indexes[:3]]
            )
            if len(support_indexes) < 2:
                continue
            attachment_indexes = _stable_unique_indexes(
                [*entry_indexes[:1], *target_indexes]
            )
            paths.append(
                _build_attack_path(
                    path_id=f"path-{len(paths) + 1}",
                    entry_point=entry_point,
                    target_asset=target_asset,
                    contexts=contexts,
                    decisions=decisions,
                    support_indexes=support_indexes,
                    attachment_indexes=attachment_indexes,
                )
            )

    return paths


def evaluate_security_review_context(
    context: SecurityReviewContext,
) -> SecurityReviewDecision:
    """Evaluate one security-review finding deterministically."""

    baseline_context = _build_baseline_context(context)
    baseline_decision = _evaluate_core_context(baseline_context)
    final_decision = _evaluate_core_context(context)
    final_decision.evidence_adjustments = _build_evidence_adjustments(
        context, baseline_decision, final_decision
    )
    (
        final_decision.risk_acceptance,
        final_decision.review_delta,
    ) = _build_risk_acceptance_and_delta(context, final_decision)
    return final_decision


def evaluate_security_review_contexts(
    contexts: list[SecurityReviewContext],
) -> list[SecurityReviewDecision]:
    """Evaluate a set of related findings and attach attack-path context."""

    decisions = [evaluate_security_review_context(context) for context in contexts]
    attack_paths = synthesize_attack_paths(contexts, decisions)
    if not attack_paths:
        return decisions

    for context, decision in zip(contexts, decisions, strict=True):
        decision.related_attack_paths = [
            path
            for path in attack_paths
            if (context.finding_key or context.title) in path.finding_keys
        ]
    return decisions

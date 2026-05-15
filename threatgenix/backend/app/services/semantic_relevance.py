"""Deterministic semantic relevance scoring.

This layer converts evidence quality into promotion decisions without relying on
model prose. AI-only text can explain a hypothesis, but it cannot raise
confidence by itself.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.schemas.evidence import EvidenceConfidenceLabel
from app.schemas.semantic import (
    SemanticDecision,
    SemanticEvidenceSignal,
    SemanticRelevanceAssessment,
)

SOURCE_WEIGHTS: dict[str, float] = {
    "confirmed_scan": 35.0,
    "exact_external": 25.0,
    "rule": 20.0,
    "exact_code_binding": 20.0,
    "dfd_topology": 15.0,
    "semantic_threat_intel": 8.0,
    "human_attestation": 25.0,
    "ai_only": 0.0,
}

QUALITY_MULTIPLIERS: dict[str, float] = {
    "validated": 1.0,
    "exact": 1.0,
    "indicated": 0.75,
    "semantic": 0.6,
    "contextual": 0.45,
    "ai_text": 0.3,
    "unknown": 0.0,
}

GROUNDED_SIGNAL_TYPES = set(SOURCE_WEIGHTS) - {"ai_only"}


def semantic_confidence_label(
    score: float,
    *,
    grounded_signal_count: int,
) -> EvidenceConfidenceLabel:
    if grounded_signal_count == 0:
        return "suppressed"
    if score >= 80:
        return "validated"
    if score >= 60:
        return "strongly_indicated"
    if score >= 35:
        return "contextual"
    if score > 0:
        return "theoretical"
    return "suppressed"


def semantic_decision(
    score: float,
    *,
    grounded_signal_count: int,
) -> SemanticDecision:
    if grounded_signal_count == 0 or score <= 0:
        return "suppress_noise"
    if score >= 60:
        return "promote"
    if score >= 35:
        return "queue_gather_evidence"
    return "suppress_noise"


def evaluate_semantic_relevance(
    signals: Iterable[SemanticEvidenceSignal],
) -> SemanticRelevanceAssessment:
    score = 0.0
    reasons: list[str] = []
    suppressed_reasons: list[str] = []
    grounded_signal_count = 0
    seen_signal_keys: set[str] = set()

    for signal in signals:
        if not signal.present:
            suppressed_reasons.append(f"missing:{signal.signal_type}")
            continue
        signal_key = signal.source_key or (
            f"{signal.signal_type}:{signal.quality}:{signal.rationale}"
        )
        if signal_key in seen_signal_keys:
            suppressed_reasons.append(f"duplicate:{signal.signal_type}")
            continue
        seen_signal_keys.add(signal_key)
        if signal.signal_type == "ai_only":
            suppressed_reasons.append("ai_only_cannot_promote")
            continue
        if signal.quality == "ai_text":
            suppressed_reasons.append(f"ai_text_cannot_ground:{signal.signal_type}")
            continue

        base_weight = (
            signal.weight_override
            if signal.weight_override is not None
            else SOURCE_WEIGHTS[signal.signal_type]
        )
        multiplier = QUALITY_MULTIPLIERS[signal.quality]
        contribution = base_weight * multiplier

        if signal.signal_type in GROUNDED_SIGNAL_TYPES and contribution > 0:
            grounded_signal_count += 1
            reasons.append(f"{signal.signal_type}:{signal.quality}:{contribution:.1f}")

        score += contribution

    score = min(round(score, 2), 100.0)
    label = semantic_confidence_label(
        score,
        grounded_signal_count=grounded_signal_count,
    )
    return SemanticRelevanceAssessment(
        score=score,
        confidence_label=label,
        decision=semantic_decision(
            score,
            grounded_signal_count=grounded_signal_count,
        ),
        grounded_signal_count=grounded_signal_count,
        reasons=reasons,
        suppressed_reasons=suppressed_reasons,
    )

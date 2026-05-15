from __future__ import annotations

from app.schemas.semantic import SemanticEvidenceSignal
from app.services.semantic_relevance import evaluate_semantic_relevance


def test_semantic_relevance_suppresses_ai_only_claims():
    assessment = evaluate_semantic_relevance(
        [
            SemanticEvidenceSignal(
                signal_type="ai_only",
                quality="ai_text",
                rationale="The model speculated about SQL injection.",
            )
        ]
    )

    assert assessment.score == 0
    assert assessment.confidence_label == "suppressed"
    assert assessment.decision == "suppress_noise"
    assert assessment.grounded_signal_count == 0
    assert assessment.suppressed_reasons == ["ai_only_cannot_promote"]


def test_semantic_relevance_ignores_ai_only_weight_override():
    assessment = evaluate_semantic_relevance(
        [
            SemanticEvidenceSignal(
                signal_type="ai_only",
                quality="ai_text",
                rationale="The model assigned a high score without evidence.",
                weight_override=100,
            )
        ]
    )

    assert assessment.score == 0
    assert assessment.confidence_label == "suppressed"
    assert assessment.decision == "suppress_noise"


def test_semantic_relevance_rejects_ai_text_for_grounded_signal_type():
    assessment = evaluate_semantic_relevance(
        [
            SemanticEvidenceSignal(
                signal_type="confirmed_scan",
                quality="ai_text",
                rationale="AI prose was mislabeled as scanner output.",
            )
        ]
    )

    assert assessment.score == 0
    assert assessment.grounded_signal_count == 0
    assert assessment.suppressed_reasons == ["ai_text_cannot_ground:confirmed_scan"]


def test_semantic_relevance_dedupes_repeated_signal_source():
    assessment = evaluate_semantic_relevance(
        [
            SemanticEvidenceSignal(
                signal_type="rule",
                quality="validated",
                rationale="Rule matched a specific threat precondition.",
                source_key="rule:T-001",
            ),
            SemanticEvidenceSignal(
                signal_type="rule",
                quality="validated",
                rationale="Rule matched a specific threat precondition.",
                source_key="rule:T-001",
            ),
        ]
    )

    assert assessment.score == 20
    assert assessment.grounded_signal_count == 1
    assert assessment.suppressed_reasons == ["duplicate:rule"]


def test_semantic_relevance_promotes_validated_grounded_evidence():
    assessment = evaluate_semantic_relevance(
        [
            SemanticEvidenceSignal(
                signal_type="confirmed_scan",
                quality="validated",
                rationale="Nuclei matched a vulnerability template on the node target.",
            ),
            SemanticEvidenceSignal(
                signal_type="exact_external",
                quality="exact",
                rationale="CVE affects the detected package and version.",
            ),
        ]
    )

    assert assessment.score == 60
    assert assessment.confidence_label == "strongly_indicated"
    assert assessment.decision == "promote"
    assert assessment.grounded_signal_count == 2


def test_semantic_relevance_suppresses_low_weight_contextual_matches():
    assessment = evaluate_semantic_relevance(
        [
            SemanticEvidenceSignal(
                signal_type="rule",
                quality="contextual",
                rationale="Rule matched a broad architecture pattern.",
            ),
            SemanticEvidenceSignal(
                signal_type="dfd_topology",
                quality="indicated",
                rationale="The data flow crosses a trust boundary.",
            ),
            SemanticEvidenceSignal(
                signal_type="semantic_threat_intel",
                quality="semantic",
                rationale="Threat intel mentions a similar component family.",
            ),
        ]
    )

    assert assessment.score == 25.05
    assert assessment.confidence_label == "theoretical"
    assert assessment.decision == "suppress_noise"
    assert assessment.grounded_signal_count == 3


def test_semantic_relevance_needs_enough_grounded_weight_for_gather_evidence():
    assessment = evaluate_semantic_relevance(
        [
            SemanticEvidenceSignal(
                signal_type="rule",
                quality="validated",
                rationale="Rule matched a specific threat precondition.",
            ),
            SemanticEvidenceSignal(
                signal_type="dfd_topology",
                quality="validated",
                rationale="The exact affected edge crosses a boundary.",
            ),
        ]
    )

    assert assessment.score == 35
    assert assessment.confidence_label == "contextual"
    assert assessment.decision == "queue_gather_evidence"


def test_semantic_relevance_deduplicates_and_rejects_ai_text_grounding():
    assessment = evaluate_semantic_relevance(
        [
            SemanticEvidenceSignal(
                signal_type="confirmed_scan",
                quality="validated",
                rationale="Nuclei matched the affected route.",
                source_key="scan-finding:1",
            ),
            SemanticEvidenceSignal(
                signal_type="confirmed_scan",
                quality="validated",
                rationale="Same Nuclei finding repeated by another mapper.",
                source_key="scan-finding:1",
            ),
            SemanticEvidenceSignal(
                signal_type="semantic_threat_intel",
                quality="ai_text",
                rationale="The generated narrative says this might be related.",
            ),
        ]
    )

    assert assessment.score == 35
    assert assessment.grounded_signal_count == 1
    assert assessment.decision == "queue_gather_evidence"
    assert assessment.suppressed_reasons == [
        "duplicate:confirmed_scan",
        "ai_text_cannot_ground:semantic_threat_intel",
    ]

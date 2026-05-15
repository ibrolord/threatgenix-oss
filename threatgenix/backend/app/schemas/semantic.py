"""Schemas for deterministic semantic relevance scoring."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.evidence import EvidenceConfidenceLabel


SemanticSignalType = Literal[
    "confirmed_scan",
    "exact_external",
    "rule",
    "exact_code_binding",
    "dfd_topology",
    "semantic_threat_intel",
    "ai_only",
    "human_attestation",
]
SemanticMatchQuality = Literal[
    "validated",
    "exact",
    "indicated",
    "semantic",
    "contextual",
    "ai_text",
    "unknown",
]
SemanticDecision = Literal[
    "promote",
    "queue_gather_evidence",
    "suppress_noise",
]


class SemanticEvidenceSignal(BaseModel):
    signal_type: SemanticSignalType
    quality: SemanticMatchQuality
    rationale: str = Field(min_length=1, max_length=500)
    present: bool = True
    weight_override: float | None = Field(default=None, ge=0, le=100)
    source_key: str | None = Field(default=None, max_length=500)


class SemanticRelevanceAssessment(BaseModel):
    score: float
    confidence_label: EvidenceConfidenceLabel
    decision: SemanticDecision
    grounded_signal_count: int
    reasons: list[str] = Field(default_factory=list)
    suppressed_reasons: list[str] = Field(default_factory=list)

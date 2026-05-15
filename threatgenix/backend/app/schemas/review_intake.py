"""Versioned intake question bank for application security reviews."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

ReviewInputKind = Literal["diff", "snapshot", "metadata"]
IntakeQuestionType = Literal[
    "text",
    "textarea",
    "single_select",
    "multi_select",
    "boolean",
    "string_list",
]


class IntakeQuestionOption(BaseModel):
    value: str = Field(min_length=1, max_length=120)
    label: str = Field(min_length=1, max_length=160)


class IntakeQuestion(BaseModel):
    id: str = Field(min_length=1, max_length=120)
    label: str = Field(min_length=1, max_length=240)
    description: str = Field(default="", max_length=1000)
    answer_type: IntakeQuestionType
    required_for: list[ReviewInputKind] = Field(default_factory=list)
    optional_for: list[ReviewInputKind] = Field(default_factory=list)
    options: list[IntakeQuestionOption] = Field(default_factory=list)
    max_length: int | None = Field(default=None, ge=1, le=5000)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("question id must not be blank")
        return candidate

    @model_validator(mode="after")
    def validate_options_for_selects(self) -> "IntakeQuestion":
        if self.answer_type in {"single_select", "multi_select"} and not self.options:
            raise ValueError("select questions require options")
        if self.answer_type not in {"single_select", "multi_select"} and self.options:
            raise ValueError("only select questions may define options")
        return self


class IntakeQuestionBankResponse(BaseModel):
    version: str
    review_type: ReviewInputKind
    questions: list[IntakeQuestion]


class IntakeValidationRequest(BaseModel):
    version: str = "threatgenix_appsec_v1"
    review_type: ReviewInputKind
    answers: dict[str, object] = Field(default_factory=dict)


class IntakeValidationResponse(BaseModel):
    version: str
    review_type: ReviewInputKind
    valid: bool
    normalized_answers: dict[str, object] = Field(default_factory=dict)
    missing_required: list[str] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)
    adaptive_followups: list[IntakeQuestion] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

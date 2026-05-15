from __future__ import annotations

from typing import Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.security_review import ReviewArtifactKind, ReviewSourceObjectType


AssistantMode = Literal["ask", "explain", "review", "build"]
AssistantAnchorKind = Literal["node", "edge", "boundary", "threat"]
AssistantSeverity = Literal["high", "medium", "low", "info"]
AssistantProposalType = Literal[
    "create_connected_node",
    "create_node",
    "create_edge",
    "create_boundary",
    "update_node",
    "create_assumption",
]
AssistantGuidedStepStatus = Literal["done", "current", "up_next"]

MAX_ASSISTANT_MESSAGE_LENGTH = 20_000
MAX_ASSISTANT_ANSWER_LENGTH = 20_000


class AssistantAnchor(BaseModel):
    kind: AssistantAnchorKind
    id: UUID


class AssistantRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=MAX_ASSISTANT_MESSAGE_LENGTH)
    mode_hint: Optional[AssistantMode] = None
    anchor: Optional[AssistantAnchor] = None
    review_finding_id: Optional[str] = Field(default=None, min_length=1, max_length=255)


class AssistantReference(BaseModel):
    kind: AssistantAnchorKind
    id: UUID
    label: str = Field(..., min_length=1, max_length=255)


class AssistantReviewFinding(BaseModel):
    severity: AssistantSeverity
    title: str = Field(..., min_length=1, max_length=160)
    description: str = Field(..., min_length=1, max_length=1200)
    references: list[AssistantReference] = Field(default_factory=list)


class AssistantActionArtifact(BaseModel):
    kind: ReviewArtifactKind
    title: str = Field(..., min_length=1, max_length=160)
    summary: str = Field(..., min_length=1, max_length=500)
    body: str = Field(..., min_length=1, max_length=4000)
    review_finding_id: str = Field(..., min_length=1, max_length=255)
    source_object_type: ReviewSourceObjectType
    source_object_id: str = Field(..., min_length=1, max_length=255)
    references: list[AssistantReference] = Field(default_factory=list)


class AssistantGuidedStep(BaseModel):
    id: str = Field(..., min_length=1, max_length=80)
    title: str = Field(..., min_length=1, max_length=160)
    description: str = Field(..., min_length=1, max_length=1200)
    prompt: str = Field(..., min_length=1, max_length=1200)
    status: AssistantGuidedStepStatus
    anchor: Optional[AssistantAnchor] = None
    references: list[AssistantReference] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list, max_length=5)
    proposal_bundle: Optional["AssistantProposalBundle"] = None


class AssistantProposal(BaseModel):
    proposal_type: AssistantProposalType
    title: str = Field(..., min_length=1, max_length=160)
    summary: str = Field(..., min_length=1, max_length=1500)

    anchor_node_id: Optional[UUID] = None
    anchor_handle: Optional[Literal["source", "target"]] = None

    node_id: Optional[UUID] = None
    node_type: Optional[str] = None
    node_name: Optional[str] = None
    position_x: Optional[float] = None
    position_y: Optional[float] = None

    source_node_id: Optional[UUID] = None
    target_node_id: Optional[UUID] = None
    edge_label: str = ""
    edge_properties: dict[str, Any] = Field(default_factory=dict)

    boundary_name: Optional[str] = None
    boundary_node_ids: list[UUID] = Field(default_factory=list)

    name_patch: Optional[str] = None
    properties_patch: dict[str, Any] = Field(default_factory=dict)

    assumption_title: Optional[str] = Field(default=None, max_length=160)
    assumption_description: Optional[str] = Field(default=None, max_length=2000)
    assumption_status: Optional[Literal["open", "validated", "challenged"]] = None
    assumption_anchor_kind: Optional[Literal["node", "edge", "boundary"]] = None
    assumption_anchor_id: Optional[UUID] = None
    assumption_anchor_label: Optional[str] = Field(default=None, max_length=255)


class AssistantProposalBundle(BaseModel):
    title: str = Field(..., min_length=1, max_length=160)
    summary: str = Field(..., min_length=1, max_length=1500)
    proposals: list[AssistantProposal] = Field(default_factory=list, min_length=1, max_length=6)


class AssistantResponse(BaseModel):
    mode: AssistantMode
    answer: str = Field(..., min_length=1, max_length=MAX_ASSISTANT_ANSWER_LENGTH)
    references: list[AssistantReference] = Field(default_factory=list)
    findings: list[AssistantReviewFinding] = Field(default_factory=list)
    action_artifacts: list[AssistantActionArtifact] = Field(default_factory=list)
    guided_steps: list[AssistantGuidedStep] = Field(default_factory=list)
    proposal: Optional[AssistantProposal] = None
    degraded_reason: Optional[str] = None

"""Agent-facing schemas for invoke-anywhere reviews."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.application_review import ApplicationReviewResponse
from app.schemas.application_review_context import ApplicationReviewContextEntryResponse
from app.schemas.application_review_decision import ApplicationReviewDecisionResponse
from app.schemas.application_review_orchestration import ApplicationReviewOrchestrationResponse

AGENT_CONTRACT_VERSION = "threatgenix.agent.v1"


class AgentCommandHint(BaseModel):
    label: str
    command: str
    description: str


class AgentToolHint(BaseModel):
    name: str
    method: str
    endpoint: str
    description: str
    input_schema: dict = Field(default_factory=dict)
    output_schema: dict = Field(default_factory=dict)
    rate_limit: dict = Field(default_factory=dict)
    quota_cost: dict = Field(default_factory=dict)


class AgentRateLimitMetadata(BaseModel):
    window_seconds: int
    token_limit: int
    token_remaining: int
    tenant_limit: int
    tenant_remaining: int
    retry_after_seconds: int
    token_fingerprint: str


class AgentQuotaBucket(BaseModel):
    window_seconds: int
    limit: int
    used: int
    remaining: int


class AgentAccessMetadata(BaseModel):
    rate_limit: AgentRateLimitMetadata
    quotas: dict[str, AgentQuotaBucket] = Field(default_factory=dict)


class AgentReviewStatusResponse(BaseModel):
    contract_version: str = AGENT_CONTRACT_VERSION
    review: ApplicationReviewResponse
    web_url: str
    api_status_url: str
    terminal_commands: list[AgentCommandHint] = Field(default_factory=list)
    agent_tools: list[AgentToolHint] = Field(default_factory=list)
    access: AgentAccessMetadata | None = None


class AgentReviewFindingsResponse(BaseModel):
    contract_version: str = AGENT_CONTRACT_VERSION
    review_id: UUID
    findings: list[ApplicationReviewContextEntryResponse] = Field(default_factory=list)
    access: AgentAccessMetadata | None = None


class AgentEvidenceChainResponse(BaseModel):
    review_id: UUID
    finding_id: UUID
    source_refs: list[dict] = Field(default_factory=list)
    content_hash: str
    access: AgentAccessMetadata | None = None


class AgentOpenReviewResponse(BaseModel):
    contract_version: str = AGENT_CONTRACT_VERSION
    review_id: UUID
    web_url: str
    access: AgentAccessMetadata | None = None


class AgentRerunReviewResponse(BaseModel):
    contract_version: str = AGENT_CONTRACT_VERSION
    review_id: UUID
    indexed_entry_count: int
    decision: ApplicationReviewDecisionResponse
    access: AgentAccessMetadata | None = None


class AgentReviewOrchestrationResponse(BaseModel):
    contract_version: str = AGENT_CONTRACT_VERSION
    orchestration: ApplicationReviewOrchestrationResponse
    agent_tools: list[AgentToolHint] = Field(default_factory=list)
    access: AgentAccessMetadata | None = None

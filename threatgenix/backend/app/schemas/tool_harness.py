"""Schemas for managed scanner harness output."""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

ToolHarnessStatus = Literal["completed", "failed", "blocked"]
ToolHarnessSeverity = Literal["Critical", "High", "Medium", "Low"]
ToolHarnessConfidence = Literal["high", "medium", "low"]
ToolHarnessSourceType = Literal[
    "sast",
    "dependency",
    "secret",
    "iac",
    "ai_system",
    "external",
]
ToolHarnessName = Literal[
    "semgrep",
    "osv-scanner",
    "trivy",
    "checkov",
    "trufflehog",
    "nuclei",
    "ai-red-team",
]
HarnessToolName = Literal[
    "bundle_parser",
    "code_context_extractor",
    "managed_sast",
    "dependency_scanner",
    "secrets_scanner",
    "iac_scanner",
    "sarif_importer",
    "evidence_graph_rebuild",
    "security_context_indexer",
    "context_packet_builder",
    "deterministic_decision_engine",
    "ai_fix_plan_generator",
]
HarnessExecutionStatus = Literal["completed", "failed", "blocked", "timeout"]
HarnessEventType = Literal["started", "completed", "failed", "blocked", "timeout", "warning"]
HarnessNetworkPolicy = Literal["none", "internal", "external_passive", "external_active"]
EvidenceItemType = Literal[
    "bundle_file",
    "scanner_finding",
    "code_context",
    "security_context",
    "evidence_graph",
    "context_packet",
    "decision_trace",
    "ai_explanation",
]


class ToolHarnessProvenance(BaseModel):
    issuer: str = Field(min_length=1, max_length=120)
    tool_name: str = Field(min_length=1, max_length=120)
    scanner_run_id: str = Field(min_length=1, max_length=120)
    bundle_id: UUID
    output_format: str = Field(min_length=1, max_length=80)
    scanner_image: str | None = Field(default=None, max_length=500)
    scanner_image_digest: str | None = Field(default=None, max_length=160)
    ruleset_digest: str | None = Field(default=None, max_length=160)


class ToolHarnessFinding(BaseModel):
    rule_id: str = Field(min_length=1, max_length=240)
    title: str = Field(min_length=1, max_length=500)
    severity: ToolHarnessSeverity
    path: str = Field(min_length=1, max_length=500)
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    evidence_snippet_sha256: str = Field(min_length=64, max_length=64)
    confidence: ToolHarnessConfidence = "medium"
    source_type: ToolHarnessSourceType

    @field_validator("rule_id", "title", "path")
    @classmethod
    def strip_required_string(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("value must not be blank")
        return candidate

    @field_validator("evidence_snippet_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        candidate = value.strip().lower()
        if len(candidate) != 64 or any(char not in "0123456789abcdef" for char in candidate):
            raise ValueError("evidence_snippet_sha256 must be a 64-character hex digest")
        return candidate

    @model_validator(mode="after")
    def validate_line_range(self) -> "ToolHarnessFinding":
        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class ToolHarnessOutput(BaseModel):
    tool_name: ToolHarnessName
    tool_version: str = Field(min_length=1, max_length=120)
    ruleset_version: str = Field(min_length=1, max_length=120)
    scanner_run_id: str = Field(min_length=1, max_length=120)
    bundle_id: UUID
    status: ToolHarnessStatus
    findings: list[ToolHarnessFinding] = Field(default_factory=list, max_length=10_000)
    raw_artifact_refs: list[str] = Field(default_factory=list, max_length=100)
    provenance: ToolHarnessProvenance

    @model_validator(mode="after")
    def validate_status_findings(self) -> "ToolHarnessOutput":
        if self.status in {"failed", "blocked"} and self.findings:
            raise ValueError("failed or blocked scanner output cannot include findings")
        return self


class NormalizedToolHarnessFinding(ToolHarnessFinding):
    finding_key: str


class NormalizedToolHarnessOutput(BaseModel):
    tool_name: ToolHarnessName
    tool_version: str
    ruleset_version: str
    scanner_run_id: str
    bundle_id: UUID
    status: ToolHarnessStatus
    trusted: bool
    findings: list[NormalizedToolHarnessFinding] = Field(default_factory=list)
    raw_artifact_refs: list[str] = Field(default_factory=list)
    provenance: ToolHarnessProvenance


class HarnessPolicy(BaseModel):
    network: HarnessNetworkPolicy = "none"
    timeout_seconds: int = Field(default=120, ge=1, le=900)
    allowed_targets: list[str] = Field(default_factory=list, max_length=100)
    allow_active_scanning: bool = False
    redact_secrets: bool = True

    @model_validator(mode="after")
    def validate_active_network_policy(self) -> "HarnessPolicy":
        if self.network == "external_active" and not self.allow_active_scanning:
            raise ValueError("external_active network policy requires allow_active_scanning")
        return self


class HarnessRequest(BaseModel):
    tool_name: HarnessToolName
    tool_version: str = Field(min_length=1, max_length=120)
    tenant_key: str = Field(min_length=1, max_length=120)
    app_id: str | None = Field(default=None, max_length=160)
    review_id: UUID
    bundle_id: UUID | None = None
    idempotency_key: str = Field(min_length=1, max_length=240)
    inputs: dict[str, Any] = Field(default_factory=dict)
    policy: HarnessPolicy = Field(default_factory=HarnessPolicy)


class HarnessEvidenceItem(BaseModel):
    item_type: EvidenceItemType
    title: str = Field(min_length=1, max_length=500)
    source_refs: list[str] = Field(default_factory=list, max_length=100)
    content_hash: str = Field(min_length=64, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("content_hash")
    @classmethod
    def validate_content_hash(cls, value: str) -> str:
        candidate = value.strip().lower()
        if len(candidate) != 64 or any(char not in "0123456789abcdef" for char in candidate):
            raise ValueError("content_hash must be a 64-character hex digest")
        return candidate


class HarnessRedaction(BaseModel):
    source_ref: str = Field(min_length=1, max_length=500)
    redaction_type: str = Field(min_length=1, max_length=120)
    count: int = Field(ge=1)


class HarnessResult(BaseModel):
    status: HarnessExecutionStatus
    evidence_items: list[HarnessEvidenceItem] = Field(default_factory=list, max_length=10_000)
    normalized_findings: list[dict[str, Any]] = Field(default_factory=list, max_length=10_000)
    warnings: list[str] = Field(default_factory=list, max_length=200)
    redactions: list[HarnessRedaction] = Field(default_factory=list, max_length=1_000)
    error_message: str | None = Field(default=None, max_length=2_000)

    @model_validator(mode="after")
    def validate_status_payload(self) -> "HarnessResult":
        if self.status in {"failed", "blocked", "timeout"} and self.normalized_findings:
            raise ValueError("failed, blocked, or timeout harness result cannot include findings")
        return self


class HarnessEvent(BaseModel):
    event_type: HarnessEventType
    message: str = Field(min_length=1, max_length=1_000)
    elapsed_ms: int = Field(ge=0)


class HarnessEnvelope(BaseModel):
    contract_version: Literal["threatgenix.harness.v1"] = "threatgenix.harness.v1"
    request: HarnessRequest
    result: HarnessResult
    events: list[HarnessEvent] = Field(min_length=1, max_length=1_000)
    duration_ms: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_event_status_alignment(self) -> "HarnessEnvelope":
        event_types = {event.event_type for event in self.events}
        if "started" not in event_types:
            raise ValueError("harness envelope must include a started event")
        if self.result.status not in event_types:
            raise ValueError("harness envelope must include an event matching result status")
        if self.result.status == "timeout" and self.duration_ms < self.request.policy.timeout_seconds * 1000:
            raise ValueError("timeout result duration must meet or exceed timeout_seconds")
        return self

"""Threat-scoped validation and remediation agent workflows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.models.application_review import ApplicationSecurityReview
from app.models.application_review_context import ApplicationReviewContextEntry
from app.models.audit import ThreatAuditLog
from app.models.orchestration import OrchestrationEvent, OrchestrationJob, OrchestrationTask
from app.models.scan import ScanAuthorization, ScanFinding, ScanJob
from app.models.threat import Threat
from app.models.threat_agent_orchestration import ThreatRemediationRun, ThreatValidationRun
from app.models.user import User
from app.schemas.scan import AUTHORIZATION_TEXT
from app.schemas.security_review import (
    AgentRemediationAction,
    AgentRemediationConnectorTicketCreateRequest,
    AgentRemediationTicketDraft,
    AgentRemediationTransition,
)
from app.schemas.threat_agent_orchestration import (
    AgentToolCapabilityResponse,
    AgentRunMetadata,
    AgentTraceResponse,
    DomainAgentExecutionResult,
    DomainAgentPlanItem,
    DomainAgentToolMode,
    DomainAgentTargetRequest,
    ExploitabilityAssessment,
    ThreatScanPlanApproveRequest,
    ThreatScanPlanRejectRequest,
    ThreatRemediationEvidenceRequest,
    ThreatRemediationHandoffConfirmRequest,
    ThreatRemediationRunResponse,
    ThreatValidationRunResponse,
)
from app.services.agent_model_adapter import (
    AgentModelAdapter,
    DeterministicFallbackAgentModelAdapter,
    LLMAgentModelAdapter,
    validate_agent_model_payload,
)
from app.services.agent_orchestration_hardening import (
    AgentProbeRateLimitExceeded,
    agent_event_payload_hash,
    enforce_validation_probe_rate_limit,
    evidence_integrity_findings_payload,
    verify_validation_evidence_integrity,
)
from app.services.application_review import tenant_key_for_user
from app.services.application_review_context import (
    ApplicationReviewContextError,
    search_review_context_index,
)
from app.services.orchestration import serialize_orchestration_event
from app.services.remediation_connectors import (
    RemediationConnectorError,
    create_remediation_provider_ticket,
)
from app.services.validation_execution_policy import (
    NETWORK_NONE,
    NETWORK_TARGET_ONLY,
    build_validation_tool_inventory,
    default_validation_execution_policy_registry,
    validation_tool_runtime_availability,
)
from app.services.validation_runtime import validation_run_submission_enabled
from app.services.validation_sandbox import (
    ValidationSandboxTargetError,
    validate_validation_target_reference,
)
from app.services.validation_tools import default_validation_tool_registry
from app.services.validation_target_bundles import (
    ValidationTargetBundleError,
    is_validation_target_bundle_ref,
    validate_target_bundle_ref_for_model,
)

AGENT_CONTRACT_VERSION = "threatgenix.agent_orchestration.v1"
POLICY_VERSION = "threat-validation-policy-v1"
THREAT_VALIDATION_AGENT_VERSION = "threat-validation-agent-v1"
FIX_AGENT_VERSION = "fix-agent-v1"
INPUT_SCHEMA_VERSION = "threat-agent-input-v1"
OUTPUT_SCHEMA_VERSION = "threat-agent-output-v1"
TOOL_HARNESS_VERSIONS = {
    "nuclei": "threatgenix-harness-v1",
    "semgrep": "threatgenix-harness-v1",
    "osv-scanner": "threatgenix-harness-v1",
    "trivy": "threatgenix-harness-v1",
    "checkov": "threatgenix-harness-v1",
    "trufflehog": "threatgenix-harness-v1",
    "ai-red-team": "threatgenix-harness-v1",
    "external-report": "threatgenix-harness-v1",
    "pentest-report": "threatgenix-harness-v1",
}
SAFE_DEFAULT_TOOLS = ["semgrep"]
SAFE_DEFAULT_DOMAIN_AGENTS = ["sast"]
DIRECT_TARGET_KEY = "direct"


@dataclass(frozen=True)
class DomainValidationAgentContract:
    name: str
    label: str
    default_tools: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    default_instructions: str


DOMAIN_VALIDATION_AGENT_CONTRACTS: dict[str, DomainValidationAgentContract] = {
    "sast": DomainValidationAgentContract(
        name="sast",
        label="SAST Agent",
        default_tools=("semgrep",),
        allowed_tools=("semgrep",),
        default_instructions="Validate source-code exploitability and cite file, rule, and code-path evidence.",
    ),
    "dast": DomainValidationAgentContract(
        name="dast",
        label="DAST Agent",
        default_tools=("nuclei",),
        allowed_tools=("nuclei",),
        default_instructions="Validate reachable HTTP/API evidence only when target authorization and scanner policy allow it.",
    ),
    "llm_security": DomainValidationAgentContract(
        name="llm_security",
        label="LLM Security Agent",
        default_tools=("ai-red-team",),
        allowed_tools=("ai-red-team", "external-report", "pentest-report"),
        default_instructions=(
            "Validate prompt injection, jailbreak, RAG poisoning, sensitive data leakage, "
            "model DoS, and agent tool-abuse evidence without model-provider truth claims."
        ),
    ),
    "iac": DomainValidationAgentContract(
        name="iac",
        label="IaC Agent",
        default_tools=("checkov", "trivy"),
        allowed_tools=("checkov", "trivy"),
        default_instructions="Validate Terraform, Kubernetes, Docker, and cloud IaC misconfiguration evidence.",
    ),
    "dependency": DomainValidationAgentContract(
        name="dependency",
        label="Dependency Agent",
        default_tools=("osv-scanner", "trivy"),
        allowed_tools=("osv-scanner", "trivy"),
        default_instructions="Validate dependency advisories and package evidence against lockfile or repository context.",
    ),
    "secrets": DomainValidationAgentContract(
        name="secrets",
        label="Secrets Agent",
        default_tools=("trufflehog",),
        allowed_tools=("trufflehog",),
        default_instructions="Validate credential exposure evidence without revealing secret material.",
    ),
    "configuration": DomainValidationAgentContract(
        name="configuration",
        label="Configuration Agent",
        default_tools=("trivy", "external-report"),
        allowed_tools=("trivy", "external-report", "pentest-report"),
        default_instructions="Validate runtime, platform, header, CORS, feature-flag, and configuration-drift evidence.",
    ),
}
TOOL_PRIMARY_DOMAIN_AGENT = {
    "semgrep": "sast",
    "nuclei": "dast",
    "ai-red-team": "llm_security",
    "checkov": "iac",
    "osv-scanner": "dependency",
    "trufflehog": "secrets",
    "trivy": "iac",
    "external-report": "configuration",
    "pentest-report": "configuration",
}


class ThreatAgentOrchestrationError(ValueError):
    """Raised when an agent workflow cannot be completed."""


async def create_threat_validation_run(
    db: AsyncSession,
    *,
    current_user: User,
    threat: Threat,
    application_review_id: UUID | None = None,
    requested_tools: list[str] | None = None,
    domain_agents: list[str] | None = None,
    domain_agent_tools: dict[str, list[str]] | None = None,
    domain_agent_tool_mode: dict[str, str] | None = None,
    domain_agent_instructions: dict[str, str] | None = None,
    domain_agent_targets: dict[str, DomainAgentTargetRequest] | None = None,
    excluded_tools: dict[str, list[str]] | None = None,
    required_tools: dict[str, list[str]] | None = None,
    domain_agent_plan: list[dict[str, Any]] | None = None,
    question: str | None = None,
) -> ThreatValidationRun:
    if not settings.agent_orchestration_enabled:
        raise ThreatAgentOrchestrationError("Agent orchestration is disabled by configuration.")
    tenant_key = tenant_key_for_user(current_user)
    try:
        enforce_validation_probe_rate_limit(tenant_key=tenant_key, threat_id=threat.id)
    except AgentProbeRateLimitExceeded as exc:
        raise ThreatAgentOrchestrationError(str(exc)) from exc
    plan = _resolve_domain_agent_plan(
        requested_tools=requested_tools,
        domain_agents=domain_agents,
        domain_agent_tools=domain_agent_tools,
        domain_agent_tool_mode=domain_agent_tool_mode,
        domain_agent_instructions=domain_agent_instructions,
        excluded_tools=excluded_tools,
        required_tools=required_tools,
        existing_plan=domain_agent_plan,
    )
    tools = _tools_for_domain_agent_plan(plan)
    run_id = uuid4()
    review = await _select_review(
        db,
        tenant_key=tenant_key,
        threat_model_id=threat.threat_model_id,
        application_review_id=application_review_id,
    )
    job = _new_job(
        current_user=current_user,
        threat=threat,
        run_id=run_id,
        agent_type="threat_validation",
        tools=tools,
        domain_agent_plan=plan,
    )
    run = ThreatValidationRun(
        id=run_id,
        tenant_key=tenant_key,
        owner_id=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
        threat_model_id=threat.threat_model_id,
        threat_id=threat.id,
        application_review_id=review.id if review is not None else None,
        orchestration_job_id=job.id,
        status="running",
        question=question or _default_validation_question(threat),
        requested_tools=tools,
        domain_agent_plan=plan,
        domain_agent_results=[],
        evidence_refs=[],
        exploitability={},
        agent_type="threat_validation",
        agent_version=THREAT_VALIDATION_AGENT_VERSION,
        input_schema_version=INPUT_SCHEMA_VERSION,
        output_schema_version=OUTPUT_SCHEMA_VERSION,
        policy_version=POLICY_VERSION,
        tool_harness_versions=TOOL_HARNESS_VERSIONS,
        deterministic_fallback_used=True,
    )
    db.add(job)
    db.add(run)
    await _emit_event(
        db,
        job=job,
        event_type="created",
        agent_event="agent.started",
        message="Threat Validation Agent started.",
        payload={"domain_agent_plan": plan},
    )
    for item in plan:
        await _emit_event(
            db,
            job=job,
            event_type="note",
            agent_event="domain_agent.planned",
            message=(
                f"{item['label']} planned with "
                f"{', '.join(item['tools']) or 'no tools'}."
            ),
            payload=item,
        )
    await _emit_event(
        db,
        job=job,
        event_type="tool_called",
        agent_event="tool.requested",
        message=f"Requested controlled validation tools: {', '.join(tools)}.",
        payload={
            "requested_tools": tools,
            "domain_agent_plan": plan,
        },
    )
    entries = await _collect_validation_entries(
        db,
        current_user=current_user,
        review=review,
        threat=threat,
    )
    evidence_refs = [_evidence_ref(entry) for entry in entries]
    domain_agent_results = await _build_domain_agent_results(
        db,
        current_user=current_user,
        job=job,
        threat=threat,
        plan=plan,
        evidence_refs=evidence_refs,
        domain_agent_targets=domain_agent_targets or {},
    )
    exploitability = build_exploitability_assessment(
        has_review=review is not None,
        threat=threat,
        evidence_refs=evidence_refs,
        entries=entries,
    )
    conclusion = evaluate_validation_conclusion(
        has_review=review is not None,
        evidence_refs=evidence_refs,
        entries=entries,
        exploitability=exploitability,
    )
    run.domain_agent_results = domain_agent_results
    has_authorized_runner_work = _has_authorized_runner_work(domain_agent_results)
    if has_authorized_runner_work:
        run.evidence_refs = evidence_refs
        run.exploitability = ExploitabilityAssessment(
            status="needs_more_evidence",
            evidence_refs=[str(ref.get("id")) for ref in evidence_refs if ref.get("id")],
            confidence="low",
            rationale=(
                "Controlled domain-agent runner job(s) were authorized. Poll this validation "
                "run until tool evidence is collected or execution fails."
            ),
        ).model_dump()
        run.conclusion = None
        run.status = "running"
        run.summary = "Controlled domain-agent validation job(s) were queued; evidence is pending."
        job.status = "running"
        job.result_summary = run.summary
    else:
        run.evidence_refs = evidence_refs
        run.exploitability = exploitability.model_dump()
        run.conclusion = conclusion
        run.status = "completed"
        run.summary = _validation_summary(conclusion, threat, evidence_refs, exploitability)
        job.status = "completed"
        job.result_summary = run.summary
        job.completed_at = _now()
    if evidence_refs:
        await _emit_event(
            db,
            job=job,
            event_type="evidence_added",
            agent_event="evidence.added",
            message=f"Attached {len(evidence_refs)} evidence reference(s).",
            payload={"evidence_count": len(evidence_refs)},
        )
    await _emit_agent_audit_log(
        db,
        current_user=current_user,
        threat=threat,
        action="agent_validation_started",
        new_status="running",
        reason=f"Started validation run {run.id}.",
    )
    if not has_authorized_runner_work:
        await _emit_event(
            db,
            job=job,
            event_type="completed",
            agent_event="validation.concluded",
            message=f"Validation concluded as {conclusion}.",
            payload={
                "conclusion": conclusion,
                "exploitability_status": exploitability.status,
                "exploitability_confidence": exploitability.confidence,
            },
        )
        await _emit_agent_audit_log(
            db,
            current_user=current_user,
            threat=threat,
            action="agent_validation_done",
            new_status=conclusion,
            reason=run.summary,
        )
    await db.flush()
    await db.refresh(run)
    return run


def list_agent_tool_capabilities() -> list[AgentToolCapabilityResponse]:
    inventory_by_tool = {item.name: item for item in build_validation_tool_inventory()}
    policies = default_validation_execution_policy_registry()
    capabilities: list[AgentToolCapabilityResponse] = []
    for agent_name, contract in DOMAIN_VALIDATION_AGENT_CONTRACTS.items():
        for tool_name in contract.allowed_tools:
            inventory = inventory_by_tool.get(tool_name)
            try:
                policy = policies.get(tool_name)
            except KeyError:
                policy = None
            network_mode = policy.network_mode if policy is not None else NETWORK_NONE
            if network_mode == NETWORK_TARGET_ONLY:
                runtime_risk = "high"
            elif network_mode == NETWORK_NONE:
                runtime_risk = "low"
            else:
                runtime_risk = "medium"
            capabilities.append(
                AgentToolCapabilityResponse(
                    domain_agent=agent_name,  # type: ignore[arg-type]
                    tool=tool_name,
                    label=format_tool_label(tool_name),
                    supported_target_types=list(policy.supported_targets) if policy else [],
                    best_for=list(policy.recommended_for or []) if policy else [],
                    runtime_risk=runtime_risk,  # type: ignore[arg-type]
                    requires_network=network_mode != NETWORK_NONE,
                    requires_credentials=False,
                    requires_human_approval=True,
                    available=bool(inventory.available) if inventory else False,
                    enabled=bool(inventory.execution_enabled) if inventory else False,
                    readiness_status=inventory.readiness_status if inventory else "unregistered",
                    setup_actions=list(inventory.setup_actions) if inventory else [],
                    recommendation_notes=contract.default_instructions,
                )
            )
    return capabilities


async def create_threat_scan_plan(
    db: AsyncSession,
    *,
    current_user: User,
    threat: Threat,
    application_review_id: UUID | None = None,
    requested_tools: list[str] | None = None,
    domain_agents: list[str] | None = None,
    domain_agent_tools: dict[str, list[str]] | None = None,
    domain_agent_tool_mode: dict[str, str] | None = None,
    domain_agent_instructions: dict[str, str] | None = None,
    excluded_tools: dict[str, list[str]] | None = None,
    required_tools: dict[str, list[str]] | None = None,
    question: str | None = None,
) -> ThreatValidationRun:
    if not settings.agent_orchestration_enabled:
        raise ThreatAgentOrchestrationError("Agent orchestration is disabled by configuration.")
    tenant_key = tenant_key_for_user(current_user)
    plan = _resolve_domain_agent_plan(
        requested_tools=requested_tools,
        domain_agents=domain_agents,
        domain_agent_tools=domain_agent_tools,
        domain_agent_tool_mode=domain_agent_tool_mode,
        domain_agent_instructions=domain_agent_instructions,
        excluded_tools=excluded_tools,
        required_tools=required_tools,
    )
    tools = _tools_for_domain_agent_plan(plan)
    run_id = uuid4()
    review = await _select_review(
        db,
        tenant_key=tenant_key,
        threat_model_id=threat.threat_model_id,
        application_review_id=application_review_id,
    )
    job = _new_job(
        current_user=current_user,
        threat=threat,
        run_id=run_id,
        agent_type="threat_validation",
        tools=tools,
        domain_agent_plan=plan,
    )
    job.status = "pending"
    job.result_summary = "Agent scan plan is awaiting human approval."
    run = ThreatValidationRun(
        id=run_id,
        tenant_key=tenant_key,
        owner_id=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
        threat_model_id=threat.threat_model_id,
        threat_id=threat.id,
        application_review_id=review.id if review is not None else None,
        orchestration_job_id=job.id,
        status="created",
        question=question or _default_validation_question(threat),
        requested_tools=tools,
        domain_agent_plan=plan,
        domain_agent_results=_planned_domain_agent_results(plan),
        evidence_refs=[],
        exploitability=ExploitabilityAssessment(
            status="needs_more_evidence",
            confidence="low",
            rationale="Agent scan plan is awaiting human approval before tools run.",
        ).model_dump(),
        summary="Agent scan plan proposed. Review tools, targets, and instructions before approving execution.",
        agent_type="threat_validation",
        agent_version=THREAT_VALIDATION_AGENT_VERSION,
        input_schema_version=INPUT_SCHEMA_VERSION,
        output_schema_version=OUTPUT_SCHEMA_VERSION,
        policy_version=POLICY_VERSION,
        tool_harness_versions=TOOL_HARNESS_VERSIONS,
        deterministic_fallback_used=True,
    )
    db.add(job)
    db.add(run)
    await _emit_event(
        db,
        job=job,
        event_type="created",
        agent_event="scan_plan.proposed",
        message="Threat Validation Agent proposed a scan plan.",
        payload={"domain_agent_plan": plan, "requested_tools": tools},
    )
    await _emit_event(
        db,
        job=job,
        event_type="note",
        agent_event="scan_plan.approval_required",
        message="Human approval is required before controlled tools are executed.",
        payload={"approval_required": True},
    )
    await _emit_agent_audit_log(
        db,
        current_user=current_user,
        threat=threat,
        action="agent_scan_plan",
        new_status="created",
        reason=f"Proposed scan plan {run.id}.",
    )
    await db.flush()
    await db.refresh(run)
    return run


async def approve_threat_scan_plan(
    db: AsyncSession,
    *,
    current_user: User,
    run: ThreatValidationRun,
    body: ThreatScanPlanApproveRequest,
) -> ThreatValidationRun:
    if run.status != "created":
        raise ThreatAgentOrchestrationError("Only a proposed scan plan can be approved.")
    threat = run.threat or await db.get(Threat, run.threat_id)
    if threat is None:
        raise ThreatAgentOrchestrationError("Scan plan is missing its threat.")
    has_plan_override = (
        body.domain_agents is not None
        or body.domain_agent_tools is not None
        or body.domain_agent_tool_mode is not None
        or body.domain_agent_instructions is not None
        or body.excluded_tools is not None
        or body.required_tools is not None
    )
    if has_plan_override:
        plan = _resolve_domain_agent_plan(
            domain_agents=body.domain_agents,
            domain_agent_tools=body.domain_agent_tools,
            domain_agent_tool_mode=body.domain_agent_tool_mode,
            domain_agent_instructions=body.domain_agent_instructions,
            excluded_tools=body.excluded_tools,
            required_tools=body.required_tools,
        )
    else:
        plan = _normalize_existing_domain_agent_plan(run.domain_agent_plan or [])
    tools = _tools_for_domain_agent_plan(plan)
    run.domain_agent_plan = plan
    run.requested_tools = tools
    job = run.orchestration_job
    if job is None:
        job = _new_job(
            current_user=current_user,
            threat=threat,
            run_id=run.id,
            agent_type="threat_validation",
            tools=tools,
            domain_agent_plan=plan,
        )
        db.add(job)
        run.orchestration_job_id = job.id
    job.requested_tools = tools
    job.inputs = {**(job.inputs or {}), "domain_agent_plan": plan}
    job.status = "running"
    job.started_at = job.started_at or _now()
    await _emit_event(
        db,
        job=job,
        event_type="started",
        agent_event="scan_plan.approved",
        message="Human approved the agent scan plan.",
        payload={
            "approval_note": body.approval_note,
            "domain_agent_plan": plan,
            "requested_tools": tools,
        },
    )
    await _emit_event(
        db,
        job=job,
        event_type="tool_called",
        agent_event="tool.requested",
        message=f"Requested approved controlled validation tools: {', '.join(tools)}.",
        payload={"requested_tools": tools, "domain_agent_plan": plan},
    )
    review = await _select_review(
        db,
        tenant_key=run.tenant_key,
        threat_model_id=run.threat_model_id,
        application_review_id=run.application_review_id,
    )
    entries = await _collect_validation_entries(
        db,
        current_user=current_user,
        review=review,
        threat=threat,
    )
    evidence_refs = [_evidence_ref(entry) for entry in entries]
    domain_agent_results = await _build_domain_agent_results(
        db,
        current_user=current_user,
        job=job,
        threat=threat,
        plan=plan,
        evidence_refs=evidence_refs,
        domain_agent_targets=body.domain_agent_targets,
    )
    exploitability = build_exploitability_assessment(
        has_review=review is not None,
        threat=threat,
        evidence_refs=evidence_refs,
        entries=entries,
    )
    conclusion = evaluate_validation_conclusion(
        has_review=review is not None,
        evidence_refs=evidence_refs,
        entries=entries,
        exploitability=exploitability,
    )
    run.domain_agent_results = domain_agent_results
    has_authorized_runner_work = _has_authorized_runner_work(domain_agent_results)
    if has_authorized_runner_work:
        run.evidence_refs = evidence_refs
        run.exploitability = ExploitabilityAssessment(
            status="needs_more_evidence",
            evidence_refs=[str(ref.get("id")) for ref in evidence_refs if ref.get("id")],
            confidence="low",
            rationale="Approved controlled domain-agent runner job(s) are pending evidence.",
        ).model_dump()
        run.conclusion = None
        run.status = "running"
        run.summary = "Approved domain-agent validation job(s) are running; evidence is pending."
        job.status = "running"
        job.result_summary = run.summary
    else:
        run.evidence_refs = evidence_refs
        run.exploitability = exploitability.model_dump()
        run.conclusion = conclusion
        run.status = "completed"
        run.summary = _validation_summary(conclusion, threat, evidence_refs, exploitability)
        job.status = "completed"
        job.result_summary = run.summary
        job.completed_at = _now()
    if evidence_refs:
        await _emit_event(
            db,
            job=job,
            event_type="evidence_added",
            agent_event="evidence.added",
            message=f"Attached {len(evidence_refs)} evidence reference(s).",
            payload={"evidence_count": len(evidence_refs)},
        )
    if not has_authorized_runner_work:
        await _emit_event(
            db,
            job=job,
            event_type="completed",
            agent_event="validation.concluded",
            message=f"Validation concluded as {conclusion}.",
            payload={
                "conclusion": conclusion,
                "exploitability_status": exploitability.status,
                "exploitability_confidence": exploitability.confidence,
            },
        )
    await _emit_agent_audit_log(
        db,
        current_user=current_user,
        threat=threat,
        action="agent_scan_approved",
        new_status=run.status,
        reason=f"Approved scan plan {run.id}.",
    )
    await db.flush()
    await db.refresh(run)
    return run


async def reject_threat_scan_plan(
    db: AsyncSession,
    *,
    current_user: User,
    run: ThreatValidationRun,
    body: ThreatScanPlanRejectRequest,
) -> ThreatValidationRun:
    if run.status != "created":
        raise ThreatAgentOrchestrationError("Only a proposed scan plan can be rejected.")
    threat = run.threat or await db.get(Threat, run.threat_id)
    if threat is None:
        raise ThreatAgentOrchestrationError("Scan plan is missing its threat.")
    run.status = "blocked"
    run.failure_reason = body.reason
    run.summary = f"Agent scan plan rejected: {body.reason}"
    if run.orchestration_job is not None:
        run.orchestration_job.status = "blocked"
        run.orchestration_job.error_message = body.reason
        run.orchestration_job.completed_at = _now()
        await _emit_event(
            db,
            job=run.orchestration_job,
            event_type="blocked",
            agent_event="scan_plan.rejected",
            message="Human rejected the agent scan plan.",
            payload={"reason": body.reason},
            level="warning",
        )
    await _emit_agent_audit_log(
        db,
        current_user=current_user,
        threat=threat,
        action="agent_scan_rejected",
        new_status="blocked",
        reason=body.reason,
    )
    await db.flush()
    await db.refresh(run)
    return run


async def rerun_threat_validation(
    db: AsyncSession,
    *,
    current_user: User,
    run: ThreatValidationRun,
) -> ThreatValidationRun:
    threat = run.threat
    if threat is None:
        raise ThreatAgentOrchestrationError("Validation run is missing its threat.")
    new_run = await create_threat_validation_run(
        db,
        current_user=current_user,
        threat=threat,
        application_review_id=run.application_review_id,
        requested_tools=run.requested_tools,
        domain_agent_plan=getattr(run, "domain_agent_plan", None),
        question=run.question,
    )
    integrity_findings = await verify_validation_evidence_integrity(db, run)
    if integrity_findings:
        new_run.evidence_refs = new_run.evidence_refs or []
        new_run.exploitability = {
            **(new_run.exploitability or {}),
            "status": "conflicting_evidence",
            "confidence": "medium",
            "rationale": (
                "Prior validation evidence failed integrity checks. A reviewer must inspect the evidence chain "
                "before using this run for remediation or closure."
            ),
        }
        new_run.conclusion = "needs_human_review"
        new_run.summary = (
            f"{threat.display_id} rerun found tamper or staleness in prior validation evidence. "
            "ThreatGenix requires reviewer inspection and fresh evidence before changing risk state."
        )
        if new_run.orchestration_job is not None:
            await _emit_event(
                db,
                job=new_run.orchestration_job,
                event_type="blocked",
                agent_event="evidence.integrity_failed",
                message="Prior validation evidence failed integrity checks during rerun.",
                payload=evidence_integrity_findings_payload(integrity_findings),
                level="warning",
            )
    remediation_evidence = await _remediation_evidence_for_validation(db, run.id)
    if remediation_evidence:
        new_run.evidence_refs = [*(new_run.evidence_refs or []), *remediation_evidence]
        new_run.exploitability = {
            **(new_run.exploitability or {}),
            "status": "conflicting_evidence",
            "confidence": "medium",
            "rationale": (
                "Remediation evidence is attached. A fresh code or scanner check is required "
                "before downgrading this finding."
            ),
        }
        new_run.conclusion = "needs_human_review"
        new_run.summary = (
            f"{threat.display_id} has remediation evidence attached, but ThreatGenix needs a fresh "
            "code or scanner signal before treating the exploit path as removed."
        )
    if new_run.orchestration_job is not None:
        await _emit_event(
            db,
            job=new_run.orchestration_job,
            event_type="note",
            agent_event="rerun.completed",
            message=f"Rerun completed from prior validation {run.id}.",
            payload={
                "previous_validation_run_id": str(run.id),
                "remediation_evidence_count": len(remediation_evidence),
            },
        )
    await _emit_agent_audit_log(
        db,
        current_user=current_user,
        threat=threat,
        action="agent_rerun_done",
        new_status=new_run.conclusion or "completed",
        reason=new_run.summary,
    )
    await db.flush()
    await db.refresh(new_run)
    return new_run


async def create_threat_remediation_run(
    db: AsyncSession,
    *,
    current_user: User,
    validation_run: ThreatValidationRun,
    agent_type: str,
    model_adapter: AgentModelAdapter | None = None,
) -> ThreatRemediationRun:
    if agent_type not in {"code_fix", "iac_fix", "configuration_fix"}:
        raise ThreatAgentOrchestrationError("Unsupported remediation agent type.")
    if validation_run.conclusion not in {"confirmed", "needs_human_review"}:
        raise ThreatAgentOrchestrationError(
            "Remediation drafting requires a confirmed validation or a human-review validation result."
        )
    integrity_findings = await verify_validation_evidence_integrity(db, validation_run)
    if integrity_findings:
        raise ThreatAgentOrchestrationError("Validation evidence integrity check failed.")
    threat = validation_run.threat
    if threat is None:
        raise ThreatAgentOrchestrationError("Validation run is missing its threat.")
    tenant_key = tenant_key_for_user(current_user)
    remediation_id = uuid4()
    job = _new_job(
        current_user=current_user,
        threat=threat,
        run_id=remediation_id,
        agent_type=agent_type,
        tools=[],
    )
    db.add(job)
    await _emit_event(
        db,
        job=job,
        event_type="created",
        agent_event="agent.started",
        message=f"{_agent_label(agent_type)} started.",
    )
    adapter = model_adapter or _default_agent_model_adapter()
    await _emit_event(
        db,
        job=job,
        event_type="note",
        agent_event="model.requested",
        message="Requested model-agnostic structured remediation draft.",
    )
    model_result = await adapter.generate_structured(
        agent_type=agent_type,
        context_packet=_remediation_context_packet(validation_run, threat),
        output_schema=_remediation_output_schema(),
    )
    payload = validate_agent_model_payload(model_result.payload)
    await _emit_event(
        db,
        job=job,
        event_type="note",
        agent_event="model.fallback_used"
        if model_result.deterministic_fallback_used
        else "model.completed",
        message=(
            "Deterministic fallback generated the remediation draft."
            if model_result.deterministic_fallback_used
            else "Model adapter generated a schema-valid remediation draft."
        ),
        payload={
            "model_provider": model_result.model_provider,
            "model_name": model_result.model_name,
            "prompt_version": model_result.prompt_version,
        },
    )
    run = ThreatRemediationRun(
        id=remediation_id,
        tenant_key=tenant_key,
        owner_id=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
        validation_run_id=validation_run.id,
        threat_model_id=validation_run.threat_model_id,
        threat_id=validation_run.threat_id,
        application_review_id=validation_run.application_review_id,
        orchestration_job_id=job.id,
        agent_type=agent_type,
        status="awaiting_confirmation",
        fix_summary=str(payload["summary"]),
        patch_preview=str(payload["patch_preview"]),
        ticket_draft=dict(payload["ticket_draft"]),
        pr_draft=dict(payload["pr_draft"]),
        evidence_refs=validation_run.evidence_refs,
        agent_version=FIX_AGENT_VERSION,
        input_schema_version=INPUT_SCHEMA_VERSION,
        output_schema_version=OUTPUT_SCHEMA_VERSION,
        policy_version=POLICY_VERSION,
        tool_harness_versions=TOOL_HARNESS_VERSIONS,
        model_provider=model_result.model_provider,
        model_name=model_result.model_name,
        prompt_version=model_result.prompt_version,
        model_output_hash=model_result.model_output_hash,
        deterministic_fallback_used=model_result.deterministic_fallback_used,
    )
    db.add(run)
    job.status = "completed"
    job.result_summary = run.fix_summary
    job.completed_at = _now()
    await _emit_event(
        db,
        job=job,
        event_type="completed",
        agent_event="fix.drafted",
        message=f"{_agent_label(agent_type)} drafted a confirmed-handoff remediation.",
    )
    await _emit_event(
        db,
        job=job,
        event_type="note",
        agent_event="handoff.confirmation_required",
        message="Explicit user confirmation is required before creating a PR or ticket handoff.",
    )
    await _emit_agent_audit_log(
        db,
        current_user=current_user,
        threat=threat,
        action="agent_fix_drafted",
        new_status="drafted",
        reason=f"{_agent_label(agent_type)} drafted a remediation handoff for {threat.display_id}.",
    )
    await db.flush()
    await db.refresh(run)
    return run


def _default_agent_model_adapter() -> AgentModelAdapter:
    if settings.agent_model_drafting_enabled and not settings.audit_force_ai_unavailable:
        return LLMAgentModelAdapter(timeout_seconds=settings.agent_model_drafting_timeout_seconds)
    return DeterministicFallbackAgentModelAdapter()


async def confirm_remediation_handoff(
    db: AsyncSession,
    *,
    current_user: User,
    run: ThreatRemediationRun,
    body: ThreatRemediationHandoffConfirmRequest,
) -> ThreatRemediationRun:
    if not body.confirmed:
        raise ThreatAgentOrchestrationError("PR/ticket handoff requires explicit confirmation.")
    request_key = body.handoff_idempotency_key or f"{body.provider}:{run.id}"
    existing_key = getattr(run, "handoff_idempotency_key", None)
    if (
        body.provider == "github_issue"
        and run.handoff_delivery_status == "delivered"
        and run.external_ticket_id
    ):
        if existing_key == request_key:
            return run
        raise ThreatAgentOrchestrationError(
            "GitHub Issue handoff was already delivered with a different idempotency key."
        )
    run.handoff_provider = body.provider
    run.handoff_idempotency_key = request_key
    if body.provider == "github_issue" and not body.external_ticket_id:
        await _deliver_github_issue_handoff(db, current_user=current_user, run=run, body=body)
        if run.handoff_delivery_status == "failed":
            return run
    else:
        run.handoff_delivery_status = "recorded"
        run.handoff_error = None
        run.external_ticket_id = body.external_ticket_id or f"{body.provider}:{run.id}"
        run.external_ticket_url = body.external_ticket_url
        run.external_pr_url = body.external_pr_url
    run.status = "handoff_created"
    run.evidence_refs = [
        *(run.evidence_refs or []),
        {
            "type": "handoff",
            "provider": body.provider,
            "delivery_status": run.handoff_delivery_status,
            "external_ticket_id": run.external_ticket_id,
            "external_ticket_url": run.external_ticket_url,
            "external_pr_url": run.external_pr_url,
            "confirmed_by": body.confirmed_by or "confirmed reviewer",
            "created_at": _now().isoformat(),
        },
    ]
    if run.orchestration_job is not None:
        await _emit_event(
            db,
            job=run.orchestration_job,
            event_type="completed",
            agent_event="handoff.created",
            message=f"Confirmed remediation handoff through {body.provider}.",
            payload={
                "provider": body.provider,
                "delivery_status": run.handoff_delivery_status,
                "external_ticket_id": run.external_ticket_id,
            },
        )
    if run.threat is not None:
        await _emit_agent_audit_log(
            db,
            current_user=current_user,
            threat=run.threat,
            action="agent_handoff_done",
            new_status=run.handoff_delivery_status,
            reason=f"Confirmed {body.provider} handoff for remediation run {run.id}.",
        )
    await db.flush()
    await db.refresh(run)
    return run


async def attach_remediation_evidence(
    db: AsyncSession,
    *,
    current_user: User,
    run: ThreatRemediationRun,
    body: ThreatRemediationEvidenceRequest,
) -> ThreatRemediationRun:
    evidence_ref = {
        "type": "remediation_evidence",
        "provider": body.provider,
        "summary": body.evidence_summary,
        "external_ticket_id": body.external_ticket_id,
        "external_ticket_url": body.external_ticket_url,
        "external_pr_url": body.external_pr_url,
        "commit_sha": body.commit_sha,
        "evidence_url": body.evidence_url,
        "created_at": _now().isoformat(),
    }
    run.evidence_refs = [*(run.evidence_refs or []), evidence_ref]
    if run.orchestration_job is not None:
        await _emit_event(
            db,
            job=run.orchestration_job,
            event_type="evidence_added",
            agent_event="evidence.added",
            message="Attached external remediation evidence.",
            payload=evidence_ref,
        )
    if run.threat is not None:
        await _emit_agent_audit_log(
            db,
            current_user=current_user,
            threat=run.threat,
            action="agent_evidence_added",
            new_status="evidence",
            reason=body.evidence_summary,
        )
    await db.flush()
    await db.refresh(run)
    return run


async def _deliver_github_issue_handoff(
    db: AsyncSession,
    *,
    current_user: User,
    run: ThreatRemediationRun,
    body: ThreatRemediationHandoffConfirmRequest,
) -> None:
    if not body.github_repository:
        raise ThreatAgentOrchestrationError("GitHub Issue handoff requires github_repository.")
    if body.access_token is None:
        raise ThreatAgentOrchestrationError(
            "GitHub Issue handoff requires a customer-owned access token."
        )
    if not settings.agent_github_handoff_enabled:
        await _mark_handoff_delivery_failed(
            db,
            current_user=current_user,
            run=run,
            provider="github_issue",
            error="GitHub Issue creation is disabled by configuration.",
        )
        return

    request = AgentRemediationConnectorTicketCreateRequest(
        action_id=str(run.id),
        provider="github_issue",
        confirmed=True,
        access_token=body.access_token,
        github_repository=body.github_repository,
        created_by=body.confirmed_by,
    )
    try:
        result = await create_remediation_provider_ticket(
            body=request,
            action=_remediation_action_for_run(run),
        )
    except RemediationConnectorError as exc:
        await _mark_handoff_delivery_failed(
            db,
            current_user=current_user,
            run=run,
            provider="github_issue",
            error=str(exc),
        )
        return

    run.handoff_delivery_status = "delivered"
    run.handoff_error = None
    run.external_ticket_id = result.external_ticket_id
    run.external_ticket_url = result.external_ticket_url
    run.external_pr_url = None


async def _mark_handoff_delivery_failed(
    db: AsyncSession,
    *,
    current_user: User,
    run: ThreatRemediationRun,
    provider: str,
    error: str,
) -> None:
    run.status = "awaiting_confirmation"
    run.handoff_delivery_status = "failed"
    run.handoff_provider = provider
    run.handoff_error = _safe_error(error)
    if run.orchestration_job is not None:
        await _emit_event(
            db,
            job=run.orchestration_job,
            event_type="failed",
            agent_event="handoff.failed",
            message=f"{provider} handoff delivery failed.",
            payload={"provider": provider, "error": run.handoff_error},
            level="warning",
        )
    if run.threat is not None:
        await _emit_agent_audit_log(
            db,
            current_user=current_user,
            threat=run.threat,
            action="agent_handoff_failed",
            new_status="failed",
            reason=run.handoff_error,
        )


def _remediation_action_for_run(run: ThreatRemediationRun) -> AgentRemediationAction:
    draft = run.ticket_draft or {}
    title = str(draft.get("title") or run.fix_summary or "ThreatGenix remediation")
    body = str(draft.get("body") or run.patch_preview or "Review the evidence-backed remediation draft.")
    labels = [
        str(label)
        for label in draft.get("labels", ["threatgenix", "security-remediation"])
        if str(label).strip()
    ]
    return AgentRemediationAction(
        action_id=str(run.id),
        finding_id=str(run.threat_id),
        source_object_type="threat",
        source_object_id=str(run.threat_id),
        title=title,
        current_decision="fix_now",
        action_kind="patch_guidance",
        artifact_kind="remediation_note",
        priority="p1_now",
        instruction=body,
        verification_required=True,
        evidence_needed=["Attach PR, commit, ticket, or scanner evidence before rerunning validation."],
        expected_next_decision="verify",
        rerun_required=True,
        ticket_draft=AgentRemediationTicketDraft(
            provider="github_issue",
            title=title,
            body=body,
            labels=labels,
            priority="p1_now",
        ),
        transition=AgentRemediationTransition(
            status="needs_action",
            current_decision="fix_now",
            expected_next_decision="verify",
            rationale="Confirmed handoff creates an external issue; validation still requires fresh evidence.",
            artifact_count=0,
            evidence_count=len(run.evidence_refs or []),
        ),
    )


def _safe_error(error: str) -> str:
    redacted = error.replace("\n", " ").strip()
    return redacted[:500] or "Provider handoff failed."


async def list_validation_runs(
    db: AsyncSession,
    *,
    tenant_key: str,
    threat_id: UUID,
    limit: int = 20,
) -> list[ThreatValidationRun]:
    result = await db.execute(
        select(ThreatValidationRun)
        .options(selectinload(ThreatValidationRun.threat), selectinload(ThreatValidationRun.orchestration_job))
        .where(ThreatValidationRun.tenant_key == tenant_key, ThreatValidationRun.threat_id == threat_id)
        .order_by(desc(ThreatValidationRun.created_at))
        .limit(limit)
    )
    return list(result.scalars().all())


async def get_validation_run(
    db: AsyncSession,
    *,
    tenant_key: str,
    run_id: UUID,
) -> ThreatValidationRun | None:
    result = await db.execute(
        select(ThreatValidationRun)
        .options(selectinload(ThreatValidationRun.threat), selectinload(ThreatValidationRun.orchestration_job))
        .where(ThreatValidationRun.tenant_key == tenant_key, ThreatValidationRun.id == run_id)
        .limit(1)
    )
    return result.scalar_one_or_none()


async def get_remediation_run(
    db: AsyncSession,
    *,
    tenant_key: str,
    run_id: UUID,
) -> ThreatRemediationRun | None:
    result = await db.execute(
        select(ThreatRemediationRun)
        .options(
            selectinload(ThreatRemediationRun.threat),
            selectinload(ThreatRemediationRun.validation_run),
            selectinload(ThreatRemediationRun.orchestration_job),
        )
        .where(ThreatRemediationRun.tenant_key == tenant_key, ThreatRemediationRun.id == run_id)
        .limit(1)
    )
    return result.scalar_one_or_none()


async def serialize_validation_run(
    db: AsyncSession,
    run: ThreatValidationRun,
) -> ThreatValidationRunResponse:
    return ThreatValidationRunResponse(
        id=run.id,
        tenant_key=run.tenant_key,
        owner_id=run.owner_id,
        organization_id=run.organization_id,
        threat_model_id=run.threat_model_id,
        threat_id=run.threat_id,
        application_review_id=run.application_review_id,
        orchestration_job_id=run.orchestration_job_id,
        status=run.status,  # type: ignore[arg-type]
        conclusion=run.conclusion,  # type: ignore[arg-type]
        question=run.question,
        requested_tools=run.requested_tools or [],
        domain_agent_plan=[
            DomainAgentPlanItem.model_validate(item)
            for item in (getattr(run, "domain_agent_plan", None) or [])
        ],
        domain_agent_results=[
            DomainAgentExecutionResult.model_validate(item)
            for item in (getattr(run, "domain_agent_results", None) or [])
        ],
        evidence_refs=run.evidence_refs or [],
        exploitability=ExploitabilityAssessment.model_validate(run.exploitability or {}),
        summary=run.summary,
        failure_reason=run.failure_reason,
        metadata=_metadata(run),
        trace=AgentTraceResponse(events=await _events_for_job(db, run.orchestration_job_id)),
        created_at=run.created_at,
        updated_at=run.updated_at,
    )


async def refresh_validation_run_from_controlled_scans(
    db: AsyncSession,
    run: ThreatValidationRun,
) -> ThreatValidationRun:
    if run.status != "running":
        return run
    pending_scan_ids = _scan_job_ids_from_domain_results(run.domain_agent_results or [])
    if not pending_scan_ids:
        return run
    result = await db.execute(
        select(ScanJob)
        .options(selectinload(ScanJob.findings))
        .where(
            ScanJob.id.in_(pending_scan_ids),
            ScanJob.owner_id == run.owner_id,
            ScanJob.threat_model_id == run.threat_model_id,
        )
    )
    jobs = {
        str(job.id): job
        for job in result.scalars().all()
        if job.owner_id == run.owner_id and job.threat_model_id == run.threat_model_id
    }
    domain_results = []
    collected_refs = list(run.evidence_refs or [])
    still_running = False
    any_failed = False
    now = _now().isoformat()
    for domain in run.domain_agent_results or []:
        updated_domain = dict(domain)
        updated_tools = []
        domain_evidence: list[dict[str, Any]] = list(updated_domain.get("evidence_refs") or [])
        for tool in domain.get("tools") or []:
            updated_tool = dict(tool)
            scan_job_id = str(updated_tool.get("scan_job_id") or "")
            job = jobs.get(scan_job_id)
            if updated_tool.get("status") == "authorized" and job is not None:
                if job.status == "completed":
                    refs = [_evidence_ref_for_scan_finding(finding, job) for finding in job.findings]
                    updated_tool["status"] = "completed"
                    updated_tool["evidence_refs"] = refs
                    updated_tool["completed_at"] = now
                    domain_evidence.extend(refs)
                    collected_refs.extend(refs)
                elif job.status == "failed":
                    updated_tool["status"] = "failed"
                    updated_tool["skipped_reason"] = job.error_message or "Controlled runner job failed."
                    updated_tool["completed_at"] = now
                    any_failed = True
                else:
                    still_running = True
            elif updated_tool.get("status") == "authorized" and scan_job_id:
                updated_tool["status"] = "failed"
                updated_tool["skipped_reason"] = (
                    "Controlled runner job was not found in this tenant and threat model scope."
                )
                updated_tool["completed_at"] = now
                any_failed = True
            updated_tools.append(updated_tool)
        updated_domain["tools"] = updated_tools
        updated_domain["evidence_refs"] = _dedupe_evidence_refs(domain_evidence)
        statuses = {str(tool.get("status")) for tool in updated_tools}
        if "authorized" in statuses:
            updated_domain["status"] = "running"
            still_running = True
        elif "failed" in statuses:
            updated_domain["status"] = "failed"
            updated_domain["skipped_reason"] = "One or more controlled runner jobs failed."
            any_failed = True
        elif "completed" in statuses:
            updated_domain["status"] = "completed"
            updated_domain["skipped_reason"] = None
        domain_results.append(updated_domain)

    run.domain_agent_results = domain_results
    run.evidence_refs = _dedupe_evidence_refs(collected_refs)
    if still_running:
        run.summary = "Controlled domain-agent validation job(s) are still running."
        await db.flush()
        await db.refresh(run)
        return run

    threat = run.threat
    if threat is None:
        run.status = "failed"
        run.conclusion = "failed"
        run.failure_reason = "Validation run is missing its threat."
        return run
    exploitability = build_exploitability_assessment(
        has_review=bool(run.application_review_id or run.evidence_refs),
        threat=threat,
        evidence_refs=run.evidence_refs or [],
        entries=[],
    )
    conclusion = evaluate_validation_conclusion(
        has_review=bool(run.application_review_id or run.evidence_refs),
        evidence_refs=run.evidence_refs or [],
        entries=[],
        exploitability=exploitability,
    )
    if any_failed and conclusion == "more_evidence_required":
        conclusion = "failed"
        run.failure_reason = "One or more controlled runner jobs failed before producing evidence."
    run.exploitability = exploitability.model_dump()
    run.conclusion = conclusion
    run.status = "completed" if conclusion != "failed" else "failed"
    run.summary = _validation_summary(conclusion, threat, run.evidence_refs or [], exploitability)
    if run.orchestration_job is not None:
        run.orchestration_job.status = run.status
        run.orchestration_job.result_summary = run.summary
        run.orchestration_job.completed_at = _now()
        await _emit_event(
            db,
            job=run.orchestration_job,
            event_type="completed" if run.status == "completed" else "failed",
            agent_event="validation.concluded",
            message=f"Controlled runner validation concluded as {conclusion}.",
            payload={"conclusion": conclusion, "evidence_count": len(run.evidence_refs or [])},
            level="warning" if run.status == "failed" else "info",
        )
    await db.flush()
    await db.refresh(run)
    return run


async def serialize_remediation_run(
    db: AsyncSession,
    run: ThreatRemediationRun,
) -> ThreatRemediationRunResponse:
    await db.refresh(run)
    return ThreatRemediationRunResponse(
        id=run.id,
        tenant_key=run.tenant_key,
        owner_id=run.owner_id,
        organization_id=run.organization_id,
        validation_run_id=run.validation_run_id,
        threat_model_id=run.threat_model_id,
        threat_id=run.threat_id,
        application_review_id=run.application_review_id,
        orchestration_job_id=run.orchestration_job_id,
        agent_type=run.agent_type,  # type: ignore[arg-type]
        status=run.status,  # type: ignore[arg-type]
        fix_summary=run.fix_summary,
        patch_preview=run.patch_preview,
        ticket_draft=run.ticket_draft or {},
        pr_draft=run.pr_draft or {},
        external_ticket_id=run.external_ticket_id,
        external_ticket_url=run.external_ticket_url,
        external_pr_url=run.external_pr_url,
        handoff_delivery_status=getattr(run, "handoff_delivery_status", "recorded"),
        handoff_provider=getattr(run, "handoff_provider", None),
        handoff_error=getattr(run, "handoff_error", None),
        handoff_idempotency_key=getattr(run, "handoff_idempotency_key", None),
        evidence_refs=run.evidence_refs or [],
        failure_reason=run.failure_reason,
        metadata=_metadata(run),
        trace=AgentTraceResponse(events=await _events_for_job(db, run.orchestration_job_id)),
        created_at=run.created_at,
        updated_at=run.updated_at,
    )


def evaluate_validation_conclusion(
    *,
    has_review: bool,
    evidence_refs: list[dict[str, Any]],
    entries: list[ApplicationReviewContextEntry],
    exploitability: ExploitabilityAssessment | None = None,
) -> str:
    if not has_review:
        return "more_evidence_required"
    if not evidence_refs:
        return "more_evidence_required"
    if exploitability is not None:
        if exploitability.status == "exploitable" and exploitability.confidence in {"medium", "high"}:
            return "confirmed"
        if exploitability.status == "blocked_by_control":
            return "not_supported"
        if exploitability.status == "conflicting_evidence":
            return "needs_human_review"
        if exploitability.status in {"theoretical", "needs_more_evidence"}:
            return "more_evidence_required"
    joined = " ".join(f"{entry.title} {entry.body}" for entry in entries).casefold()
    if any(term in joined for term in ("conflicting", "compensating control", "manual verification")):
        return "needs_human_review"
    if any(ref.get("item_type") == "scanner_finding" for ref in evidence_refs):
        return "confirmed"
    if any(ref.get("item_type") in {"code_context", "security_context"} for ref in evidence_refs):
        return "needs_human_review"
    return "more_evidence_required"


def build_exploitability_assessment(
    *,
    has_review: bool,
    threat: Threat,
    evidence_refs: list[dict[str, Any]],
    entries: list[ApplicationReviewContextEntry],
) -> ExploitabilityAssessment:
    if not has_review or not evidence_refs:
        return ExploitabilityAssessment(
            status="needs_more_evidence",
            rationale="No application review evidence is available for this threat.",
        )
    joined = _evidence_text(threat, evidence_refs, entries)
    evidence_ids = [str(ref.get("id")) for ref in evidence_refs if ref.get("id")]
    has_scanner = any(ref.get("item_type") == "scanner_finding" for ref in evidence_refs)
    has_code = any(_has_source_path(ref) for ref in evidence_refs) or "code reference" in joined
    has_dfd = (
        any(ref.get("item_type") in {"dfd_context", "architecture_context"} for ref in evidence_refs)
        or "dfd" in joined
        or "dfd_edge" in joined
    )
    sensitive_export = "export" in joined and any(term in joined for term in ("sensitive", "customer", "restricted"))
    missing_auth = any(
        term in joined
        for term in (
            "missing authorization",
            "missing auth",
            "without an authorization",
            "no authorization guard",
            "not scoped",
            "missing scoped authorization",
        )
    )
    if any(term in joined for term in ("conflicting", "manual verification", "ambiguous evidence")):
        return ExploitabilityAssessment(
            status="conflicting_evidence",
            attacker_profile="requires reviewer confirmation",
            evidence_refs=evidence_ids,
            confidence="medium",
            rationale="Evidence contains conflict markers that require human review.",
        )
    if any(term in joined for term in ("compensating control", "blocked by control", "authorization guard present")):
        return ExploitabilityAssessment(
            status="blocked_by_control",
            attacker_profile="authenticated user",
            blocking_controls=["Evidence indicates an authorization or compensating control may block the path."],
            evidence_refs=evidence_ids,
            confidence="medium",
            rationale="Current evidence indicates the suspected path is blocked by a control.",
        )
    if has_scanner and has_code and sensitive_export and missing_auth:
        confidence = "high" if has_dfd else "medium"
        return ExploitabilityAssessment(
            status="exploitable",
            attacker_profile="authenticated low-privilege tenant user",
            attack_path=[
                "Attacker authenticates with a normal tenant account.",
                "Attacker reaches the sensitive export route.",
                "The route accepts the export request without a scoped authorization guard.",
                "Sensitive customer export data can be returned outside intended permission.",
            ],
            preconditions=[
                "Valid low-privilege account exists.",
                "Export route is reachable from the application boundary.",
                "Route handles restricted or customer data.",
                "Scoped export authorization is missing or not enforced.",
            ],
            blocking_controls=[],
            evidence_refs=evidence_ids,
            confidence=confidence,
            rationale=(
                "Scanner, code-path, and data-context evidence support a realistic exploit path."
                if has_dfd
                else "Scanner and code-path evidence support a realistic path; DFD context would raise confidence."
            ),
        )
    if has_scanner or has_code:
        return ExploitabilityAssessment(
            status="theoretical",
            attacker_profile="unknown until route reachability and controls are verified",
            preconditions=[
                "Confirm route reachability.",
                "Confirm data sensitivity.",
                "Confirm whether a scoped authorization control exists.",
            ],
            evidence_refs=evidence_ids,
            confidence="low",
            rationale="Evidence exists, but not enough to prove exploitability in this threat model.",
        )
    return ExploitabilityAssessment(
        status="needs_more_evidence",
        evidence_refs=evidence_ids,
        confidence="low",
        rationale="Evidence does not map to code, scanner, or DFD context.",
    )


async def _build_domain_agent_results(
    db: AsyncSession,
    *,
    current_user: User,
    job: OrchestrationJob,
    threat: Threat,
    plan: list[dict[str, Any]],
    evidence_refs: list[dict[str, Any]],
    domain_agent_targets: dict[str, DomainAgentTargetRequest] | None = None,
) -> list[dict[str, Any]]:
    now = _now().isoformat()
    results: list[dict[str, Any]] = []
    target_specs = domain_agent_targets or {}
    for item in plan:
        agent_name = str(item.get("domain_agent") or "")
        label = str(item.get("label") or agent_name)
        tool_results: list[dict[str, Any]] = []
        agent_evidence: list[dict[str, Any]] = []
        for tool in item.get("tools") or []:
            tool_name = str(tool).strip()
            tool_evidence = _evidence_refs_for_tool(tool_name, evidence_refs)
            started_at = _now()
            target_spec = _target_spec_for_domain_tool(
                target_specs,
                agent_name=agent_name,
                tool_name=tool_name,
            )
            scan_job_id = None
            attached_evidence: list[dict[str, Any]] = []
            if tool_evidence and target_spec is None:
                status = "evidence_attached"
                skipped_reason = None
                attached_evidence = tool_evidence
                task_kind = "evidence_projection"
                task_status = "completed"
                output_payload = {
                    "evidence_refs": tool_evidence,
                    "controlled_runner": bool(settings.agent_controlled_runner_enabled),
                    "runner_submission_enabled": validation_run_submission_enabled(),
                }
            else:
                submission = await _create_controlled_runner_submission(
                    db,
                    current_user=current_user,
                    threat=threat,
                    job=job,
                    agent_name=agent_name,
                    tool_name=tool_name,
                    target_spec=target_spec,
                )
                status = submission["status"]
                skipped_reason = submission.get("skipped_reason")
                scan_job_id = submission.get("scan_job_id")
                task_kind = "tool_execution"
                task_status = "completed" if status == "authorized" else "blocked"
                output_payload = {
                    "evidence_refs": [],
                    "controlled_runner": bool(settings.agent_controlled_runner_enabled),
                    "runner_submission_enabled": validation_run_submission_enabled(),
                    "scan_job_id": scan_job_id,
                    "target_type": submission.get("target_type"),
                    "target": submission.get("target"),
                }
            task = OrchestrationTask(
                id=uuid4(),
                job_id=job.id,
                threat_model_id=job.threat_model_id,
                task_kind=task_kind,
                agent_name=agent_name,
                tool_name=tool_name,
                status=task_status,
                input_payload={
                    "domain_agent": agent_name,
                    "tool_name": tool_name,
                    "max_runtime_seconds": settings.agent_validation_tool_max_runtime_seconds,
                    "direct_mutation_allowed": False,
                    "target_supplied": target_spec is not None,
                },
                output_payload=output_payload,
                error_message=skipped_reason,
                started_at=started_at,
                completed_at=_now(),
            )
            db.add(task)
            if status == "evidence_attached" and attached_evidence:
                agent_evidence.extend(attached_evidence)
                await _emit_event(
                    db,
                    job=job,
                    event_type="tool_called",
                    agent_event="tool.authorized",
                    message=f"{format_tool_label(tool_name)} evidence was authorized for {label}.",
                    payload={
                        "domain_agent": agent_name,
                        "tool_name": tool_name,
                        "task_id": str(task.id),
                    },
                )
                await _emit_event(
                    db,
                    job=job,
                    event_type="evidence_added",
                    agent_event="tool.evidence_attached",
                    message=(
                        f"{format_tool_label(tool_name)} used {len(attached_evidence)} "
                        "pre-collected evidence reference(s); no live tool execution was performed."
                    ),
                    payload={
                        "domain_agent": agent_name,
                        "tool_name": tool_name,
                        "task_id": str(task.id),
                        "evidence_count": len(attached_evidence),
                    },
                )
            elif status == "authorized":
                await _emit_event(
                    db,
                    job=job,
                    event_type="tool_called",
                    agent_event="tool.authorized",
                    message=(
                        f"{format_tool_label(tool_name)} controlled runner job "
                        f"{scan_job_id} was authorized for {label}."
                    ),
                    payload={
                        "domain_agent": agent_name,
                        "tool_name": tool_name,
                        "task_id": str(task.id),
                        "scan_job_id": scan_job_id,
                    },
                )
            else:
                await _emit_event(
                    db,
                    job=job,
                    event_type="blocked",
                    agent_event="tool.skipped",
                    message=f"{format_tool_label(tool_name)} skipped for {label}: {skipped_reason}",
                    payload={
                        "domain_agent": agent_name,
                        "tool_name": tool_name,
                        "task_id": str(task.id),
                        "skipped_reason": skipped_reason,
                    },
                    level="warning",
                )
            tool_results.append(
                {
                    "tool": tool_name,
                    "status": status,
                    "evidence_refs": attached_evidence,
                    "task_id": str(task.id),
                    "scan_job_id": scan_job_id,
                    "skipped_reason": skipped_reason,
                    "started_at": started_at.isoformat(),
                    "completed_at": _now().isoformat(),
                }
            )
        if tool_results and all(result["status"] == "evidence_attached" for result in tool_results):
            agent_status = "evidence_attached"
            skipped_reason = None
        elif tool_results and any(result["status"] == "authorized" for result in tool_results):
            agent_status = "running"
            skipped_reason = "Controlled runner evidence is pending for one or more planned tools."
        elif tool_results and any(result["status"] == "evidence_attached" for result in tool_results):
            agent_status = "evidence_attached"
            skipped_reason = "Some planned tools were skipped; attached evidence is shown per tool."
        elif tool_results:
            agent_status = "skipped"
            skipped_reason = "; ".join(
                sorted(
                    {
                        str(result.get("skipped_reason") or "Tool did not run.")
                        for result in tool_results
                    }
                )
            )
        else:
            agent_status = "skipped"
            skipped_reason = "No tools were planned for this domain agent."
        results.append(
            DomainAgentExecutionResult(
                domain_agent=agent_name,  # type: ignore[arg-type]
                label=label,
                status=agent_status,  # type: ignore[arg-type]
                tools=tool_results,
                evidence_refs=_dedupe_evidence_refs(agent_evidence),
                skipped_reason=skipped_reason,
                started_at=datetime.fromisoformat(now),
                completed_at=_now(),
            ).model_dump(mode="json")
        )
    return results


def _has_authorized_runner_work(domain_agent_results: list[dict[str, Any]]) -> bool:
    return any(
        tool.get("status") == "authorized"
        for result in domain_agent_results
        for tool in result.get("tools", [])
    )


def _planned_domain_agent_results(plan: list[dict[str, Any]]) -> list[dict[str, Any]]:
    now = _now()
    return [
        DomainAgentExecutionResult(
            domain_agent=str(item.get("domain_agent") or ""),  # type: ignore[arg-type]
            label=str(item.get("label") or item.get("domain_agent") or "Domain Agent"),
            status="planned",
            tools=[
                {
                    "tool": str(tool),
                    "status": "planned",
                    "evidence_refs": [],
                    "started_at": now,
                    "completed_at": None,
                }
                for tool in item.get("tools") or []
            ],
            evidence_refs=[],
            skipped_reason=None,
            started_at=now,
            completed_at=None,
        ).model_dump(mode="json")
        for item in plan
    ]


def _target_spec_for_domain_tool(
    targets: dict[str, DomainAgentTargetRequest],
    *,
    agent_name: str,
    tool_name: str,
) -> DomainAgentTargetRequest | None:
    return (
        targets.get(f"{agent_name}:{tool_name}")
        or targets.get(tool_name)
        or targets.get(agent_name)
    )


async def _create_controlled_runner_submission(
    db: AsyncSession,
    *,
    current_user: User,
    threat: Threat,
    job: OrchestrationJob,
    agent_name: str,
    tool_name: str,
    target_spec: DomainAgentTargetRequest | None,
) -> dict[str, Any]:
    if target_spec is None:
        return {"status": "skipped", "skipped_reason": _tool_skipped_reason(tool_name, agent_name)}
    if not target_spec.authorization_acknowledged:
        return {
            "status": "skipped",
            "skipped_reason": "Explicit target authorization acknowledgment is required before runner submission.",
            "target_type": str(target_spec.target_type),
            "target": target_spec.target,
        }
    if agent_name == "dast" and not settings.agent_dast_enabled:
        return {
            "status": "skipped",
            "skipped_reason": "DAST is disabled until an allowlisted target and isolated runner are configured.",
            "target_type": str(target_spec.target_type),
            "target": target_spec.target,
        }
    if not settings.agent_controlled_runner_enabled:
        return {
            "status": "skipped",
            "skipped_reason": "Controlled runner execution is disabled; attach approved evidence or enable the runner.",
            "target_type": str(target_spec.target_type),
            "target": target_spec.target,
        }
    if not validation_run_submission_enabled():
        return {
            "status": "skipped",
            "skipped_reason": "Validation runtime is not configured to accept controlled runner submissions.",
            "target_type": str(target_spec.target_type),
            "target": target_spec.target,
        }
    try:
        default_validation_tool_registry().get(tool_name)
        policy = default_validation_execution_policy_registry().get(tool_name)
    except KeyError:
        return {
            "status": "skipped",
            "skipped_reason": "Tool is not registered in the approved validation tool registry.",
            "target_type": str(target_spec.target_type),
            "target": target_spec.target,
        }
    target_type = str(target_spec.target_type)
    target = target_spec.target.strip()
    bundle_error = await _validate_domain_agent_target_access(
        db,
        current_user=current_user,
        threat=threat,
        tool_name=tool_name,
        target_type=target_type,
        target=target,
    )
    if bundle_error:
        return {
            "status": "skipped",
            "skipped_reason": bundle_error,
            "target_type": target_type,
            "target": target,
        }
    decision = policy.evaluate(target_type, target)
    if not decision.allowed:
        return {
            "status": "skipped",
            "skipped_reason": decision.reason,
            "target_type": target_type,
            "target": target,
        }

    scan_job = ScanJob(
        threat_model_id=threat.threat_model_id,
        owner_id=current_user.id,
        status="pending",
        scan_type="unauthenticated",
        scope=getattr(target_spec.scope, "value", str(target_spec.scope)),
        tool_name=tool_name,
        target_type=target_type,
        targets={
            str(target_spec.target_node_id) if target_spec.target_node_id else DIRECT_TARGET_KEY: target
        },
        nuclei_templates=[],
        finding_count=0,
        credential_id=None,
    )
    db.add(scan_job)
    await db.flush()
    db.add(
        ScanAuthorization(
            scan_job_id=scan_job.id,
            user_id=current_user.id,
            acknowledged_text=AUTHORIZATION_TEXT,
            ip_address="agent-orchestration",
            targets_snapshot=dict(scan_job.targets or {}),
        )
    )
    if job.inputs is not None:
        runner_jobs = [*(job.inputs.get("controlled_runner_scan_jobs") or [])]
        runner_jobs.append(
            {
                "scan_job_id": str(scan_job.id),
                "domain_agent": agent_name,
                "tool_name": tool_name,
                "target_type": target_type,
            }
        )
        job.inputs = {**job.inputs, "controlled_runner_scan_jobs": runner_jobs}
    return {
        "status": "authorized",
        "scan_job_id": str(scan_job.id),
        "target_type": target_type,
        "target": target,
    }


async def _validate_domain_agent_target_access(
    db: AsyncSession,
    *,
    current_user: User,
    threat: Threat,
    tool_name: str,
    target_type: str,
    target: str,
) -> str | None:
    if is_validation_target_bundle_ref(target):
        try:
            await validate_target_bundle_ref_for_model(
                db,
                threat_model_id=threat.threat_model_id,
                owner_id=current_user.id,
                target_ref=target,
            )
        except ValidationTargetBundleError as exc:
            return str(exc)
        return None
    if target_type == "url":
        if tool_name == "nuclei" and not _url_allowed_for_agent_dast(target):
            return "DAST target is not in the agent external target allowlist."
        return None
    try:
        validate_validation_target_reference(target, target_type)
    except ValidationSandboxTargetError as exc:
        return str(exc)
    return None


def _url_allowed_for_agent_dast(target: str) -> bool:
    allowlist = [
        item.strip().casefold()
        for item in (settings.agent_external_target_allowlist or "").split(",")
        if item.strip()
    ]
    if not allowlist:
        return False
    parsed = urlparse(target)
    host = (parsed.hostname or "").casefold()
    if not host:
        return False
    return any(host == entry or host.endswith(f".{entry}") for entry in allowlist)


def _tool_skipped_reason(tool_name: str, agent_name: str) -> str:
    if agent_name == "dast" and not settings.agent_dast_enabled:
        return "DAST is disabled until an allowlisted target and isolated runner are configured."
    if not settings.agent_controlled_runner_enabled:
        return "Controlled runner execution is disabled; attach approved evidence or enable the runner."
    if not validation_run_submission_enabled():
        return "Validation runtime is not configured to accept controlled runner submissions."
    try:
        adapter = default_validation_tool_registry().get(tool_name)
        policy = default_validation_execution_policy_registry().get(tool_name)
    except KeyError:
        return "Tool is not registered in the approved validation tool registry."
    runtime = validation_tool_runtime_availability(adapter)
    if not runtime.available:
        return runtime.detail
    if not policy.execution_enabled:
        return f"{tool_name} execution is disabled by policy."
    return "No authorized validation target bundle was attached to this threat validation request."


def _evidence_refs_for_tool(
    tool_name: str,
    evidence_refs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not evidence_refs:
        return []
    normalized_tool = tool_name.casefold()
    matched: list[dict[str, Any]] = []
    for ref in evidence_refs:
        haystack = " ".join(
            [
                str(ref.get("source_type") or ""),
                str(ref.get("item_type") or ""),
                str(ref.get("title") or ""),
                str(ref.get("scanner") or ""),
                str(ref.get("rule_id") or ""),
                repr(ref.get("source_refs") or []),
            ]
        ).casefold()
        if normalized_tool in haystack:
            matched.append(ref)
            continue
        if normalized_tool == "semgrep" and any(
            term in haystack for term in ("scanner_finding", "scan_finding", "source-code", "code reference")
        ):
            matched.append(ref)
        elif normalized_tool == "ai-red-team" and any(
            term in haystack for term in ("ai system", "prompt", "jailbreak", "red team")
        ):
            matched.append(ref)
        elif normalized_tool in {"external-report", "pentest-report"} and any(
            term in haystack for term in ("external", "pentest", "evidence_item", "policy")
        ):
            matched.append(ref)
    return _dedupe_evidence_refs(matched)


def _dedupe_evidence_refs(evidence_refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for ref in evidence_refs:
        key = str(ref.get("id") or ref)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ref)
    return deduped


def format_tool_label(tool_name: str) -> str:
    labels = {
        "semgrep": "Semgrep",
        "nuclei": "Nuclei",
        "ai-red-team": "AI Red Team",
        "checkov": "Checkov",
        "trivy": "Trivy",
        "osv-scanner": "OSV Scanner",
        "trufflehog": "TruffleHog",
        "external-report": "External Report",
        "pentest-report": "Pentest Report",
    }
    return labels.get(tool_name, tool_name)


def _safe_requested_tools(requested_tools: list[str] | None) -> list[str]:
    plan = _resolve_domain_agent_plan(requested_tools=requested_tools)
    return _tools_for_domain_agent_plan(plan)


def _resolve_domain_agent_plan(
    *,
    requested_tools: list[str] | None = None,
    domain_agents: list[str] | None = None,
    domain_agent_tools: dict[str, list[str]] | None = None,
    domain_agent_tool_mode: dict[str, str] | None = None,
    domain_agent_instructions: dict[str, str] | None = None,
    excluded_tools: dict[str, list[str]] | None = None,
    required_tools: dict[str, list[str]] | None = None,
    existing_plan: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if existing_plan:
        return _normalize_existing_domain_agent_plan(existing_plan)

    explicit_domain_agents = bool(domain_agents)
    requested_tool_names = _dedupe(
        [tool.strip() for tool in requested_tools or [] if tool.strip()]
    )
    tools_by_agent = _normalize_domain_agent_tools(domain_agent_tools or {})
    excluded_by_agent = _normalize_domain_agent_tools(excluded_tools or {})
    required_by_agent = _normalize_domain_agent_tools(required_tools or {})
    tool_mode_by_agent = _normalize_domain_agent_tool_modes(domain_agent_tool_mode or {})
    if explicit_domain_agents:
        selected_agent_names = [
            *(domain_agents or []),
            *tools_by_agent,
            *excluded_by_agent,
            *required_by_agent,
        ]
    elif tools_by_agent:
        selected_agent_names = [
            *tools_by_agent,
            *excluded_by_agent,
            *required_by_agent,
        ]
    elif requested_tool_names:
        selected_agent_names = []
        for tool in requested_tool_names:
            agent_name = TOOL_PRIMARY_DOMAIN_AGENT.get(tool)
            if agent_name is None:
                raise ThreatAgentOrchestrationError(f"Unsupported validation tool: {tool}")
            selected_agent_names.append(agent_name)
    else:
        selected_agent_names = list(SAFE_DEFAULT_DOMAIN_AGENTS)

    selected_agents = _normalize_domain_agents(selected_agent_names)
    instructions = {
        key.strip(): value.strip()
        for key, value in (domain_agent_instructions or {}).items()
        if key.strip() and value.strip()
    }
    for agent_name in instructions:
        if agent_name not in DOMAIN_VALIDATION_AGENT_CONTRACTS:
            raise ThreatAgentOrchestrationError(
                f"Unsupported domain validation agent instruction target: {agent_name}"
            )

    use_default_tools = explicit_domain_agents or not requested_tool_names
    plan_by_agent: dict[str, dict[str, Any]] = {}
    for agent_name in selected_agents:
        contract = DOMAIN_VALIDATION_AGENT_CONTRACTS[agent_name]
        mode = tool_mode_by_agent.get(agent_name, "recommended")
        if mode == "all":
            tools = list(contract.allowed_tools)
        elif mode == "manual":
            tools = list(tools_by_agent.get(agent_name, []))
        elif agent_name in tools_by_agent:
            tools = tools_by_agent[agent_name]
        elif use_default_tools:
            tools = list(contract.default_tools)
        else:
            tools = []
        if required_by_agent.get(agent_name):
            tools = _dedupe([*tools, *required_by_agent[agent_name]])
        if excluded_by_agent.get(agent_name):
            excluded = set(excluded_by_agent[agent_name])
            tools = [tool for tool in tools if tool not in excluded]
        plan_by_agent[agent_name] = {
            "domain_agent": contract.name,
            "label": contract.label,
            "tools": tools,
            "instructions": instructions.get(contract.name, contract.default_instructions),
        }

    for tool in requested_tool_names:
        agent_name = TOOL_PRIMARY_DOMAIN_AGENT.get(tool)
        if agent_name is None:
            raise ThreatAgentOrchestrationError(f"Unsupported validation tool: {tool}")
        contract = DOMAIN_VALIDATION_AGENT_CONTRACTS[agent_name]
        if tool not in contract.allowed_tools:
            raise ThreatAgentOrchestrationError(
                f"{tool} is not allowed for {contract.label}."
            )
        if agent_name not in plan_by_agent:
            plan_by_agent[agent_name] = {
                "domain_agent": contract.name,
                "label": contract.label,
                "tools": [],
                "instructions": instructions.get(contract.name, contract.default_instructions),
            }
        plan_by_agent[agent_name]["tools"] = _dedupe(
            [*plan_by_agent[agent_name]["tools"], tool]
        )

    return [
        plan_by_agent[name]
        for name in DOMAIN_VALIDATION_AGENT_CONTRACTS
        if name in plan_by_agent
    ]


def _normalize_existing_domain_agent_plan(
    existing_plan: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    plan: list[dict[str, Any]] = []
    for item in existing_plan:
        raw_name = str(item.get("domain_agent") or "").strip()
        if raw_name not in DOMAIN_VALIDATION_AGENT_CONTRACTS:
            continue
        contract = DOMAIN_VALIDATION_AGENT_CONTRACTS[raw_name]
        tools = [
            tool
            for tool in _dedupe([str(tool).strip() for tool in item.get("tools") or []])
            if tool in contract.allowed_tools
        ]
        if not tools and "tools" not in item:
            tools = list(contract.default_tools)
        instruction = str(item.get("instructions") or "").strip()
        plan.append(
            {
                "domain_agent": contract.name,
                "label": contract.label,
                "tools": tools,
                "instructions": instruction or contract.default_instructions,
            }
        )
    return plan or _resolve_domain_agent_plan()


def _normalize_domain_agents(domain_agents: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw_agent in domain_agents:
        agent = raw_agent.strip()
        if not agent:
            continue
        if agent not in DOMAIN_VALIDATION_AGENT_CONTRACTS:
            raise ThreatAgentOrchestrationError(
                f"Unsupported domain validation agent: {agent}"
            )
        normalized.append(agent)
    return _dedupe(normalized) or list(SAFE_DEFAULT_DOMAIN_AGENTS)


def _normalize_domain_agent_tools(
    domain_agent_tools: dict[str, list[str]],
) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for raw_agent, raw_tools in domain_agent_tools.items():
        agent = raw_agent.strip()
        if agent not in DOMAIN_VALIDATION_AGENT_CONTRACTS:
            raise ThreatAgentOrchestrationError(
                f"Unsupported domain validation agent tool target: {agent}"
            )
        contract = DOMAIN_VALIDATION_AGENT_CONTRACTS[agent]
        tools = _dedupe([str(tool).strip() for tool in raw_tools if str(tool).strip()])
        disallowed = [tool for tool in tools if tool not in contract.allowed_tools]
        if disallowed:
            raise ThreatAgentOrchestrationError(
                f"{', '.join(disallowed)} is not allowed for {contract.label}."
            )
        normalized[agent] = tools
    return normalized


def _normalize_domain_agent_tool_modes(
    domain_agent_tool_mode: dict[str, str],
) -> dict[str, DomainAgentToolMode]:
    normalized: dict[str, DomainAgentToolMode] = {}
    for raw_agent, raw_mode in domain_agent_tool_mode.items():
        agent = raw_agent.strip()
        if agent not in DOMAIN_VALIDATION_AGENT_CONTRACTS:
            raise ThreatAgentOrchestrationError(
                f"Unsupported domain validation agent tool mode target: {agent}"
            )
        mode = str(raw_mode).strip()
        if mode not in {"recommended", "all", "manual"}:
            raise ThreatAgentOrchestrationError(
                f"Unsupported tool mode for {agent}: {mode}"
            )
        normalized[agent] = mode  # type: ignore[assignment]
    return normalized


def _tools_for_domain_agent_plan(plan: list[dict[str, Any]]) -> list[str]:
    tools = _dedupe(
        [
            str(tool).strip()
            for item in plan
            for tool in item.get("tools") or []
            if str(tool).strip()
        ]
    )
    if tools or plan:
        return tools
    return list(SAFE_DEFAULT_TOOLS)


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


async def _select_review(
    db: AsyncSession,
    *,
    tenant_key: str,
    threat_model_id: UUID,
    application_review_id: UUID | None,
) -> ApplicationSecurityReview | None:
    stmt = select(ApplicationSecurityReview).where(
        ApplicationSecurityReview.tenant_key == tenant_key,
        ApplicationSecurityReview.threat_model_id == threat_model_id,
    )
    if application_review_id is not None:
        stmt = stmt.where(ApplicationSecurityReview.id == application_review_id)
    stmt = stmt.order_by(desc(ApplicationSecurityReview.created_at)).limit(1)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def _collect_validation_entries(
    db: AsyncSession,
    *,
    current_user: User,
    review: ApplicationSecurityReview | None,
    threat: Threat,
) -> list[ApplicationReviewContextEntry]:
    if review is None:
        return []
    query = " ".join(
        item
        for item in [
            threat.display_id,
            threat.rule_id or "",
            threat.threat_subtype or "",
            threat.description[:240],
        ]
        if item
    )
    try:
        return await search_review_context_index(
            db,
            current_user=current_user,
            review_id=review.id,
            query=query,
            limit=20,
        )
    except ApplicationReviewContextError:
        return []


def _evidence_ref(entry: ApplicationReviewContextEntry) -> dict[str, Any]:
    return {
        "id": str(entry.id),
        "review_id": str(entry.review_id),
        "source_type": entry.source_type,
        "source_object_id": str(entry.source_object_id) if entry.source_object_id else None,
        "item_type": entry.item_type,
        "title": entry.title,
        "content_hash": entry.content_hash,
        "source_refs": entry.source_refs or [],
        "status": entry.status,
    }


def _scan_job_ids_from_domain_results(domain_results: list[dict[str, Any]]) -> list[UUID]:
    ids: list[UUID] = []
    for domain in domain_results:
        for tool in domain.get("tools") or []:
            raw = tool.get("scan_job_id")
            if not raw:
                continue
            try:
                ids.append(UUID(str(raw)))
            except ValueError:
                continue
    return ids


def scan_job_ids_from_domain_results(domain_results: list[dict[str, Any]]) -> list[UUID]:
    return _scan_job_ids_from_domain_results(domain_results)


def _evidence_ref_for_scan_finding(finding: ScanFinding, job: ScanJob) -> dict[str, Any]:
    metadata = finding.validation_metadata
    source_refs: list[dict[str, Any]] = [
        {
            "scan_job_id": str(job.id),
            "tool": job.tool_name,
            "target_type": job.target_type,
            "target": finding.validation_target or finding.matched_at,
            "rule_id": finding.template_id,
        }
    ]
    raw_path = (finding.raw_output or {}).get("path") or metadata.get("path")
    if raw_path:
        source_refs.append({"path": str(raw_path)})
    return {
        "id": str(finding.id),
        "review_id": None,
        "source_type": "scan_finding",
        "source_object_id": str(job.id),
        "item_type": "scanner_finding",
        "title": finding.template_name,
        "scanner": job.tool_name,
        "rule_id": finding.template_id,
        "content_hash": metadata.get("output_sha256"),
        "source_refs": source_refs,
        "status": "active",
    }


def _validation_summary(
    conclusion: str,
    threat: Threat,
    evidence_refs: list[dict[str, Any]],
    exploitability: ExploitabilityAssessment,
) -> str:
    if conclusion == "confirmed":
        return (
            f"{threat.display_id} is realistically exploitable as "
            f"{exploitability.attacker_profile or 'the assessed attacker'} and is supported by "
            f"{len(evidence_refs)} trusted evidence reference(s). This validates the threat for "
            "remediation planning."
        )
    if conclusion == "needs_human_review":
        return (
            f"{threat.display_id} has partial or conflicting evidence. A reviewer should inspect "
            "the evidence chain before treating the threat as confirmed."
        )
    if conclusion == "not_supported":
        return f"{threat.display_id} is not supported by current evidence."
    return (
        f"{threat.display_id} needs more evidence before ThreatGenix can validate it. "
        "Attach a review bundle, scanner output, or reviewer evidence and rerun validation."
    )


def _default_validation_question(threat: Threat) -> str:
    return f"Validate whether {threat.display_id}: {threat.description}"


def _new_job(
    *,
    current_user: User,
    threat: Threat,
    run_id: UUID,
    agent_type: str,
    tools: list[str],
    domain_agent_plan: list[dict[str, Any]] | None = None,
) -> OrchestrationJob:
    return OrchestrationJob(
        id=uuid4(),
        threat_model_id=threat.threat_model_id,
        owner_id=current_user.id,
        job_kind="security_audit",
        status="running",
        objective=f"{agent_type} for threat {threat.display_id}",
        requested_tools=tools,
        idempotency_key=f"{agent_type}:{run_id}",
        inputs={
            "agent_type": agent_type,
            "agent_contract_version": AGENT_CONTRACT_VERSION,
            "run_id": str(run_id),
            "threat_id": str(threat.id),
            "domain_agent_plan": domain_agent_plan or [],
        },
        policy={"model_agnostic": True, "direct_mutation_allowed": False},
        started_at=_now(),
    )


async def _emit_event(
    db: AsyncSession,
    *,
    job: OrchestrationJob,
    event_type: str,
    agent_event: str,
    message: str,
    payload: dict[str, Any] | None = None,
    level: str = "info",
) -> None:
    event_payload = {"agent_event": agent_event, **(payload or {})}
    event_payload["event_payload_hash"] = agent_event_payload_hash(
        event_type=event_type,
        level=level,
        message=message,
        payload=event_payload,
    )
    event = OrchestrationEvent(
        id=uuid4(),
        job_id=job.id,
        threat_model_id=job.threat_model_id,
        event_type=event_type,
        level=level,
        message=message,
        payload=event_payload,
        created_at=_now(),
    )
    db.add(event)


async def _emit_agent_audit_log(
    db: AsyncSession,
    *,
    current_user: User,
    threat: Threat,
    action: str,
    new_status: str,
    reason: str | None = None,
) -> None:
    db.add(
        ThreatAuditLog(
            id=uuid4(),
            threat_id=threat.id,
            threat_model_id=threat.threat_model_id,
            user_id=current_user.id,
            action=action[:30],
            old_status=None,
            new_status=_audit_status(new_status),
            reason=reason,
        )
    )


def _audit_status(value: str) -> str:
    aliases = {
        "more_evidence_required": "more_evidence",
        "needs_human_review": "needs_review",
        "not_supported": "not_supported",
        "awaiting_confirmation": "awaiting_confirm",
    }
    return aliases.get(value, value)[:20]


async def _events_for_job(db: AsyncSession, job_id: UUID | None):
    if job_id is None:
        return []
    result = await db.execute(
        select(OrchestrationEvent)
        .where(OrchestrationEvent.job_id == job_id)
        .order_by(OrchestrationEvent.created_at, OrchestrationEvent.id)
    )
    return [serialize_orchestration_event(event) for event in result.scalars().all()]


async def _remediation_evidence_for_validation(db: AsyncSession, validation_run_id: UUID) -> list[dict[str, Any]]:
    result = await db.execute(
        select(ThreatRemediationRun).where(ThreatRemediationRun.validation_run_id == validation_run_id)
    )
    evidence: list[dict[str, Any]] = []
    for remediation in result.scalars().all():
        for ref in remediation.evidence_refs or []:
            if ref.get("type") in {"remediation_evidence", "handoff"}:
                evidence.append(
                    {
                        **ref,
                        "remediation_run_id": str(remediation.id),
                        "agent_type": remediation.agent_type,
                    }
                )
    return evidence


def _metadata(run: ThreatValidationRun | ThreatRemediationRun) -> AgentRunMetadata:
    return AgentRunMetadata(
        agent_type=run.agent_type,  # type: ignore[arg-type]
        agent_version=run.agent_version,
        input_schema_version=run.input_schema_version,
        output_schema_version=run.output_schema_version,
        policy_version=run.policy_version,
        tool_harness_versions=run.tool_harness_versions or {},
        model_provider=run.model_provider,
        model_name=run.model_name,
        prompt_version=run.prompt_version,
        model_output_hash=run.model_output_hash,
        deterministic_fallback_used=run.deterministic_fallback_used,
    )


def _remediation_context_packet(validation_run: ThreatValidationRun, threat: Threat) -> dict[str, Any]:
    return {
        "validation_run_id": str(validation_run.id),
        "conclusion": validation_run.conclusion,
        "summary": validation_run.summary,
        "exploitability": validation_run.exploitability or {},
        "evidence_refs": validation_run.evidence_refs or [],
        "threat": {
            "id": str(threat.id),
            "display_id": threat.display_id,
            "description": threat.description,
            "severity": threat.severity,
            "stride_category": threat.stride_category,
            "rule_id": threat.rule_id,
        },
    }


def _evidence_text(
    threat: Threat,
    evidence_refs: list[dict[str, Any]],
    entries: list[ApplicationReviewContextEntry],
) -> str:
    chunks = [threat.display_id, threat.description, threat.threat_subtype or "", threat.rule_id or ""]
    for entry in entries:
        chunks.extend([entry.title, entry.body])
    for ref in evidence_refs:
        chunks.append(str(ref.get("item_type") or ""))
        chunks.append(str(ref.get("title") or ""))
        for source_ref in ref.get("source_refs") or []:
            chunks.append(str(source_ref))
    return " ".join(chunks).casefold()


def _has_source_path(ref: dict[str, Any]) -> bool:
    for source_ref in ref.get("source_refs") or []:
        if isinstance(source_ref, dict) and source_ref.get("path"):
            return True
    return False


def _remediation_output_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["summary", "patch_preview", "ticket_draft", "pr_draft"],
        "properties": {
            "summary": {
                "type": "string",
                "description": "Short evidence-backed remediation summary. Do not claim fixed or secure.",
            },
            "patch_preview": {
                "type": "string",
                "description": "Draft-only implementation guidance with target files or config areas.",
            },
            "ticket_draft": {
                "type": "object",
                "required": ["title", "body"],
                "properties": {
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                    "labels": {"type": "array", "items": {"type": "string"}},
                },
            },
            "pr_draft": {
                "type": "object",
                "required": ["title", "body"],
                "properties": {
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                    "target_files": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    }


def _agent_label(agent_type: str) -> str:
    return {
        "code_fix": "Code Fix Agent",
        "iac_fix": "IaC Fix Agent",
        "configuration_fix": "Configuration Fix Agent",
    }.get(agent_type, "Threat Agent")


def _now() -> datetime:
    return datetime.now(timezone.utc)

"""Hardening gates for model-agnostic threat agent orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from uuid import UUID

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.application_review_context import ApplicationReviewContextEntry
from app.models.scan import ScanFinding, ScanJob
from app.models.threat_agent_orchestration import ThreatValidationRun
from app.services.agent_model_adapter import (
    AgentModelAdapter,
    DeterministicFallbackAgentModelAdapter,
    validate_agent_model_payload,
)


@dataclass(frozen=True)
class EvidenceIntegrityFinding:
    finding_id: str
    evidence_id: str | None
    reason: str
    expected: Any = None
    actual: Any = None


@dataclass(frozen=True)
class IacValidationResult:
    artifact_type: str
    valid: bool
    tool_used: str
    diagnostics: list[str]


class AgentProbeRateLimitExceeded(ValueError):
    """Raised when a tenant/threat validation probe quota is exceeded."""


class NoMutationViolation(RuntimeError):
    """Raised when an agent workflow attempts a direct mutation in V1."""


_VALIDATION_PROBE_ATTEMPTS: dict[tuple[str, str], deque[float]] = defaultdict(deque)
_FORBIDDEN_MUTATION_PATTERNS = (
    re.compile(r"\bgh\s+pr\s+create\b", re.IGNORECASE),
    re.compile(r"\bgh\s+issue\s+create\b", re.IGNORECASE),
    re.compile(r"\bgit\s+push\b", re.IGNORECASE),
    re.compile(r"\bkubectl\s+apply\b", re.IGNORECASE),
    re.compile(r"\bterraform\s+apply\b", re.IGNORECASE),
    re.compile(r"\baws\s+.*\b(put|update|delete|create)-", re.IGNORECASE),
    re.compile(r"\bcloudformation\s+(deploy|update-stack|create-stack)\b", re.IGNORECASE),
    re.compile(r"\brequests\.(post|put|patch|delete)\b", re.IGNORECASE),
    re.compile(r"\bboto3\.client\b", re.IGNORECASE),
)


async def verify_validation_evidence_integrity(
    db: AsyncSession,
    run: ThreatValidationRun,
) -> list[EvidenceIntegrityFinding]:
    """Verify validation evidence refs still match active tenant-owned context rows."""

    findings: list[EvidenceIntegrityFinding] = []
    for ref in run.evidence_refs or []:
        if _is_external_evidence_ref(ref):
            continue
        if _is_scan_finding_ref(ref):
            findings.extend(await _verify_scan_finding_ref(db, run, ref))
            continue
        evidence_id = ref.get("id")
        if not evidence_id:
            findings.append(
                EvidenceIntegrityFinding(
                    finding_id="evidence_id_missing",
                    evidence_id=None,
                    reason="Evidence ref does not include a context entry id.",
                )
            )
            continue
        try:
            entry_id = UUID(str(evidence_id))
        except (TypeError, ValueError):
            findings.append(
                EvidenceIntegrityFinding(
                    finding_id="evidence_id_invalid",
                    evidence_id=str(evidence_id),
                    reason="Evidence ref id is not a valid UUID.",
                )
            )
            continue
        result = await db.execute(
            select(ApplicationReviewContextEntry).where(
                ApplicationReviewContextEntry.id == entry_id,
                ApplicationReviewContextEntry.tenant_key == run.tenant_key,
            )
        )
        entry = result.scalar_one_or_none()
        if entry is None:
            findings.append(
                EvidenceIntegrityFinding(
                    finding_id="evidence_context_missing",
                    evidence_id=str(evidence_id),
                    reason="Evidence context entry is missing or belongs to another tenant.",
                )
            )
            continue
        if run.application_review_id is not None and entry.review_id != run.application_review_id:
            findings.append(
                EvidenceIntegrityFinding(
                    finding_id="evidence_review_mismatch",
                    evidence_id=str(evidence_id),
                    reason="Evidence context entry is no longer attached to the validation review.",
                    expected=str(run.application_review_id),
                    actual=str(entry.review_id),
                )
            )
        if entry.status != "active":
            findings.append(
                EvidenceIntegrityFinding(
                    finding_id="evidence_not_active",
                    evidence_id=str(evidence_id),
                    reason="Evidence context entry is stale or deleted.",
                    expected="active",
                    actual=entry.status,
                )
            )
        _compare_ref_field(findings, ref, entry, "content_hash")
        _compare_ref_field(findings, ref, entry, "source_refs")
        _compare_ref_field(findings, ref, entry, "item_type")
        _compare_ref_field(findings, ref, entry, "source_type")
    return findings


async def _verify_scan_finding_ref(
    db: AsyncSession,
    run: ThreatValidationRun,
    ref: dict[str, Any],
) -> list[EvidenceIntegrityFinding]:
    findings: list[EvidenceIntegrityFinding] = []
    evidence_id = ref.get("id")
    try:
        finding_id = UUID(str(evidence_id))
    except (TypeError, ValueError):
        return [
            EvidenceIntegrityFinding(
                finding_id="scan_finding_id_invalid",
                evidence_id=str(evidence_id),
                reason="Scan evidence ref id is not a valid UUID.",
            )
        ]

    finding = await db.get(ScanFinding, finding_id)
    if finding is None:
        return [
            EvidenceIntegrityFinding(
                finding_id="scan_finding_missing",
                evidence_id=str(evidence_id),
                reason="Scan finding is missing.",
            )
        ]
    scan_job = await db.get(ScanJob, finding.scan_job_id)
    if scan_job is None:
        findings.append(
            EvidenceIntegrityFinding(
                finding_id="scan_job_missing",
                evidence_id=str(evidence_id),
                reason="Scan finding job is missing.",
                expected=str(finding.scan_job_id),
                actual=None,
            )
        )
        return findings
    if scan_job.threat_model_id != run.threat_model_id:
        findings.append(
            EvidenceIntegrityFinding(
                finding_id="scan_job_threat_model_mismatch",
                evidence_id=str(evidence_id),
                reason="Scan finding belongs to a different threat model.",
                expected=str(run.threat_model_id),
                actual=str(scan_job.threat_model_id),
            )
        )
    if scan_job.owner_id != run.owner_id:
        findings.append(
            EvidenceIntegrityFinding(
                finding_id="scan_job_owner_mismatch",
                evidence_id=str(evidence_id),
                reason="Scan finding belongs to a different owner.",
                expected=str(run.owner_id),
                actual=str(scan_job.owner_id),
            )
        )
    if scan_job.status != "completed":
        findings.append(
            EvidenceIntegrityFinding(
                finding_id="scan_job_not_completed",
                evidence_id=str(evidence_id),
                reason="Scan finding job is not completed.",
                expected="completed",
                actual=scan_job.status,
            )
        )
    source_object_id = ref.get("source_object_id")
    if source_object_id and str(source_object_id) != str(scan_job.id):
        findings.append(
            EvidenceIntegrityFinding(
                finding_id="scan_source_object_mismatch",
                evidence_id=str(evidence_id),
                reason="Scan evidence source object does not match its scan job.",
                expected=str(scan_job.id),
                actual=str(source_object_id),
            )
        )
    expected_hash = finding.validation_metadata.get("output_sha256")
    if ref.get("content_hash") and expected_hash and ref.get("content_hash") != expected_hash:
        findings.append(
            EvidenceIntegrityFinding(
                finding_id="scan_content_hash_mismatch",
                evidence_id=str(evidence_id),
                reason="Scan evidence content hash does not match finding metadata.",
                expected=expected_hash,
                actual=ref.get("content_hash"),
            )
        )
    source_refs = ref.get("source_refs") or []
    source_scan_job_ids = {
        str(source_ref.get("scan_job_id"))
        for source_ref in source_refs
        if isinstance(source_ref, dict) and source_ref.get("scan_job_id")
    }
    if source_scan_job_ids and str(scan_job.id) not in source_scan_job_ids:
        findings.append(
            EvidenceIntegrityFinding(
                finding_id="scan_source_ref_job_mismatch",
                evidence_id=str(evidence_id),
                reason="Scan evidence source refs do not include the owning scan job.",
                expected=str(scan_job.id),
                actual=sorted(source_scan_job_ids),
            )
        )
    return findings


def evidence_integrity_findings_payload(findings: Iterable[EvidenceIntegrityFinding]) -> dict[str, Any]:
    return {"findings": [asdict(finding) for finding in findings]}


def enforce_validation_probe_rate_limit(
    *,
    tenant_key: str,
    threat_id: UUID | str,
    now: float | None = None,
    limit: int | None = None,
    window_seconds: int = 60,
) -> None:
    """Limit repeated human-triggered validation probes per tenant and threat."""

    effective_limit = settings.agent_scan_minute_quota if limit is None else limit
    if effective_limit <= 0:
        return
    current_time = time.monotonic() if now is None else now
    key = (tenant_key, str(threat_id))
    attempts = _VALIDATION_PROBE_ATTEMPTS[key]
    while attempts and attempts[0] <= current_time - window_seconds:
        attempts.popleft()
    if len(attempts) >= effective_limit:
        raise AgentProbeRateLimitExceeded(
            f"Validation probe rate limit exceeded for this threat: {effective_limit} per {window_seconds}s."
        )
    attempts.append(current_time)


def reset_validation_probe_rate_limit_state() -> None:
    _VALIDATION_PROBE_ATTEMPTS.clear()


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def agent_event_payload_hash(
    *,
    event_type: str,
    level: str,
    message: str,
    payload: dict[str, Any],
) -> str:
    clean_payload = {key: value for key, value in payload.items() if key != "event_payload_hash"}
    return stable_hash(
        {
            "event_type": event_type,
            "level": level,
            "message": message,
            "payload": clean_payload,
        }
    )


def build_agent_audit_export(events: Iterable[Any]) -> dict[str, Any]:
    """Create a tamper-evident audit export from orchestration events."""

    records: list[dict[str, Any]] = []
    previous_hash = "0" * 64
    for event in events:
        payload = dict(_event_value(event, "payload") or {})
        stored_payload_hash = payload.get("event_payload_hash")
        clean_payload = {key: value for key, value in payload.items() if key != "event_payload_hash"}
        record = {
            "id": str(_event_value(event, "id")),
            "job_id": str(_event_value(event, "job_id")),
            "task_id": str(_event_value(event, "task_id")) if _event_value(event, "task_id") else None,
            "threat_model_id": str(_event_value(event, "threat_model_id")),
            "event_type": _event_value(event, "event_type"),
            "level": _event_value(event, "level"),
            "message": _event_value(event, "message"),
            "payload": clean_payload,
            "stored_payload_hash": stored_payload_hash,
            "payload_hash": agent_event_payload_hash(
                event_type=str(_event_value(event, "event_type")),
                level=str(_event_value(event, "level")),
                message=str(_event_value(event, "message")),
                payload=clean_payload,
            ),
            "previous_hash": previous_hash,
            "created_at": str(_event_value(event, "created_at")),
        }
        record["event_hash"] = _audit_record_hash(record)
        previous_hash = record["event_hash"]
        records.append(record)
    return {
        "schema_version": "threatgenix.agent_audit_export.v1",
        "records": records,
        "chain_head": previous_hash,
    }


def verify_agent_audit_export(export: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    previous_hash = "0" * 64
    records = export.get("records") or []
    if not isinstance(records, list):
        return [{"finding_id": "audit_records_invalid", "reason": "Audit records must be a list."}]
    for index, record in enumerate(records):
        if record.get("previous_hash") != previous_hash:
            findings.append(
                {
                    "finding_id": "audit_chain_previous_hash_mismatch",
                    "index": index,
                    "expected": previous_hash,
                    "actual": record.get("previous_hash"),
                }
            )
        payload_hash = agent_event_payload_hash(
            event_type=str(record.get("event_type")),
            level=str(record.get("level")),
            message=str(record.get("message")),
            payload=dict(record.get("payload") or {}),
        )
        if record.get("payload_hash") != payload_hash:
            findings.append(
                {
                    "finding_id": "audit_payload_hash_mismatch",
                    "index": index,
                    "expected": payload_hash,
                    "actual": record.get("payload_hash"),
                }
            )
        stored_payload_hash = record.get("stored_payload_hash")
        if stored_payload_hash and stored_payload_hash != payload_hash:
            findings.append(
                {
                    "finding_id": "audit_stored_payload_hash_mismatch",
                    "index": index,
                    "expected": payload_hash,
                    "actual": stored_payload_hash,
                }
            )
        event_hash = _audit_record_hash(record)
        if record.get("event_hash") != event_hash:
            findings.append(
                {
                    "finding_id": "audit_event_hash_mismatch",
                    "index": index,
                    "expected": event_hash,
                    "actual": record.get("event_hash"),
                }
            )
        previous_hash = str(record.get("event_hash") or "")
    if export.get("chain_head") != previous_hash:
        findings.append(
            {
                "finding_id": "audit_chain_head_mismatch",
                "expected": previous_hash,
                "actual": export.get("chain_head"),
            }
        )
    return findings


async def compare_model_adapter_outputs(
    *,
    agent_type: str,
    context_packet: dict[str, Any],
    output_schema: dict[str, Any],
    adapters: dict[str, AgentModelAdapter] | None = None,
    timeout_seconds: float = 20.0,
) -> dict[str, Any]:
    """Run schema validation across configured model adapters and deterministic fallback."""

    provider_adapters = adapters or {}
    results: list[dict[str, Any]] = []
    for provider_name, adapter in provider_adapters.items():
        started = time.monotonic()
        try:
            model_result = await asyncio.wait_for(
                adapter.generate_structured(
                    agent_type=agent_type,
                    context_packet=context_packet,
                    output_schema=output_schema,
                ),
                timeout=timeout_seconds,
            )
            payload = validate_agent_model_payload(model_result.payload)
            results.append(
                {
                    "provider": provider_name,
                    "status": "schema_valid",
                    "model_provider": model_result.model_provider,
                    "model_name": model_result.model_name,
                    "prompt_version": model_result.prompt_version,
                    "model_output_hash": model_result.model_output_hash or stable_hash(payload),
                    "deterministic_fallback_used": model_result.deterministic_fallback_used,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                }
            )
        except Exception as exc:
            results.append(
                {
                    "provider": provider_name,
                    "status": "failed",
                    "error": _redact_error(exc),
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                }
            )
    fallback = await DeterministicFallbackAgentModelAdapter().generate_structured(
        agent_type=agent_type,
        context_packet=context_packet,
        output_schema=output_schema,
    )
    fallback_payload = validate_agent_model_payload(fallback.payload)
    results.append(
        {
            "provider": "deterministic_fallback",
            "status": "schema_valid",
            "model_provider": fallback.model_provider,
            "model_name": fallback.model_name,
            "prompt_version": fallback.prompt_version,
            "model_output_hash": fallback.model_output_hash or stable_hash(fallback_payload),
            "deterministic_fallback_used": True,
            "elapsed_ms": 0,
        }
    )
    valid_hashes = {
        result["model_output_hash"]
        for result in results
        if result.get("status") == "schema_valid" and result.get("model_output_hash")
    }
    return {
        "schema_version": "threatgenix.agent_model_comparison.v1",
        "providers_configured": sorted(provider_adapters),
        "fallback_required": not provider_adapters,
        "all_outputs_schema_valid": all(result["status"] == "schema_valid" for result in results),
        "distinct_valid_output_hashes": sorted(valid_hashes),
        "results": results,
    }


def configured_model_provider_names(env: dict[str, str] | None = None) -> list[str]:
    source = env or os.environ
    configured = []
    if source.get("ANTHROPIC_API_KEY"):
        configured.append("anthropic")
    if source.get("OPENAI_API_KEY"):
        configured.append("openai")
    if source.get("OPENROUTER_API_KEY"):
        configured.append("openrouter")
    if source.get("GEMINI_API_KEY") or source.get("GOOGLE_API_KEY"):
        configured.append("gemini")
    if source.get("XAI_API_KEY"):
        configured.append("xai")
    if source.get("ZAI_API_KEY"):
        configured.append("zai")
    if source.get("PERPLEXITY_API_KEY"):
        configured.append("perplexity")
    if source.get("AWS_ACCESS_KEY_ID") or source.get("AWS_PROFILE"):
        configured.append("bedrock")
    if source.get("OLLAMA_BASE_URL"):
        configured.append("ollama")
    return configured


class NoMutationRuntimeMonitor:
    """Records agent runtime actions and fails closed on direct mutations."""

    def __init__(self) -> None:
        self.operations: list[dict[str, Any]] = []

    def record(self, action: str, *, target: str | None = None, metadata: dict[str, Any] | None = None) -> None:
        operation = {"action": action, "target": target, "metadata": metadata or {}}
        self.operations.append(operation)
        findings = validate_no_mutation_operations([operation])
        if findings:
            raise NoMutationViolation(findings[0]["reason"])

    def assert_no_forbidden_operations(self) -> None:
        findings = validate_no_mutation_operations(self.operations)
        if findings:
            raise NoMutationViolation(findings[0]["reason"])


def validate_no_mutation_operations(operations: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, operation in enumerate(operations):
        haystack = canonical_json(operation)
        for pattern in _FORBIDDEN_MUTATION_PATTERNS:
            if pattern.search(haystack):
                findings.append(
                    {
                        "finding_id": "direct_mutation_attempt",
                        "index": index,
                        "reason": f"Forbidden direct mutation action matched {pattern.pattern}.",
                        "operation": operation,
                    }
                )
    return findings


def validate_iac_draft_artifact(
    *,
    path: str,
    content: str,
    artifact_type: str | None = None,
) -> IacValidationResult:
    """Validate IaC draft syntax and least-privilege guardrails without applying it."""

    detected = artifact_type or _detect_iac_type(path)
    diagnostics = _broad_permission_findings(content)
    if diagnostics:
        return IacValidationResult(detected, False, "static-policy", diagnostics)
    if detected == "terraform":
        return _validate_terraform(path=path, content=content)
    if detected == "cloudformation":
        return _validate_cloudformation(content)
    if detected == "kubernetes":
        return _validate_kubernetes(content)
    return IacValidationResult(detected, False, "static", [f"Unsupported IaC artifact type: {detected}."])


def _compare_ref_field(
    findings: list[EvidenceIntegrityFinding],
    ref: dict[str, Any],
    entry: ApplicationReviewContextEntry,
    field: str,
) -> None:
    expected = getattr(entry, field)
    actual = ref.get(field)
    if canonical_json(actual) != canonical_json(expected):
        findings.append(
            EvidenceIntegrityFinding(
                finding_id=f"evidence_{field}_mismatch",
                evidence_id=str(ref.get("id")),
                reason=f"Evidence ref {field} does not match the active context entry.",
                expected=expected,
                actual=actual,
            )
        )


def _is_external_evidence_ref(ref: dict[str, Any]) -> bool:
    return ref.get("type") in {"handoff", "remediation_evidence"}


def _is_scan_finding_ref(ref: dict[str, Any]) -> bool:
    source_refs = ref.get("source_refs") or []
    return (
        ref.get("item_type") == "scanner_finding"
        and ref.get("source_type") == "scan_finding"
        and any(
            isinstance(source_ref, dict) and source_ref.get("scan_job_id")
            for source_ref in source_refs
        )
    )


def _event_value(event: Any, field: str) -> Any:
    if isinstance(event, dict):
        return event.get(field)
    return getattr(event, field, None)


def _audit_record_hash(record: dict[str, Any]) -> str:
    return stable_hash({key: value for key, value in record.items() if key != "event_hash"})


def _redact_error(exc: Exception) -> str:
    message = str(exc)
    message = re.sub(r"(?i)(api[_-]?key['\"]?\s*[:=]\s*['\"]?)[^'\"\s,;]+", r"\1[redacted]", message)
    message = re.sub(r"(?i)(authorization:\s*bearer\s+)[^\s,;]+", r"\1[redacted]", message)
    return message[:500]


def _detect_iac_type(path: str) -> str:
    name = Path(path).name.lower()
    suffix = Path(path).suffix.lower()
    if suffix == ".tf":
        return "terraform"
    if name in {"template.yaml", "template.yml"} or suffix == ".template":
        return "cloudformation"
    if suffix in {".yaml", ".yml", ".json"}:
        text = path.casefold()
        if "cloudformation" in text or "cfn" in text:
            return "cloudformation"
        return "kubernetes"
    return "unknown"


def _broad_permission_findings(content: str) -> list[str]:
    lowered = content.casefold()
    diagnostics: list[str] = []
    if "0.0.0.0/0" in lowered or "::/0" in lowered:
        if any(term in lowered for term in ("ingress", "cidr_blocks", "source_ranges", "allow")):
            diagnostics.append("Draft introduces broad public ingress instead of a least-privilege fix.")
    if re.search(r"(?i)\b(principal|action|resource)\s*[:=]\s*[\"']?\*", content):
        diagnostics.append("Draft introduces wildcard IAM scope instead of a least-privilege fix.")
    return diagnostics


def _validate_terraform(*, path: str, content: str) -> IacValidationResult:
    terraform = shutil.which("terraform")
    if terraform:
        with tempfile.TemporaryDirectory(prefix="tgx-iac-") as temp_dir:
            candidate = Path(temp_dir) / Path(path).name
            candidate.write_text(content, encoding="utf-8")
            completed = subprocess.run(
                [terraform, "validate", "-no-color"],
                cwd=temp_dir,
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )
            if completed.returncode == 0:
                return IacValidationResult("terraform", True, "terraform validate", [])
            diagnostics = [completed.stdout.strip(), completed.stderr.strip()]
            if _terraform_tool_unavailable(diagnostics):
                return _static_terraform_validation(content, tool_used="static-terraform")
            return IacValidationResult(
                "terraform",
                False,
                "terraform validate",
                diagnostics,
            )
    return _static_terraform_validation(content, tool_used="static-terraform")


def _static_terraform_validation(content: str, *, tool_used: str) -> IacValidationResult:
    if content.count("{") != content.count("}"):
        return IacValidationResult("terraform", False, tool_used, ["Unbalanced Terraform braces."])
    if not re.search(r'\b(resource|module|variable|terraform)\s+"?[\w_-]*"?', content):
        return IacValidationResult("terraform", False, tool_used, ["No Terraform block was detected."])
    return IacValidationResult("terraform", True, tool_used, [])


def _terraform_tool_unavailable(diagnostics: list[str]) -> bool:
    joined = "\n".join(diagnostics).casefold()
    return any(
        marker in joined
        for marker in (
            "tfenv",
            "version could not be resolved",
            "no such file or directory",
            "command not found",
            "failed to query available provider packages",
        )
    )


def _validate_cloudformation(content: str) -> IacValidationResult:
    parsed = _load_iac_document(content)
    if not isinstance(parsed, dict):
        return IacValidationResult("cloudformation", False, "static-cloudformation", ["Template is not an object."])
    resources = parsed.get("Resources")
    if not isinstance(resources, dict) or not resources:
        return IacValidationResult("cloudformation", False, "static-cloudformation", ["Template has no Resources."])
    cfn_lint = shutil.which("cfn-lint")
    if cfn_lint:
        with tempfile.TemporaryDirectory(prefix="tgx-cfn-") as temp_dir:
            candidate = Path(temp_dir) / "template.yaml"
            candidate.write_text(content, encoding="utf-8")
            completed = subprocess.run(
                [cfn_lint, str(candidate)],
                text=True,
                capture_output=True,
                check=False,
                timeout=20,
            )
            if completed.returncode != 0:
                return IacValidationResult(
                    "cloudformation",
                    False,
                    "cfn-lint",
                    [completed.stdout.strip(), completed.stderr.strip()],
                )
            return IacValidationResult("cloudformation", True, "cfn-lint", [])
    return IacValidationResult("cloudformation", True, "static-cloudformation", [])


def _validate_kubernetes(content: str) -> IacValidationResult:
    try:
        documents = [doc for doc in yaml.safe_load_all(content) if doc is not None]
    except yaml.YAMLError as exc:
        return IacValidationResult("kubernetes", False, "static-kubernetes", [str(exc)])
    if not documents:
        return IacValidationResult("kubernetes", False, "static-kubernetes", ["No Kubernetes document found."])
    for index, document in enumerate(documents):
        if not isinstance(document, dict):
            return IacValidationResult("kubernetes", False, "static-kubernetes", [f"Document {index} is not an object."])
        metadata = document.get("metadata")
        if not document.get("apiVersion") or not document.get("kind") or not isinstance(metadata, dict) or not metadata.get("name"):
            return IacValidationResult(
                "kubernetes",
                False,
                "static-kubernetes",
                [f"Document {index} is missing apiVersion, kind, or metadata.name."],
            )
    return IacValidationResult("kubernetes", True, "static-kubernetes", [])


def _load_iac_document(content: str) -> Any:
    stripped = content.strip()
    if stripped.startswith("{"):
        return json.loads(stripped)
    return yaml.safe_load(stripped)

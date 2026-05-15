"""Normalize and validate managed scanner harness output."""

from __future__ import annotations

import hashlib

from app.models.application_review_bundle import ApplicationReviewBundle
from app.schemas.tool_harness import (
    HarnessEnvelope,
    HarnessRequest,
    NormalizedToolHarnessFinding,
    NormalizedToolHarnessOutput,
    ToolHarnessFinding,
    ToolHarnessOutput,
)
from app.services.application_review_bundles import (
    ReviewBundleValidationError,
    canonical_json,
    safe_manifest_path,
)

TRUSTED_HARNESS_ISSUER = "threatgenix-managed-scanner"

ALLOWED_TOOL_SOURCE_TYPES: dict[str, set[str]] = {
    "semgrep": {"sast"},
    "osv-scanner": {"dependency"},
    "trivy": {"dependency", "iac"},
    "checkov": {"iac"},
    "trufflehog": {"secret"},
    "nuclei": {"external"},
}

REQUIRED_V1_HARNESS_TOOLS = {
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
}

HARNESS_TOOL_EVIDENCE_TYPES: dict[str, set[str]] = {
    "bundle_parser": {"bundle_file"},
    "code_context_extractor": {"code_context", "bundle_file"},
    "managed_sast": {"scanner_finding"},
    "dependency_scanner": {"scanner_finding"},
    "secrets_scanner": {"scanner_finding"},
    "iac_scanner": {"scanner_finding"},
    "sarif_importer": {"scanner_finding"},
    "evidence_graph_rebuild": {"evidence_graph"},
    "security_context_indexer": {"security_context"},
    "context_packet_builder": {"context_packet"},
    "deterministic_decision_engine": {"decision_trace"},
    "ai_fix_plan_generator": {"ai_explanation"},
}


class ToolHarnessValidationError(ValueError):
    """Raised when scanner harness output cannot be trusted."""


def validate_harness_envelope(
    envelope: HarnessEnvelope,
    *,
    tenant_key: str,
    review_id,
    authorized_targets: set[str] | None = None,
) -> HarnessEnvelope:
    request = envelope.request
    if request.tool_name not in REQUIRED_V1_HARNESS_TOOLS:
        raise ToolHarnessValidationError(f"Unsupported harness tool: {request.tool_name}")
    if request.tenant_key != tenant_key:
        raise ToolHarnessValidationError("Harness tenant_key does not match caller tenant.")
    if request.review_id != review_id:
        raise ToolHarnessValidationError("Harness review_id does not match review.")
    _validate_harness_targets(request.policy.allowed_targets, authorized_targets or set())
    _validate_evidence_contract(envelope)
    _validate_evidence_only_boundary(envelope)
    return envelope


def stable_harness_execution_key(request: HarnessRequest) -> str:
    payload = {
        "tenant_key": request.tenant_key,
        "review_id": str(request.review_id),
        "tool_name": request.tool_name,
        "tool_version": request.tool_version,
        "bundle_id": str(request.bundle_id) if request.bundle_id else None,
        "idempotency_key": request.idempotency_key,
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"harness-execution:{request.tool_name}:{digest}"


def _validate_harness_targets(allowed_targets: list[str], authorized_targets: set[str]) -> None:
    if not allowed_targets:
        return
    if not authorized_targets:
        raise ToolHarnessValidationError("Harness target authorization is required.")
    unauthorized = [target for target in allowed_targets if target not in authorized_targets]
    if unauthorized:
        raise ToolHarnessValidationError(f"Harness target is not authorized: {unauthorized[0]}")


def _validate_evidence_contract(envelope: HarnessEnvelope) -> None:
    allowed_types = HARNESS_TOOL_EVIDENCE_TYPES[envelope.request.tool_name]
    for item in envelope.result.evidence_items:
        if item.item_type not in allowed_types:
            raise ToolHarnessValidationError(
                f"{envelope.request.tool_name} cannot emit {item.item_type} evidence"
            )


def _validate_evidence_only_boundary(envelope: HarnessEnvelope) -> None:
    forbidden_keys = {
        "block",
        "blocking",
        "block_decision",
        "decision",
        "accept_risk",
        "promote",
        "promote_to_blocking",
    }
    for finding in envelope.result.normalized_findings:
        if forbidden_keys & set(finding):
            raise ToolHarnessValidationError(
                "Harness output must stay evidence-only and cannot promote decisions."
            )
    for item in envelope.result.evidence_items:
        if forbidden_keys & set(item.metadata):
            raise ToolHarnessValidationError(
                "Harness evidence-only metadata must not include decision promotion fields."
            )


def normalize_tool_output_against_bundle(
    output: ToolHarnessOutput,
    bundle: ApplicationReviewBundle,
) -> NormalizedToolHarnessOutput:
    validate_tool_output_against_bundle(output, bundle)
    return NormalizedToolHarnessOutput(
        tool_name=output.tool_name,
        tool_version=output.tool_version,
        ruleset_version=output.ruleset_version,
        scanner_run_id=output.scanner_run_id,
        bundle_id=output.bundle_id,
        status=output.status,
        trusted=True,
        findings=[
            NormalizedToolHarnessFinding(
                **finding.model_dump(),
                finding_key=stable_finding_key(output.tool_name, finding),
            )
            for finding in output.findings
        ],
        raw_artifact_refs=list(dict.fromkeys(output.raw_artifact_refs)),
        provenance=output.provenance,
    )


def validate_tool_output_against_bundle(
    output: ToolHarnessOutput,
    bundle: ApplicationReviewBundle,
) -> None:
    if output.tool_name not in ALLOWED_TOOL_SOURCE_TYPES:
        raise ToolHarnessValidationError(f"Unsupported harness tool: {output.tool_name}")
    if output.bundle_id != bundle.id:
        raise ToolHarnessValidationError("Harness output bundle_id does not match review bundle.")
    _validate_provenance(output)
    try:
        manifest_paths = {
            safe_manifest_path(str(item.get("path", "")))
            for item in (bundle.manifest or [])
        }
    except ReviewBundleValidationError as exc:
        raise ToolHarnessValidationError(str(exc)) from exc
    if output.status in {"failed", "blocked"}:
        if output.findings:
            raise ToolHarnessValidationError("Failed or blocked output cannot include findings.")
        return
    if output.status == "completed" and not output.findings:
        return
    allowed_source_types = ALLOWED_TOOL_SOURCE_TYPES[output.tool_name]
    for finding in output.findings:
        try:
            safe_path = safe_manifest_path(finding.path)
        except ReviewBundleValidationError as exc:
            raise ToolHarnessValidationError(str(exc)) from exc
        if safe_path not in manifest_paths:
            raise ToolHarnessValidationError(
                f"Finding path is not present in bundle manifest: {safe_path}"
            )
        if finding.source_type not in allowed_source_types:
            raise ToolHarnessValidationError(
                f"{output.tool_name} cannot emit {finding.source_type} findings"
            )


def _validate_provenance(output: ToolHarnessOutput) -> None:
    provenance = output.provenance
    if provenance.issuer != TRUSTED_HARNESS_ISSUER:
        raise ToolHarnessValidationError("Harness output provenance issuer is not trusted.")
    if provenance.tool_name != output.tool_name:
        raise ToolHarnessValidationError("Harness output provenance tool_name mismatch.")
    if provenance.scanner_run_id != output.scanner_run_id:
        raise ToolHarnessValidationError("Harness output provenance scanner_run_id mismatch.")
    if provenance.bundle_id != output.bundle_id:
        raise ToolHarnessValidationError("Harness output provenance bundle_id mismatch.")


def stable_finding_key(tool_name: str, finding: ToolHarnessFinding) -> str:
    payload = {
        "tool_name": tool_name,
        "source_type": finding.source_type,
        "rule_id": finding.rule_id,
        "path": _safe_finding_path_for_key(finding.path),
        "start_line": finding.start_line,
        "end_line": finding.end_line,
        "evidence_snippet_sha256": finding.evidence_snippet_sha256,
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"harness:{tool_name}:{digest}"


def _safe_finding_path_for_key(path: str) -> str:
    try:
        return safe_manifest_path(path)
    except ReviewBundleValidationError as exc:
        raise ToolHarnessValidationError(str(exc)) from exc


def can_harness_output_drive_block_decision(output: NormalizedToolHarnessOutput) -> bool:
    if not output.trusted or output.status != "completed":
        return False
    return any(finding.severity in {"Critical", "High"} for finding in output.findings)

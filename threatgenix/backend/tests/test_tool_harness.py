from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models.application_review_bundle import ApplicationReviewBundle
from app.schemas.tool_harness import (
    HarnessEnvelope,
    ToolHarnessFinding,
    ToolHarnessOutput,
    ToolHarnessProvenance,
)
from app.services.application_review_bundles import build_bundle_integrity, compute_bundle_hash
from app.services.tool_harness import (
    REQUIRED_V1_HARNESS_TOOLS,
    TRUSTED_HARNESS_ISSUER,
    ToolHarnessValidationError,
    can_harness_output_drive_block_decision,
    normalize_tool_output_against_bundle,
    stable_harness_execution_key,
    stable_finding_key,
    validate_harness_envelope,
)


def _bundle() -> ApplicationReviewBundle:
    now = datetime.now(timezone.utc)
    manifest = [
        {
            "path": "apps/api/users.py",
            "file_kind": "source",
            "sha256": "a" * 64,
            "byte_size": 120,
            "source": "cli",
        }
    ]
    content_hash = compute_bundle_hash("diff", manifest)
    return ApplicationReviewBundle(
        id=uuid.uuid4(),
        tenant_key="user:owner",
        review_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        organization_id=None,
        bundle_kind="diff",
        source="cli",
        status="ready",
        manifest=manifest,
        redaction_report={},
        integrity=build_bundle_integrity(
            bundle_kind="diff",
            manifest=manifest,
            content_hash=content_hash,
            byte_size=120,
            file_count=1,
        ),
        storage_backend="database_manifest",
        encryption_status="metadata_only",
        content_hash=content_hash,
        byte_size=120,
        file_count=1,
        legal_hold=False,
        created_at=now,
        updated_at=now,
    )


def _finding(**overrides) -> ToolHarnessFinding:
    payload = {
        "rule_id": "python.fastapi.missing-authz",
        "title": "Sensitive export route is missing authorization",
        "severity": "High",
        "path": "apps/api/users.py",
        "start_line": 42,
        "end_line": 45,
        "evidence_snippet_sha256": "c" * 64,
        "confidence": "high",
        "source_type": "sast",
    }
    payload.update(overrides)
    return ToolHarnessFinding(**payload)


def _output(bundle: ApplicationReviewBundle, **overrides) -> ToolHarnessOutput:
    payload = {
        "tool_name": "semgrep",
        "tool_version": "1.2.3",
        "ruleset_version": "rules-2026-05-01",
        "scanner_run_id": "run-123",
        "bundle_id": bundle.id,
        "status": "completed",
        "findings": [_finding()],
        "raw_artifact_refs": ["artifact://semgrep/run-123"],
        "provenance": {
            "issuer": TRUSTED_HARNESS_ISSUER,
            "tool_name": "semgrep",
            "scanner_run_id": "run-123",
            "bundle_id": bundle.id,
            "output_format": "threatgenix-harness-v1",
        },
    }
    payload.update(overrides)
    return ToolHarnessOutput(**payload)


def _envelope(bundle: ApplicationReviewBundle, **overrides) -> HarnessEnvelope:
    payload = {
        "request": {
            "tool_name": "code_context_extractor",
            "tool_version": "ctx-1.0.0",
            "tenant_key": bundle.tenant_key,
            "review_id": bundle.review_id,
            "bundle_id": bundle.id,
            "idempotency_key": "ctx-key-1",
            "inputs": {"paths": ["apps/api/users.py"]},
            "policy": {
                "network": "none",
                "timeout_seconds": 30,
                "allowed_targets": [f"tgx-review-bundle://{bundle.id}"],
            },
        },
        "result": {
            "status": "completed",
            "evidence_items": [
                {
                    "item_type": "code_context",
                    "title": "FastAPI export endpoint context",
                    "source_refs": ["apps/api/users.py"],
                    "content_hash": "d" * 64,
                    "metadata": {"language": "python"},
                }
            ],
            "normalized_findings": [],
            "warnings": [],
            "redactions": [
                {
                    "source_ref": "apps/api/users.py",
                    "redaction_type": "secret_pattern",
                    "count": 1,
                }
            ],
        },
        "events": [
            {"event_type": "started", "message": "started context extraction", "elapsed_ms": 0},
            {"event_type": "completed", "message": "completed context extraction", "elapsed_ms": 500},
        ],
        "duration_ms": 500,
    }
    payload.update(overrides)
    return HarnessEnvelope(**payload)


def test_valid_semgrep_output_normalizes_with_stable_finding_key():
    bundle = _bundle()
    output = _output(bundle)

    normalized = normalize_tool_output_against_bundle(output, bundle)

    assert normalized.trusted is True
    assert normalized.status == "completed"
    assert normalized.findings[0].finding_key == stable_finding_key("semgrep", output.findings[0])
    assert normalized.raw_artifact_refs == ["artifact://semgrep/run-123"]
    assert can_harness_output_drive_block_decision(normalized) is True


def test_missing_scanner_version_is_rejected():
    bundle = _bundle()

    with pytest.raises(ValidationError):
        _output(bundle, tool_version="")


def test_unknown_tool_is_rejected():
    bundle = _bundle()

    with pytest.raises(ValidationError):
        _output(bundle, tool_name="made-up-scanner")


def test_finding_path_must_exist_in_bundle_manifest():
    bundle = _bundle()
    output = _output(bundle, findings=[_finding(path="apps/api/admin.py")])

    with pytest.raises(ToolHarnessValidationError, match="not present"):
        normalize_tool_output_against_bundle(output, bundle)


def test_finding_path_traversal_is_rejected():
    bundle = _bundle()
    output = _output(bundle, findings=[_finding(path="../secrets.py")])

    with pytest.raises(ToolHarnessValidationError):
        normalize_tool_output_against_bundle(output, bundle)


def test_failed_output_cannot_include_findings():
    bundle = _bundle()

    with pytest.raises(ValidationError):
        _output(bundle, status="failed", findings=[_finding()])


def test_malicious_provenance_spoof_is_rejected():
    bundle = _bundle()
    spoofed_provenance = ToolHarnessProvenance(
        issuer="uploaded-sarif",
        tool_name="semgrep",
        scanner_run_id="run-123",
        bundle_id=bundle.id,
        output_format="sarif",
    )
    output = _output(bundle, provenance=spoofed_provenance)

    with pytest.raises(ToolHarnessValidationError, match="issuer"):
        normalize_tool_output_against_bundle(output, bundle)


def test_provenance_must_match_output_identity():
    bundle = _bundle()
    output = _output(
        bundle,
        provenance={
            "issuer": TRUSTED_HARNESS_ISSUER,
            "tool_name": "semgrep",
            "scanner_run_id": "different-run",
            "bundle_id": bundle.id,
            "output_format": "threatgenix-harness-v1",
        },
    )

    with pytest.raises(ToolHarnessValidationError, match="scanner_run_id"):
        normalize_tool_output_against_bundle(output, bundle)


def test_tool_cannot_emit_wrong_source_type():
    bundle = _bundle()
    output = _output(bundle, findings=[_finding(source_type="dependency")])

    with pytest.raises(ToolHarnessValidationError, match="cannot emit"):
        normalize_tool_output_against_bundle(output, bundle)


def test_same_input_has_same_key_and_rule_path_line_changes_change_key():
    base = _finding()
    same = _finding()
    changed_rule = _finding(rule_id="different")
    changed_path = _finding(path="apps/api/users.py", start_line=43)

    assert stable_finding_key("semgrep", base) == stable_finding_key("semgrep", same)
    assert stable_finding_key("semgrep", base) != stable_finding_key("semgrep", changed_rule)
    assert stable_finding_key("semgrep", base) != stable_finding_key("semgrep", changed_path)


def test_untrusted_output_cannot_drive_block_decision():
    bundle = _bundle()
    normalized = normalize_tool_output_against_bundle(_output(bundle), bundle)

    assert can_harness_output_drive_block_decision(
        normalized.model_copy(update={"trusted": False})
    ) is False


def test_required_v1_harness_registry_is_complete():
    assert REQUIRED_V1_HARNESS_TOOLS == {
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


def test_formal_harness_envelope_validates_permissions_targets_and_evidence_contract():
    bundle = _bundle()
    target = f"tgx-review-bundle://{bundle.id}"
    envelope = _envelope(bundle)

    validated = validate_harness_envelope(
        envelope,
        tenant_key=bundle.tenant_key,
        review_id=bundle.review_id,
        authorized_targets={target},
    )

    assert validated.contract_version == "threatgenix.harness.v1"
    assert validated.result.evidence_items[0].item_type == "code_context"


def test_harness_envelope_rejects_cross_tenant_execution():
    bundle = _bundle()

    with pytest.raises(ToolHarnessValidationError, match="tenant_key"):
        validate_harness_envelope(
            _envelope(bundle),
            tenant_key="user:other",
            review_id=bundle.review_id,
            authorized_targets={f"tgx-review-bundle://{bundle.id}"},
        )


def test_harness_envelope_rejects_unauthorized_target():
    bundle = _bundle()

    with pytest.raises(ToolHarnessValidationError, match="not authorized"):
        validate_harness_envelope(
            _envelope(bundle),
            tenant_key=bundle.tenant_key,
            review_id=bundle.review_id,
            authorized_targets={"tgx-review-bundle://different"},
        )


def test_harness_envelope_rejects_wrong_evidence_type_for_tool():
    bundle = _bundle()
    envelope = _envelope(
        bundle,
        request={
            "tool_name": "deterministic_decision_engine",
            "tool_version": "decision-1.0.0",
            "tenant_key": bundle.tenant_key,
            "review_id": bundle.review_id,
            "idempotency_key": "decision-key-1",
        },
    )

    with pytest.raises(ToolHarnessValidationError, match="cannot emit"):
        validate_harness_envelope(
            envelope,
            tenant_key=bundle.tenant_key,
            review_id=bundle.review_id,
        )


def test_harness_envelope_rejects_decision_promotion_fields():
    bundle = _bundle()
    envelope = _envelope(
        bundle,
        result={
            "status": "completed",
            "evidence_items": [
                {
                    "item_type": "code_context",
                    "title": "Context",
                    "source_refs": ["apps/api/users.py"],
                    "content_hash": "d" * 64,
                    "metadata": {"block_decision": True},
                }
            ],
            "normalized_findings": [],
        },
    )

    with pytest.raises(ToolHarnessValidationError, match="evidence-only"):
        validate_harness_envelope(
            envelope,
            tenant_key=bundle.tenant_key,
            review_id=bundle.review_id,
            authorized_targets={f"tgx-review-bundle://{bundle.id}"},
        )


def test_harness_timeout_result_requires_matching_timeout_event_and_duration():
    bundle = _bundle()

    with pytest.raises(ValidationError, match="matching result status"):
        _envelope(
            bundle,
            result={"status": "timeout", "evidence_items": [], "normalized_findings": []},
            events=[{"event_type": "started", "message": "started", "elapsed_ms": 0}],
            duration_ms=30_000,
        )

    with pytest.raises(ValidationError, match="duration"):
        _envelope(
            bundle,
            result={"status": "timeout", "evidence_items": [], "normalized_findings": []},
            events=[
                {"event_type": "started", "message": "started", "elapsed_ms": 0},
                {"event_type": "timeout", "message": "timed out", "elapsed_ms": 10_000},
            ],
            duration_ms=10_000,
        )


def test_harness_policy_requires_explicit_active_scanning_authorization():
    bundle = _bundle()

    with pytest.raises(ValidationError, match="external_active"):
        _envelope(
            bundle,
            request={
                "tool_name": "bundle_parser",
                "tool_version": "bundle-1.0.0",
                "tenant_key": bundle.tenant_key,
                "review_id": bundle.review_id,
                "idempotency_key": "bundle-key-1",
                "policy": {"network": "external_active"},
            },
        )


def test_malformed_harness_evidence_hash_is_rejected():
    bundle = _bundle()

    with pytest.raises(ValidationError, match="content_hash"):
        _envelope(
            bundle,
            result={
                "status": "completed",
                "evidence_items": [
                    {
                        "item_type": "code_context",
                        "title": "Context",
                        "source_refs": ["apps/api/users.py"],
                        "content_hash": "not-a-hash",
                    }
                ],
                "normalized_findings": [],
            },
        )


def test_harness_execution_key_is_stable_for_duplicate_execution():
    bundle = _bundle()
    first = _envelope(bundle).request
    second = _envelope(bundle).request
    changed = first.model_copy(update={"idempotency_key": "ctx-key-2"})

    assert stable_harness_execution_key(first) == stable_harness_execution_key(second)
    assert stable_harness_execution_key(first) != stable_harness_execution_key(changed)

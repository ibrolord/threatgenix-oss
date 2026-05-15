"""Scan worker: runs policy-gated validation tools and stores findings."""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import time as _monotonic_time
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models.scan import ScanCredential, ScanExecutionArtifact, ScanFinding, ScanJob
from app.services.validation_execution_policy import (
    NETWORK_NONE,
    TARGET_URL,
    ValidationExecutionPolicy,
    default_validation_execution_policy_registry,
    validation_tool_runtime_availability,
)
from app.services.validation_isolated_runner import (
    isolated_runner_can_handle,
    run_isolated_validation_tool,
)
from app.services.validation_sandbox import (
    create_validation_sandbox_runner,
    validation_sandbox_mode,
)
from app.services.target_safety import LiveTargetSafetyError, validate_live_url_target
from app.services.scan_target_authorization import (
    require_verified_nuclei_target_authorization,
)
from app.services.validation_target_bundles import (
    MaterializedValidationTarget,
    ValidationTargetBundleError,
    is_validation_target_bundle_ref,
    materialize_validation_target_ref,
)
from app.services.validation_runtime import (
    RUNTIME_MANAGED,
    validation_runtime_mode,
    validation_worker_execution_blocked_reason,
    validation_worker_execution_enabled,
)
from app.services.validation_runner_observability import (
    record_worker_heartbeat,
    validation_runner_id,
    validation_worker_lease_seconds,
    validation_worker_max_attempts,
)
from app.services.validation_tools import (
    NUCLEI_SEVERITY_MAP,
    NUCLEI_TAGS_AUTH_EXTRA,
    NUCLEI_TAGS_BASE,
    NUCLEI_TOOL_NAME,
    NUCLEI_TOTAL_TIMEOUT,
    NUCLEI_TIMEOUT_PER_TARGET as _VALIDATION_NUCLEI_TIMEOUT_PER_TARGET,
    NucleiValidationAdapter,
    ValidationToolAdapter,
    ValidationToolResult,
    ValidationToolUnavailable,
    default_validation_tool_registry,
    redact_validation_command,
    sanitize_validation_target_for_storage,
)

logger = logging.getLogger("threatgenix.scan_worker")

NUCLEI_TIMEOUT_PER_TARGET = _VALIDATION_NUCLEI_TIMEOUT_PER_TARGET

# Base tags used for all scans
_NUCLEI_TAGS_BASE = NUCLEI_TAGS_BASE
# Additional tags injected when scan_type="authenticated"
_NUCLEI_TAGS_AUTH_EXTRA = NUCLEI_TAGS_AUTH_EXTRA
_SEVERITY_MAP = NUCLEI_SEVERITY_MAP
_MAX_STDERR_SUMMARY_CHARS = 1_000


def _nuclei_available(adapter: ValidationToolAdapter | None = None) -> bool:
    adapter = adapter or default_validation_tool_registry().get(NUCLEI_TOOL_NAME)
    if validation_sandbox_mode() == "container":
        return validation_tool_runtime_availability(adapter).available
    return adapter.is_available()


def _validation_tool_runtime_available(adapter: ValidationToolAdapter) -> bool:
    if adapter.name == NUCLEI_TOOL_NAME and validation_sandbox_mode() != "container":
        return _nuclei_available(adapter)
    return validation_tool_runtime_availability(adapter).available


def _managed_process_network_blocked(policy: ValidationExecutionPolicy) -> bool:
    return (
        validation_runtime_mode() == RUNTIME_MANAGED
        and validation_sandbox_mode() != "container"
        and policy.network_mode != NETWORK_NONE
        and not isolated_runner_can_handle(policy.tool_name, policy)
    )


def _build_auth_headers(cred: ScanCredential) -> list[str]:
    """Return Nuclei -H flag pairs for the given credential.

    Never logs or returns the plaintext secret — only builds the CLI args.
    """
    from app.services.credential_crypto import decrypt_secret

    secret = decrypt_secret(cred.encrypted_secret)
    cred_type = cred.credential_type

    if cred_type == "bearer_token":
        return ["-H", f"Authorization: Bearer {secret}"]

    if cred_type == "api_key_header":
        header = cred.header_name or "X-API-Key"
        return ["-H", f"{header}: {secret}"]

    if cred_type == "basic_auth":
        # secret expected as "username:password"
        encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
        return ["-H", f"Authorization: Basic {encoded}"]

    if cred_type == "cookie":
        return ["-H", f"Cookie: {secret}"]

    logger.warning(
        "unknown_credential_type type=%s — skipping auth injection", cred_type
    )
    return []


async def run_scan_job(scan_job_id: UUID) -> None:
    """Entry point called by BackgroundTasks. Opens its own DB session."""
    async with async_session() as db:
        await _execute_scan(db, scan_job_id)


async def _execute_scan(db: AsyncSession, scan_job_id: UUID) -> None:
    # Load job
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
    job = result.scalar_one_or_none()
    if job is None:
        logger.error("scan_job_not_found id=%s", scan_job_id)
        return

    raw_tool_name = getattr(job, "tool_name", None)
    raw_target_type = getattr(job, "target_type", None)
    tool_name = (
        raw_tool_name
        if isinstance(raw_tool_name, str) and raw_tool_name
        else NUCLEI_TOOL_NAME
    )
    target_type = (
        raw_target_type
        if isinstance(raw_target_type, str) and raw_target_type
        else TARGET_URL
    )

    # Defense in depth: API endpoints and the scheduler already block hosted
    # SaaS runtimes, but a queued/stale job must not execute if the deployment
    # is later switched back to the safe hosted default.
    if job.status not in {"pending", "running"}:
        logger.info(
            "scan_job_not_claimable id=%s status=%s skipping", scan_job_id, job.status
        )
        return

    if not validation_worker_execution_enabled():
        job.status = "failed"
        job.failure_code = "runtime_blocked"
        job.error_message = validation_worker_execution_blocked_reason()
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.warning(
            "scan_worker_execution_blocked job=%s runtime_mode_disabled", scan_job_id
        )
        return

    try:
        validation_tool = default_validation_tool_registry().get(tool_name)
        validation_policy = default_validation_execution_policy_registry().get(
            tool_name
        )
    except KeyError:
        job.status = "failed"
        job.failure_code = "policy_denied"
        job.error_message = f"Unsupported validation tool: {tool_name}"
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.warning("scan_unsupported_tool job=%s tool=%s", scan_job_id, tool_name)
        return

    if target_type not in validation_policy.supported_targets:
        job.status = "failed"
        job.failure_code = "policy_denied"
        job.error_message = (
            f"{validation_tool.name} does not support target type {target_type}"
        )
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.warning(
            "scan_validation_policy_denied job=%s tool=%s reason=%s",
            scan_job_id,
            validation_tool.name,
            job.error_message,
        )
        return
    if not validation_policy.execution_enabled:
        job.status = "failed"
        job.failure_code = "policy_denied"
        job.error_message = f"{validation_tool.name} execution is disabled until sandbox enforcement is enabled"
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.warning(
            "scan_validation_policy_denied job=%s tool=%s reason=%s",
            scan_job_id,
            validation_tool.name,
            job.error_message,
        )
        return
    if _managed_process_network_blocked(validation_policy):
        job.status = "failed"
        job.failure_code = "policy_denied"
        job.error_message = (
            f"{validation_policy.network_mode} network policy requires an isolated "
            "network runner in managed mode."
        )
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.warning(
            "scan_validation_policy_denied job=%s tool=%s reason=%s",
            scan_job_id,
            validation_tool.name,
            job.error_message,
        )
        return

    # Check active tool availability after policy gates execution.
    if (
        validation_tool.name == NUCLEI_TOOL_NAME
        and not _validation_tool_runtime_available(validation_tool)
    ):
        runtime_availability = validation_tool_runtime_availability(validation_tool)
        job.status = "failed"
        job.failure_code = "tool_unavailable"
        job.error_message = (
            "Nuclei CLI not installed. Install from https://github.com/projectdiscovery/nuclei"
            if validation_sandbox_mode() != "container"
            else runtime_availability.detail
        )
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.warning("nuclei_not_installed scan_job_id=%s", scan_job_id)
        return
    if (
        validation_tool.name != NUCLEI_TOOL_NAME
        and not _validation_tool_runtime_available(validation_tool)
    ):
        runtime_availability = validation_tool_runtime_availability(validation_tool)
        job.status = "failed"
        job.failure_code = "tool_unavailable"
        job.error_message = runtime_availability.detail
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.warning(
            "validation_tool_not_installed scan_job_id=%s tool=%s",
            scan_job_id,
            validation_tool.name,
        )
        return

    if job.scan_type == "authenticated" and target_type != TARGET_URL:
        job.status = "failed"
        job.failure_code = "policy_denied"
        job.error_message = (
            "Authenticated validation scans are only supported for URL targets."
        )
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.warning(
            "scan_authenticated_unsupported_target job=%s tool=%s target_type=%s",
            scan_job_id,
            validation_tool.name,
            target_type,
        )
        return

    # S2: resolve auth headers once for the whole job (avoids repeated decryption)
    auth_headers: list[str] = []
    nuclei_tags = _NUCLEI_TAGS_BASE
    if job.scan_type == "authenticated":
        # Fail fast: ON DELETE SET NULL may have cleared credential_id after job was queued
        if job.credential_id is None:
            job.status = "failed"
            job.failure_code = "target_invalid"
            job.error_message = "Authenticated scan has no credential — credential may have been deleted after the scan was queued."
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            logger.warning("scan_authenticated_no_credential job=%s", scan_job_id)
            return

        # Constrained lookup: enforce ownership so a compromised job can't use another user's credential
        from app.services.scan_credential_service import get_credential_for_job

        credential = await get_credential_for_job(
            db, job.credential_id, job.owner_id, job.threat_model_id
        )
        if credential is None:
            job.status = "failed"
            job.failure_code = "target_invalid"
            job.error_message = (
                f"Credential {job.credential_id} not found or access denied."
            )
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            logger.warning(
                "scan_credential_missing job=%s cred=%s", scan_job_id, job.credential_id
            )
            return
        try:
            auth_headers = _build_auth_headers(credential)
        except Exception as exc:
            job.status = "failed"
            job.failure_code = "unexpected_error"
            job.error_message = (
                f"Credential decryption failed for credential {job.credential_id} "
                "— key rotation may be required."
            )
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            logger.error(
                "credential_decrypt_failed job=%s cred=%s error=%s",
                scan_job_id,
                job.credential_id,
                exc,
            )
            return
        nuclei_tags = f"{_NUCLEI_TAGS_BASE},{_NUCLEI_TAGS_AUTH_EXTRA}"
        logger.info(
            "scan_authenticated job=%s credential_type=%s",
            scan_job_id,
            credential.credential_type,
        )

    _extend_job_lease(job)
    job.status = "running"
    if job.started_at is None:
        job.started_at = datetime.now(timezone.utc)
    await db.commit()

    findings: list[ScanFinding] = []
    try:
        targets: dict = job.targets or {}
        if not targets:
            job.status = "failed"
            job.failure_code = "target_invalid"
            job.error_message = "No targets configured"
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return

        total_timeout = max(
            validation_policy.max_runtime_seconds,
            min(
                NUCLEI_TOTAL_TIMEOUT,
                validation_policy.max_runtime_seconds * max(1, len(targets)),
            ),
        )
        async with asyncio.timeout(total_timeout):
            for node_id, url in targets.items():
                # Re-check for external cancellation before each target
                await db.refresh(job)
                if job.status == "cancelled":
                    logger.info("scan_cancelled_mid_run job=%s", scan_job_id)
                    return
                _extend_job_lease(job)
                await db.commit()

                new_findings = await _scan_target(
                    db,
                    job.id,
                    url,
                    node_id,
                    threat_model_id=job.threat_model_id,
                    owner_id=job.owner_id,
                    auth_headers=auth_headers,
                    nuclei_tags=nuclei_tags,
                    tool=validation_tool,
                    target_type=target_type,
                    policy=validation_policy,
                )
                findings.extend(new_findings)
                _extend_job_lease(job)
                await db.commit()

        # Final cancellation check before marking complete
        await db.refresh(job)
        if job.status == "cancelled":
            logger.info("scan_cancelled_after_loop job=%s", scan_job_id)
            return

        # Run semantic mapping to link findings -> threats
        from app.services.scan_mapper import run_semantic_mapping

        await run_semantic_mapping(db, scan_job_id)

        job.status = "completed"
        job.finding_count = len(findings)
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        await _rebuild_evidence_projection_after_scan(db, job)
        logger.info("scan_completed job=%s findings=%d", scan_job_id, len(findings))

    except TimeoutError:
        job.status = "failed"
        job.failure_code = "sandbox_timeout"
        job.error_message = "Scan timed out before all targets completed"
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.warning("scan_timeout job=%s", scan_job_id)
    except ValidationToolUnavailable as exc:
        job.status = "failed"
        job.failure_code = "tool_unavailable"
        job.error_message = str(exc)
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.warning(
            "scan_validation_tool_unavailable job=%s error=%s", scan_job_id, exc
        )
    except Exception:
        job.status = "failed"
        job.failure_code = "unexpected_error"
        job.error_message = "Unexpected scan error — check server logs"
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.exception("scan_error job=%s", scan_job_id)


async def _scan_target(
    db: AsyncSession,
    scan_job_id: UUID,
    url: str,
    node_id: str,
    threat_model_id: UUID | None = None,
    owner_id: UUID | None = None,
    auth_headers: list[str] | None = None,
    nuclei_tags: str = _NUCLEI_TAGS_BASE,
    tool: ValidationToolAdapter | None = None,
    target_type: str = TARGET_URL,
    policy: ValidationExecutionPolicy | None = None,
) -> list[ScanFinding]:
    """Run a validation tool against one URL target.

    Returns list of ScanFinding objects (already committed).

    ``auth_headers`` is a flat list of ["-H", "Header: value"] pairs injected
    as additional CLI flags when the scan is authenticated.
    """
    del node_id
    validation_tool = tool or default_validation_tool_registry().get(NUCLEI_TOOL_NAME)
    validation_policy = policy or default_validation_execution_policy_registry().get(
        validation_tool.name
    )
    run_target = url
    artifact_target = url
    materialized: MaterializedValidationTarget | None = None
    if is_validation_target_bundle_ref(url):
        if threat_model_id is None or owner_id is None:
            raise ValidationToolUnavailable(
                "hosted validation target requires scan job tenant context"
            )
        try:
            materialized = await materialize_validation_target_ref(
                db,
                threat_model_id=threat_model_id,
                owner_id=owner_id,
                target_ref=url,
                target_type=target_type,
            )
        except ValidationTargetBundleError as exc:
            now = datetime.now(timezone.utc)
            db.add(
                _build_execution_artifact(
                    scan_job_id=scan_job_id,
                    tool=validation_tool,
                    target=url,
                    target_type=target_type,
                    policy=validation_policy,
                    policy_decision=str(exc),
                    status="blocked",
                    stderr_summary=str(exc),
                    started_at=now,
                    completed_at=now,
                )
            )
            raise ValidationToolUnavailable(str(exc)) from exc
        run_target = materialized.target
        artifact_target = materialized.display_target
    if target_type == TARGET_URL:
        try:
            validate_live_url_target(run_target)
        except LiveTargetSafetyError as exc:
            now = datetime.now(timezone.utc)
            db.add(
                _build_execution_artifact(
                    scan_job_id=scan_job_id,
                    tool=validation_tool,
                    target=artifact_target,
                    command_target=run_target,
                    target_type=target_type,
                    policy=validation_policy,
                    policy_decision=str(exc),
                    status="blocked",
                    started_at=now,
                    completed_at=now,
                )
            )
            raise ValidationToolUnavailable(str(exc)) from exc
    decision = validation_policy.evaluate(target_type, run_target)
    if not decision.allowed:
        now = datetime.now(timezone.utc)
        db.add(
            _build_execution_artifact(
                scan_job_id=scan_job_id,
                tool=validation_tool,
                target=artifact_target,
                command_target=run_target,
                target_type=target_type,
                policy=validation_policy,
                policy_decision=decision.reason,
                status="blocked",
                started_at=now,
                completed_at=now,
            )
        )
        raise ValidationToolUnavailable(decision.reason)
    if _managed_process_network_blocked(validation_policy):
        now = datetime.now(timezone.utc)
        reason = (
            f"{validation_policy.network_mode} network policy requires an isolated "
            "network runner in managed mode."
        )
        db.add(
            _build_execution_artifact(
                scan_job_id=scan_job_id,
                tool=validation_tool,
                target=artifact_target,
                command_target=run_target,
                target_type=target_type,
                policy=validation_policy,
                policy_decision=reason,
                status="blocked",
                started_at=now,
                completed_at=now,
            )
        )
        raise ValidationToolUnavailable(reason)
    use_isolated_runner = (
        validation_runtime_mode() == RUNTIME_MANAGED
        and validation_sandbox_mode() != "container"
        and validation_policy.network_mode != NETWORK_NONE
        and isolated_runner_can_handle(validation_tool.name, validation_policy)
    )

    started_at = datetime.now(timezone.utc)
    safe_target = (
        sanitize_validation_target_for_storage(artifact_target, target_type)
        or "[target-redacted]"
    )
    logger.info(
        "validation_tool_start tool=%s target=%s job=%s authenticated=%s",
        validation_tool.name,
        safe_target,
        scan_job_id,
        bool(auth_headers),
    )

    try:
        if use_isolated_runner:
            if validation_tool.name == NUCLEI_TOOL_NAME:
                await require_verified_nuclei_target_authorization(
                    db,
                    owner_id=owner_id,
                    threat_model_id=threat_model_id,
                    target=run_target,
                )
            result = await run_isolated_validation_tool(
                scan_job_id=scan_job_id,
                threat_model_id=threat_model_id,
                owner_id=owner_id,
                tool=validation_tool,
                target=run_target,
                target_type=target_type,
                policy=validation_policy,
                auth_headers=auth_headers,
                template_tags=nuclei_tags if validation_tool.name == NUCLEI_TOOL_NAME else None,
                target_authorization_checked=validation_tool.name == NUCLEI_TOOL_NAME,
            )
        else:
            run_kwargs: dict[str, Any] = {"auth_headers": auth_headers}
            if validation_tool.name == NUCLEI_TOOL_NAME:
                run_kwargs["template_tags"] = nuclei_tags
                run_kwargs.update(
                    {
                        "target_type": target_type,
                        "policy": validation_policy,
                    }
                )
                if validation_sandbox_mode() == "container":
                    run_kwargs.update(
                        {
                            "sandbox_runner": create_validation_sandbox_runner(
                                network_mode=validation_policy.network_mode
                            ),
                        }
                    )
            else:
                run_kwargs.update(
                    {
                        "target_type": target_type,
                        "policy": validation_policy,
                    }
                )
                if validation_policy.runs_in_sandbox_required:
                    run_kwargs["sandbox_runner"] = create_validation_sandbox_runner(
                        network_mode=validation_policy.network_mode
                    )
            result = await validation_tool.run(run_target, **run_kwargs)
        completed_at = datetime.now(timezone.utc)
        db.add(
            _build_execution_artifact(
                scan_job_id=scan_job_id,
                tool=validation_tool,
                target=artifact_target,
                command_target=run_target,
                target_type=target_type,
                policy=validation_policy,
                policy_decision=decision.reason,
                result=result,
                started_at=started_at,
                completed_at=completed_at,
            )
        )

        if result.timed_out:
            logger.warning(
                "%s_target_timeout target=%s", validation_tool.name, safe_target
            )
            return []

        if result.returncode != 0:
            logger.warning(
                "%s_nonzero_exit target=%s rc=%d stderr=%s",
                validation_tool.name,
                safe_target,
                result.returncode,
                _summarize_stderr(result.stderr),
            )
            return []

        findings = []
        for evidence in result.findings:
            finding = evidence.to_scan_finding(
                scan_job_id,
                target_type=target_type,
                evidence_origin="execution",
                synthetic=False,
            )
            db.add(finding)
            findings.append(finding)

        try:
            await db.commit()
        except Exception as db_exc:
            await db.rollback()
            logger.warning(
                "%s_db_commit_failed target=%s error=%s",
                validation_tool.name,
                safe_target,
                db_exc,
            )
            raise

        logger.info(
            "validation_tool_done tool=%s target=%s findings=%d",
            validation_tool.name,
            safe_target,
            len(findings),
        )
        return findings

    except ValidationToolUnavailable as exc:
        completed_at = datetime.now(timezone.utc)
        db.add(
            _build_execution_artifact(
                scan_job_id=scan_job_id,
                tool=validation_tool,
                target=artifact_target,
                command_target=run_target,
                target_type=target_type,
                policy=validation_policy,
                policy_decision=str(exc),
                status="blocked",
                stderr_summary=str(exc),
                started_at=started_at,
                completed_at=completed_at,
            )
        )
        raise
    except Exception as exc:
        completed_at = datetime.now(timezone.utc)
        db.add(
            _build_execution_artifact(
                scan_job_id=scan_job_id,
                tool=validation_tool,
                target=artifact_target,
                command_target=run_target,
                target_type=target_type,
                policy=validation_policy,
                policy_decision=decision.reason,
                status="failed",
                stderr_summary=str(exc),
                started_at=started_at,
                completed_at=completed_at,
            )
        )
        logger.warning(
            "%s_target_error target=%s error=%s",
            validation_tool.name,
            safe_target,
            exc,
        )
        raise
    finally:
        if materialized is not None:
            materialized.cleanup()


def _build_execution_artifact(
    *,
    scan_job_id: UUID,
    tool: ValidationToolAdapter,
    target: str,
    target_type: str,
    policy: ValidationExecutionPolicy,
    policy_decision: str,
    command_target: str | None = None,
    result: ValidationToolResult | None = None,
    status: str | None = None,
    stderr_summary: str | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> ScanExecutionArtifact:
    if result is not None:
        status = _status_from_validation_result(result)
    resolved_target = (
        sanitize_validation_target_for_storage(result.resolved_target, target_type)
        if result is not None
        else None
    )
    command = (
        redact_validation_command(
            result.command,
            target=command_target or target,
            resolved_target=resolved_target,
            target_type=target_type,
        )
        if result is not None
        else []
    )
    returncode = result.returncode if result is not None else None
    timed_out = result.timed_out if result is not None else False
    output_limit_exceeded = (
        result.output_limit_exceeded if result is not None else False
    )
    stdout_bytes = result.stdout_bytes if result is not None else 0
    output_sha256 = result.output_sha256 if result is not None else None
    stderr = (
        stderr_summary
        if stderr_summary is not None
        else (result.stderr if result is not None else None)
    )
    sandboxed = (
        bool(result.sandboxed)
        if result is not None
        else policy.runs_in_sandbox_required
    )
    sandbox_mode = (
        getattr(result, "sandbox_mode", None)
        if result is not None
        else ("process" if policy.runs_in_sandbox_required else None)
    )
    container_image = (
        getattr(result, "container_image", None) if result is not None else None
    )
    resource_limits = (
        getattr(result, "resource_limits", None) if result is not None else {}
    )

    stored_target = (
        target
        if command_target is not None
        else sanitize_validation_target_for_storage(target, target_type) or target
    )

    return ScanExecutionArtifact(
        scan_job_id=scan_job_id,
        source="execution",
        tool_name=tool.name,
        target_type=target_type,
        target=stored_target,
        resolved_target=resolved_target,
        status=status or "completed",
        deterministic=tool.deterministic,
        sandboxed=sandboxed,
        sandbox_mode=sandbox_mode,
        container_image=container_image,
        resource_limits=resource_limits or {},
        policy_decision=policy_decision,
        command=command,
        command_redacted=True,
        returncode=returncode,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        stdout_bytes=stdout_bytes,
        output_sha256=output_sha256,
        stderr_summary=_summarize_stderr(stderr),
        network_mode=policy.network_mode,
        max_runtime_seconds=policy.max_runtime_seconds,
        max_output_bytes=policy.max_output_bytes,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=_duration_ms(started_at, completed_at),
    )


def _extend_job_lease(job: ScanJob) -> None:
    now = datetime.now(timezone.utc)
    if not getattr(job, "runner_id", None):
        job.runner_id = validation_runner_id()
    job.heartbeat_at = now
    job.lease_expires_at = now + timedelta(seconds=validation_worker_lease_seconds())
    if not getattr(job, "max_attempts", None):
        job.max_attempts = validation_worker_max_attempts()


def _status_from_validation_result(result: ValidationToolResult) -> str:
    if result.timed_out:
        return "timed_out"
    if result.output_limit_exceeded:
        return "failed"
    if result.returncode != 0:
        return "failed"
    return "completed"


def _duration_ms(
    started_at: datetime | None, completed_at: datetime | None
) -> int | None:
    if started_at is None or completed_at is None:
        return None
    return max(0, int((completed_at - started_at).total_seconds() * 1000))


def _summarize_stderr(stderr: str | None) -> str | None:
    if not stderr:
        return None
    normalized = " ".join(str(stderr).split())
    normalized = re.sub(
        r"(?i)(authorization:\s*)(bearer\s+)?[^\s]+",
        r"\1[redacted]",
        normalized,
    )
    normalized = re.sub(
        r"(?i)((?:token|password|secret|api[_-]?key)=)[^\s]+",
        r"\1[redacted]",
        normalized,
    )
    normalized = re.sub(
        r"(?i)(/Users|/private|/var|/tmp|/home)/[^\s]+",
        "[local-path-redacted]",
        normalized,
    )
    if len(normalized) <= _MAX_STDERR_SUMMARY_CHARS:
        return normalized
    return normalized[: _MAX_STDERR_SUMMARY_CHARS - 3] + "..."


def _parse_nuclei_finding(scan_job_id: UUID, data: dict) -> ScanFinding | None:
    """Parse one line of Nuclei JSONL output into a ScanFinding."""
    evidence = NucleiValidationAdapter().parse_json_line("unknown", data)
    if evidence is None:
        return None
    return evidence.to_scan_finding(scan_job_id, include_validation_metadata=False)


async def _rebuild_evidence_projection_after_scan(
    db: AsyncSession, job: ScanJob
) -> None:
    """Best-effort evidence graph projection after a scan finishes."""
    from app.models.threat_model import ThreatModel
    from app.services.evidence_projection import rebuild_evidence_graph

    job_id = job.id
    threat_model_id = job.threat_model_id
    result = await db.execute(
        select(ThreatModel).where(ThreatModel.id == threat_model_id)
    )
    threat_model = result.scalar_one_or_none()
    if threat_model is None:
        logger.warning(
            "scan_evidence_projection_missing_model job=%s threat_model=%s",
            job_id,
            threat_model_id,
        )
        return

    try:
        status = await rebuild_evidence_graph(db, threat_model)
        await db.commit()
        logger.info(
            "scan_evidence_projection_rebuilt job=%s threat_model=%s findings=%d sources=%d",
            job_id,
            threat_model_id,
            status.finding_count,
            status.source_count,
        )
    except Exception:
        await db.rollback()
        logger.exception(
            "scan_evidence_projection_failed job=%s threat_model=%s",
            job_id,
            threat_model_id,
        )


# ---------------------------------------------------------------------------
# Managed runner: polling loop
# ---------------------------------------------------------------------------


async def _claim_next_pending_job(runner_id: str | None = None) -> UUID | None:
    """Atomically claim one pending ScanJob by transitioning it to running.

    Uses SELECT FOR UPDATE SKIP LOCKED so multiple worker replicas never
    double-execute the same job.  Returns the job UUID or None when the queue
    is empty.
    """
    runner_id = runner_id or validation_runner_id()
    async with async_session() as db:
        async with db.begin():
            result = await db.execute(
                select(ScanJob)
                .where(
                    ScanJob.status == "pending",
                    ScanJob.attempt_count < ScanJob.max_attempts,
                )
                .order_by(ScanJob.created_at)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            job = result.scalar_one_or_none()
            if job is None:
                return None
            job_id = job.id
            now = datetime.now(timezone.utc)
            job.status = "running"
            job.runner_id = runner_id
            job.claimed_at = now
            job.started_at = now
            job.heartbeat_at = now
            job.max_attempts = job.max_attempts or validation_worker_max_attempts()
            job.attempt_count = (job.attempt_count or 0) + 1
            job.lease_expires_at = now + timedelta(
                seconds=validation_worker_lease_seconds()
            )
        # Transaction committed; lock released with ownership transferred
        return job_id


_STUCK_JOB_TIMEOUT_SECONDS = int(
    os.environ.get("VALIDATION_WORKER_STUCK_JOB_TIMEOUT", "1800")  # 30 min default
)


async def _reap_stuck_jobs() -> int:
    """Reset or fail jobs whose runner lease has expired.

    This handles the case where a worker process is killed hard (SIGKILL/OOM)
    after claiming a job but before it completes.  Only runs on the worker side.

    Returns the number of jobs reset.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=_STUCK_JOB_TIMEOUT_SECONDS)
    now = datetime.now(timezone.utc)
    async with async_session() as db:
        result = await db.execute(
            select(ScanJob)
            .where(
                ScanJob.status == "running",
                (
                    (
                        ScanJob.lease_expires_at.is_not(None)
                        & (ScanJob.lease_expires_at < now)
                    )
                    | (
                        ScanJob.lease_expires_at.is_(None)
                        & (ScanJob.started_at < cutoff)
                    )
                ),
            )
            .order_by(ScanJob.started_at.asc())
            .limit(25)
        )
        jobs = list(result.scalars().all())
        for job in jobs:
            max_attempts = job.max_attempts or validation_worker_max_attempts()
            if (job.attempt_count or 0) >= max_attempts:
                job.status = "failed"
                job.failure_code = "worker_lost"
                job.error_message = "Managed validation worker lease expired after maximum retry attempts."
                job.completed_at = now
            else:
                job.status = "pending"
                job.failure_code = "worker_lost"
                job.runner_id = None
                job.claimed_at = None
                job.started_at = None
                job.heartbeat_at = None
                job.lease_expires_at = None
                job.error_message = (
                    "Reset by worker after expired runner lease; will retry."
                )
        await db.commit()
    if jobs:
        logger.warning(
            "validation_worker_reaped_stuck_jobs count=%d ids=%s",
            len(jobs),
            [str(job.id) for job in jobs],
        )
    return len(jobs)


async def run_polling_loop(
    poll_interval_seconds: float = 5.0,
    idle_backoff_max: float = 30.0,
    reap_interval_seconds: float = 300.0,
    heartbeat_interval_seconds: float = 10.0,
) -> None:
    """Long-running job poller for the managed validation runner service.

    Designed to be the asyncio main loop of the worker container.  Responds
    to SIGTERM / SIGINT for graceful shutdown (finishes the current job before
    exiting).

    Also runs a periodic stuck-job reaper so jobs left in 'running' by a
    previously crashed worker are automatically retried.
    """
    import signal

    shutdown = asyncio.Event()

    def _handle_signal(signum: int, frame: object) -> None:  # noqa: ARG001
        logger.info("validation_worker_shutdown_requested signal=%d", signum)
        shutdown.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    idle_wait = poll_interval_seconds
    last_reap = _monotonic_time.monotonic() - reap_interval_seconds
    runner_id = validation_runner_id()
    logger.info(
        "validation_worker_started runner_id=%s poll_interval=%.1fs idle_backoff_max=%.1fs reap_interval=%.1fs heartbeat_interval=%.1fs",
        runner_id,
        poll_interval_seconds,
        idle_backoff_max,
        reap_interval_seconds,
        heartbeat_interval_seconds,
    )

    while not shutdown.is_set():
        await _record_runner_heartbeat(runner_id, status="idle")
        # Periodically reap stuck jobs from previously crashed workers
        now = _monotonic_time.monotonic()
        if now - last_reap >= reap_interval_seconds:
            try:
                await _reap_stuck_jobs()
            except Exception:
                logger.exception("validation_worker_reap_error")
            last_reap = now

        job_id = await _claim_next_pending_job(runner_id)

        if job_id is not None:
            idle_wait = poll_interval_seconds  # reset backoff whenever work is found
            logger.info("validation_worker_claimed_job job=%s", job_id)
            await _record_runner_heartbeat(
                runner_id,
                status="running",
                current_scan_job_id=job_id,
            )
            heartbeat_task = asyncio.create_task(
                _heartbeat_until_cancelled(
                    runner_id,
                    status="running",
                    current_scan_job_id=job_id,
                    interval_seconds=heartbeat_interval_seconds,
                )
            )
            try:
                await run_scan_job(job_id)
            except Exception:
                logger.exception("validation_worker_job_error job=%s", job_id)
            finally:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass
                await _record_runner_heartbeat(runner_id, status="idle")
        else:
            orchestration_task_id = None
            try:
                from app.services.orchestration_worker import (
                    run_one_pending_orchestration_task,
                )

                orchestration_task_id = await run_one_pending_orchestration_task()
            except Exception:
                logger.exception("validation_worker_orchestration_task_error")

            if orchestration_task_id is not None:
                idle_wait = poll_interval_seconds
                logger.info(
                    "validation_worker_claimed_orchestration_task task=%s",
                    orchestration_task_id,
                )
                continue

            # Exponential backoff while idle; cap at idle_backoff_max
            idle_wait = min(idle_wait * 1.5, idle_backoff_max)
            logger.debug("validation_worker_idle next_poll_in=%.1fs", idle_wait)
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=idle_wait)
            except asyncio.TimeoutError:
                pass  # normal wakeup — check queue again

    await _record_runner_heartbeat(runner_id, status="stopping")
    logger.info("validation_worker_stopped runner_id=%s", runner_id)


async def _record_runner_heartbeat(
    runner_id: str,
    *,
    status: str,
    current_scan_job_id: UUID | None = None,
) -> None:
    try:
        async with async_session() as db:
            await record_worker_heartbeat(
                db,
                runner_id=runner_id,
                status=status,
                current_scan_job_id=current_scan_job_id,
            )
            if current_scan_job_id is not None:
                result = await db.execute(
                    select(ScanJob).where(
                        ScanJob.id == current_scan_job_id,
                        ScanJob.status == "running",
                    )
                )
                job = result.scalar_one_or_none()
                if job is not None:
                    job.runner_id = runner_id
                    _extend_job_lease(job)
            await db.commit()
    except Exception:
        logger.exception("validation_worker_heartbeat_error runner_id=%s", runner_id)


async def _heartbeat_until_cancelled(
    runner_id: str,
    *,
    status: str,
    current_scan_job_id: UUID | None,
    interval_seconds: float,
) -> None:
    while True:
        await asyncio.sleep(max(1.0, interval_seconds))
        await _record_runner_heartbeat(
            runner_id,
            status=status,
            current_scan_job_id=current_scan_job_id,
        )

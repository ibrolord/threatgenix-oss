"""Import tenant-scoped validation evidence artifact bundles."""

from __future__ import annotations

import hashlib
import json
import os
import tarfile
import zipfile
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from io import BytesIO
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.dfd import DFDNode
from app.models.scan import (
    ScanExecutionArtifact,
    ScanJob,
    ValidationArtifactBundle,
    ValidationArtifactBundleItem,
)
from app.models.threat_model import ThreatModel
from app.models.user import User
from app.schemas.scan import ScanJobDetailResponse
from app.services.scan_mapper import run_semantic_mapping
from app.services.validation_artifact_contract import (
    LEGACY_VALIDATION_MANIFEST_NAME,
    SEMANTIC_REVIEW_VALIDATION_MANIFEST_NAME,
    VALIDATION_MANIFEST_NAMES,
)
from app.services.validation_binding import infer_validation_targets_for_findings
from app.services.validation_execution_policy import (
    TARGET_URL,
    default_evidence_ingest_policy_registry,
)
from app.services.validation_tools import (
    EVIDENCE_IMPORT_TOOL_NAMES,
    default_evidence_import_tool_registry,
    sanitize_validation_target_for_storage,
)

INGESTED_TARGET_KEY = "ingested"
_BUNDLE_MAX_BYTES = int(os.getenv("VALIDATION_ARTIFACT_BUNDLE_MAX_BYTES", "15000000"))
_BUNDLE_MAX_ITEMS = int(os.getenv("VALIDATION_ARTIFACT_BUNDLE_MAX_ITEMS", "20"))
_MANIFEST_NAMES = VALIDATION_MANIFEST_NAMES


@dataclass(frozen=True)
class ValidationArtifactInput:
    tool_name: str
    target_type: str
    target: str
    raw_output: bytes
    source_path: str
    target_node_id: UUID | None = None


def validation_artifact_bundle_size_limit() -> int:
    return _BUNDLE_MAX_BYTES


def build_single_validation_artifact_input(
    *,
    tool_name: str,
    target_type: str,
    target: str,
    raw_output: bytes,
    filename: str,
    target_node_id: UUID | None = None,
) -> ValidationArtifactInput:
    return ValidationArtifactInput(
        tool_name=tool_name.strip(),
        target_type=target_type.strip(),
        target=target.strip(),
        raw_output=raw_output,
        source_path=_safe_display_path(filename),
        target_node_id=target_node_id,
    )


def parse_validation_artifact_bundle_upload(
    content: bytes,
    filename: str,
) -> tuple[list[ValidationArtifactInput], dict[str, Any]]:
    """Parse a multi-artifact zip/tar or JSON manifest upload.

    The manifest format is intentionally simple:
    ``{"items": [{"path": "semgrep.json", "tool_name": "semgrep", ...}]}``.
    A JSON upload may also include ``raw_output`` inline for each item.
    """
    if _is_archive_name(filename):
        return _parse_archive_bundle(content, filename)
    try:
        document = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                "Artifact bundles require a manifest. Upload a zip/tar bundle "
                f"with {SEMANTIC_REVIEW_VALIDATION_MANIFEST_NAME} or "
                f"{LEGACY_VALIDATION_MANIFEST_NAME}, or provide tool "
                "metadata for a single evidence file."
            ),
        ) from exc
    return _parse_inline_manifest(document, filename)


async def import_validation_artifact_bundle(
    db: AsyncSession,
    *,
    threat_model: ThreatModel,
    current_user: User,
    filename: str,
    content_type: str | None,
    content: bytes,
    inputs: list[ValidationArtifactInput],
    manifest: dict[str, Any],
) -> tuple[ValidationArtifactBundle, list[ScanJobDetailResponse]]:
    if not content:
        raise HTTPException(
            status_code=422, detail="Validation artifact upload is empty."
        )
    if len(content) > validation_artifact_bundle_size_limit():
        raise HTTPException(
            status_code=413,
            detail=(
                "Validation artifact bundle is too large. "
                f"Limit is {validation_artifact_bundle_size_limit()} bytes."
            ),
        )
    if not inputs:
        raise HTTPException(
            status_code=422,
            detail="Validation artifact bundle contains no evidence items.",
        )
    if len(inputs) > _BUNDLE_MAX_ITEMS:
        raise HTTPException(
            status_code=413,
            detail=f"Validation artifact bundle has too many items. Limit is {_BUNDLE_MAX_ITEMS}.",
        )

    bundle = ValidationArtifactBundle(
        threat_model_id=threat_model.id,
        owner_id=current_user.id,
        organization_id=getattr(threat_model, "organization_id", None),
        filename=_safe_display_path(filename),
        content_type=content_type,
        byte_size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        status="imported",
        manifest=_manifest_summary(manifest),
        storage_backend="metadata_only",
        item_count=len(inputs),
    )
    db.add(bundle)
    await db.flush()

    created_scan_ids: list[UUID] = []
    for item in inputs:
        scan_job = await _import_bundle_item(
            db,
            threat_model_id=threat_model.id,
            owner_id=current_user.id,
            bundle_id=bundle.id,
            item=item,
        )
        created_scan_ids.append(scan_job.id)

    await db.commit()

    result = await db.execute(
        select(ValidationArtifactBundle)
        .where(ValidationArtifactBundle.id == bundle.id)
        .options(selectinload(ValidationArtifactBundle.items))
    )
    created_bundle = result.scalar_one()

    scan_details: list[ScanJobDetailResponse] = []
    for scan_id in created_scan_ids:
        scan_result = await db.execute(
            select(ScanJob)
            .where(ScanJob.id == scan_id)
            .options(
                selectinload(ScanJob.findings),
                selectinload(ScanJob.threat_results),
                selectinload(ScanJob.execution_artifacts),
            )
        )
        scan_details.append(
            ScanJobDetailResponse.model_validate(scan_result.scalar_one())
        )
    return created_bundle, scan_details


async def _import_bundle_item(
    db: AsyncSession,
    *,
    threat_model_id: UUID,
    owner_id: UUID,
    bundle_id: UUID,
    item: ValidationArtifactInput,
) -> ScanJob:
    adapter = _get_import_adapter_or_422(item.tool_name)
    policy = _get_import_policy_or_422(item.tool_name)
    decision = policy.evaluate_parse_only(item.target_type, item.target)
    if not decision.allowed:
        raise HTTPException(status_code=422, detail=decision.reason)
    if len(item.raw_output) > policy.max_output_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"{item.tool_name} evidence exceeds max_output_bytes="
                f"{policy.max_output_bytes}"
            ),
        )

    parsed_findings = adapter.parse_output(item.target, item.raw_output)
    targets = await _resolve_targets(
        db,
        threat_model_id=threat_model_id,
        tool_name=item.tool_name,
        target_type=item.target_type,
        target=item.target,
        target_node_id=item.target_node_id,
        parsed_findings=parsed_findings,
    )
    now = datetime.now(timezone.utc)
    scan_job = ScanJob(
        threat_model_id=threat_model_id,
        owner_id=owner_id,
        status="completed",
        scan_type="unauthenticated",
        scope="external",
        tool_name=item.tool_name,
        target_type=item.target_type,
        targets=targets,
        nuclei_templates=[],
        started_at=now,
        completed_at=now,
        finding_count=len(parsed_findings),
    )
    db.add(scan_job)
    await db.flush()

    for evidence in parsed_findings:
        db.add(
            evidence.to_scan_finding(
                scan_job.id,
                target_type=item.target_type,
                evidence_origin="artifact_bundle",
                synthetic=False,
            )
        )

    execution_artifact = ScanExecutionArtifact(
        scan_job_id=scan_job.id,
        source="ingest",
        tool_name=item.tool_name,
        target_type=item.target_type,
        target=sanitize_validation_target_for_storage(item.target, item.target_type)
        or item.target,
        resolved_target=sanitize_validation_target_for_storage(
            item.target, item.target_type
        ),
        status="completed",
        deterministic=adapter.deterministic,
        sandboxed=False,
        sandbox_mode=None,
        container_image=None,
        resource_limits={},
        policy_decision=decision.reason,
        command=[],
        command_redacted=True,
        returncode=0,
        timed_out=False,
        output_limit_exceeded=False,
        stdout_bytes=len(item.raw_output),
        output_sha256=hashlib.sha256(item.raw_output).hexdigest(),
        stderr_summary=None,
        network_mode=policy.network_mode,
        max_runtime_seconds=None,
        max_output_bytes=policy.max_output_bytes,
        started_at=now,
        completed_at=now,
        duration_ms=0,
    )
    db.add(execution_artifact)
    await db.flush()

    db.add(
        ValidationArtifactBundleItem(
            bundle_id=bundle_id,
            scan_job_id=scan_job.id,
            scan_execution_artifact_id=execution_artifact.id,
            tool_name=item.tool_name,
            target_type=item.target_type,
            target=sanitize_validation_target_for_storage(item.target, item.target_type)
            or item.target,
            target_node_id=item.target_node_id,
            source_path=item.source_path,
            raw_output_sha256=hashlib.sha256(item.raw_output).hexdigest(),
            raw_output_bytes=len(item.raw_output),
            status="imported",
            finding_count=len(parsed_findings),
        )
    )
    await db.flush()
    await run_semantic_mapping(db, scan_job.id)
    return scan_job


async def _resolve_targets(
    db: AsyncSession,
    *,
    threat_model_id: UUID,
    tool_name: str,
    target_type: str,
    target: str,
    target_node_id: UUID | None,
    parsed_findings: list[Any],
) -> dict[str, str]:
    if target_node_id is not None:
        node_result = await db.execute(
            select(DFDNode).where(
                DFDNode.id == target_node_id,
                DFDNode.threat_model_id == threat_model_id,
            )
        )
        node = node_result.scalar_one_or_none()
        if node is None:
            raise HTTPException(
                status_code=422,
                detail="target_node_id does not belong to this threat model",
            )
        if tool_name in EVIDENCE_IMPORT_TOOL_NAMES:
            for index, evidence in enumerate(parsed_findings):
                parsed_findings[index] = replace(evidence, matched_url=target)
        return {str(node.id): target}

    if target_type == TARGET_URL:
        node_result = await db.execute(
            select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
        )
        url_targets: dict[str, str] = {}
        for node in node_result.scalars().all():
            configured_target = (node.scan_target_url or "").strip()
            if configured_target and (
                _scan_target_matches(target, configured_target)
                or _scan_target_matches(configured_target, target)
            ):
                url_targets[str(node.id)] = configured_target
        if url_targets:
            return url_targets

    node_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
    )
    inferred = infer_validation_targets_for_findings(
        node_result.scalars().all(),
        parsed_findings,
        target_type=target_type,
    )
    return inferred or {INGESTED_TARGET_KEY: target}


def _parse_archive_bundle(
    content: bytes,
    filename: str,
) -> tuple[list[ValidationArtifactInput], dict[str, Any]]:
    members = _read_archive_members(content, filename)
    manifest_path = next((path for path in members if path in _MANIFEST_NAMES), None)
    if manifest_path is None:
        raise HTTPException(
            status_code=422,
            detail=(
                "Validation artifact archive is missing "
                f"{SEMANTIC_REVIEW_VALIDATION_MANIFEST_NAME} or "
                f"{LEGACY_VALIDATION_MANIFEST_NAME}."
            ),
        )
    try:
        manifest = json.loads(members[manifest_path].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=422, detail="Validation artifact manifest is invalid JSON."
        ) from exc
    inputs = _inputs_from_manifest(manifest, filename, members)
    return inputs, manifest


def _parse_inline_manifest(
    document: Any,
    filename: str,
) -> tuple[list[ValidationArtifactInput], dict[str, Any]]:
    if not isinstance(document, dict):
        raise HTTPException(
            status_code=422,
            detail="Validation artifact manifest must be a JSON object.",
        )
    inputs = _inputs_from_manifest(document, filename, {})
    return inputs, document


def _inputs_from_manifest(
    manifest: dict[str, Any],
    filename: str,
    members: dict[str, bytes],
) -> list[ValidationArtifactInput]:
    raw_items = manifest.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise HTTPException(
            status_code=422,
            detail="Validation artifact manifest requires a non-empty items array.",
        )
    inputs: list[ValidationArtifactInput] = []
    seen_paths: set[str] = set()
    for index, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, dict):
            raise HTTPException(
                status_code=422, detail=f"Manifest item {index + 1} must be an object."
            )
        source_path = _safe_display_path(
            str(raw_item.get("path") or raw_item.get("source_path") or filename)
        )
        if source_path in seen_paths:
            raise HTTPException(
                status_code=422,
                detail=f"Duplicate artifact path in manifest: {source_path}",
            )
        seen_paths.add(source_path)
        raw_output = raw_item.get("raw_output")
        if raw_output is None:
            if source_path not in members:
                raise HTTPException(
                    status_code=422,
                    detail=f"Manifest path not found in bundle: {source_path}",
                )
            raw_bytes = members[source_path]
        elif isinstance(raw_output, str):
            raw_bytes = raw_output.encode("utf-8")
        else:
            raw_bytes = json.dumps(raw_output, separators=(",", ":")).encode("utf-8")
        target_node_raw = raw_item.get("target_node_id")
        try:
            target_node_id = UUID(str(target_node_raw)) if target_node_raw else None
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail=f"Invalid target_node_id in {source_path}."
            ) from exc
        inputs.append(
            ValidationArtifactInput(
                tool_name=str(raw_item.get("tool_name") or "").strip(),
                target_type=str(raw_item.get("target_type") or "").strip(),
                target=str(raw_item.get("target") or "").strip(),
                target_node_id=target_node_id,
                raw_output=raw_bytes,
                source_path=source_path,
            )
        )
    return inputs


def _read_archive_members(content: bytes, filename: str) -> dict[str, bytes]:
    if zipfile.is_zipfile(BytesIO(content)):
        return _read_zip_members(content)
    try:
        return _read_tar_members(content)
    except tarfile.TarError as exc:
        raise HTTPException(
            status_code=422, detail=f"{filename} is not a supported zip or tar archive."
        ) from exc


def _read_zip_members(content: bytes) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    total_bytes = 0
    with zipfile.ZipFile(BytesIO(content)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if len(members) >= _BUNDLE_MAX_ITEMS + len(_MANIFEST_NAMES):
                raise HTTPException(
                    status_code=413,
                    detail="Validation artifact archive has too many files.",
                )
            safe_name = _validate_archive_name(info.filename)
            if safe_name is None:
                raise HTTPException(
                    status_code=422, detail=f"Unsafe archive path: {info.filename}"
                )
            if safe_name in members:
                raise HTTPException(
                    status_code=422, detail=f"Duplicate archive path: {safe_name}"
                )
            if info.file_size > _BUNDLE_MAX_BYTES:
                raise HTTPException(
                    status_code=413, detail=f"Archive member is too large: {safe_name}"
                )
            with archive.open(info) as handle:
                members[safe_name] = handle.read(_BUNDLE_MAX_BYTES + 1)
            if len(members[safe_name]) > _BUNDLE_MAX_BYTES:
                raise HTTPException(
                    status_code=413, detail=f"Archive member is too large: {safe_name}"
                )
            total_bytes += len(members[safe_name])
            if total_bytes > _BUNDLE_MAX_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Validation artifact archive is too large after decompression.",
                )
    return members


def _read_tar_members(content: bytes) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    total_bytes = 0
    with tarfile.open(fileobj=BytesIO(content), mode="r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            if len(members) >= _BUNDLE_MAX_ITEMS + len(_MANIFEST_NAMES):
                raise HTTPException(
                    status_code=413,
                    detail="Validation artifact archive has too many files.",
                )
            safe_name = _validate_archive_name(member.name)
            if safe_name is None:
                raise HTTPException(
                    status_code=422, detail=f"Unsafe archive path: {member.name}"
                )
            if safe_name in members:
                raise HTTPException(
                    status_code=422, detail=f"Duplicate archive path: {safe_name}"
                )
            if member.size > _BUNDLE_MAX_BYTES:
                raise HTTPException(
                    status_code=413, detail=f"Archive member is too large: {safe_name}"
                )
            handle = archive.extractfile(member)
            if handle is None:
                continue
            members[safe_name] = handle.read(_BUNDLE_MAX_BYTES + 1)
            if len(members[safe_name]) > _BUNDLE_MAX_BYTES:
                raise HTTPException(
                    status_code=413, detail=f"Archive member is too large: {safe_name}"
                )
            total_bytes += len(members[safe_name])
            if total_bytes > _BUNDLE_MAX_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Validation artifact archive is too large after decompression.",
                )
    return members


def _validate_archive_name(name: str) -> str | None:
    normalized = name.replace("\\", "/").strip()
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        return None
    if ":" in path.parts[0]:
        return None
    return str(path)


def _safe_display_path(name: str) -> str:
    safe = _validate_archive_name(name)
    if safe is not None:
        return safe[:500]
    leaf = name.replace("\\", "/").rstrip("/").split("/")[-1].strip()
    return (leaf or "artifact")[:500]


def _manifest_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    items = manifest.get("items")
    if not isinstance(items, list):
        return {}
    return {
        "item_count": len(items),
        "items": [
            {
                "tool_name": str(item.get("tool_name") or ""),
                "target_type": str(item.get("target_type") or ""),
                "target": sanitize_validation_target_for_storage(
                    str(item.get("target") or ""),
                    str(item.get("target_type") or ""),
                )
                or str(item.get("target") or ""),
                "path": _safe_display_path(
                    str(item.get("path") or item.get("source_path") or "artifact")
                ),
                "target_node_id": str(item.get("target_node_id"))
                if item.get("target_node_id")
                else None,
            }
            for item in items[:_BUNDLE_MAX_ITEMS]
            if isinstance(item, dict)
        ],
    }


def _is_archive_name(filename: str) -> bool:
    lowered = filename.lower()
    return lowered.endswith((".zip", ".tar", ".tgz", ".tar.gz"))


def _get_import_adapter_or_422(tool_name: str):
    try:
        return default_evidence_import_tool_registry().get(tool_name)
    except KeyError as exc:
        raise HTTPException(
            status_code=422, detail=f"Unsupported evidence source: {tool_name}"
        ) from exc


def _get_import_policy_or_422(tool_name: str):
    try:
        return default_evidence_ingest_policy_registry().get(tool_name)
    except KeyError as exc:
        raise HTTPException(
            status_code=422, detail=f"Unsupported evidence source: {tool_name}"
        ) from exc


def _scan_target_matches(matched_at: str, scan_target: str) -> bool:
    matched = matched_at.strip().casefold()
    target = scan_target.strip().rstrip("/").casefold()
    if not matched or not target:
        return False
    return (
        matched == target
        or matched.startswith(f"{target}/")
        or matched.startswith(f"{target}?")
        or matched.startswith(f"{target}#")
    )

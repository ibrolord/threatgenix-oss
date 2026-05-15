"""Service layer for review-scoped manifest bundles."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import PurePosixPath
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.application_review_bundle import ApplicationReviewBundle
from app.models.user import User
from app.schemas.application_review_bundle import (
    ApplicationReviewBundleCreate,
    ApplicationReviewBundleManifestItem,
    ApplicationReviewBundleResponse,
)
from app.services.application_review import (
    get_application_review,
    tenant_key_for_user,
    transition_application_review_status,
)

DEFAULT_MAX_BUNDLE_BYTES = 50_000_000
CONTENT_ADDRESS_NAMESPACE = uuid.UUID("7f6f0d9b-798a-45db-86ce-cb91f9b8346a")


class ReviewBundleValidationError(ValueError):
    """Raised when a review bundle manifest cannot be trusted."""


def review_bundle_size_limit() -> int:
    return int(os.getenv("APPLICATION_REVIEW_BUNDLE_MAX_BYTES", str(DEFAULT_MAX_BUNDLE_BYTES)))


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def normalize_manifest(
    manifest: list[ApplicationReviewBundleManifestItem],
) -> tuple[list[dict[str, object]], int]:
    normalized: list[dict[str, object]] = []
    seen_paths: set[str] = set()
    total_bytes = 0
    for item in manifest:
        safe_path = safe_manifest_path(item.path)
        if safe_path in seen_paths:
            raise ReviewBundleValidationError(f"Duplicate manifest path: {safe_path}")
        seen_paths.add(safe_path)
        total_bytes += item.byte_size
        normalized.append(
            {
                "path": safe_path,
                "file_kind": item.file_kind,
                "sha256": item.sha256,
                "byte_size": item.byte_size,
                "source": item.source,
            }
        )
    max_bytes = review_bundle_size_limit()
    if total_bytes > max_bytes:
        raise ReviewBundleValidationError(
            f"Review bundle is too large. Limit is {max_bytes} bytes."
        )
    return sorted(normalized, key=lambda entry: (str(entry["path"]), str(entry["sha256"]))), total_bytes


def safe_manifest_path(path: str) -> str:
    raw = path.strip()
    if not raw:
        raise ReviewBundleValidationError("Manifest path must not be blank.")
    if "\x00" in raw:
        raise ReviewBundleValidationError("Manifest path contains a null byte.")
    if "\\" in raw:
        raise ReviewBundleValidationError("Manifest path must use POSIX separators.")
    candidate = PurePosixPath(raw)
    if candidate.is_absolute():
        raise ReviewBundleValidationError("Manifest path must be relative.")
    parts = candidate.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ReviewBundleValidationError("Manifest path must stay inside the bundle root.")
    return str(candidate)


def compute_bundle_hash(bundle_kind: str, manifest: list[dict[str, object]]) -> str:
    payload = {
        "version": 1,
        "bundle_kind": bundle_kind,
        "manifest": manifest,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def bundle_id_for_content(*, tenant_key: str, review_id: UUID, content_hash: str) -> UUID:
    return uuid.uuid5(
        CONTENT_ADDRESS_NAMESPACE,
        f"{tenant_key}:{review_id}:{content_hash}",
    )


def build_bundle_integrity(
    *,
    bundle_kind: str,
    manifest: list[dict[str, object]],
    content_hash: str,
    byte_size: int,
    file_count: int,
) -> dict[str, object]:
    return {
        "version": 1,
        "bundle_kind": bundle_kind,
        "content_hash": content_hash,
        "byte_size": byte_size,
        "file_count": file_count,
        "manifest_sha256": hashlib.sha256(
            canonical_json(manifest).encode("utf-8")
        ).hexdigest(),
        "storage_backend": "database_manifest",
        "server_side_encryption": "metadata_only",
    }


def verify_bundle_integrity(bundle: ApplicationReviewBundle) -> None:
    normalized_manifest, total_bytes = normalize_manifest(
        [
            ApplicationReviewBundleManifestItem.model_validate(item)
            for item in (bundle.manifest or [])
        ]
    )
    recomputed_hash = compute_bundle_hash(bundle.bundle_kind, normalized_manifest)
    if recomputed_hash != bundle.content_hash:
        raise ReviewBundleValidationError("Review bundle content hash verification failed.")
    if total_bytes != bundle.byte_size or len(normalized_manifest) != bundle.file_count:
        raise ReviewBundleValidationError("Review bundle manifest counters do not match.")
    integrity = bundle.integrity or {}
    expected_manifest_hash = hashlib.sha256(
        canonical_json(normalized_manifest).encode("utf-8")
    ).hexdigest()
    if integrity.get("manifest_sha256") and integrity["manifest_sha256"] != expected_manifest_hash:
        raise ReviewBundleValidationError("Review bundle manifest hash verification failed.")


def serialize_application_review_bundle(
    bundle: ApplicationReviewBundle,
) -> ApplicationReviewBundleResponse:
    return ApplicationReviewBundleResponse(
        id=bundle.id,
        tenant_key=bundle.tenant_key,
        review_id=bundle.review_id,
        owner_id=bundle.owner_id,
        organization_id=bundle.organization_id,
        bundle_kind=bundle.bundle_kind,
        source=bundle.source,
        status=bundle.status,
        manifest=bundle.manifest or [],
        redaction_report=bundle.redaction_report or {},
        integrity=bundle.integrity or {},
        storage_backend=bundle.storage_backend,
        encryption_status=bundle.encryption_status,
        content_hash=bundle.content_hash,
        byte_size=bundle.byte_size,
        file_count=bundle.file_count,
        retention_expires_at=bundle.retention_expires_at,
        legal_hold=bundle.legal_hold,
        created_at=bundle.created_at,
        updated_at=bundle.updated_at,
    )


async def get_review_bundle_by_hash(
    db: AsyncSession,
    *,
    tenant_key: str,
    review_id: UUID,
    content_hash: str,
) -> ApplicationReviewBundle | None:
    result = await db.execute(
        select(ApplicationReviewBundle)
        .where(
            ApplicationReviewBundle.tenant_key == tenant_key,
            ApplicationReviewBundle.review_id == review_id,
            ApplicationReviewBundle.content_hash == content_hash,
            ApplicationReviewBundle.status != "deleted",
        )
        .limit(1)
    )
    bundle = result.scalar_one_or_none()
    if bundle is not None:
        verify_bundle_integrity(bundle)
    return bundle


async def get_review_bundle(
    db: AsyncSession,
    *,
    tenant_key: str,
    review_id: UUID,
    bundle_id: UUID,
) -> ApplicationReviewBundle | None:
    result = await db.execute(
        select(ApplicationReviewBundle)
        .where(
            ApplicationReviewBundle.tenant_key == tenant_key,
            ApplicationReviewBundle.review_id == review_id,
            ApplicationReviewBundle.id == bundle_id,
            ApplicationReviewBundle.status == "ready",
        )
        .limit(1)
    )
    bundle = result.scalar_one_or_none()
    if bundle is not None:
        verify_bundle_integrity(bundle)
    return bundle


async def list_review_bundles(
    db: AsyncSession,
    *,
    tenant_key: str,
    review_id: UUID,
) -> list[ApplicationReviewBundle]:
    result = await db.execute(
        select(ApplicationReviewBundle)
        .where(
            ApplicationReviewBundle.tenant_key == tenant_key,
            ApplicationReviewBundle.review_id == review_id,
            ApplicationReviewBundle.status == "ready",
        )
        .order_by(ApplicationReviewBundle.created_at.desc())
    )
    bundles = list(result.scalars().all())
    for bundle in bundles:
        verify_bundle_integrity(bundle)
    return bundles


async def supersede_ready_review_bundles(
    db: AsyncSession,
    *,
    tenant_key: str,
    review_id: UUID,
    except_bundle_id: UUID | None = None,
) -> None:
    result = await db.execute(
        select(ApplicationReviewBundle).where(
            ApplicationReviewBundle.tenant_key == tenant_key,
            ApplicationReviewBundle.review_id == review_id,
            ApplicationReviewBundle.status == "ready",
        )
    )
    for bundle in result.scalars().all():
        if except_bundle_id is not None and bundle.id == except_bundle_id:
            continue
        bundle.status = "superseded"


async def create_review_bundle(
    db: AsyncSession,
    *,
    current_user: User,
    review_id: UUID,
    request: ApplicationReviewBundleCreate,
) -> ApplicationReviewBundle:
    tenant_key = tenant_key_for_user(current_user)
    review = await get_application_review(db, tenant_key=tenant_key, review_id=review_id)
    if review is None:
        raise ReviewBundleValidationError("Review was not found for this tenant.")

    normalized_manifest, total_bytes = normalize_manifest(request.manifest)
    content_hash = compute_bundle_hash(request.bundle_kind, normalized_manifest)
    bundle_id = bundle_id_for_content(
        tenant_key=tenant_key,
        review_id=review_id,
        content_hash=content_hash,
    )
    existing = await get_review_bundle_by_hash(
        db,
        tenant_key=tenant_key,
        review_id=review_id,
        content_hash=content_hash,
    )
    if existing is not None:
        verify_bundle_integrity(existing)
        if existing.status != "ready":
            await supersede_ready_review_bundles(
                db,
                tenant_key=tenant_key,
                review_id=review_id,
                except_bundle_id=existing.id,
            )
            existing.status = "ready"
        if review.status in {"created", "intake_required", "bundle_required"}:
            transition_application_review_status(review, "bundle_received")
        return existing

    await supersede_ready_review_bundles(db, tenant_key=tenant_key, review_id=review_id)
    bundle = ApplicationReviewBundle(
        id=bundle_id,
        tenant_key=tenant_key,
        review_id=review_id,
        owner_id=current_user.id,
        organization_id=getattr(current_user, "organization_id", None),
        bundle_kind=request.bundle_kind,
        source=request.source,
        status="ready",
        manifest=normalized_manifest,
        redaction_report=request.redaction_report,
        integrity=build_bundle_integrity(
            bundle_kind=request.bundle_kind,
            manifest=normalized_manifest,
            content_hash=content_hash,
            byte_size=total_bytes,
            file_count=len(normalized_manifest),
        ),
        storage_backend="database_manifest",
        encryption_status="metadata_only",
        content_hash=content_hash,
        byte_size=total_bytes,
        file_count=len(normalized_manifest),
        retention_expires_at=request.retention_expires_at,
        legal_hold=request.legal_hold,
    )
    db.add(bundle)
    transition_application_review_status(review, "bundle_received")
    await db.flush()
    return bundle

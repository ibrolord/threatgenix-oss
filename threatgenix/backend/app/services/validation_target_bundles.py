"""Hosted validation target bundles for managed scanner workers."""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import tempfile
import zipfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path, PurePosixPath
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import ValidationTargetBundle
from app.models.threat_model import ThreatModel
from app.models.user import User
from app.services.validation_execution_policy import (
    TARGET_AI_SYSTEM,
    TARGET_IAC_DIRECTORY,
    TARGET_LOCKFILE,
    TARGET_REPOSITORY_PATH,
)
from app.services.validation_sandbox import configured_validation_allowed_roots

HOSTED_VALIDATION_TARGET_SCHEME = "tgx-target://"
_PATH_TARGET_TYPES = {
    TARGET_REPOSITORY_PATH,
    TARGET_LOCKFILE,
    TARGET_IAC_DIRECTORY,
    TARGET_AI_SYSTEM,
}
_ARCHIVE_EXTENSIONS = (".zip", ".tar", ".tar.gz", ".tgz")
_DEFAULT_MAX_BYTES = 25_000_000
_DEFAULT_MAX_FILES = 5_000
_DEFAULT_MAX_EXTRACTED_BYTES = 100_000_000


class ValidationTargetBundleError(RuntimeError):
    """Raised when a hosted validation target bundle cannot be used safely."""


@dataclass(frozen=True)
class ParsedValidationTargetRef:
    bundle_id: UUID
    subpath: str | None = None


@dataclass
class MaterializedValidationTarget:
    target: str
    display_target: str
    bundle_id: UUID
    root_dir: str

    def cleanup(self) -> None:
        with suppress(FileNotFoundError):
            shutil.rmtree(self.root_dir)


def validation_target_bundle_size_limit() -> int:
    return int(os.getenv("VALIDATION_TARGET_BUNDLE_MAX_BYTES", str(_DEFAULT_MAX_BYTES)))


def target_ref_for_bundle(bundle_id: UUID, subpath: str | None = None) -> str:
    suffix = f"#{_safe_relative_path(subpath)}" if subpath else ""
    return f"{HOSTED_VALIDATION_TARGET_SCHEME}{bundle_id}{suffix}"


def is_validation_target_bundle_ref(target: str | None) -> bool:
    return bool(target and target.strip().startswith(HOSTED_VALIDATION_TARGET_SCHEME))


def parse_validation_target_ref(target: str) -> ParsedValidationTargetRef:
    raw = target.strip()
    if not raw.startswith(HOSTED_VALIDATION_TARGET_SCHEME):
        raise ValidationTargetBundleError(
            "target is not a hosted validation target reference"
        )
    rest = raw[len(HOSTED_VALIDATION_TARGET_SCHEME) :]
    bundle_part, _, subpath = rest.partition("#")
    try:
        bundle_id = UUID(bundle_part)
    except ValueError as exc:
        raise ValidationTargetBundleError(
            "hosted validation target reference has an invalid id"
        ) from exc
    normalized_subpath = _safe_relative_path(subpath) if subpath else None
    return ParsedValidationTargetRef(bundle_id=bundle_id, subpath=normalized_subpath)


async def create_validation_target_bundle(
    db: AsyncSession,
    *,
    threat_model: ThreatModel,
    current_user: User,
    filename: str,
    content_type: str | None,
    content: bytes,
    name: str | None = None,
) -> ValidationTargetBundle:
    if not content:
        raise ValidationTargetBundleError("Validation target bundle is empty.")
    max_bytes = validation_target_bundle_size_limit()
    if len(content) > max_bytes:
        raise ValidationTargetBundleError(
            f"Validation target bundle is too large. Limit is {max_bytes} bytes."
        )

    safe_filename = _safe_display_path(filename or "validation-target")
    manifest = _inspect_bundle(content, safe_filename)
    retention_expires_at = datetime.now(timezone.utc) + timedelta(
        days=int(os.getenv("VALIDATION_TARGET_BUNDLE_RETENTION_DAYS", "7"))
    )
    bundle = ValidationTargetBundle(
        threat_model_id=threat_model.id,
        owner_id=current_user.id,
        organization_id=getattr(threat_model, "organization_id", None),
        name=(name or safe_filename).strip()[:200] or safe_filename,
        filename=safe_filename,
        content_type=content_type,
        byte_size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        status="ready",
        storage_backend="database",
        archive_bytes=content,
        manifest=manifest,
        retention_expires_at=retention_expires_at,
    )
    db.add(bundle)
    await db.commit()
    await db.refresh(bundle)
    return bundle


async def list_validation_target_bundles(
    db: AsyncSession,
    threat_model_id: UUID,
    *,
    limit: int = 25,
) -> list[ValidationTargetBundle]:
    result = await db.execute(
        select(ValidationTargetBundle)
        .where(
            ValidationTargetBundle.threat_model_id == threat_model_id,
            ValidationTargetBundle.status == "ready",
        )
        .order_by(ValidationTargetBundle.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def validate_target_bundle_ref_for_model(
    db: AsyncSession,
    *,
    threat_model_id: UUID,
    owner_id: UUID,
    target_ref: str,
) -> ValidationTargetBundle:
    parsed = parse_validation_target_ref(target_ref)
    bundle = await _get_accessible_bundle(
        db,
        bundle_id=parsed.bundle_id,
        threat_model_id=threat_model_id,
        owner_id=owner_id,
    )
    if parsed.subpath:
        _assert_subpath_in_manifest(bundle, parsed.subpath)
    return bundle


async def materialize_validation_target_ref(
    db: AsyncSession,
    *,
    threat_model_id: UUID,
    owner_id: UUID,
    target_ref: str,
    target_type: str,
) -> MaterializedValidationTarget:
    if target_type not in _PATH_TARGET_TYPES:
        raise ValidationTargetBundleError(
            f"hosted target bundles do not support {target_type}"
        )

    parsed = parse_validation_target_ref(target_ref)
    bundle = await _get_accessible_bundle(
        db,
        bundle_id=parsed.bundle_id,
        threat_model_id=threat_model_id,
        owner_id=owner_id,
    )
    if not bundle.archive_bytes:
        raise ValidationTargetBundleError(
            "hosted validation target bundle has no stored content"
        )

    root = _materialization_root()
    extract_root = tempfile.mkdtemp(prefix=f"target-{bundle.id}-", dir=root)
    try:
        _extract_bundle(bundle.archive_bytes, bundle.filename, Path(extract_root))
        selected = _selected_target_path(
            Path(extract_root),
            target_type=target_type,
            subpath=parsed.subpath,
            manifest=bundle.manifest or {},
        )
        return MaterializedValidationTarget(
            target=str(selected),
            display_target=_display_target(bundle, parsed.subpath),
            bundle_id=bundle.id,
            root_dir=extract_root,
        )
    except Exception:
        with suppress(FileNotFoundError):
            shutil.rmtree(extract_root)
        raise


def _materialization_root() -> str:
    roots = configured_validation_allowed_roots()
    for root in roots:
        path = Path(root).expanduser()
        if path.is_absolute():
            path.mkdir(parents=True, exist_ok=True)
            return str(path)
    fallback = Path(tempfile.gettempdir()) / "threatgenix-validation-targets"
    fallback.mkdir(parents=True, exist_ok=True)
    return str(fallback)


async def _get_accessible_bundle(
    db: AsyncSession,
    *,
    bundle_id: UUID,
    threat_model_id: UUID,
    owner_id: UUID,
) -> ValidationTargetBundle:
    result = await db.execute(
        select(ValidationTargetBundle).where(
            ValidationTargetBundle.id == bundle_id,
            ValidationTargetBundle.threat_model_id == threat_model_id,
            ValidationTargetBundle.owner_id == owner_id,
            ValidationTargetBundle.status == "ready",
        )
    )
    bundle = result.scalar_one_or_none()
    if bundle is None:
        raise ValidationTargetBundleError(
            "hosted validation target bundle was not found or is not accessible"
        )
    return bundle


def _inspect_bundle(content: bytes, filename: str) -> dict:
    if _is_archive_name(filename):
        return _archive_manifest(content, filename)
    safe_name = _safe_relative_path(filename)
    return {
        "archive_type": "single_file",
        "file_count": 1,
        "total_uncompressed_bytes": len(content),
        "paths": [safe_name],
        "sample_paths": [safe_name],
    }


def _archive_manifest(content: bytes, filename: str) -> dict:
    file_count = 0
    total_size = 0
    paths: list[str] = []
    sample_paths: list[str] = []
    max_files = int(
        os.getenv("VALIDATION_TARGET_BUNDLE_MAX_FILES", str(_DEFAULT_MAX_FILES))
    )
    max_extracted = int(
        os.getenv(
            "VALIDATION_TARGET_BUNDLE_MAX_EXTRACTED_BYTES",
            str(_DEFAULT_MAX_EXTRACTED_BYTES),
        )
    )
    lowered_filename = filename.lower()
    if lowered_filename.endswith(".zip"):
        with zipfile.ZipFile(BytesIO(content)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                _assert_safe_zip_member(info)
                safe_path = _safe_relative_path(info.filename)
                _assert_unique_member_path(safe_path, paths)
                file_count += 1
                total_size += int(info.file_size)
                if len(sample_paths) < 20:
                    sample_paths.append(safe_path)
                _enforce_archive_limits(
                    file_count, total_size, max_files, max_extracted
                )
        archive_type = "zip"
    elif _is_tar_name(lowered_filename):
        with tarfile.open(fileobj=BytesIO(content), mode="r:*") as archive:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                _assert_safe_tar_member(member)
                safe_path = _safe_relative_path(member.name)
                _assert_unique_member_path(safe_path, paths)
                file_count += 1
                total_size += int(member.size or 0)
                if len(sample_paths) < 20:
                    sample_paths.append(safe_path)
                _enforce_archive_limits(
                    file_count, total_size, max_files, max_extracted
                )
        archive_type = "tar"
    else:
        raise ValidationTargetBundleError(
            "Validation target must be a .zip, .tar, .tar.gz, .tgz, or single file upload."
        )
    if file_count == 0:
        raise ValidationTargetBundleError(
            "Validation target archive contains no files."
        )
    return {
        "archive_type": archive_type,
        "file_count": file_count,
        "total_uncompressed_bytes": total_size,
        "paths": paths,
        "sample_paths": sample_paths,
    }


def _extract_bundle(content: bytes, filename: str, destination: Path) -> None:
    lowered_filename = filename.lower()
    if lowered_filename.endswith(".zip"):
        with zipfile.ZipFile(BytesIO(content)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                _assert_safe_zip_member(info)
                _write_member(
                    destination, _safe_relative_path(info.filename), archive.read(info)
                )
        return
    if _is_tar_name(lowered_filename):
        with tarfile.open(fileobj=BytesIO(content), mode="r:*") as archive:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                _assert_safe_tar_member(member)
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                _write_member(
                    destination, _safe_relative_path(member.name), stream.read()
                )
        return
    _write_member(destination, _safe_relative_path(filename), content)


def _write_member(destination: Path, relative_path: str, data: bytes) -> None:
    target = (destination / relative_path).resolve()
    if not _path_within(target, destination.resolve()):
        raise ValidationTargetBundleError(
            f"archive member escapes target root: {relative_path}"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _selected_target_path(
    root: Path,
    *,
    target_type: str,
    subpath: str | None,
    manifest: dict,
) -> Path:
    selected = root / subpath if subpath else root
    selected = selected.resolve()
    if not _path_within(selected, root.resolve()):
        raise ValidationTargetBundleError(
            "hosted validation target subpath escapes bundle root"
        )
    if target_type == TARGET_LOCKFILE:
        if subpath is None and selected.is_dir():
            candidates = [
                selected / "package-lock.json",
                selected / "yarn.lock",
                selected / "pnpm-lock.yaml",
                selected / "poetry.lock",
                selected / "requirements.txt",
            ]
            selected = next(
                (candidate for candidate in candidates if candidate.is_file()), selected
            )
        if not selected.is_file():
            raise ValidationTargetBundleError(
                "hosted lockfile target must point to a file inside the bundle"
            )
        return selected
    if target_type == TARGET_AI_SYSTEM:
        if subpath is None and selected.is_dir():
            candidates = [
                selected / "ai-system.json",
                selected / "ai_system.json",
                selected / "redteam.json",
                selected / "red-team.json",
                selected / "promptfoo-redteam.json",
                selected / "promptfoo-results.json",
            ]
            selected = next(
                (candidate for candidate in candidates if candidate.is_file()), selected
            )
        if not selected.is_file():
            raise ValidationTargetBundleError(
                "hosted AI-system target must point to a JSON evidence file inside the bundle"
            )
        return selected
    if not selected.is_dir():
        kind = "IaC directory" if target_type == TARGET_IAC_DIRECTORY else "repository"
        raise ValidationTargetBundleError(
            f"hosted {kind} target must point to a directory inside the bundle"
        )
    if target_type == TARGET_IAC_DIRECTORY and subpath is None:
        sample_paths = (
            manifest.get("sample_paths") if isinstance(manifest, dict) else None
        )
        if isinstance(sample_paths, list) and any(
            str(path).startswith("infra/") for path in sample_paths
        ):
            infra = (root / "infra").resolve()
            if infra.is_dir():
                return infra
    return selected


def _assert_safe_zip_member(info: zipfile.ZipInfo) -> None:
    _safe_relative_path(info.filename)
    mode = (info.external_attr >> 16) & 0o170000
    if mode == 0o120000:
        raise ValidationTargetBundleError(
            f"archive symlinks are not allowed: {info.filename}"
        )


def _assert_safe_tar_member(member: tarfile.TarInfo) -> None:
    _safe_relative_path(member.name)
    if not member.isfile():
        raise ValidationTargetBundleError(
            f"archive member type is not allowed: {member.name}"
        )
    if member.issym() or member.islnk():
        raise ValidationTargetBundleError(
            f"archive links are not allowed: {member.name}"
        )


def _safe_relative_path(path: str) -> str:
    raw = (path or "").strip().replace("\\", "/")
    candidate = PurePosixPath(raw)
    if not raw or candidate.is_absolute():
        raise ValidationTargetBundleError(f"archive path must be relative: {path}")
    parts = [part for part in candidate.parts if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        raise ValidationTargetBundleError(f"archive path is not safe: {path}")
    return str(PurePosixPath(*parts))


def _safe_display_path(path: str) -> str:
    try:
        return _safe_relative_path(Path(path).name or "validation-target")
    except ValidationTargetBundleError:
        return "validation-target"


def _display_target(bundle: ValidationTargetBundle, subpath: str | None) -> str:
    suffix = f"#{subpath}" if subpath else ""
    return f"{bundle.name}{suffix} (bundle:{str(bundle.id)[:8]}, sha256:{bundle.sha256[:12]})"


def _assert_subpath_in_manifest(bundle: ValidationTargetBundle, subpath: str) -> None:
    manifest = bundle.manifest or {}
    paths = manifest.get("paths")
    if not isinstance(paths, list):
        paths = manifest.get("sample_paths")
    if not isinstance(paths, list):
        return
    if not any(
        str(path) == subpath or str(path).startswith(f"{subpath.rstrip('/')}/")
        for path in paths
    ):
        raise ValidationTargetBundleError(
            "hosted validation target subpath is not present in the bundle manifest"
        )


def _enforce_archive_limits(
    file_count: int,
    total_size: int,
    max_files: int,
    max_extracted: int,
) -> None:
    if file_count > max_files:
        raise ValidationTargetBundleError(
            f"Validation target archive has too many files. Limit is {max_files}."
        )
    if total_size > max_extracted:
        raise ValidationTargetBundleError(
            f"Validation target archive expands beyond {max_extracted} bytes."
        )


def _assert_unique_member_path(path: str, paths: list[str]) -> None:
    if path in paths:
        raise ValidationTargetBundleError(
            f"archive contains duplicate member path: {path}"
        )
    paths.append(path)


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _is_archive_name(filename: str) -> bool:
    lowered = filename.lower()
    return lowered.endswith(_ARCHIVE_EXTENSIONS)


def _is_tar_name(filename: str) -> bool:
    lowered = filename.lower()
    return lowered.endswith((".tar", ".tar.gz", ".tgz"))

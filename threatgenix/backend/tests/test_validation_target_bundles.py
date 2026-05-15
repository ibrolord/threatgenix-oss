from __future__ import annotations

from io import BytesIO
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
import zipfile

import pytest

from app.services.validation_execution_policy import (
    NETWORK_NONE,
    TARGET_AI_SYSTEM,
    TARGET_LOCKFILE,
    TARGET_REPOSITORY_PATH,
    ValidationExecutionPolicy,
)
from app.services.validation_target_bundles import (
    MaterializedValidationTarget,
    ValidationTargetBundleError,
    _archive_manifest,
    _extract_bundle,
    _selected_target_path,
    parse_validation_target_ref,
    target_ref_for_bundle,
)
from app.services.validation_tools import ValidationToolResult


def _zip_bytes(files: dict[str, bytes | str]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            payload = content.encode("utf-8") if isinstance(content, str) else content
            archive.writestr(name, payload)
    return buffer.getvalue()


def test_target_ref_round_trips_safe_subpath() -> None:
    bundle_id = uuid4()

    ref = target_ref_for_bundle(bundle_id, "infra/main.tf")
    parsed = parse_validation_target_ref(ref)

    assert parsed.bundle_id == bundle_id
    assert parsed.subpath == "infra/main.tf"


def test_target_ref_rejects_unsafe_subpath() -> None:
    with pytest.raises(ValidationTargetBundleError, match="not safe"):
        target_ref_for_bundle(uuid4(), "../secrets.txt")


def test_archive_manifest_records_all_safe_paths() -> None:
    content = _zip_bytes({f"src/file_{index}.py": "print('ok')" for index in range(25)})

    manifest = _archive_manifest(content, "Repo.ZIP")

    assert manifest["archive_type"] == "zip"
    assert manifest["file_count"] == 25
    assert len(manifest["paths"]) == 25
    assert len(manifest["sample_paths"]) == 20
    assert "src/file_24.py" in manifest["paths"]


def test_archive_manifest_rejects_zip_path_traversal() -> None:
    content = _zip_bytes({"../secret.txt": "nope"})

    with pytest.raises(ValidationTargetBundleError, match="not safe"):
        _archive_manifest(content, "repo.zip")


def test_extract_bundle_selects_default_lockfile(tmp_path) -> None:
    content = _zip_bytes(
        {
            "package.json": "{}",
            "package-lock.json": '{"lockfileVersion": 3}',
            "src/app.js": "console.log('ok')",
        }
    )

    _extract_bundle(content, "repo.zip", tmp_path)
    selected = _selected_target_path(
        tmp_path,
        target_type=TARGET_LOCKFILE,
        subpath=None,
        manifest={},
    )

    assert selected == tmp_path / "package-lock.json"


def test_extract_bundle_selects_default_ai_system_evidence_file(tmp_path) -> None:
    content = _zip_bytes(
        {
            "ai-system.json": '{"system":{"name":"Northstar Agent"},"test_cases":[]}',
            "README.md": "fixture",
        }
    )

    _extract_bundle(content, "ai-target.zip", tmp_path)
    selected = _selected_target_path(
        tmp_path,
        target_type=TARGET_AI_SYSTEM,
        subpath=None,
        manifest={},
    )

    assert selected == tmp_path / "ai-system.json"


@pytest.mark.asyncio
async def test_scan_worker_materializes_hosted_target_and_cleans_up(
    monkeypatch,
) -> None:
    from app.services.scan_worker import _scan_target

    cleanup_calls: list[str] = []
    materialized = MaterializedValidationTarget(
        target="/tmp/threatgenix-validation-targets/repo",
        display_target="repo.zip (bundle:abc12345, sha256:1234567890ab)",
        bundle_id=uuid4(),
        root_dir="/tmp/threatgenix-validation-targets/materialized",
    )

    def cleanup() -> None:
        cleanup_calls.append(materialized.root_dir)

    materialized.cleanup = cleanup
    materialize = AsyncMock(return_value=materialized)
    monkeypatch.setattr(
        "app.services.scan_worker.materialize_validation_target_ref",
        materialize,
    )

    class FakeTool:
        name = "semgrep"
        deterministic = True
        timeout_seconds = 60

        def __init__(self) -> None:
            self.calls: list[str] = []

        async def run(self, target: str, **_kwargs):
            self.calls.append(target)
            return ValidationToolResult(
                tool_name=self.name,
                target=target,
                command=["semgrep", "scan", "--json", target],
                resolved_target=target,
                findings=[],
            )

    db = MagicMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    tool = FakeTool()
    policy = ValidationExecutionPolicy(
        tool_name="semgrep",
        supported_targets=[TARGET_REPOSITORY_PATH],
        runs_in_sandbox_required=False,
        execution_enabled=True,
        network_mode=NETWORK_NONE,
        max_runtime_seconds=60,
        max_output_bytes=4096,
        artifact_capture_enabled=True,
    )
    hosted_ref = f"tgx-target://{uuid4()}"

    findings = await _scan_target(
        db,
        uuid4(),
        hosted_ref,
        "repo-node",
        threat_model_id=uuid4(),
        owner_id=uuid4(),
        tool=tool,
        target_type=TARGET_REPOSITORY_PATH,
        policy=policy,
    )

    assert findings == []
    assert tool.calls == [materialized.target]
    assert cleanup_calls == [materialized.root_dir]
    artifact = next(
        call.args[0]
        for call in db.add.call_args_list
        if call.args[0].__class__.__name__ == "ScanExecutionArtifact"
    )
    assert artifact.target == materialized.display_target
    assert materialized.target not in " ".join(artifact.command)
    assert "[repository_path:repo:sha256:" in " ".join(artifact.command)
    materialize.assert_awaited_once()

from __future__ import annotations

import json
import tarfile
import zipfile
from io import BytesIO

import pytest
from fastapi import HTTPException

from app.services.validation_artifact_bundles import (
    build_single_validation_artifact_input,
    parse_validation_artifact_bundle_upload,
)
from app.services import validation_artifact_bundles


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_build_single_validation_artifact_input_strips_metadata():
    item = build_single_validation_artifact_input(
        tool_name=" semgrep ",
        target_type=" repository_path ",
        target=" /repo ",
        filename="../semgrep.json",
        raw_output=b'{"results":[]}',
    )

    assert item.tool_name == "semgrep"
    assert item.target_type == "repository_path"
    assert item.target == "/repo"
    assert item.source_path == "semgrep.json"


def test_parse_validation_artifact_zip_manifest():
    manifest = {
        "items": [
            {
                "path": "outputs/semgrep.json",
                "tool_name": "semgrep",
                "target_type": "repository_path",
                "target": "/repo",
            }
        ]
    }
    content = _zip_bytes(
        {
            "threatgenix-validation-manifest.json": json.dumps(manifest).encode(
                "utf-8"
            ),
            "outputs/semgrep.json": b'{"results":[]}',
        }
    )

    items, parsed_manifest = parse_validation_artifact_bundle_upload(
        content, "bundle.zip"
    )

    assert parsed_manifest == manifest
    assert len(items) == 1
    assert items[0].tool_name == "semgrep"
    assert items[0].raw_output == b'{"results":[]}'


def test_parse_validation_artifact_zip_accepts_semantic_manifest_alias():
    manifest = {
        "items": [
            {
                "path": "outputs/semgrep.json",
                "tool_name": "semgrep",
                "target_type": "repository_path",
                "target": "/repo",
            }
        ]
    }
    content = _zip_bytes(
        {
            "threatgenix-validation-manifest.json": json.dumps(
                manifest
            ).encode("utf-8"),
            "outputs/semgrep.json": b'{"results":[]}',
        }
    )

    items, parsed_manifest = parse_validation_artifact_bundle_upload(
        content, "bundle.zip"
    )

    assert parsed_manifest == manifest
    assert len(items) == 1
    assert items[0].source_path == "outputs/semgrep.json"


def test_parse_validation_artifact_zip_rejects_path_traversal():
    manifest = {
        "items": [
            {
                "path": "../semgrep.json",
                "tool_name": "semgrep",
                "target_type": "repository_path",
                "target": "/repo",
            }
        ]
    }
    content = _zip_bytes(
        {
            "threatgenix-validation-manifest.json": json.dumps(manifest).encode(
                "utf-8"
            ),
            "../semgrep.json": b'{"results":[]}',
        }
    )

    with pytest.raises(HTTPException) as exc:
        parse_validation_artifact_bundle_upload(content, "bundle.zip")

    assert exc.value.status_code == 422
    assert "Unsafe archive path" in str(exc.value.detail)


def test_parse_validation_artifact_zip_rejects_duplicate_member_paths():
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w") as archive:
        archive.writestr(
            "threatgenix-validation-manifest.json",
            json.dumps(
                {
                    "items": [
                        {
                            "path": "outputs/semgrep.json",
                            "tool_name": "semgrep",
                            "target_type": "repository_path",
                            "target": "/repo",
                        }
                    ]
                }
            ),
        )
        archive.writestr("outputs/semgrep.json", b'{"results":[]}')
        archive.writestr("outputs/semgrep.json", b'{"results":[{"check_id":"shadow"}]}')

    with pytest.raises(HTTPException) as exc:
        parse_validation_artifact_bundle_upload(buffer.getvalue(), "bundle.zip")

    assert exc.value.status_code == 422
    assert "Duplicate archive path" in str(exc.value.detail)


def test_parse_validation_artifact_tar_rejects_duplicate_member_paths():
    manifest = json.dumps(
        {
            "items": [
                {
                    "path": "outputs/semgrep.json",
                    "tool_name": "semgrep",
                    "target_type": "repository_path",
                    "target": "/repo",
                }
            ]
        }
    ).encode("utf-8")
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in [
            ("threatgenix-validation-manifest.json", manifest),
            ("outputs/semgrep.json", b'{"results":[]}'),
            ("outputs/semgrep.json", b'{"results":[{"check_id":"shadow"}]}'),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, BytesIO(content))

    with pytest.raises(HTTPException) as exc:
        parse_validation_artifact_bundle_upload(buffer.getvalue(), "bundle.tar")

    assert exc.value.status_code == 422
    assert "Duplicate archive path" in str(exc.value.detail)


def test_parse_validation_artifact_zip_rejects_aggregate_decompressed_size(monkeypatch):
    monkeypatch.setattr(validation_artifact_bundles, "_BUNDLE_MAX_BYTES", 120)
    content = _zip_bytes(
        {
            "threatgenix-validation-manifest.json": json.dumps({"items": []}).encode(
                "utf-8"
            ),
            "outputs/a.json": b"a" * 80,
            "outputs/b.json": b"b" * 80,
        }
    )

    with pytest.raises(HTTPException) as exc:
        parse_validation_artifact_bundle_upload(content, "bundle.zip")

    assert exc.value.status_code == 413
    assert "too large after decompression" in str(exc.value.detail)


def test_parse_validation_artifact_tar_rejects_aggregate_decompressed_size(monkeypatch):
    monkeypatch.setattr(validation_artifact_bundles, "_BUNDLE_MAX_BYTES", 120)
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in [
            (
                "threatgenix-validation-manifest.json",
                json.dumps({"items": []}).encode(),
            ),
            ("outputs/a.json", b"a" * 80),
            ("outputs/b.json", b"b" * 80),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, BytesIO(content))

    with pytest.raises(HTTPException) as exc:
        parse_validation_artifact_bundle_upload(buffer.getvalue(), "bundle.tar")

    assert exc.value.status_code == 413
    assert "too large after decompression" in str(exc.value.detail)


def test_parse_inline_manifest_rejects_duplicate_paths():
    manifest = {
        "items": [
            {
                "path": "semgrep.json",
                "tool_name": "semgrep",
                "target_type": "repository_path",
                "target": "/repo",
                "raw_output": {"results": []},
            },
            {
                "path": "semgrep.json",
                "tool_name": "semgrep",
                "target_type": "repository_path",
                "target": "/repo",
                "raw_output": {"results": []},
            },
        ]
    }

    with pytest.raises(HTTPException) as exc:
        parse_validation_artifact_bundle_upload(
            json.dumps(manifest).encode("utf-8"),
            "manifest.json",
        )

    assert exc.value.status_code == 422
    assert "Duplicate artifact path" in str(exc.value.detail)

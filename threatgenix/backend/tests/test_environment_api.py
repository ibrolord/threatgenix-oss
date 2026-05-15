from __future__ import annotations

import io
import json
import uuid
import zipfile
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.schemas.environment_evidence import (
    GitHubPullRequestChangedFile,
    GitHubPullRequestMetadata,
)
from app.services.auth import get_current_user
from app.services.environment_evidence import EvidenceValidationError

BASE_URL = "http://test"
FAKE_USER_ID = uuid.uuid4()


class FakeUser:
    id = FAKE_USER_ID
    email = "test@example.com"
    full_name = "Test User"
    role = "admin"
    is_active = True


class FakeThreatModel:
    def __init__(self, *, owner_id: uuid.UUID | None = None):
        self.id = uuid.uuid4()
        self.system_name = "Environment Test System"
        self.description = ""
        self.data_classification = "Internal"
        self.regulatory_scope = []
        self.deployment_model = None
        self.environment_context_summary = None
        self.repository_evidence = None
        self.cloud_scan_evidence = None
        self.iac_evidence = None
        self.owner_id = owner_id if owner_id is not None else FAKE_USER_ID
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)


async def override_get_db():
    yield AsyncMock()


async def override_get_current_user():
    return FakeUser()


@pytest.fixture(autouse=True)
def _apply_overrides():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user


def _make_repo_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("package.json", json.dumps({"dependencies": {"fastapi": "1.0.0"}}))
        archive.writestr("app/api/auth.py", "def login():\n    return True\n")
    return buffer.getvalue()


def _cloud_json() -> bytes:
    return json.dumps(
        [
            {
                "Status": "FAIL",
                "Severity": "high",
                "StatusExtended": "Security group allows 0.0.0.0/0",
                "ServiceName": "ec2",
                "ResourceArn": "sg-12345",
            }
        ]
    ).encode("utf-8")


def _iac_terraform() -> bytes:
    return b'resource "aws_s3_bucket" "uploads" {}\nresource "aws_security_group" "public_api" {}\n'


@pytest.mark.asyncio
async def test_upload_repository_evidence_stores_structured_result():
    fake_tm = FakeThreatModel()
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_tm.id}/environment/repository",
                files={"file": ("repo.zip", _make_repo_zip(), "application/zip")},
                data={"reference": "private/main"},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["repository_evidence"]["reference"] == "private/main"
    assert body["repository_evidence"]["file_count"] >= 1
    assert "Repository Evidence" in body["environment_context_summary"]
    mock_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_import_repository_evidence_from_github_stores_structured_result():
    fake_tm = FakeThreatModel()
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
        patch(
            "app.api.environment.fetch_github_repository_archive",
            new_callable=AsyncMock,
            return_value=(_make_repo_zip(), "octocat/private-service", "main"),
        ) as fetch_mock,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_tm.id}/environment/repository/github",
                json={
                    "repository": "https://github.com/octocat/private-service",
                    "ref": "main",
                    "reference": "payments-api",
                },
                headers={"X-GitHub-Token": "ghp_secret"},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["repository_evidence"]["reference"] == "octocat/private-service@main :: payments-api"
    assert body["repository_evidence"]["connection"] == {
        "provider": "github",
        "repository": "octocat/private-service",
        "transport": "https",
        "ref": "main",
        "reference": "payments-api",
        "connected_at": body["repository_evidence"]["connection"]["connected_at"],
        "last_synced_at": body["repository_evidence"]["connection"]["last_synced_at"],
    }
    assert "ghp_secret" not in json.dumps(body)
    fetch_mock.assert_awaited_once_with(
        "octocat/private-service",
        ref="main",
        transport="https",
        github_token="ghp_secret",
        ssh_private_key=None,
    )
    mock_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_import_repository_evidence_from_github_attaches_pull_request_metadata():
    fake_tm = FakeThreatModel()
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    pull_request = GitHubPullRequestMetadata(
        repository="octocat/private-service",
        number=22,
        url="https://github.com/octocat/private-service/pull/22",
        title="Add payment callback",
        state="open",
        base_ref="main",
        head_ref="payment-callback",
        head_sha="abc123",
        changed_file_count=1,
        changed_files=[
            GitHubPullRequestChangedFile(
                path="app/api/payments.py",
                status="modified",
                additions=12,
                deletions=3,
                changes=15,
            )
        ],
        truncated=False,
        fetched_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )

    with (
        patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
        patch(
            "app.api.environment.fetch_github_repository_archive",
            new_callable=AsyncMock,
            return_value=(_make_repo_zip(), "octocat/private-service", "refs/pull/22/head"),
        ),
        patch(
            "app.api.environment.fetch_github_pull_request_metadata",
            new_callable=AsyncMock,
            return_value=pull_request,
        ) as fetch_pr_mock,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_tm.id}/environment/repository/github",
                json={
                    "repository": "https://github.com/octocat/private-service",
                    "ref": "refs/pull/22/head",
                    "reference": "Pull request #22",
                    "pull_request_number": 22,
                },
                headers={"X-GitHub-Token": "ghp_secret"},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["repository_evidence"]["pull_request"]["number"] == 22
    assert body["repository_evidence"]["pull_request"]["base_ref"] == "main"
    assert body["repository_evidence"]["pull_request"]["changed_files"] == [
        {
            "path": "app/api/payments.py",
            "status": "modified",
            "previous_path": None,
            "additions": 12,
            "deletions": 3,
            "changes": 15,
        }
    ]
    assert "ghp_secret" not in json.dumps(body)
    fetch_pr_mock.assert_awaited_once_with(
        "octocat/private-service",
        22,
        github_token="ghp_secret",
    )
    mock_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_import_repository_evidence_from_github_accepts_pr_url_as_import_target():
    fake_tm = FakeThreatModel()
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    pull_request = GitHubPullRequestMetadata(
        repository="octocat/private-service",
        number=22,
        url="https://github.com/octocat/private-service/pull/22",
        title="Add payment callback",
        state="open",
        base_ref="main",
        head_ref="payment-callback",
        head_sha="abc123",
        changed_file_count=0,
        changed_files=[],
        truncated=False,
        fetched_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )

    with (
        patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
        patch(
            "app.api.environment.fetch_github_repository_archive",
            new_callable=AsyncMock,
            return_value=(_make_repo_zip(), "octocat/private-service", "refs/pull/22/head"),
        ) as fetch_repo_mock,
        patch(
            "app.api.environment.fetch_github_pull_request_metadata",
            new_callable=AsyncMock,
            return_value=pull_request,
        ) as fetch_pr_mock,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_tm.id}/environment/repository/github",
                json={"repository": "https://github.com/octocat/private-service/pull/22"},
                headers={"X-GitHub-Token": "ghp_secret"},
            )

    assert response.status_code == 200
    body = response.json()
    assert (
        body["repository_evidence"]["reference"]
        == "octocat/private-service@refs/pull/22/head :: Pull request #22"
    )
    assert body["repository_evidence"]["connection"]["repository"] == "octocat/private-service"
    assert body["repository_evidence"]["connection"]["ref"] == "refs/pull/22/head"
    assert body["repository_evidence"]["connection"]["reference"] == "Pull request #22"
    assert body["repository_evidence"]["pull_request"]["number"] == 22
    assert "ghp_secret" not in json.dumps(body)
    fetch_repo_mock.assert_awaited_once_with(
        "octocat/private-service",
        ref="refs/pull/22/head",
        transport="https",
        github_token="ghp_secret",
        ssh_private_key=None,
    )
    fetch_pr_mock.assert_awaited_once_with(
        "octocat/private-service",
        22,
        github_token="ghp_secret",
    )
    mock_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_import_repository_evidence_from_github_warns_when_pull_request_metadata_fails():
    fake_tm = FakeThreatModel()
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
        patch(
            "app.api.environment.fetch_github_repository_archive",
            new_callable=AsyncMock,
            return_value=(_make_repo_zip(), "octocat/private-service", "refs/pull/22/head"),
        ),
        patch(
            "app.api.environment.fetch_github_pull_request_metadata",
            new_callable=AsyncMock,
            side_effect=EvidenceValidationError("GitHub rate limit exceeded while fetching pull request metadata."),
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_tm.id}/environment/repository/github",
                json={
                    "repository": "https://github.com/octocat/private-service",
                    "ref": "refs/pull/22/head",
                    "reference": "Pull request #22",
                },
            )

    assert response.status_code == 200
    body = response.json()
    assert body["repository_evidence"]["pull_request"] is None
    assert body["repository_evidence"]["warnings"] == [
        "Pull request metadata could not be fetched: GitHub rate limit exceeded while fetching pull request metadata."
    ]
    mock_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_refresh_repository_evidence_from_saved_github_connection():
    fake_tm = FakeThreatModel()
    fake_tm.repository_evidence = {
        "source_type": "archive",
        "filename": "octocat/private-service.zip",
        "reference": "octocat/private-service@main :: payments-api",
        "connection": {
            "provider": "github",
            "repository": "octocat/private-service",
            "transport": "https",
            "ref": "main",
            "reference": "payments-api",
            "connected_at": "2026-04-23T00:00:00Z",
            "last_synced_at": "2026-04-23T00:00:00Z",
        },
        "parsed_at": "2026-04-23T00:00:00Z",
    }
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
        patch(
            "app.api.environment.fetch_github_repository_archive",
            new_callable=AsyncMock,
            return_value=(_make_repo_zip(), "octocat/private-service", "main"),
        ) as fetch_mock,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_tm.id}/environment/repository/github/refresh",
                json={},
                headers={"X-GitHub-Token": "ghp_refresh"},
            )

    assert response.status_code == 200
    body = response.json()
    connection = body["repository_evidence"]["connection"]
    assert connection["repository"] == "octocat/private-service"
    assert connection["ref"] == "main"
    assert connection["reference"] == "payments-api"
    assert connection["connected_at"] == "2026-04-23T00:00:00Z"
    assert connection["last_synced_at"] != "2026-04-23T00:00:00Z"
    assert "ghp_refresh" not in json.dumps(body)
    fetch_mock.assert_awaited_once_with(
        "octocat/private-service",
        ref="main",
        transport="https",
        github_token="ghp_refresh",
        ssh_private_key=None,
    )
    mock_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_refresh_repository_evidence_requires_saved_github_connection():
    fake_tm = FakeThreatModel()
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_tm.id}/environment/repository/github/refresh",
                json={},
            )

    assert response.status_code == 400
    assert response.json()["detail"] == "No GitHub repository connection is saved for this threat model."
    mock_db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_import_repository_evidence_from_github_over_ssh_stores_structured_result():
    fake_tm = FakeThreatModel()
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
        patch(
            "app.api.environment.fetch_github_repository_archive",
            new_callable=AsyncMock,
            return_value=(_make_repo_zip(), "octocat/private-service", "main"),
        ) as fetch_mock,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_tm.id}/environment/repository/github",
                json={
                    "repository": "git@github.com:octocat/private-service.git",
                    "transport": "ssh",
                    "ref": "main",
                    "reference": "payments-api",
                    "ssh_private_key": "FAKE_OPENSSH_PRIVATE_KEY_FOR_TESTS",
                },
            )

    assert response.status_code == 200
    fetch_mock.assert_awaited_once_with(
        "octocat/private-service",
        ref="main",
        transport="ssh",
        github_token=None,
        ssh_private_key="FAKE_OPENSSH_PRIVATE_KEY_FOR_TESTS",
    )
    mock_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_import_repository_evidence_from_github_surfaces_fetch_error():
    fake_tm = FakeThreatModel()
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
        patch(
            "app.api.environment.fetch_github_repository_archive",
            new_callable=AsyncMock,
            side_effect=EvidenceValidationError("GitHub access was denied.", status_code=403),
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_tm.id}/environment/repository/github",
                json={"repository": "octocat/private-service"},
            )

    assert response.status_code == 403
    assert response.json()["detail"] == "GitHub access was denied."


@pytest.mark.asyncio
async def test_upload_cloud_scan_stores_structured_result():
    fake_tm = FakeThreatModel()
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_tm.id}/environment/cloud-scan",
                files={"file": ("prowler.json", _cloud_json(), "application/json")},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["cloud_scan_evidence"]["provider"] == "prowler"
    assert body["cloud_scan_evidence"]["finding_count"] == 1
    assert "Cloud Posture Evidence" in body["environment_context_summary"]
    mock_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_clear_repository_recomputes_summary():
    fake_tm = FakeThreatModel()
    fake_tm.repository_evidence = {"filename": "repo.zip", "source_type": "archive", "parsed_at": "2026-04-13T00:00:00Z"}
    fake_tm.cloud_scan_evidence = {
        "provider": "prowler",
        "filename": "prowler.json",
        "finding_count": 1,
        "high_signal_findings": [],
        "exposed_services": [],
        "identity_risks": [],
        "encryption_gaps": [],
        "logging_gaps": [],
        "warnings": [],
        "parsed_at": "2026-04-13T00:00:00Z",
    }
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.delete(
                f"/api/threat-models/{fake_tm.id}/environment/repository"
            )

    assert response.status_code == 200
    body = response.json()
    assert body["repository_evidence"] is None
    assert body["cloud_scan_evidence"] is not None
    assert "Cloud Posture Evidence" in (body["environment_context_summary"] or "")


@pytest.mark.asyncio
async def test_clear_cloud_scan_recomputes_summary():
    fake_tm = FakeThreatModel()
    fake_tm.repository_evidence = {
        "filename": "repo.zip",
        "source_type": "archive",
        "file_count": 1,
        "languages": ["Python"],
        "frameworks": ["FastAPI"],
        "entrypoints": ["app/main.py"],
        "auth_surfaces": [],
        "data_stores": [],
        "queues": [],
        "external_integrations": [],
        "deployment_clues": [],
        "security_sensitive_paths": [],
        "warnings": [],
        "parsed_at": "2026-04-13T00:00:00Z",
    }
    fake_tm.cloud_scan_evidence = {
        "provider": "prowler",
        "filename": "prowler.json",
        "finding_count": 1,
        "high_signal_findings": [],
        "exposed_services": [],
        "identity_risks": [],
        "encryption_gaps": [],
        "logging_gaps": [],
        "warnings": [],
        "parsed_at": "2026-04-13T00:00:00Z",
    }
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.delete(
                f"/api/threat-models/{fake_tm.id}/environment/cloud-scan"
            )

    assert response.status_code == 200
    body = response.json()
    assert body["cloud_scan_evidence"] is None
    assert body["repository_evidence"] is not None
    assert "Repository Evidence" in (body["environment_context_summary"] or "")


@pytest.mark.asyncio
async def test_upload_iac_evidence_stores_structured_result():
    fake_tm = FakeThreatModel()
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"/api/threat-models/{fake_tm.id}/environment/iac",
                files={"file": ("main.tf", _iac_terraform(), "text/plain")},
                data={"reference": "prod/network"},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["iac_evidence"]["reference"] == "prod/network"
    assert body["iac_evidence"]["resource_count"] >= 2
    assert "IaC Evidence" in body["environment_context_summary"]
    mock_db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_clear_iac_recomputes_summary():
    fake_tm = FakeThreatModel()
    fake_tm.repository_evidence = {
        "filename": "repo.zip",
        "source_type": "archive",
        "file_count": 1,
        "languages": ["Python"],
        "frameworks": ["FastAPI"],
        "entrypoints": ["app/main.py"],
        "auth_surfaces": [],
        "data_stores": [],
        "queues": [],
        "external_integrations": [],
        "deployment_clues": [],
        "security_sensitive_paths": [],
        "warnings": [],
        "parsed_at": "2026-04-13T00:00:00Z",
    }
    fake_tm.iac_evidence = {
        "source_type": "single_file",
        "filename": "main.tf",
        "reference": "prod/network",
        "resource_count": 2,
        "resource_types": ["aws_s3_bucket", "aws_security_group"],
        "resource_names": ["uploads", "public_api"],
        "public_exposure": ["0.0.0.0/0 ingress"],
        "iam_bindings": [],
        "network_paths": ["public ingress"],
        "secret_refs": [],
        "warnings": [],
        "parsed_at": "2026-04-13T00:00:00Z",
    }
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.delete(f"/api/threat-models/{fake_tm.id}/environment/iac")

    assert response.status_code == 200
    body = response.json()
    assert body["iac_evidence"] is None
    assert body["repository_evidence"] is not None
    assert "Repository Evidence" in (body["environment_context_summary"] or "")


@pytest.mark.asyncio
async def test_get_environment_evidence_returns_current_state():
    fake_tm = FakeThreatModel()
    fake_tm.repository_evidence = {
        "filename": "repo.zip",
        "source_type": "archive",
        "file_count": 1,
        "languages": ["Python"],
        "frameworks": ["FastAPI"],
        "entrypoints": ["app/main.py"],
        "auth_surfaces": [],
        "data_stores": [],
        "queues": [],
        "external_integrations": [],
        "deployment_clues": [],
        "security_sensitive_paths": [],
        "warnings": [],
        "parsed_at": "2026-04-13T00:00:00Z",
    }
    fake_tm.iac_evidence = {
        "source_type": "single_file",
        "filename": "main.tf",
        "reference": None,
        "resource_count": 1,
        "resource_types": ["aws_s3_bucket"],
        "resource_names": ["uploads"],
        "public_exposure": [],
        "iam_bindings": [],
        "network_paths": [],
        "secret_refs": [],
        "warnings": [],
        "parsed_at": "2026-04-13T00:00:00Z",
    }
    fake_tm.environment_context_summary = "## Repository Evidence\n- Frameworks: FastAPI"

    with patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"/api/threat-models/{fake_tm.id}/environment")

    assert response.status_code == 200
    body = response.json()
    assert body["repository_evidence"]["frameworks"] == ["FastAPI"]
    assert body["iac_evidence"]["resource_types"] == ["aws_s3_bucket"]
    assert body["environment_context_summary"] == "## Repository Evidence\n- Frameworks: FastAPI"


@pytest.mark.asyncio
async def test_environment_endpoints_require_ownership():
    fake_tm = FakeThreatModel(owner_id=uuid.uuid4())
    mock_db = AsyncMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=fake_tm):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"/api/threat-models/{fake_tm.id}/environment")

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_environment_get_returns_404_for_missing_model():
    with patch("app.api.environment.get_threat_model", new_callable=AsyncMock, return_value=None):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"/api/threat-models/{uuid.uuid4()}/environment")

    assert response.status_code == 404

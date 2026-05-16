from __future__ import annotations

import io
import json
import shlex
import sys
import zipfile
from pathlib import Path

import pytest

import app.services.environment_evidence as environment_evidence
from tests.evals import prepare_environment_evidence_fixtures
from app.services.environment_evidence import (
    CLOUD_SCAN_EVIDENCE_MAX_BYTES,
    EvidenceValidationError,
    ENVIRONMENT_CONTEXT_CHAR_BUDGET,
    MAX_PULL_REQUEST_CHANGED_FILES,
    REPOSITORY_EVIDENCE_MAX_BYTES,
    fetch_github_repository_archive,
    fetch_github_repository_archive_over_ssh,
    fetch_github_pull_request_metadata,
    infer_github_pull_request_number,
    normalize_github_repository_slug,
    compose_environment_context_summary,
    parse_iac_evidence,
    parse_cloud_scan_evidence,
    parse_repository_evidence,
    parse_github_pull_request_url,
    resolve_github_repository_import_target,
)


def _make_repo_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "package.json",
            json.dumps(
                {
                    "dependencies": {
                        "next": "14.1.0",
                        "react": "18.2.0",
                        "@aws-sdk/client-s3": "3.0.0",
                    }
                }
            ),
        )
        archive.writestr(
            "requirements.txt",
            "\n".join(
                [
                    "fastapi==0.115.0",
                    "python-jose[cryptography]==3.3.0",
                    "auth0-python==4.7.2",
                    "boto3==1.35.0",
                    "stripe==10.12.0",
                ]
            ),
        )
        archive.writestr("app/api/auth/route.ts", "export async function POST() { return Response.json({ ok: true }); }")
        archive.writestr(
            "app/auth/callback.py",
            'from fastapi import APIRouter\nrouter = APIRouter(prefix="/auth")\n@router.get("/callback")\nasync def oidc_callback(code: str):\n    return {"ok": True}\n',
        )
        archive.writestr(
            "app/api/payments.py",
            "import stripe\nfrom fastapi import APIRouter, Depends\n\nasync def get_current_user():\n    return {'sub': '123'}\n\nrouter = APIRouter(prefix='/payments', dependencies=[Depends(get_current_user)])\n@router.post('/charge')\nasync def create_charge(card_number: str, account_number: str, email: str):\n    return stripe.Charge.create(amount=2000, currency='cad', metadata={'card_number': card_number, 'account_number': account_number, 'email': email})\n",
        )
        archive.writestr(
            "app/services/notifications.py",
            'import boto3\nsqs = boto3.client("sqs", region_name="ca-central-1")\ndef publish_notification(queue_url: str, message: str):\n    return sqs.send_message(QueueUrl=queue_url, MessageBody=message)\n',
        )
        archive.writestr(
            "src/routes/admin.js",
            "const express = require('express');\nconst router = express.Router();\nrouter.use(authMiddleware);\nrouter.get('/charges', listCharges);\nrouter.post('/webhook', webhookHandler);\nmodule.exports = router;\n",
        )
        archive.writestr("Dockerfile", "FROM node:20-alpine\n")
        archive.writestr("infra/main.tf", 'resource "aws_s3_bucket" "uploads" {}\n')
        archive.writestr(".env", "SECRET_KEY=should-not-be-read\n")
    return buffer.getvalue()


def test_parse_repository_evidence_extracts_high_signal_facts():
    evidence = parse_repository_evidence(
        _make_repo_zip(),
        "repo.zip",
        reference="private/main",
    )

    assert evidence.source_type == "archive"
    assert evidence.reference == "private/main"
    assert "TypeScript" in evidence.languages
    assert "Next.js" in evidence.frameworks
    assert "AWS services" in evidence.external_integrations
    assert "POST /api/auth" in evidence.api_routes
    assert "GET /auth/callback" in evidence.api_routes
    assert "POST /payments/charge" in evidence.api_routes
    assert "GET /auth/callback" in evidence.webhook_endpoints
    assert "Dockerfile present" in evidence.deployment_clues
    assert "OAuth 2.0 / OIDC" in evidence.auth_mechanisms
    assert "JWT bearer tokens" in evidence.auth_mechanisms
    assert "Stripe API calls" in evidence.outbound_calls
    assert "Amazon SQS publisher/client" in evidence.outbound_calls
    assert "Amazon S3 bucket" in evidence.infrastructure_resources
    route_auth_map = {(entry.method, entry.path): entry for entry in evidence.route_auth_map}
    assert route_auth_map[("POST", "/payments/charge")].auth_guards == ["get_current_user"]
    assert route_auth_map[("POST", "/payments/charge")].sensitive_data_signals == [
        "Payment card data",
        "Financial account data",
        "Personal contact data",
    ]
    assert route_auth_map[("POST", "/payments/charge")].validation_signals == ["Typed request parameters"]
    assert route_auth_map[("POST", "/payments/charge")].outbound_call_signals == ["Stripe SDK-authenticated call"]
    assert route_auth_map[("POST", "/payments/charge")].risk_flags == []
    assert route_auth_map[("GET", "/auth/callback")].auth_guards == []
    assert "GET /auth/callback" in evidence.unprotected_routes
    assert "POST /payments/charge -> Payment card data, Financial account data, Personal contact data" in evidence.sensitive_routes
    assert evidence.routes_with_raw_input == []
    assert evidence.risky_routes == []
    assert "GET /charges" in evidence.api_routes
    assert route_auth_map[("GET", "/charges")].auth_guards == ["authMiddleware"]
    payment_surface = next(
        surface for surface in evidence.code_surfaces if surface.name == "POST /payments/charge"
    )
    assert payment_surface.kind == "route"
    assert payment_surface.source_file == "app/api/payments.py"
    payment_control_types = {
        signal.control_type
        for signal in evidence.code_control_signals
        if signal.surface_id == payment_surface.id
    }
    assert {"authentication", "validation"} <= payment_control_types
    assert evidence.code_evidence_summary.surface_count >= 3
    assert evidence.code_evidence_summary.control_signal_count >= 2
    seed_labels = {suggestion.label for suggestion in evidence.dfd_seed_suggestions}
    assert "Application service" in seed_labels
    assert "API layer" in seed_labels
    assert "Object storage" in seed_labels
    assert "Amazon SQS" in seed_labels
    assert "Stripe" in seed_labels
    flow_labels = {flow.label for flow in evidence.dfd_seed_flow_suggestions}
    assert "reads/writes persisted data" in flow_labels
    assert "publishes async work" in flow_labels
    assert "calls external service" in flow_labels
    stripe_flow = next(
        flow
        for flow in evidence.dfd_seed_flow_suggestions
        if flow.label == "calls external service"
        and flow.target_seed_id == "repo-seed-external-entity-stripe"
    )
    assert stripe_flow.lifecycle_stage == "egress"
    boundary_names = {boundary.name for boundary in evidence.dfd_seed_boundary_suggestions}
    assert "Public API Boundary" in boundary_names
    assert "Data Tier Boundary" in boundary_names
    assert "Async Messaging Boundary" in boundary_names
    assert "Third-Party Boundary" in boundary_names
    third_party_boundary = next(
        boundary
        for boundary in evidence.dfd_seed_boundary_suggestions
        if boundary.name == "Third-Party Boundary"
    )
    assert third_party_boundary.boundary_type == "organizational"
    assert "repo-seed-external-entity-stripe" in third_party_boundary.seed_ids
    assert any("auth" in path.lower() for path in evidence.auth_surfaces)
    assert all(".env" not in path for path in evidence.security_sensitive_paths)


def test_parse_repository_evidence_rejects_empty_file():
    with pytest.raises(EvidenceValidationError, match="Repository evidence file is empty"):
        parse_repository_evidence(b"", "repo.zip")


def test_parse_repository_evidence_rejects_oversized_file(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(environment_evidence, "REPOSITORY_EVIDENCE_MAX_BYTES", 8)

    with pytest.raises(EvidenceValidationError, match="under 25 MB"):
        parse_repository_evidence(b"012345678", "repo.zip")


def test_parse_repository_evidence_rejects_path_traversal():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../evil.py", "print('bad')\n")

    with pytest.raises(EvidenceValidationError, match="invalid file path"):
        parse_repository_evidence(buffer.getvalue(), "repo.zip")


def test_parse_repository_evidence_rejects_binary_only_archive():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("logo.png", b"\x89PNG\r\n\x1a\n\x00\x00")
        archive.writestr("payload.exe", b"MZ\x00\x02")

    with pytest.raises(EvidenceValidationError, match="readable manifest or source files"):
        parse_repository_evidence(buffer.getvalue(), "repo.zip")


def test_parse_repository_evidence_rejects_unsupported_format():
    with pytest.raises(EvidenceValidationError, match="Unsupported repository evidence format"):
        parse_repository_evidence(b"not a zip", "repo.rar")


def test_parse_repository_evidence_rejects_corrupt_archive():
    with pytest.raises(EvidenceValidationError, match="Repository archive could not be read"):
        parse_repository_evidence(b"not-a-real-zip", "repo.zip")


def test_parse_repository_evidence_accepts_manifest_bundle_file():
    evidence = parse_repository_evidence(
        json.dumps({"dependencies": {"fastapi": "0.115.0"}}).encode("utf-8"),
        "package.json",
    )

    assert evidence.source_type == "manifest_bundle"
    assert "FastAPI" in evidence.frameworks


def test_parse_repository_evidence_accepts_single_source_file():
    evidence = parse_repository_evidence(
        b"from fastapi import APIRouter\nrouter = APIRouter()\n",
        "payments.py",
    )

    assert evidence.source_type == "single_file"
    assert evidence.file_count == 1
    assert "Python" in evidence.languages


def test_normalize_github_repository_slug_accepts_common_inputs():
    assert normalize_github_repository_slug("openai/threatgenix") == "openai/threatgenix"
    assert (
        normalize_github_repository_slug("https://github.com/openai/threatgenix")
        == "openai/threatgenix"
    )
    assert (
        normalize_github_repository_slug("git@github.com:openai/threatgenix.git")
        == "openai/threatgenix"
    )
    assert (
        normalize_github_repository_slug("ssh://git@github.com/openai/threatgenix.git")
        == "openai/threatgenix"
    )


def test_infer_github_pull_request_number_accepts_pull_refs():
    assert infer_github_pull_request_number("refs/pull/22/head") == 22
    assert infer_github_pull_request_number("refs/pull/22/merge") == 22
    assert infer_github_pull_request_number("main") is None


def test_parse_github_pull_request_url_accepts_github_pr_urls():
    parsed = parse_github_pull_request_url(
        "https://github.com/openai/threatgenix/pull/22/files"
    )

    assert parsed is not None
    assert parsed.repository == "openai/threatgenix"
    assert parsed.number == 22
    assert parsed.url == "https://github.com/openai/threatgenix/pull/22"


def test_resolve_github_repository_import_target_promotes_pr_url_to_ref():
    target = resolve_github_repository_import_target(
        repository="https://github.com/openai/threatgenix/pull/22"
    )

    assert target.repository == "openai/threatgenix"
    assert target.ref == "refs/pull/22/head"
    assert target.reference == "Pull request #22"
    assert target.pull_request_number == 22
    assert target.pull_request_url == "https://github.com/openai/threatgenix/pull/22"


def test_resolve_github_repository_import_target_rejects_conflicting_pr_inputs():
    with pytest.raises(
        EvidenceValidationError,
        match="must point at the same pull request",
    ):
        resolve_github_repository_import_target(
            repository="openai/threatgenix",
            ref="refs/pull/23/head",
            pull_request_url="https://github.com/openai/threatgenix/pull/22",
        )


@pytest.mark.asyncio
async def test_fetch_github_repository_archive_uses_bearer_token(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, object] = {}

    class _FakeResponse:
        status_code = 200
        headers: dict[str, str] = {}
        content = _make_repo_zip()

    class _FakeAsyncClient:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url: str, headers: dict[str, str]):
            captured["url"] = url
            captured["headers"] = headers
            return _FakeResponse()

    monkeypatch.setattr(environment_evidence.httpx, "AsyncClient", _FakeAsyncClient)

    archive_bytes, repository_slug, ref = await fetch_github_repository_archive(
        "https://github.com/openai/threatgenix",
        ref="main",
        github_token="ghp_secret",
    )

    assert archive_bytes == _make_repo_zip()
    assert repository_slug == "openai/threatgenix"
    assert ref == "main"
    assert captured["url"] == "https://api.github.com/repos/openai/threatgenix/zipball/main"
    assert captured["headers"] == {
        "Accept": "application/vnd.github+json",
        "User-Agent": "threatgenix/1.0",
        "Authorization": "Bearer ghp_secret",
    }


@pytest.mark.asyncio
async def test_fetch_github_pull_request_metadata_uses_bearer_token(monkeypatch: pytest.MonkeyPatch):
    captured: list[dict[str, object]] = []

    class _FakeResponse:
        status_code = 200
        headers: dict[str, str] = {}

        def __init__(self, payload: object):
            self._payload = payload

        def json(self):
            return self._payload

    class _FakeAsyncClient:
        def __init__(self, **kwargs):
            captured.append({"client_kwargs": kwargs})

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url: str, headers: dict[str, str], params: dict[str, int] | None = None):
            captured.append({"url": url, "headers": headers, "params": params})
            if url.endswith("/pulls/22"):
                return _FakeResponse(
                    {
                        "html_url": "https://github.com/openai/threatgenix/pull/22",
                        "title": "Harden payment callback",
                        "state": "open",
                        "base": {"ref": "main"},
                        "head": {"ref": "feature/payment-callback", "sha": "abc123"},
                        "changed_files": 2,
                    }
                )
            return _FakeResponse(
                [
                    {
                        "filename": "app/api/payments.py",
                        "status": "modified",
                        "additions": 12,
                        "deletions": 3,
                        "changes": 15,
                    },
                    {
                        "filename": "infra/main.tf",
                        "status": "added",
                        "additions": 8,
                        "deletions": 0,
                        "changes": 8,
                    },
                ]
            )

    monkeypatch.setattr(environment_evidence.httpx, "AsyncClient", _FakeAsyncClient)

    metadata = await fetch_github_pull_request_metadata(
        "https://github.com/openai/threatgenix",
        22,
        github_token="ghp_secret",
    )

    assert metadata.repository == "openai/threatgenix"
    assert metadata.number == 22
    assert metadata.title == "Harden payment callback"
    assert metadata.base_ref == "main"
    assert metadata.head_sha == "abc123"
    assert metadata.changed_file_count == 2
    assert [file.path for file in metadata.changed_files] == ["app/api/payments.py", "infra/main.tf"]
    assert captured[1]["headers"] == {
        "Accept": "application/vnd.github+json",
        "User-Agent": "threatgenix/1.0",
        "Authorization": "Bearer ghp_secret",
    }
    assert captured[2]["params"] == {"per_page": 100, "page": 1}


@pytest.mark.asyncio
async def test_fetch_github_pull_request_metadata_caps_changed_files(monkeypatch: pytest.MonkeyPatch):
    class _FakeResponse:
        status_code = 200
        headers: dict[str, str] = {}

        def __init__(self, payload: object):
            self._payload = payload

        def json(self):
            return self._payload

    class _FakeAsyncClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url: str, headers: dict[str, str], params: dict[str, int] | None = None):
            if url.endswith("/pulls/22"):
                return _FakeResponse({"changed_files": MAX_PULL_REQUEST_CHANGED_FILES + 50})
            page = params["page"] if params else 1
            return _FakeResponse(
                [
                    {"filename": f"src/file_{page}_{index}.py", "status": "modified"}
                    for index in range(100)
                ]
            )

    monkeypatch.setattr(environment_evidence.httpx, "AsyncClient", _FakeAsyncClient)

    metadata = await fetch_github_pull_request_metadata("openai/threatgenix", 22)

    assert len(metadata.changed_files) == MAX_PULL_REQUEST_CHANGED_FILES
    assert metadata.changed_file_count == MAX_PULL_REQUEST_CHANGED_FILES + 50
    assert metadata.truncated is True


@pytest.mark.asyncio
async def test_fetch_github_repository_archive_maps_not_found(monkeypatch: pytest.MonkeyPatch):
    class _FakeResponse:
        status_code = 404
        headers: dict[str, str] = {}
        content = b""

    class _FakeAsyncClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url: str, headers: dict[str, str]):
            return _FakeResponse()

    monkeypatch.setattr(environment_evidence.httpx, "AsyncClient", _FakeAsyncClient)

    with pytest.raises(EvidenceValidationError, match="repository not found"):
        await fetch_github_repository_archive("openai/missing-private-repo", github_token="ghp_secret")


@pytest.mark.asyncio
async def test_fetch_github_repository_archive_over_ssh_uses_private_key(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, object] = {"calls": []}

    async def _fake_run_git_command(args, *, cwd, env, timeout_seconds=60.0):
        ssh_parts = shlex.split(env["GIT_SSH_COMMAND"])
        captured["calls"].append({"args": args, "cwd": str(cwd), "ssh_parts": ssh_parts})
        if "-i" in ssh_parts and "private_key" not in captured:
            key_path = Path(ssh_parts[ssh_parts.index("-i") + 1])
            captured["private_key"] = key_path.read_text(encoding="utf-8")
        known_hosts_flag = next(part for part in ssh_parts if part.startswith("UserKnownHostsFile="))
        if "known_hosts" not in captured:
            known_hosts_path = Path(known_hosts_flag.split("=", 1)[1])
            captured["known_hosts"] = known_hosts_path.read_text(encoding="utf-8")
        if args[:2] == ["git", "checkout"]:
            repo_dir = Path(cwd)
            (repo_dir / "package.json").write_text(
                json.dumps({"dependencies": {"fastapi": "0.115.0"}}),
                encoding="utf-8",
            )
            (repo_dir / "app" / "api").mkdir(parents=True, exist_ok=True)
            (repo_dir / "app" / "api" / "auth.py").write_text(
                "from fastapi import APIRouter\nrouter = APIRouter()\n",
                encoding="utf-8",
            )
            (repo_dir / ".env").write_text("SECRET_KEY=skip-me\n", encoding="utf-8")
        return "", ""

    monkeypatch.setattr(environment_evidence, "_run_git_command", _fake_run_git_command)
    private_key_header = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    private_key_footer = "-----END " + "OPENSSH PRIVATE KEY-----"

    archive_bytes, repository_slug, ref = await fetch_github_repository_archive_over_ssh(
        "git@github.com:openai/threatgenix.git",
        ref="main",
        ssh_private_key=(
            f"{private_key_header}\n"
            "FAKE_OPENSSH_PRIVATE_KEY_FOR_TESTS\n"
            f"{private_key_footer}"
        ),
    )

    evidence = parse_repository_evidence(archive_bytes, "openai-threatgenix.zip")

    assert repository_slug == "openai/threatgenix"
    assert ref == "main"
    assert evidence.source_type == "archive"
    assert "Python" in evidence.languages
    assert all(".env" not in path for path in evidence.security_sensitive_paths)
    assert str(captured["private_key"]).startswith(f"{private_key_header}\n")
    assert "FAKE_OPENSSH_PRIVATE_KEY_FOR_TESTS\n" in str(captured["private_key"])
    assert str(captured["private_key"]).endswith(f"{private_key_footer}\n")
    assert "github.com ssh-ed25519" in str(captured["known_hosts"])
    calls = captured["calls"]
    assert any(call["args"][:3] == ["git", "remote", "add"] for call in calls)
    assert any(call["args"][:4] == ["git", "fetch", "--depth", "1"] for call in calls)


def test_parse_cloud_scan_evidence_from_prowler_json():
    content = json.dumps(
        [
            {
                "FindingUniqueId": "prowler-ec2-sg-public-443",
                "Status": "FAIL",
                "Severity": "high",
                "StatusExtended": "Security group allows 0.0.0.0/0 on port 443",
                "ServiceName": "ec2",
                "ResourceArn": "sg-12345",
            },
            {
                "Status": "PASS",
                "Severity": "low",
                "StatusExtended": "This should be ignored",
                "ServiceName": "s3",
                "ResourceArn": "bucket-1",
            },
        ]
    ).encode("utf-8")

    evidence = parse_cloud_scan_evidence(content, "prowler.json")

    assert evidence.provider == "prowler"
    assert evidence.finding_count == 1
    assert evidence.exposed_services
    assert evidence.high_signal_findings[0].category == "internet_exposure"
    assert evidence.high_signal_findings[0].source_finding_id == "prowler-ec2-sg-public-443"


def test_parse_cloud_scan_evidence_rejects_oversized_file(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(environment_evidence, "CLOUD_SCAN_EVIDENCE_MAX_BYTES", 8)

    with pytest.raises(EvidenceValidationError, match="under 50 MB"):
        parse_cloud_scan_evidence(b"012345678", "prowler.json")


def test_parse_cloud_scan_evidence_rejects_invalid_json():
    with pytest.raises(EvidenceValidationError, match="Cloud scan JSON could not be parsed"):
        parse_cloud_scan_evidence(b"{invalid", "prowler.json")


def test_parse_cloud_scan_evidence_from_scoutsuite_js():
    payload = {
        "services": {
            "iam": {
                "findings": [
                    {
                        "description": "Cross-account trust with external principal and no MFA",
                        "severity": "high",
                    }
                ]
            }
        },
        "metadata": {"provider": "aws"},
    }
    content = f"var scoutsuite_results = {json.dumps(payload)};".encode("utf-8")

    evidence = parse_cloud_scan_evidence(content, "scoutsuite_results.js")

    assert evidence.provider == "scoutsuite"
    assert evidence.finding_count >= 1
    categories = {finding.category for finding in evidence.high_signal_findings}
    assert "cross_account_trust" in categories or "mfa_gap" in categories


def test_parse_cloud_scan_evidence_from_scoutsuite_zip():
    payload = {
        "services": {
            "storage": {
                "findings": [
                    {"description": "Publicly accessible bucket with encryption disabled"}
                ]
            }
        },
        "metadata": {"provider": "aws"},
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "scoutsuite-report/scoutsuite_results.js",
            f"var scoutsuite_results = {json.dumps(payload)};",
        )

    evidence = parse_cloud_scan_evidence(buffer.getvalue(), "scoutsuite-output.zip")

    assert evidence.provider == "scoutsuite"
    assert evidence.finding_count >= 1
    assert any(finding.category == "public_storage" for finding in evidence.high_signal_findings)


def test_parse_cloud_scan_evidence_allows_zero_matching_findings():
    evidence = parse_cloud_scan_evidence(
        json.dumps(
            [
                {
                    "Status": "FAIL",
                    "Severity": "low",
                    "StatusExtended": "Minor naming convention drift only",
                    "ServiceName": "ec2",
                    "ResourceArn": "sg-12345",
                }
            ]
        ).encode("utf-8"),
        "prowler.json",
    )

    assert evidence.finding_count == 0
    assert evidence.exposed_services == []
    assert evidence.identity_risks == []


def test_parse_cloud_scan_evidence_rejects_corrupt_zip():
    with pytest.raises(EvidenceValidationError, match="Cloud scan archive could not be read"):
        parse_cloud_scan_evidence(b"not-a-real-zip", "scan.zip")


def test_compose_environment_context_summary_includes_both_sources():
    repo = parse_repository_evidence(_make_repo_zip(), "repo.zip", reference="monorepo/api")
    cloud = parse_cloud_scan_evidence(
        json.dumps(
            [
                {
                    "Status": "FAIL",
                    "Severity": "critical",
                    "StatusExtended": "AdministratorAccess attached with wildcard permissions",
                    "ServiceName": "iam",
                    "ResourceArn": "role/admin",
                }
            ]
        ).encode("utf-8"),
        "prowler.json",
    )

    summary = compose_environment_context_summary(repo, cloud)

    assert summary is not None
    assert "## Repository Evidence" in summary
    assert "## Cloud Posture Evidence" in summary
    assert "Frameworks" in summary
    assert "API routes" in summary
    assert "Routes with no detected auth guard" in summary
    assert "Routes touching sensitive data" in summary
    assert "Route outbound-call posture" in summary
    assert "Outbound calls and publishers" in summary


def test_parse_iac_evidence_extracts_terraform_and_kubernetes_signals():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "main.tf",
            '\n'.join(
                [
                    'resource "aws_security_group" "public_api" {}',
                    'resource "aws_iam_role" "app_role" {}',
                    'resource "aws_db_instance" "payments" {}',
                    'cidr_blocks = ["0.0.0.0/0"]',
                    'secret_key = "aws_secretsmanager_secret.db_password"',
                ]
            ),
        )
        archive.writestr(
            "deployment.yaml",
            """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
spec: {}
---
apiVersion: v1
kind: Service
metadata:
  name: payments-public
spec:
  type: LoadBalancer
""",
        )

    evidence = parse_iac_evidence(buffer.getvalue(), "infra.zip", reference="prod/payments")

    assert evidence.source_type == "archive"
    assert evidence.reference == "prod/payments"
    assert evidence.resource_count >= 4
    assert "aws_security_group" in evidence.resource_types
    assert "Deployment" in evidence.resource_types
    assert "Deployment:payments-api" in evidence.resource_names
    assert any("public" in item.lower() for item in evidence.public_exposure)
    assert any("iam" in item.lower() for item in evidence.iam_bindings)
    assert any("network" in item.lower() for item in evidence.network_paths)
    assert any("secret" in item.lower() for item in evidence.secret_refs)


def test_parse_iac_evidence_accepts_single_manifest_file():
    content = json.dumps(
        {
            "Resources": {
                "PublicBucket": {"Type": "AWS::S3::Bucket"},
                "AdminRole": {"Type": "AWS::IAM::Role"},
            }
        }
    ).encode("utf-8")

    evidence = parse_iac_evidence(content, "template.json")

    assert evidence.source_type == "single_file"
    assert evidence.resource_count == 2
    assert "AWS::S3::Bucket" in evidence.resource_types
    assert "AWS::S3::Bucket:PublicBucket" in evidence.resource_names


def test_compose_environment_context_summary_includes_iac_section():
    repo = parse_repository_evidence(_make_repo_zip(), "repo.zip", reference="monorepo/api")
    cloud = parse_cloud_scan_evidence(
        json.dumps(
            [
                {
                    "Status": "FAIL",
                    "Severity": "critical",
                    "StatusExtended": "AdministratorAccess attached with wildcard permissions",
                    "ServiceName": "iam",
                    "ResourceArn": "role/admin",
                }
            ]
        ).encode("utf-8"),
        "prowler.json",
    )
    iac = parse_iac_evidence(
        b'resource "aws_s3_bucket" "uploads" {}\nresource "aws_iam_role" "app_role" {}\n',
        "main.tf",
        reference="prod/network",
    )

    summary = compose_environment_context_summary(repo, cloud, iac)

    assert summary is not None
    assert "## IaC Evidence" in summary
    assert "Infrastructure resources parsed" in summary
    assert "Resource types" in summary
    assert "IAM or trust risks" in summary


def test_parse_repository_evidence_extracts_flask_route_guard_mapping():
    content = (
        b"from flask import Flask\n"
        b"from flask_login import login_required\n"
        b"app = Flask(__name__)\n\n"
        b"@app.route('/admin/users', methods=['GET'])\n"
        b"@login_required\n"
        b"def admin_users():\n"
        b"    return 'ok'\n"
    )

    evidence = parse_repository_evidence(content, "admin.py")

    route_auth_map = {(entry.method, entry.path): entry for entry in evidence.route_auth_map}
    assert route_auth_map[("GET", "/admin/users")].auth_guards == ["login_required"]
    assert evidence.unprotected_routes == []


def test_parse_repository_evidence_propagates_router_level_fastapi_dependencies():
    content = (
        b"from fastapi import APIRouter, Depends\n\n"
        b"async def require_admin():\n"
        b"    return {'ok': True}\n\n"
        b"router = APIRouter(prefix='/admin', dependencies=[Depends(require_admin)])\n"
        b"@router.get('/users')\n"
        b"async def list_users():\n"
        b"    return []\n"
    )

    evidence = parse_repository_evidence(content, "admin_routes.py")

    route_auth_map = {(entry.method, entry.path): entry for entry in evidence.route_auth_map}
    assert route_auth_map[("GET", "/admin/users")].auth_guards == ["require_admin"]


def test_parse_repository_evidence_scopes_express_router_use_by_prefix():
    content = (
        b"const express = require('express');\n"
        b"const router = express.Router();\n"
        b"router.use('/admin', authMiddleware);\n"
        b"router.get('/admin/users', listUsers);\n"
        b"router.get('/health', healthHandler);\n"
    )

    evidence = parse_repository_evidence(content, "routes.ts")

    route_auth_map = {(entry.method, entry.path): entry for entry in evidence.route_auth_map}
    assert route_auth_map[("GET", "/admin/users")].auth_guards == ["authMiddleware"]
    assert route_auth_map[("GET", "/health")].auth_guards == []


def test_parse_repository_evidence_extracts_sensitive_data_signals_from_express_handler():
    content = (
        b"const express = require('express');\n"
        b"const stripe = require('stripe')('sk_test');\n"
        b"const router = express.Router();\n"
        b"router.post('/payments/charge', authMiddleware, createCharge);\n"
        b"async function createCharge(req, res) {\n"
        b"  const { cardNumber, cvv, email } = req.body;\n"
        b"  await stripe.charges.create({ source: { number: cardNumber, cvc: cvv }, receipt_email: email });\n"
        b"  res.json({ ok: true });\n"
        b"}\n"
    )

    evidence = parse_repository_evidence(content, "charges.js")

    route_auth_map = {(entry.method, entry.path): entry for entry in evidence.route_auth_map}
    assert route_auth_map[("POST", "/payments/charge")].auth_guards == ["authMiddleware"]
    assert route_auth_map[("POST", "/payments/charge")].sensitive_data_signals == [
        "Payment card data",
        "Personal contact data",
    ]
    assert route_auth_map[("POST", "/payments/charge")].validation_signals == ["Raw JSON/body access"]
    assert route_auth_map[("POST", "/payments/charge")].outbound_call_signals == ["Stripe SDK-authenticated call"]


def test_parse_repository_evidence_correlates_unprotected_raw_unsigned_route_risk():
    content = (
        b"const express = require('express');\n"
        b"const axios = require('axios');\n"
        b"const router = express.Router();\n"
        b"router.post('/callbacks/vendor', relayVendor);\n"
        b"async function relayVendor(req, res) {\n"
        b"  const { accountNumber, token } = req.body;\n"
        b"  await axios.post('https://vendor.example/api', { accountNumber, token });\n"
        b"  res.json({ ok: true });\n"
        b"}\n"
    )

    evidence = parse_repository_evidence(content, "vendor_callbacks.js")

    route_auth_map = {(entry.method, entry.path): entry for entry in evidence.route_auth_map}
    entry = route_auth_map[("POST", "/callbacks/vendor")]
    assert entry.auth_guards == []
    assert entry.sensitive_data_signals == [
        "Tokens and session secrets",
        "Financial account data",
    ]
    assert entry.validation_signals == ["Raw JSON/body access"]
    assert entry.outbound_call_signals == ["HTTP call without auth/signing evidence"]
    assert entry.risk_flags == [
        "No auth guard on sensitive-data route",
        "Raw input on sensitive-data route",
        "No auth guard on route with unsigned outbound call",
        "Raw input reaches unsigned outbound call",
    ]
    assert "POST /callbacks/vendor" in evidence.unprotected_routes
    assert "POST /callbacks/vendor" in evidence.routes_with_raw_input
    assert any(
        item.startswith("POST /callbacks/vendor -> No auth guard on sensitive-data route")
        and "Raw input on sensitive-data route" in item
        for item in evidence.risky_routes
    )
    callback_surface = next(
        surface for surface in evidence.code_surfaces if surface.name == "POST /callbacks/vendor"
    )
    callback_risks = [
        signal for signal in evidence.code_risk_signals if signal.surface_id == callback_surface.id
    ]
    assert {signal.risk_type for signal in callback_risks} >= {
        "missing_authentication",
        "missing_validation",
        "unsigned_outbound_call",
    }
    assert evidence.code_evidence_summary.unprotected_sensitive_surface_count == 1


def test_compose_environment_context_summary_respects_budget(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(environment_evidence, "ENVIRONMENT_CONTEXT_CHAR_BUDGET", 120)

    repo = parse_repository_evidence(_make_repo_zip(), "repo.zip", reference="a" * 400)
    cloud = parse_cloud_scan_evidence(
        json.dumps(
            [
                {
                    "Status": "FAIL",
                    "Severity": "critical",
                    "StatusExtended": "AdministratorAccess attached with wildcard permissions " * 10,
                    "ServiceName": "iam",
                    "ResourceArn": "role/admin",
                }
            ]
        ).encode("utf-8"),
        "prowler.json",
    )

    summary = compose_environment_context_summary(repo, cloud)

    assert summary is not None
    assert len(summary) <= 120


def test_environment_evidence_constants_still_match_product_contract():
    assert REPOSITORY_EVIDENCE_MAX_BYTES == 25 * 1024 * 1024
    assert CLOUD_SCAN_EVIDENCE_MAX_BYTES == 50 * 1024 * 1024
    assert ENVIRONMENT_CONTEXT_CHAR_BUDGET == 3_000


def test_prepare_environment_evidence_fixtures_creates_northstar_bundle(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        sys,
        "argv",
        ["prepare_environment_evidence_fixtures", "--output-dir", str(tmp_path)],
    )

    prepare_environment_evidence_fixtures.main()

    assert (tmp_path / "northstar-mobile-api.zip").exists()
    assert (tmp_path / "northstar-manifests-only.zip").exists()
    assert (tmp_path / "northstar-prowler-staging.json").exists()
    assert (tmp_path / "scoutsuite-output.zip").exists()
    assert (tmp_path / "northstar-architecture.pdf").exists()
    manifest = json.loads((tmp_path / "environment-evidence-fixtures.json").read_text())
    assert "repo_archive" in manifest
    assert "architecture_pdf" in manifest

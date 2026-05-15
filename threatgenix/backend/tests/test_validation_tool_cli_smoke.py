"""Opt-in executable smoke tests for locally installed validation CLIs.

Run with:
    THREATGENIX_RUN_VALIDATION_CLI_SMOKE=1 pytest tests/test_validation_tool_cli_smoke.py -q
"""
from __future__ import annotations

import os
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.services.validation_execution_policy import default_validation_execution_policy_registry
from app.services.validation_sandbox import ValidationSandboxRunner, resolve_validation_executable
from app.services.validation_tools import (
    CheckovValidationAdapter,
    NUCLEI_TEMPLATES_ENV,
    NucleiValidationAdapter,
    OSVScannerValidationAdapter,
    SemgrepValidationAdapter,
    TrivyValidationAdapter,
    TrufflehogValidationAdapter,
)

pytestmark = pytest.mark.skipif(
    os.getenv("THREATGENIX_RUN_VALIDATION_CLI_SMOKE") != "1",
    reason="set THREATGENIX_RUN_VALIDATION_CLI_SMOKE=1 to run local scanner CLIs",
)

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_SOURCE_ROOT = REPO_ROOT / "tests" / "validation_tool_fixtures" / "semantic_bank"
VULNERABLE_NPM_LOCK_FIXTURE = FIXTURE_SOURCE_ROOT / "vulnerable-npm-lock.fixture.json"
NUCLEI_BASELINE_TEMPLATE = (
    REPO_ROOT
    / "threatgenix"
    / "backend"
    / "app"
    / "services"
    / "validation_rules"
    / "nuclei-safe-http-baseline.yaml"
)


class _HeaderlessHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"ThreatGenix validation smoke target"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture
def local_http_target() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HeaderlessHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def cli_fixture_root(tmp_path: Path) -> Path:
    """Materialize scanner fixtures with real manifest names outside the repo."""
    fixture_root = tmp_path / "semantic_bank"
    shutil.copytree(FIXTURE_SOURCE_ROOT, fixture_root)
    shutil.copyfile(VULNERABLE_NPM_LOCK_FIXTURE, fixture_root / "package-lock.json")
    return fixture_root


@pytest.mark.asyncio
async def test_installed_nuclei_cli_executes_safe_local_template(
    monkeypatch: pytest.MonkeyPatch,
    local_http_target: str,
) -> None:
    if resolve_validation_executable("nuclei") is None:
        pytest.skip("nuclei is not installed")

    monkeypatch.setenv(NUCLEI_TEMPLATES_ENV, str(NUCLEI_BASELINE_TEMPLATE))
    adapter = NucleiValidationAdapter()
    adapter.timeout_seconds = 20

    result = await adapter.run(local_http_target, target_type="url")

    assert result.returncode == 0, result.stderr
    assert result.output_sha256
    assert len(result.findings) >= 1
    assert result.findings[0].template_id == "threatgenix-missing-security-headers"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter", "target", "target_type", "template_tags", "expected_min_findings"),
    [
        (
            SemgrepValidationAdapter(),
            FIXTURE_SOURCE_ROOT,
            "repository_path",
            None,
            1,
        ),
        (
            OSVScannerValidationAdapter(),
            FIXTURE_SOURCE_ROOT / "package-lock.json",
            "lockfile",
            None,
            1,
        ),
        (
            TrivyValidationAdapter(),
            FIXTURE_SOURCE_ROOT / "infra",
            "iac_directory",
            "misconfig",
            1,
        ),
        (
            CheckovValidationAdapter(),
            FIXTURE_SOURCE_ROOT / "infra",
            "iac_directory",
            None,
            1,
        ),
        (
            TrufflehogValidationAdapter(),
            FIXTURE_SOURCE_ROOT,
            "repository_path",
            None,
            0,
        ),
    ],
)
async def test_installed_validation_cli_executes_through_sandbox(
    adapter,
    target: Path,
    target_type: str,
    template_tags: str | None,
    expected_min_findings: int,
    cli_fixture_root: Path,
) -> None:
    if resolve_validation_executable(adapter.executable) is None:
        pytest.skip(f"{adapter.executable} is not installed")

    resolved_target = Path(str(target).replace(str(FIXTURE_SOURCE_ROOT), str(cli_fixture_root)))
    policy = default_validation_execution_policy_registry().get(adapter.name)
    result = await adapter.run(
        str(resolved_target),
        target_type=target_type,
        template_tags=template_tags,
        policy=policy,
        sandbox_runner=ValidationSandboxRunner(allowed_roots=[str(cli_fixture_root)]),
    )

    assert result.sandboxed is True
    assert result.returncode == 0, result.stderr
    assert result.output_sha256
    assert len(result.findings) >= expected_min_findings

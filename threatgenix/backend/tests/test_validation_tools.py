"""Tests for deterministic validation tool adapters and scan worker integration."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.scan import ScanFinding, ScanJob, ValidationSchedule
from app.services.validation_tools import (
    AI_RED_TEAM_TOOL_NAME,
    AiRedTeamValidationAdapter,
    CheckovValidationAdapter,
    ExternalReportImportAdapter,
    NUCLEI_TAGS_AUTH_EXTRA,
    NUCLEI_TAGS_BASE,
    NUCLEI_TEMPLATES_ENV,
    NucleiValidationAdapter,
    OSVScannerValidationAdapter,
    PentestReportImportAdapter,
    SemgrepValidationAdapter,
    TrivyValidationAdapter,
    TrufflehogValidationAdapter,
    ValidationEvidence,
    ValidationToolUnavailable,
    ValidationToolResult,
    default_evidence_import_tool_registry,
    default_validation_tool_registry,
    redact_validation_command,
)
from app.services.validation_execution_policy import (
    TARGET_AI_SYSTEM,
    TARGET_REPOSITORY_PATH,
    TARGET_URL,
    default_validation_execution_policy_registry,
)
from app.services.validation_sandbox import ValidationSandboxResult


def test_nuclei_command_generation_unauthenticated():
    adapter = NucleiValidationAdapter()

    command = adapter.build_command("https://api.example.com")

    assert command[:6] == [
        "nuclei",
        "-u",
        "https://api.example.com",
        "-tags",
        NUCLEI_TAGS_BASE,
        "-jsonl",
    ]
    assert "-silent" in command
    assert "-no-color" in command
    assert "-duc" in command
    assert "-no-stdin" in command
    assert "-H" not in command


def test_nuclei_command_generation_authenticated():
    adapter = NucleiValidationAdapter()
    auth_headers = ["-H", "Authorization: Bearer token-123"]
    tags = f"{NUCLEI_TAGS_BASE},{NUCLEI_TAGS_AUTH_EXTRA}"

    command = adapter.build_command(
        "https://api.example.com",
        auth_headers=auth_headers,
        template_tags=tags,
    )

    assert command[command.index("-tags") + 1] == tags
    assert command[-2:] == auth_headers


def test_nuclei_command_generation_uses_operator_template_override(monkeypatch):
    adapter = NucleiValidationAdapter()
    monkeypatch.setenv(
        NUCLEI_TEMPLATES_ENV,
        "/opt/threatgenix/templates/safe.yml:/opt/threatgenix/templates/headers.yml",
    )

    command = adapter.build_command("https://api.example.com")

    assert "-tags" not in command
    assert command[command.index("-t") + 1] == "/opt/threatgenix/templates/safe.yml"
    assert command[command.index("-t", command.index("-t") + 1) + 1] == (
        "/opt/threatgenix/templates/headers.yml"
    )


@pytest.mark.asyncio
async def test_nuclei_can_run_through_container_sandbox_without_host_cli():
    adapter = NucleiValidationAdapter()
    policy = default_validation_execution_policy_registry().get("nuclei")
    output = json.dumps(
        {
            "template-id": "exposed-panel",
            "info": {
                "name": "Exposed Admin Panel",
                "severity": "high",
                "tags": ["exposure"],
            },
            "matched-at": "https://api.example.com/admin",
        }
    ).encode("utf-8")

    class FakeSandboxRunner:
        async def run(
            self,
            command,
            *,
            tool_name,
            executable,
            target,
            target_type,
            timeout_seconds,
            max_output_bytes,
        ):
            assert command[0] == "nuclei"
            assert tool_name == "nuclei"
            assert executable == "nuclei"
            assert target == "https://api.example.com"
            assert target_type == "url"
            assert timeout_seconds == policy.max_runtime_seconds
            assert max_output_bytes == policy.max_output_bytes
            return ValidationSandboxResult(
                command=[
                    "/usr/local/bin/docker",
                    "run",
                    "projectdiscovery/nuclei:latest",
                ],
                target=target,
                resolved_target=target,
                returncode=0,
                stdout=output,
                stderr="",
                sandbox_mode="container",
                container_image="projectdiscovery/nuclei:latest",
                network_policy="bridge",
                resource_limits={"cpus": "1"},
            )

    result = await adapter.run(
        "https://api.example.com",
        target_type="url",
        policy=policy,
        sandbox_runner=FakeSandboxRunner(),  # type: ignore[reportArgumentType]
    )

    assert result.sandboxed is True
    assert result.sandbox_mode == "container"
    assert result.container_image == "projectdiscovery/nuclei:latest"
    assert result.findings[0].finding_title == "Exposed Admin Panel"


@pytest.mark.asyncio
async def test_nuclei_host_cli_honors_policy_output_limit(monkeypatch):
    adapter = NucleiValidationAdapter()

    class FakeProcess:
        returncode = 0

    async def fake_create_subprocess_exec(*args, stdout, stderr):
        return FakeProcess()

    monkeypatch.setattr(adapter, "is_available", lambda: True)
    monkeypatch.setattr(
        "app.services.validation_tools.resolve_validation_executable",
        lambda executable: f"/usr/local/bin/{executable}",
    )
    monkeypatch.setattr(
        "app.services.validation_tools.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    monkeypatch.setattr(
        "app.services.validation_tools._communicate_with_output_cap",
        AsyncMock(return_value=(b"x" * 8, b"", True)),
    )

    result = await adapter.run(
        "https://api.example.com",
        policy=SimpleNamespace(max_runtime_seconds=5, max_output_bytes=8),
    )

    assert result.output_limit_exceeded is True
    assert result.stdout_bytes == 8
    assert result.findings == []


def test_default_registry_exposes_current_runnable_validation_adapters():
    registry = default_validation_tool_registry()
    tools = {adapter.name: adapter for adapter in registry.list()}

    assert set(tools) == {
        "nuclei",
        "semgrep",
        "osv-scanner",
        "trivy",
        "checkov",
        "trufflehog",
        "ai-red-team",
    }
    assert tools["nuclei"].active is True
    assert tools["semgrep"].active is True
    assert tools["osv-scanner"].active is True
    assert tools["trivy"].active is True
    assert tools["checkov"].active is True
    assert tools["trufflehog"].active is True
    assert tools["ai-red-team"].active is True
    assert tools["ai-red-team"].is_available() is True


def test_evidence_import_registry_adds_import_only_sources():
    registry = default_evidence_import_tool_registry()
    tools = {adapter.name: adapter for adapter in registry.list()}

    assert {"external-report", "pentest-report"}.issubset(tools)
    assert tools["external-report"].is_available() is True
    assert tools["external-report"].active is False
    assert tools["pentest-report"].deterministic is False


def test_scan_job_constraints_include_current_validation_tool_types():
    constraints = {
        constraint.name: str(constraint.sqltext)
        for constraint in ScanJob.__table__.constraints  # type: ignore[reportAttributeAccessIssue]
        if constraint.name in {"ck_scan_jobs_tool_name", "ck_scan_jobs_target_type"}
    }

    assert "nuclei" in constraints["ck_scan_jobs_tool_name"]
    assert "semgrep" in constraints["ck_scan_jobs_tool_name"]
    assert "checkov" in constraints["ck_scan_jobs_tool_name"]
    assert "trufflehog" in constraints["ck_scan_jobs_tool_name"]
    assert "ai-red-team" in constraints["ck_scan_jobs_tool_name"]
    assert "external-report" in constraints["ck_scan_jobs_tool_name"]
    assert "pentest-report" in constraints["ck_scan_jobs_tool_name"]
    assert "zap-baseline" not in constraints["ck_scan_jobs_tool_name"]
    assert "promptfoo" not in constraints["ck_scan_jobs_tool_name"]
    assert "container_image" in constraints["ck_scan_jobs_target_type"]
    assert "ai_system" in constraints["ck_scan_jobs_target_type"]


def test_validation_schedule_constraints_include_ai_red_team():
    constraints = {
        constraint.name: str(constraint.sqltext)
        for constraint in ValidationSchedule.__table__.constraints  # type: ignore[reportAttributeAccessIssue]
        if constraint.name
        in {"ck_validation_schedules_tool_name", "ck_validation_schedules_target_type"}
    }

    assert "ai-red-team" in constraints["ck_validation_schedules_tool_name"]
    assert "promptfoo" not in constraints["ck_validation_schedules_tool_name"]
    assert "ai_system" in constraints["ck_validation_schedules_target_type"]


def test_ai_red_team_parser_normalizes_promptfoo_failures():
    adapter = AiRedTeamValidationAdapter()
    fixture = Path("tests/fixtures/validation_lab/outputs/promptfoo-redteam.json")

    findings = adapter.parse_output("Northstar AI Assistant", fixture.read_text())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool_name == AI_RED_TEAM_TOOL_NAME
    assert finding.deterministic is True
    assert finding.severity == "high"
    assert finding.matched_url == "https"
    assert finding.template_id == "ai-red-team-promptfoo-1"
    assert "ai-red-team" in finding.tags
    assert "prompt-injection" in finding.tags
    assert "data-exfiltration" in finding.tags
    assert "sensitive-information-disclosure" in finding.tags
    assert finding.extracted_results == "category=data-exfiltration; strategy=prompt-injection; result=attack_success; score=0.2"
    assert "private account context" not in (finding.extracted_results or "")
    assert "prompts, completions" in finding.raw_output["redaction"]


def test_ai_red_team_parser_evaluates_native_ai_system_spec():
    adapter = AiRedTeamValidationAdapter()
    fixture = Path("tests/fixtures/validation_lab/outputs/ai-system-redteam.json")

    findings = adapter.parse_output("Northstar Support Agent", fixture.read_text())

    assert [finding.template_id for finding in findings] == [
        "ai-red-team-pi-001",
        "ai-red-team-jb-001",
        "ai-red-team-leak-001",
        "ai-red-team-rag-001",
        "ai-red-team-tool-001",
        "ai-red-team-dos-001",
    ]
    all_tags = {tag for finding in findings for tag in finding.tags}
    assert {"prompt-injection", "jailbreak", "data-exfiltration"}.issubset(all_tags)
    assert {"rag-poisoning", "agent-tool-abuse", "model-dos"}.issubset(all_tags)
    assert findings[0].raw_output["system"]["name"] == "Northstar Support Agent"
    assert "prompt" not in findings[0].raw_output["case"]
    assert "observed_behavior" not in findings[0].raw_output["case"]
    assert "reason" not in findings[1].raw_output["case"]
    assert "evidence" not in findings[2].raw_output["case"]


def test_ai_red_team_parser_does_not_persist_freeform_evidence_or_secrets():
    adapter = AiRedTeamValidationAdapter()
    raw_output = json.dumps(
        {
            "test_cases": [
                {
                    "id": "LEAK-SECRET",
                    "category": "sensitive_info",
                    "attack_success": True,
                    "target": "support-agent",
                    "reason": "SECRET_TOKEN=abc123 and full prompt text",
                    "evidence": "password=letmein and completion body",
                    "details": {"prompt": "reveal tenant data"},
                }
            ]
        }
    )

    findings = adapter.parse_output("Northstar Support Agent", raw_output)

    assert len(findings) == 1
    serialized = json.dumps(findings[0].raw_output).casefold()
    assert "abc123" not in serialized
    assert "full prompt text" not in serialized
    assert "completion body" not in serialized
    assert "reveal tenant data" not in serialized
    assert "secret_token" not in (findings[0].extracted_results or "").casefold()
    assert findings[0].extracted_results == "category=sensitive-info; result=attack_success"


def test_ai_red_team_execution_policy_is_native_no_network():
    registry = default_validation_execution_policy_registry()
    policy = registry.get(AI_RED_TEAM_TOOL_NAME)

    assert policy.supported_targets == [TARGET_AI_SYSTEM]
    assert policy.network_mode == "none"
    assert policy.execution_enabled is True
    assert policy.category == "ai_system_red_team"
    assert "no model provider calls" in policy.safety_boundary


def test_ai_system_target_metadata_is_redacted():
    evidence = ValidationEvidence(
        tool_name=AI_RED_TEAM_TOOL_NAME,
        target="/Users/customer/private-ai/redteam.json",
        severity="high",
        finding_title="Prompt injection exploit demonstrated",
        cve_ids=[],
        tags=["ai-red-team", "prompt-injection"],
        matched_url="support-agent",
        raw_output={"case": {"id": "PI-001"}},
        template_id="ai-red-team-pi-001",
    )

    finding = evidence.to_scan_finding(uuid.uuid4(), target_type=TARGET_AI_SYSTEM)
    metadata = finding.raw_output["threatgenix_validation"]

    assert metadata["target"].startswith("redteam.json (sha256:")
    assert "/Users/customer" not in metadata["target"]
    assert metadata["target_type"] == TARGET_AI_SYSTEM


@pytest.mark.asyncio
async def test_ai_red_team_run_reads_allowlisted_ai_system_file(tmp_path, monkeypatch):
    target_file = tmp_path / "ai-system.json"
    target_file.write_text(
        json.dumps(
            {
                "system": {"name": "Northstar Agent"},
                "test_cases": [
                    {
                        "id": "TOOL-001",
                        "category": "agent-tool-abuse",
                        "attack_success": True,
                        "target": "refund tool",
                        "reason": "Unauthorized tool call reached a privileged action.",
                    }
                ],
            }
        )
    )
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(tmp_path))
    adapter = AiRedTeamValidationAdapter()
    policy = default_validation_execution_policy_registry().get(AI_RED_TEAM_TOOL_NAME)

    result = await adapter.run(
        str(target_file),
        target_type=TARGET_AI_SYSTEM,
        policy=policy,
    )

    assert result.returncode == 0
    assert result.sandboxed is True
    assert result.network_policy == "none"
    assert result.resolved_target == str(target_file)
    assert result.findings[0].template_id == "ai-red-team-tool-001"
    assert "agent-tool-abuse" in result.findings[0].tags


@pytest.mark.asyncio
async def test_scan_target_persists_ai_red_team_findings(tmp_path, monkeypatch):
    from app.services.scan_worker import _scan_target

    target_file = tmp_path / "ai-system.json"
    target_file.write_text(
        json.dumps(
            {
                "system": {"name": "Northstar Agent"},
                "test_cases": [
                    {
                        "id": "LEAK-001",
                        "category": "data-exfiltration",
                        "attack_success": True,
                        "target": "customer context window",
                        "reason": "Returned another tenant account summary.",
                    }
                ],
            }
        )
    )
    monkeypatch.setenv("THREATGENIX_VALIDATION_ALLOWED_PATHS", str(tmp_path))
    db = MagicMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    adapter = AiRedTeamValidationAdapter()
    policy = default_validation_execution_policy_registry().get(AI_RED_TEAM_TOOL_NAME)

    findings = await _scan_target(
        db,
        uuid.uuid4(),
        str(target_file),
        "ai-system-node",
        tool=adapter,
        target_type=TARGET_AI_SYSTEM,
        policy=policy,
    )

    assert len(findings) == 1
    assert findings[0].template_id == "ai-red-team-leak-001"
    assert "data-exfiltration" in findings[0].tags
    added_objects = [call.args[0] for call in db.add.call_args_list]
    artifacts = [
        item
        for item in added_objects
        if item.__class__.__name__ == "ScanExecutionArtifact"
    ]
    assert len(artifacts) == 1
    assert artifacts[0].tool_name == AI_RED_TEAM_TOOL_NAME
    assert artifacts[0].target_type == TARGET_AI_SYSTEM
    assert artifacts[0].status == "completed"
    assert "[ai_system:ai-system.json:sha256:" in " ".join(artifacts[0].command)
    db.commit.assert_awaited_once()


def test_external_report_import_parser_normalizes_generic_json_findings():
    adapter = ExternalReportImportAdapter()
    raw_output = json.dumps(
        {
            "scanner": "Burp Enterprise",
            "findings": [
                {
                    "id": "BURP-1",
                    "title": "API Gateway accepts unsigned JWT",
                    "severity": "High",
                    "stride": "Spoofing",
                    "target": "API Gateway",
                    "description": "The API Gateway accepts unsigned JWT tokens.",
                    "tags": ["jwt", "auth bypass"],
                }
            ],
        }
    )

    findings = adapter.parse_output("Imported web assessment", raw_output)

    assert len(findings) == 1
    assert findings[0].tool_name == "external-report"
    assert findings[0].deterministic is True
    assert findings[0].template_id == "BURP-1"
    assert findings[0].severity == "high"
    assert findings[0].matched_url == "API Gateway"
    assert "spoofing" in findings[0].tags
    assert "auth-bypass" in findings[0].tags
    assert findings[0].finding_title.startswith("Burp Enterprise:")


def test_pentest_report_import_parser_accepts_plain_text_findings():
    adapter = PentestReportImportAdapter()
    raw_output = """
High: Card Token Vault privilege escalation

The tester chained an IDOR in the API Gateway to access another customer's card token record.
Impact: privilege escalation and information disclosure.
"""

    findings = adapter.parse_output("Q2 pentest report", raw_output)

    assert len(findings) == 1
    assert findings[0].tool_name == "pentest-report"
    assert findings[0].deterministic is False
    assert findings[0].severity == "high"
    assert findings[0].matched_url == "Q2 pentest report"
    assert "idor" in findings[0].tags
    assert "elevation-of-privilege" in findings[0].tags


def test_nuclei_json_parser_normalizes_representative_finding():
    adapter = NucleiValidationAdapter()
    data = {
        "template-id": "http/cves/2026/vendor-auth-bypass",
        "info": {
            "name": "Vendor Auth Bypass",
            "severity": "HIGH",
            "tags": "auth-bypass,cve,jwt",
            "classification": {
                "cve-id": ["CVE-2026-1111", "CVE-2026-2222"],
                "cvss-score": "9.1",
            },
        },
        "matched-at": "https://api.example.com/admin",
        "extracted-results": ["issuer=trusted", "role=admin"],
    }

    evidence = adapter.parse_json_line("https://api.example.com", data)

    assert evidence is not None
    assert evidence.tool_name == "nuclei"
    assert evidence.target == "https://api.example.com"
    assert evidence.deterministic is True
    assert evidence.severity == "high"
    assert evidence.finding_title == "Vendor Auth Bypass"
    assert evidence.template_id == "http/cves/2026/vendor-auth-bypass"
    assert evidence.cve_ids == ["CVE-2026-1111", "CVE-2026-2222"]
    assert evidence.tags == ["auth-bypass", "cve", "jwt"]
    assert evidence.matched_url == "https://api.example.com/admin"
    assert evidence.extracted_results == "issuer=trusted, role=admin"
    assert evidence.cvss_score == 9.1


def test_nuclei_output_parser_skips_malformed_and_empty_lines():
    adapter = NucleiValidationAdapter()
    valid = {
        "template-id": "exposure",
        "info": {"name": "Env Exposure", "severity": "low", "tags": ["exposure"]},
        "host": "https://api.example.com/.env",
    }
    output = "\n".join(
        [
            "",
            "not-json",
            json.dumps(["not", "a", "finding"]),
            json.dumps({"info": {"name": "missing template"}}),
            json.dumps(valid),
        ]
    )

    findings = adapter.parse_output("https://api.example.com", output)

    assert len(findings) == 1
    assert findings[0].template_id == "exposure"
    assert findings[0].matched_url == "https://api.example.com/.env"


def test_nuclei_output_parser_handles_noisy_real_world_jsonl():
    adapter = NucleiValidationAdapter()
    output = "\n".join(
        [
            "nuclei v3.2.8 started with 7231 templates",
            json.dumps({"template-id": "", "info": {"severity": "low"}}),
            json.dumps(
                {
                    "template-id": "http/cves/2026/api-gateway-auth-bypass",
                    "template-url": "https://github.com/projectdiscovery/nuclei-templates",
                    "info": {
                        "name": "API Gateway Authorization Bypass",
                        "author": ["threatgenix-test"],
                        "severity": "Critical",
                        "tags": "auth-bypass, jwt , cve , noisy-log",
                        "classification": {
                            "cve-id": "CVE-2026-4444",
                            "cvss-score": "not-a-number",
                        },
                    },
                    "type": "http",
                    "host": "https://merchant.example.test",
                    "matched-at": "https://merchant.example.test/admin?debug=true",
                    "ip": "203.0.113.10",
                    "timestamp": "2026-04-29T10:00:00Z",
                    "extracted-results": "status=200",
                }
            ),
        ]
    )

    findings = adapter.parse_output("https://merchant.example.test", output)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.template_id == "http/cves/2026/api-gateway-auth-bypass"
    assert finding.severity == "critical"
    assert finding.cve_ids == ["CVE-2026-4444"]
    assert "jwt" in finding.tags
    assert finding.cvss_score is None
    assert finding.matched_url == "https://merchant.example.test/admin?debug=true"
    assert finding.extracted_results == "status=200"


def test_validation_evidence_persists_tool_metadata_in_raw_output():
    evidence = ValidationEvidence(
        tool_name="nuclei",
        target="https://api.example.com",
        severity="medium",
        finding_title="SQL Injection",
        cve_ids=["CVE-2026-3333"],
        tags=["sqli", "cve"],
        matched_url="https://api.example.com/search",
        raw_output={"template-id": "sqli-template"},
        template_id="sqli-template",
    )

    finding = evidence.to_scan_finding(uuid.uuid4())

    assert finding.template_id == "sqli-template"
    assert finding.raw_output["template-id"] == "sqli-template"
    assert finding.raw_output["threatgenix_validation"] == {
        "tool_name": "nuclei",
        "tool_version": None,
        "target": "https://api.example.com",
        "deterministic": True,
    }
    assert (
        finding.raw_output["semantic_review_validation"]
        == finding.raw_output["threatgenix_validation"]
    )
    assert (
        finding.raw_output["ssr_validation"]
        == finding.raw_output["threatgenix_validation"]
    )
    assert finding.tool_name == "nuclei"
    assert finding.validation_target == "https://api.example.com"
    assert finding.deterministic is True


def test_scan_finding_reads_semantic_review_validation_metadata_alias():
    finding = ScanFinding(
        scan_job_id=uuid.uuid4(),
        template_id="semantic-check",
        template_name="Semantic Check",
        severity="medium",
        matched_at="app/main.py:12",
        cve_ids=[],
        tags=["semgrep"],
        raw_output={
            "semantic_review_validation": {
                "tool_name": "semgrep",
                "target": "repo (sha256:test)",
                "deterministic": True,
            }
        },
    )

    assert finding.tool_name == "semgrep"
    assert finding.validation_target == "repo (sha256:test)"
    assert finding.deterministic is True


def test_validation_evidence_redacts_path_target_metadata():
    evidence = ValidationEvidence(
        tool_name="semgrep",
        target="/Users/customer/private-repo",
        severity="high",
        finding_title="JWT verification disabled",
        cve_ids=[],
        tags=["semgrep"],
        matched_url="app/auth.py:42",
        raw_output={"path": "app/auth.py"},
        template_id="python.jwt.decode-without-verify",
    )

    finding = evidence.to_scan_finding(uuid.uuid4(), target_type="repository_path")
    metadata = finding.raw_output["threatgenix_validation"]

    assert metadata["target"].startswith("private-repo (sha256:")
    assert "/Users/customer" not in metadata["target"]
    assert metadata["target_type"] == "repository_path"


def test_validation_command_redaction_preserves_header_name_without_secret():
    command = [
        "nuclei",
        "-u",
        "https://api.example.com",
        "-H",
        "Authorization: Bearer secret-token",
        "--token",
        "secret-token",
    ]

    redacted = redact_validation_command(command)

    assert "secret-token" not in " ".join(redacted)
    assert redacted[redacted.index("-H") + 1] == "Authorization: [redacted]"
    assert redacted[redacted.index("--token") + 1] == "[redacted]"


def test_validation_command_redaction_replaces_local_path_targets():
    redacted = redact_validation_command(
        ["semgrep", "scan", "--json", "/Users/example/customer/repo"],
        target="/Users/example/customer/repo",
        resolved_target="/Users/example/customer/repo",
        target_type="repository_path",
    )

    joined = " ".join(redacted)
    assert "/Users/example/customer/repo" not in joined
    assert "[repository_path:repo:sha256:" in joined


def test_validation_command_redaction_keeps_executable_and_numeric_flags():
    redacted = redact_validation_command(
        [
            "/opt/homebrew/bin/nuclei",
            "-u",
            "https://api.example.com",
            "-c",
            "5",
        ],
        target="https://api.example.com",
        resolved_target="https://api.example.com",
        target_type="url",
    )

    assert redacted[0] == "/opt/homebrew/bin/nuclei"
    assert redacted[redacted.index("-c") + 1] == "5"


def test_validation_command_redaction_replaces_nuclei_template_paths():
    redacted = redact_validation_command(
        [
            "/opt/homebrew/bin/nuclei",
            "-u",
            "https://api.example.com",
            "-t",
            "/Users/example/threatgenix/templates/safe.yaml",
        ],
        target="https://api.example.com",
        resolved_target="https://api.example.com",
        target_type="url",
    )

    assert "/Users/example/threatgenix/templates/safe.yaml" not in " ".join(redacted)
    assert redacted[redacted.index("-t") + 1] == "[local-file-redacted]"


def test_validation_command_redaction_keeps_tool_binary_for_path_scans():
    redacted = redact_validation_command(
        [
            "/opt/homebrew/bin/semgrep",
            "scan",
            "--config",
            "/Users/example/threatgenix/rules.yml",
            "--project-root",
            "/Users/example/customer/repo",
            "/Users/example/customer/repo",
        ],
        target="/Users/example/customer/repo",
        resolved_target="/Users/example/customer/repo",
        target_type="repository_path",
    )

    assert redacted[0] == "/opt/homebrew/bin/semgrep"
    assert redacted[redacted.index("--config") + 1] == "[local-file-redacted]"
    assert redacted[redacted.index("--project-root") + 1] == "[local-file-redacted]"
    assert redacted[-1].startswith("[repository_path:repo:sha256:")


def test_scan_worker_stderr_summary_redacts_secret_and_local_path():
    from app.services.scan_worker import _summarize_stderr

    summary = _summarize_stderr(
        "Authorization: Bearer secret-token failed at /Users/example/customer/repo/app.py "
        "password=hunter2 token=abc in /home/render/project/src/app.py"
    )

    assert summary is not None
    assert "secret-token" not in summary
    assert "hunter2" not in summary
    assert "/Users/example/customer" not in summary
    assert "/home/render/project" not in summary
    assert "[local-path-redacted]" in summary


def test_scan_worker_execution_artifact_sanitizes_resolved_target_path():
    from app.services.scan_worker import _build_execution_artifact

    tool = default_validation_tool_registry().get("semgrep")
    policy = default_validation_execution_policy_registry().get("semgrep")
    raw_path = "/Users/example/customer/repo"
    result = ValidationToolResult(
        tool_name="semgrep",
        target=raw_path,
        findings=[],
        command=["semgrep", "scan", "--json", raw_path],
        returncode=0,
        stdout_bytes=2,
        stderr="",
        timed_out=False,
        output_limit_exceeded=False,
        output_sha256="0" * 64,
        resolved_target=raw_path,
    )

    artifact = _build_execution_artifact(
        scan_job_id=uuid.uuid4(),
        tool=tool,  # type: ignore[reportArgumentType]
        target=raw_path,
        target_type=TARGET_REPOSITORY_PATH,
        policy=policy,
        policy_decision="allowed",
        result=result,
    )

    assert artifact.resolved_target != raw_path
    assert artifact.resolved_target is not None
    assert artifact.resolved_target.startswith("repo (sha256:")


def test_scan_finding_response_exposes_validation_metadata():
    from app.schemas.scan import ScanFindingResponse

    evidence = ValidationEvidence(
        tool_name="nuclei",
        target="https://api.example.com",
        severity="high",
        finding_title="Auth Bypass",
        cve_ids=["CVE-2026-1111"],
        tags=["auth-bypass"],
        matched_url="https://api.example.com/admin",
        raw_output={"template-id": "auth-bypass"},
        template_id="auth-bypass",
    )
    finding = evidence.to_scan_finding(uuid.uuid4())
    finding.id = uuid.uuid4()
    finding.created_at = datetime(2026, 4, 25, tzinfo=timezone.utc)

    response = ScanFindingResponse.model_validate(finding)

    assert response.tool_name == "nuclei"
    assert response.validation_target == "https://api.example.com"
    assert response.deterministic is True


def test_scan_job_response_exposes_validation_dispatch_fields():
    from app.models.scan import ScanJob
    from app.schemas.scan import ScanJobResponse

    job = ScanJob(
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        status="completed",
        scan_type="unauthenticated",
        scope="external",
        tool_name="semgrep",
        target_type="repository_path",
        targets={"ingested": "/repo"},
        finding_count=2,
    )
    job.id = uuid.uuid4()
    job.created_at = datetime(2026, 4, 25, tzinfo=timezone.utc)

    response = ScanJobResponse.model_validate(job)

    assert response.tool_name == "semgrep"
    assert response.target_type == "repository_path"


def test_scan_job_detail_response_exposes_execution_artifacts():
    from app.models.scan import ScanExecutionArtifact, ScanJob
    from app.schemas.scan import ScanJobDetailResponse

    job_id = uuid.uuid4()
    job = ScanJob(
        threat_model_id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        status="completed",
        scan_type="unauthenticated",
        scope="external",
        tool_name="semgrep",
        target_type="repository_path",
        targets={"direct": "/repo"},
        finding_count=0,
    )
    job.id = job_id
    job.created_at = datetime(2026, 4, 25, tzinfo=timezone.utc)
    artifact = ScanExecutionArtifact(
        scan_job_id=job_id,
        source="execution",
        tool_name="semgrep",
        target_type="repository_path",
        target="/repo",
        status="completed",
        deterministic=True,
        sandboxed=True,
        policy_decision="execution permitted by validation policy",
        command=["semgrep", "scan", "--json", "/repo"],
        command_redacted=True,
        returncode=0,
        timed_out=False,
        output_limit_exceeded=False,
        stdout_bytes=123,
        network_mode="none",
        max_runtime_seconds=600,
        max_output_bytes=5_000_000,
        duration_ms=42,
    )
    artifact.id = uuid.uuid4()
    artifact.created_at = datetime(2026, 4, 25, tzinfo=timezone.utc)
    job.execution_artifacts.append(artifact)

    response = ScanJobDetailResponse.model_validate(job)

    assert len(response.execution_artifacts) == 1
    assert response.execution_artifacts[0].tool_name == "semgrep"
    assert response.execution_artifacts[0].sandboxed is True
    assert response.execution_artifacts[0].stdout_bytes == 123


@pytest.mark.asyncio
async def test_missing_nuclei_marks_scan_failed_with_existing_message(monkeypatch):
    from app.services.scan_worker import _execute_scan

    monkeypatch.setenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "self_hosted")
    job = MagicMock()
    job.id = uuid.uuid4()
    job.status = "pending"
    job.error_message = None
    job.completed_at = None

    result = MagicMock()
    result.scalar_one_or_none.return_value = job

    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()

    with patch("app.services.scan_worker._nuclei_available", return_value=False):
        await _execute_scan(db, job.id)

    assert job.status == "failed"
    assert job.error_message == (
        "Nuclei CLI not installed. Install from https://github.com/projectdiscovery/nuclei"
    )
    assert job.completed_at is not None
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_scan_target_passes_authenticated_headers_to_validation_tool(monkeypatch):
    from app.services.scan_worker import _scan_target

    evidence = ValidationEvidence(
        tool_name="nuclei",
        target="https://api.example.com",
        severity="high",
        finding_title="Auth Bypass",
        cve_ids=[],
        tags=["auth-bypass"],
        matched_url="https://api.example.com/admin",
        raw_output={"template-id": "auth-bypass"},
        template_id="auth-bypass",
    )

    class FakeValidationTool:
        name = "nuclei"
        deterministic = True
        timeout_seconds = 600

        def __init__(self) -> None:
            self.calls: list[dict] = []

        def is_available(self) -> bool:
            return True

        def build_command(self, target, *, auth_headers=None, template_tags=None):
            return []

        def parse_json_line(self, target, data):
            return None

        async def run(
            self,
            target,
            *,
            auth_headers=None,
            template_tags=None,
            target_type=None,
            policy=None,
        ):
            self.calls.append(
                {
                    "target": target,
                    "auth_headers": auth_headers,
                    "template_tags": template_tags,
                    "target_type": target_type,
                    "policy": policy,
                }
            )
            return ValidationToolResult(
                tool_name=self.name,
                target=target,
                findings=[evidence],
            )

    db = MagicMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    tool = FakeValidationTool()
    auth_headers = ["-H", "Authorization: Bearer token-123"]
    template_tags = f"{NUCLEI_TAGS_BASE},{NUCLEI_TAGS_AUTH_EXTRA}"
    monkeypatch.setattr(
        "app.services.scan_worker.validate_live_url_target",
        lambda target: None,
    )

    findings = await _scan_target(
        db,
        uuid.uuid4(),
        "https://api.example.com",
        "api-node",
        auth_headers=auth_headers,
        nuclei_tags=template_tags,
        tool=tool,  # type: ignore[reportArgumentType]
    )

    assert tool.calls == [
        {
            "target": "https://api.example.com",
            "auth_headers": auth_headers,
            "template_tags": template_tags,
            "target_type": TARGET_URL,
            "policy": tool.calls[0]["policy"],
        }
    ]
    assert tool.calls[0]["policy"].tool_name == "nuclei"
    assert len(findings) == 1
    assert findings[0].raw_output["threatgenix_validation"]["tool_name"] == "nuclei"
    assert (
        findings[0].raw_output["threatgenix_validation"]["evidence_origin"]
        == "execution"
    )
    assert findings[0].raw_output["threatgenix_validation"]["synthetic"] is False
    added_objects = [call.args[0] for call in db.add.call_args_list]
    assert findings[0] in added_objects
    artifacts = [
        item
        for item in added_objects
        if item.__class__.__name__ == "ScanExecutionArtifact"
    ]
    assert len(artifacts) == 1
    assert artifacts[0].tool_name == "nuclei"
    assert artifacts[0].status == "completed"
    assert artifacts[0].policy_decision == "execution permitted by validation policy"
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_scan_target_does_not_pass_nuclei_tags_to_repository_tools(monkeypatch):
    from app.services.scan_worker import _scan_target

    class FakeRepositoryTool:
        name = "semgrep"
        deterministic = True
        timeout_seconds = 600

        def __init__(self) -> None:
            self.calls: list[dict] = []

        def is_available(self) -> bool:
            return True

        def build_command(
            self, target, *, auth_headers=None, template_tags=None, target_type=None
        ):
            return []

        def parse_json_line(self, target, data):
            return None

        async def run(
            self,
            target,
            *,
            auth_headers=None,
            template_tags=None,
            target_type=None,
            policy=None,
            sandbox_runner=None,
        ):
            self.calls.append(
                {
                    "target": target,
                    "auth_headers": auth_headers,
                    "template_tags": template_tags,
                    "target_type": target_type,
                    "policy": policy,
                    "sandbox_runner": sandbox_runner,
                }
            )
            return ValidationToolResult(tool_name=self.name, target=target, findings=[])

    db = MagicMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    tool = FakeRepositoryTool()
    monkeypatch.setenv("VALIDATION_SEMGREP_ENABLED", "true")
    policy = default_validation_execution_policy_registry().get("semgrep")

    await _scan_target(
        db,
        uuid.uuid4(),
        "/repo",
        "repo-node",
        nuclei_tags=NUCLEI_TAGS_BASE,
        tool=tool,  # type: ignore[reportArgumentType]
        target_type=TARGET_REPOSITORY_PATH,
        policy=policy,
    )

    assert tool.calls == [
        {
            "target": "/repo",
            "auth_headers": None,
            "template_tags": None,
            "target_type": TARGET_REPOSITORY_PATH,
            "policy": policy,
            "sandbox_runner": tool.calls[0]["sandbox_runner"],
        }
    ]
    assert tool.calls[0]["sandbox_runner"] is not None


@pytest.mark.asyncio
async def test_scan_target_rejects_policy_denied_tool_execution():
    from app.services.scan_worker import _scan_target

    with patch.dict("os.environ", {"THREATGENIX_VALIDATION_SEMGREP_ENABLED": "false"}):
        policy = default_validation_execution_policy_registry().get("semgrep")
    adapter = SemgrepValidationAdapter()
    db = MagicMock()
    db.add = MagicMock()
    db.commit = AsyncMock()

    with pytest.raises(
        ValidationToolUnavailable, match="disabled until sandbox enforcement"
    ):
        await _scan_target(
            db,
            uuid.uuid4(),
            "/repo",
            "repo-node",
            tool=adapter,
            target_type=TARGET_REPOSITORY_PATH,
            policy=policy,
        )

    artifacts = [
        call.args[0]
        for call in db.add.call_args_list
        if call.args[0].__class__.__name__ == "ScanExecutionArtifact"
    ]
    assert len(artifacts) == 1
    assert artifacts[0].status == "blocked"
    assert "disabled until sandbox enforcement" in artifacts[0].policy_decision
    db.commit.assert_not_awaited()


def test_semgrep_command_generation_and_json_parser():
    adapter = SemgrepValidationAdapter()

    command = adapter.build_command("/repo", template_tags="p/security-audit")
    assert command == [
        "semgrep",
        "scan",
        "--config",
        "p/security-audit",
        "--json",
        "--metrics=off",
        "--quiet",
        "--no-git-ignore",
        "/repo",
    ]

    findings = adapter.parse_json_document(
        "/repo",
        {
            "results": [
                {
                    "check_id": "python.jwt.decode-without-verify",
                    "path": "app/auth.py",
                    "start": {"line": 42, "col": 9},
                    "extra": {
                        "message": "JWT verification disabled",
                        "severity": "ERROR",
                        "metadata": {
                            "category": "security",
                            "technology": ["python", "jwt"],
                            "cve": "CVE-2026-1111",
                        },
                    },
                }
            ]
        },
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool_name == "semgrep"
    assert finding.severity == "high"
    assert finding.finding_title == "JWT verification disabled"
    assert finding.template_id == "python.jwt.decode-without-verify"
    assert finding.matched_url == "app/auth.py:42"
    assert finding.cve_ids == ["CVE-2026-1111"]
    assert "sast" in finding.tags


def test_semgrep_parser_tolerates_noisy_results_and_missing_locations():
    adapter = SemgrepValidationAdapter()

    findings = adapter.parse_json_document(
        "/repo",
        {
            "version": "1.72.0",
            "errors": [{"code": 3, "message": "ignored parse warning"}],
            "paths": {"scanned": ["app/auth.py", "app/handlers.py"]},
            "results": [
                {
                    "check_id": "python.fastapi.missing-tenant-filter",
                    "path": "app/handlers.py",
                    "extra": {
                        "message": "Query omits tenant-scoped threat_model_id filter",
                        "severity": "WARNING",
                        "metadata": {
                            "category": ["security", "multi-tenant"],
                            "technology": "python,fastapi",
                            "references": ["CVE-2026-5555 tenant escape"],
                        },
                    },
                },
                {
                    "path": "app/no-rule.py",
                    "extra": {"message": "missing check id should be skipped"},
                },
            ],
        },
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.template_id == "python.fastapi.missing-tenant-filter"
    assert finding.severity == "medium"
    assert finding.matched_url == "app/handlers.py"
    assert finding.cve_ids == ["CVE-2026-5555"]
    assert "python" in finding.tags
    assert "multi-tenant" in finding.tags


def test_semgrep_command_prefers_local_rules_and_novcs_project_root(tmp_path):
    adapter = SemgrepValidationAdapter()
    repo = tmp_path / "repo"
    repo.mkdir()
    rules = repo / "semgrep-rules.yml"
    rules.write_text("rules: []\n")

    command = adapter.build_command(str(repo), target_type=TARGET_REPOSITORY_PATH)

    assert command[command.index("--config") + 1] == str(rules)
    assert "--novcs" in command
    assert command[command.index("--project-root") + 1] == str(repo)
    assert command[-1] == str(repo)


def test_semgrep_default_config_is_packaged():
    adapter = SemgrepValidationAdapter()

    assert Path(adapter.default_tags).is_file()


def test_osv_scanner_command_generation_and_json_parser():
    adapter = OSVScannerValidationAdapter()

    assert adapter.build_command("/repo") == [
        "osv-scanner",
        "scan",
        "--format",
        "json",
        "/repo",
    ]

    findings = adapter.parse_json_document(
        "/repo",
        {
            "results": [
                {
                    "source": {"path": "package-lock.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "left-pad",
                                "version": "1.3.0",
                                "ecosystem": "npm",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-aaaa-bbbb-cccc",
                                    "aliases": ["CVE-2026-2222"],
                                    "summary": "Prototype pollution",
                                    "severity": [
                                        {
                                            "type": "CVSS_V3",
                                            "score": "7.5/CVSS:3.1/AV:N",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool_name == "osv-scanner"
    assert finding.severity == "high"
    assert finding.template_id == "GHSA-aaaa-bbbb-cccc"
    assert finding.cve_ids == ["CVE-2026-2222"]
    assert finding.matched_url == "package-lock.json"
    assert "dependency" in finding.tags


def test_osv_scanner_parser_ignores_empty_packages_and_uses_database_severity():
    adapter = OSVScannerValidationAdapter()

    findings = adapter.parse_json_document(
        "/repo/package-lock.json",
        {
            "results": [
                {
                    "source": {"path": "package-lock.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "@merchant/session-store",
                                "version": "4.2.0",
                                "ecosystem": "npm",
                            },
                            "groups": [
                                {
                                    "ids": ["GHSA-osv-group"],
                                    "aliases": ["CVE-2026-7777"],
                                    "max_severity": "9.3",
                                }
                            ],
                            "vulnerabilities": [],
                        },
                        {
                            "package": {
                                "name": "express",
                                "version": "4.17.1",
                                "ecosystem": "npm",
                            },
                            "vulnerabilities": [
                                {"aliases": ["CVE-2026-6666"]},
                                {
                                    "id": "GHSA-tenant-session-fixation",
                                    "aliases": ["CVE-2026-6666"],
                                    "summary": "Session fixation in shared tenant middleware",
                                    "database_specific": {"severity": "HIGH"},
                                },
                            ],
                        },
                    ],
                },
                {"source": "not-a-dict", "packages": "not-a-list"},
            ]
        },
    )

    assert len(findings) == 2
    group_finding = findings[0]
    assert group_finding.template_id == "GHSA-osv-group"
    assert group_finding.severity == "critical"
    assert group_finding.cve_ids == ["CVE-2026-7777"]
    finding = findings[1]
    assert finding.template_id == "GHSA-tenant-session-fixation"
    assert finding.severity == "high"
    assert finding.cve_ids == ["CVE-2026-6666"]
    assert finding.matched_url == "package-lock.json"
    assert finding.extracted_results == "npm:express@4.17.1"


def test_trivy_command_generation_and_json_parser():
    adapter = TrivyValidationAdapter()

    assert adapter.build_command("/repo") == [
        "trivy",
        "fs",
        "--format",
        "json",
        "--scanners",
        "misconfig",
        "--no-progress",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--skip-version-check",
        "--skip-vex-repo-update",
        "--offline-scan",
        "/repo",
    ]
    explicit_scanners_command = adapter.build_command(
        "/repo", template_tags="vuln,misconfig"
    )
    assert (
        explicit_scanners_command[explicit_scanners_command.index("--scanners") + 1]
        == "vuln,misconfig"
    )
    assert adapter.build_command(
        "registry.example.com/api:latest", target_type="container_image"
    ) == [
        "trivy",
        "image",
        "--format",
        "json",
        "--scanners",
        "vuln",
        "--no-progress",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--skip-version-check",
        "--skip-vex-repo-update",
        "--offline-scan",
        "registry.example.com/api:latest",
    ]

    findings = adapter.parse_json_document(
        "/repo",
        {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Class": "config",
                    "Type": "dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "AVD-DS-0002",
                            "Title": "Root user",
                            "Severity": "HIGH",
                            "CauseMetadata": {"Resource": "USER root", "StartLine": 12},
                        }
                    ],
                },
                {
                    "Target": "requirements.txt",
                    "Type": "python-pkg",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-3333",
                            "PkgName": "requests",
                            "InstalledVersion": "2.0.0",
                            "Severity": "CRITICAL",
                            "Title": "TLS bypass",
                            "CVSS": {"nvd": {"V3Score": 9.8}},
                        }
                    ],
                },
            ]
        },
    )

    assert len(findings) == 2
    assert findings[0].tool_name == "trivy"
    assert findings[0].template_id == "AVD-DS-0002"
    assert findings[0].matched_url == "Dockerfile:12"
    assert findings[1].template_id == "CVE-2026-3333"
    assert findings[1].cvss_score == 9.8
    assert findings[1].cve_ids == ["CVE-2026-3333"]


def test_trivy_parser_handles_mixed_vulnerability_and_misconfig_noise():
    adapter = TrivyValidationAdapter()

    findings = adapter.parse_json_document(
        "registry.example.test/payment-api:2026.04",
        {
            "SchemaVersion": 2,
            "ArtifactName": "registry.example.test/payment-api:2026.04",
            "Metadata": {"ImageID": "sha256:test"},
            "Results": [
                {
                    "Target": "payment-api:2026.04",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "PkgName": "openssl",
                            "InstalledVersion": "3.1.0-r0",
                            "Severity": "HIGH",
                        },
                        {
                            "VulnerabilityID": "CVE-2026-7777",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.1.0-r0",
                            "Severity": "UNKNOWN",
                            "Title": "TLS tenant boundary bypass",
                            "CVSS": {
                                "redhat": {"V3Score": 6.8},
                                "nvd": {"V3Score": 9.1},
                            },
                        },
                    ],
                },
                {
                    "Target": "k8s/deployment.yaml",
                    "Class": "config",
                    "Type": "kubernetes",
                    "Misconfigurations": [
                        {
                            "AVDID": "AVD-KSV-0104",
                            "Message": "Container runs as root",
                            "Severity": "MEDIUM",
                            "CauseMetadata": "line metadata unavailable",
                        }
                    ],
                },
            ],
        },
    )

    assert len(findings) == 2
    vuln, misconfig = findings
    assert vuln.template_id == "CVE-2026-7777"
    assert vuln.cvss_score == 9.1
    assert vuln.matched_url == "payment-api:2026.04"
    assert misconfig.template_id == "AVD-KSV-0104"
    assert misconfig.matched_url == "k8s/deployment.yaml"
    assert misconfig.extracted_results == "k8s/deployment.yaml"


def test_checkov_command_generation_and_json_parser():
    adapter = CheckovValidationAdapter()

    assert adapter.build_command("/repo/infra", template_tags="CKV_AWS_20") == [
        "checkov",
        "--directory",
        "/repo/infra",
        "--output",
        "json",
        "--quiet",
        "--skip-download",
        "--skip-results-upload",
        "--soft-fail",
        "--check",
        "CKV_AWS_20",
    ]

    findings = adapter.parse_json_document(
        "/repo/infra",
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "check_name": "S3 bucket allows public read",
                        "file_path": "/s3.tf",
                        "file_line_range": [8, 20],
                        "resource": "aws_s3_bucket.public",
                        "severity": "HIGH",
                    }
                ]
            }
        },
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool_name == "checkov"
    assert finding.severity == "high"
    assert finding.template_id == "CKV_AWS_20"
    assert finding.matched_url == "/s3.tf:8"
    assert finding.extracted_results == "aws_s3_bucket.public"
    assert "iac" in finding.tags


def test_checkov_parser_handles_multi_framework_output_and_partial_ranges():
    adapter = CheckovValidationAdapter()

    findings = adapter.parse_json_document(
        "/repo/infra",
        [
            {
                "check_type": "terraform",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_20",
                            "bc_check_id": "BC_AWS_PUBLIC_1",
                            "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
                            "file_path": "/terraform/s3.tf",
                            "file_line_range": [],
                            "resource": "aws_s3_bucket_acl.public",
                            "guideline": "https://docs.bridgecrew.io/docs/s3_1-acl-read-permissions-everyone",
                            "severity": None,
                        }
                    ]
                },
            },
            {
                "check_type": "kubernetes",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_K8S_21",
                            "check_name": "The default namespace should not be used",
                            "file_path": "/k8s/deployment.yaml",
                            "file_line_range": [4, 25],
                            "resource": "Deployment.default.payment-api",
                            "severity": "LOW",
                        },
                        {"check_name": "missing id should be skipped"},
                    ]
                },
            },
        ],
    )

    assert len(findings) == 2
    public_bucket, namespace = findings
    assert public_bucket.template_id == "CKV_AWS_20"
    assert public_bucket.severity == "unknown"
    assert public_bucket.matched_url == "/terraform/s3.tf"
    assert "exposure" in public_bucket.tags
    assert namespace.template_id == "CKV_K8S_21"
    assert namespace.matched_url == "/k8s/deployment.yaml:4"


def test_trufflehog_parser_handles_noisy_ndjson_without_real_secrets():
    adapter = TrufflehogValidationAdapter()
    output = "\n".join(
        [
            json.dumps(["progress", "ignored"]),
            "not-json",
            json.dumps(
                {
                    "SourceMetadata": {
                        "Data": {
                            "Filesystem": {
                                "file": "config/.env.example",
                                "line": 7,
                            }
                        }
                    },
                    "DetectorName": "Stripe",
                    "Verified": False,
                    "Raw": "redacted_test_token_do_not_use",
                }
            ),
        ]
    )

    findings = adapter.parse_output("/repo", output)

    assert len(findings) == 1
    secret = findings[0]
    assert secret.template_id == "trufflehog-stripe"
    assert secret.severity == "low"
    assert secret.matched_url == "config/.env.example:7"
    assert "unverified" in secret.tags
    assert "redacted_test_token_do_not_use" in secret.raw_output["Raw"]


@pytest.mark.asyncio
async def test_sandboxed_adapter_run_uses_runner_and_parses_output():
    adapter = SemgrepValidationAdapter()
    raw_output = json.dumps(
        {
            "results": [
                {
                    "check_id": "python.jwt.decode-without-verify",
                    "path": "app/auth.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "JWT verification disabled",
                        "severity": "ERROR",
                    },
                }
            ]
        }
    ).encode("utf-8")

    class FakeSandboxRunner:
        def __init__(self) -> None:
            self.calls: list[dict] = []

        async def run(self, command, **kwargs):
            from app.services.validation_sandbox import ValidationSandboxResult

            self.calls.append({"command": command, **kwargs})
            return ValidationSandboxResult(
                command=command,
                target=kwargs["target"],
                resolved_target=kwargs["target"],
                returncode=0,
                stdout=raw_output,
                stderr="",
            )

    policy = default_validation_execution_policy_registry().get("semgrep")
    runner = FakeSandboxRunner()

    result = await adapter.run(
        "/repo",
        target_type=TARGET_REPOSITORY_PATH,
        policy=policy,
        sandbox_runner=runner,  # type: ignore[arg-type]
    )

    assert len(result.findings) == 1
    assert result.findings[0].template_id == "python.jwt.decode-without-verify"
    assert runner.calls[0]["command"][-1] == "/repo"
    assert runner.calls[0]["executable"] == "semgrep"


@pytest.mark.asyncio
async def test_osv_sandboxed_run_treats_findings_exit_code_as_success():
    adapter = OSVScannerValidationAdapter()
    raw_output = json.dumps(
        {
            "results": [
                {
                    "source": {"path": "package-lock.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "lodash",
                                "version": "4.17.15",
                                "ecosystem": "npm",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-29mw-wpgm-hmr9",
                                    "aliases": ["CVE-2020-28500"],
                                    "summary": "Regular expression denial of service",
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    ).encode("utf-8")

    class FakeSandboxRunner:
        async def run(self, command, **kwargs):
            return ValidationSandboxResult(
                command=command,
                target=kwargs["target"],
                resolved_target=kwargs["target"],
                returncode=1,
                stdout=raw_output,
                stderr="vulnerabilities found",
            )

    policy = default_validation_execution_policy_registry().get("osv-scanner")

    result = await adapter.run(
        "/repo/package-lock.json",
        target_type="lockfile",
        policy=policy,
        sandbox_runner=FakeSandboxRunner(),  # type: ignore[arg-type]
    )

    assert result.returncode == 0
    assert len(result.findings) == 1
    assert result.findings[0].template_id == "GHSA-29mw-wpgm-hmr9"
    assert result.findings[0].cve_ids == ["CVE-2020-28500"]


@pytest.mark.asyncio
async def test_sandboxed_adapter_requires_policy_and_target_type():
    adapter = SemgrepValidationAdapter()

    with pytest.raises(ValidationToolUnavailable, match="requires target_type"):
        await adapter.run("/repo")

"""Validation tool adapters for deterministic scanner evidence collection."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from app.models.scan import ScanFinding
from app.services.validation_artifact_contract import attach_validation_metadata
from app.services.validation_env import validation_env_value
from app.services.validation_sandbox import (
    ValidationSandboxError,
    ValidationSandboxRunner,
    resolve_validation_executable,
    validate_validation_target_access,
)

NUCLEI_TOOL_NAME = "nuclei"
SEMGREP_TOOL_NAME = "semgrep"
OSV_SCANNER_TOOL_NAME = "osv-scanner"
TRIVY_TOOL_NAME = "trivy"
CHECKOV_TOOL_NAME = "checkov"
TRUFFLEHOG_TOOL_NAME = "trufflehog"
AI_RED_TEAM_TOOL_NAME = "ai-red-team"
PROWLER_TOOL_NAME = "prowler"
EXTERNAL_REPORT_TOOL_NAME = "external-report"
PENTEST_REPORT_TOOL_NAME = "pentest-report"
EVIDENCE_IMPORT_TOOL_NAMES = frozenset(
    {EXTERNAL_REPORT_TOOL_NAME, PENTEST_REPORT_TOOL_NAME}
)
NUCLEI_TIMEOUT_PER_TARGET = 600
NUCLEI_TOTAL_TIMEOUT = 1800
NUCLEI_TAGS_BASE = (
    "cve,exposure,misconfig,default-login,xss,sqli,ssrf,rce,takeover,header"
)
NUCLEI_TAGS_AUTH_EXTRA = "jwt,auth-bypass,idor,privilege-escalation"
NUCLEI_TEMPLATES_ENV = "THREATGENIX_VALIDATION_NUCLEI_TEMPLATES"

NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}
_DORMANT_TOOL_TIMEOUT = 600
_STDERR_CAPTURE_LIMIT = 65_536
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

_GENERIC_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "error": "high",
    "medium": "medium",
    "warning": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "note": "info",
    "unknown": "unknown",
}
_PATH_TARGET_TYPES = {
    "repository_path",
    "lockfile",
    "iac_directory",
    "ai_system",
}
_AI_SYSTEM_TARGET_TYPE = "ai_system"
_EXTERNAL_FINDING_LIST_KEYS = (
    "findings",
    "results",
    "issues",
    "vulnerabilities",
    "alerts",
    "observations",
    "risks",
    "items",
)
_EXTERNAL_TITLE_KEYS = (
    "title",
    "name",
    "finding",
    "issue",
    "vulnerability",
    "summary",
    "alert",
    "check_name",
    "message",
)
_EXTERNAL_ID_KEYS = (
    "id",
    "finding_id",
    "issue_id",
    "rule_id",
    "check_id",
    "vulnerability_id",
    "plugin_id",
    "cwe",
    "cve",
)
_EXTERNAL_SEVERITY_KEYS = ("severity", "risk", "priority", "criticality", "rating")
_EXTERNAL_TARGET_KEYS = (
    "target",
    "asset",
    "host",
    "url",
    "endpoint",
    "service",
    "component",
    "affected_asset",
    "affected_component",
    "path",
)
_EXTERNAL_TAG_KEYS = (
    "tags",
    "tag",
    "category",
    "categories",
    "cwe",
    "owasp",
    "stride",
    "type",
    "weakness",
)
_EXTERNAL_DESCRIPTION_KEYS = (
    "description",
    "details",
    "evidence",
    "impact",
    "recommendation",
    "remediation",
    "proof",
    "steps",
)
_TEXT_FINDING_SPLIT_RE = re.compile(
    r"\n{2,}(?=(?:#{1,4}\s*)?(?:finding\s+\d+|critical|high|medium|moderate|low|info|p[0-4])\b)",
    re.IGNORECASE,
)
_AI_FINDING_LIST_KEYS = (
    "test_cases",
    "red_team_tests",
    "redteam_tests",
    "findings",
    "results",
    "outputs",
    "attacks",
)
_AI_CATEGORY_TAGS: dict[str, list[str]] = {
    "prompt-injection": ["llm01", "prompt-injection", "injection"],
    "prompt_injection": ["llm01", "prompt-injection", "injection"],
    "indirect-prompt-injection": ["llm01", "prompt-injection"],
    "jailbreak": ["llm07", "jailbreak", "elevation-of-privilege"],
    "data-exfiltration": [
        "llm06",
        "data-exfiltration",
        "sensitive-information-disclosure",
    ],
    "data_exfiltration": [
        "llm06",
        "data-exfiltration",
        "sensitive-information-disclosure",
    ],
    "sensitive-information-disclosure": [
        "llm06",
        "sensitive-information-disclosure",
        "data-exfiltration",
    ],
    "sensitive_info": [
        "llm06",
        "sensitive-information-disclosure",
        "data-exfiltration",
    ],
    "sensitive-info": [
        "llm06",
        "sensitive-information-disclosure",
        "data-exfiltration",
    ],
    "training-data-extraction": [
        "llm06",
        "training-data-extraction",
        "data-exfiltration",
    ],
    "training_data_extraction": [
        "llm06",
        "training-data-extraction",
        "data-exfiltration",
    ],
    "rag-poisoning": ["llm08", "rag-poisoning", "prompt-injection"],
    "rag_poisoning": ["llm08", "rag-poisoning", "prompt-injection"],
    "insecure-output-handling": ["llm02", "insecure-output-handling"],
    "insecure_output_handling": ["llm02", "insecure-output-handling"],
    "excessive-agency": ["llm10", "excessive-agency", "agent-tool-abuse"],
    "excessive_agency": ["llm10", "excessive-agency", "agent-tool-abuse"],
    "agent-tool-abuse": ["llm10", "agent-tool-abuse", "excessive-agency"],
    "tool-abuse": ["llm10", "agent-tool-abuse", "excessive-agency"],
    "tool_abuse": ["llm10", "agent-tool-abuse", "excessive-agency"],
    "insecure-plugin-design": [
        "llm07",
        "insecure-plugin-design",
        "agent-tool-abuse",
    ],
    "model-dos": ["llm04", "model-dos", "dos", "denial-of-service"],
    "model_dos": ["llm04", "model-dos", "dos", "denial-of-service"],
}
_AI_HIGH_RISK_TAGS = frozenset(
    {
        "data-exfiltration",
        "sensitive-information-disclosure",
        "training-data-extraction",
        "jailbreak",
        "agent-tool-abuse",
        "excessive-agency",
    }
)


class ValidationToolUnavailable(RuntimeError):
    """Raised when an adapter is invoked without its backing tool installed."""


@dataclass(frozen=True)
class ValidationEvidence:
    """Normalized evidence emitted by a validation tool."""

    tool_name: str
    target: str
    severity: str
    finding_title: str
    cve_ids: list[str]
    tags: list[str]
    matched_url: str
    raw_output: dict[str, Any]
    deterministic: bool = True
    tool_version: str | None = None
    template_id: str | None = None
    extracted_results: str | None = None
    cvss_score: float | None = None

    def to_scan_finding(
        self,
        scan_job_id: UUID,
        *,
        include_validation_metadata: bool = True,
        target_type: str | None = None,
        evidence_origin: str | None = None,
        synthetic: bool | None = None,
    ) -> ScanFinding:
        raw_output = dict(self.raw_output)
        if include_validation_metadata:
            metadata = {
                "tool_name": self.tool_name,
                "tool_version": self.tool_version,
                "target": sanitize_validation_target_for_storage(
                    self.target,
                    target_type,
                )
                or self.target,
                "deterministic": self.deterministic,
            }
            if target_type:
                metadata["target_type"] = target_type
            if evidence_origin:
                metadata["evidence_origin"] = evidence_origin
            if synthetic is not None:
                metadata["synthetic"] = synthetic
            attach_validation_metadata(raw_output, metadata)

        return ScanFinding(
            scan_job_id=scan_job_id,
            template_id=self.template_id or self.finding_title,
            template_name=self.finding_title,
            severity=self.severity,
            matched_at=self.matched_url,
            extracted_results=self.extracted_results,
            cve_ids=self.cve_ids,
            tags=self.tags,
            cvss_score=self.cvss_score,
            raw_output=raw_output,
        )


@dataclass(frozen=True)
class ValidationToolResult:
    """Result returned after a validation tool runs against one target."""

    tool_name: str
    target: str
    findings: list[ValidationEvidence] = field(default_factory=list)
    returncode: int = 0
    stderr: str = ""
    timed_out: bool = False
    command: list[str] = field(default_factory=list)
    resolved_target: str | None = None
    stdout_bytes: int = 0
    output_sha256: str | None = None
    output_limit_exceeded: bool = False
    sandboxed: bool = False
    sandbox_mode: str | None = None
    container_image: str | None = None
    network_policy: str | None = None
    resource_limits: dict[str, str] = field(default_factory=dict)


class ValidationToolAdapter(Protocol):
    """Adapter contract for validation tools."""

    name: str
    deterministic: bool
    timeout_seconds: int
    active: bool

    def is_available(self) -> bool: ...

    def build_command(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
    ) -> list[str]: ...

    def parse_json_line(
        self,
        target: str,
        data: dict[str, Any],
    ) -> ValidationEvidence | None: ...

    def parse_output(
        self,
        target: str,
        output: bytes | str,
    ) -> list[ValidationEvidence]: ...

    async def run(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
        policy: Any | None = None,
        sandbox_runner: ValidationSandboxRunner | None = None,
    ) -> ValidationToolResult: ...


class NucleiValidationAdapter:
    """Nuclei adapter preserving the existing scanner command and parser policy."""

    name = NUCLEI_TOOL_NAME
    deterministic = True
    active = True
    timeout_seconds = NUCLEI_TIMEOUT_PER_TARGET

    def is_available(self) -> bool:
        return resolve_validation_executable("nuclei") is not None

    def build_command(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
    ) -> list[str]:
        del target_type
        command = [
            "nuclei",
            "-u",
            target,
            *_nuclei_template_selector_args(template_tags),
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-redirects",
            "-duc",
            "-no-stdin",
            "-timeout",
            "10",
            "-rate-limit",
            "50",
            "-bulk-size",
            "25",
            "-c",
            "5",
        ]
        if auth_headers:
            command.extend(auth_headers)
        return command

    def parse_json_line(
        self,
        target: str,
        data: dict[str, Any],
    ) -> ValidationEvidence | None:
        template_id = data.get("template-id", "")
        if not template_id:
            return None
        template_id = str(template_id)

        info = data.get("info") or {}
        if not isinstance(info, dict):
            info = {}

        severity_raw = info.get("severity", "unknown")
        if not isinstance(severity_raw, str):
            severity_raw = "unknown"
        severity = NUCLEI_SEVERITY_MAP.get(severity_raw.lower(), "unknown")

        classification = info.get("classification") or {}
        if not isinstance(classification, dict):
            classification = {}

        cve_ids = _normalize_string_list(classification.get("cve-id", []) or [])
        tags = _normalize_tags(info.get("tags", []) or [])
        matched_url = str(data.get("matched-at") or data.get("host") or "unknown")
        extracted_results = _normalize_extracted_results(data.get("extracted-results"))
        cvss_score = _normalize_cvss_score(classification.get("cvss-score"))
        title = info.get("name") or template_id
        if not isinstance(title, str):
            title = str(title)

        return ValidationEvidence(
            tool_name=self.name,
            target=target,
            severity=severity,
            finding_title=title,
            cve_ids=cve_ids,
            tags=tags,
            matched_url=matched_url,
            raw_output=data,
            deterministic=self.deterministic,
            template_id=template_id,
            extracted_results=extracted_results,
            cvss_score=cvss_score,
        )

    def parse_output(
        self,
        target: str,
        output: bytes | str,
    ) -> list[ValidationEvidence]:
        text = (
            output.decode("utf-8", errors="replace")
            if isinstance(output, bytes)
            else output
        )
        findings: list[ValidationEvidence] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            finding = self.parse_json_line(target, data)
            if finding is not None:
                findings.append(finding)
        return findings

    async def run(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
        policy: Any | None = None,
        sandbox_runner: ValidationSandboxRunner | None = None,
    ) -> ValidationToolResult:
        command = self.build_command(
            target,
            auth_headers=auth_headers,
            template_tags=template_tags,
            target_type=target_type,
        )
        if sandbox_runner is not None:
            if target_type is None or policy is None:
                raise ValidationToolUnavailable(
                    "Nuclei container execution requires target_type and validation policy"
                )
            try:
                result = await sandbox_runner.run(
                    command,
                    tool_name=self.name,
                    executable="nuclei",
                    target=target,
                    target_type=target_type,
                    timeout_seconds=policy.max_runtime_seconds,
                    max_output_bytes=policy.max_output_bytes,
                )
            except ValidationSandboxError as exc:
                raise ValidationToolUnavailable(str(exc)) from exc

            redacted_command = redact_validation_command(
                result.command,
                target=target,
                resolved_target=result.resolved_target,
                target_type=target_type,
            )
            if result.timed_out or result.output_limit_exceeded:
                return ValidationToolResult(
                    tool_name=self.name,
                    target=target,
                    returncode=result.returncode,
                    stderr=result.stderr,
                    timed_out=result.timed_out,
                    command=redacted_command,
                    resolved_target=result.resolved_target,
                    stdout_bytes=len(result.stdout),
                    output_sha256=_output_sha256(result.stdout),
                    output_limit_exceeded=result.output_limit_exceeded,
                    sandboxed=True,
                    sandbox_mode=result.sandbox_mode,
                    container_image=result.container_image,
                    network_policy=result.network_policy,
                    resource_limits=result.resource_limits or {},
                )

            if result.returncode != 0:
                return ValidationToolResult(
                    tool_name=self.name,
                    target=target,
                    returncode=result.returncode or 1,
                    stderr=result.stderr,
                    command=redacted_command,
                    resolved_target=result.resolved_target,
                    stdout_bytes=len(result.stdout),
                    output_sha256=_output_sha256(result.stdout),
                    sandboxed=True,
                    sandbox_mode=result.sandbox_mode,
                    container_image=result.container_image,
                    network_policy=result.network_policy,
                    resource_limits=result.resource_limits or {},
                )

            return ValidationToolResult(
                tool_name=self.name,
                target=target,
                findings=self.parse_output(target, result.stdout),
                returncode=result.returncode or 0,
                stderr=result.stderr,
                command=redacted_command,
                resolved_target=result.resolved_target,
                stdout_bytes=len(result.stdout),
                output_sha256=_output_sha256(result.stdout),
                sandboxed=True,
                sandbox_mode=result.sandbox_mode,
                container_image=result.container_image,
                network_policy=result.network_policy,
                resource_limits=result.resource_limits or {},
            )

        if not self.is_available():
            raise ValidationToolUnavailable(
                "Nuclei CLI not installed. Install from https://github.com/projectdiscovery/nuclei"
            )
        resolved_executable = resolve_validation_executable(command[0])
        if resolved_executable is None:
            raise ValidationToolUnavailable(
                "Nuclei CLI not installed. Install from https://github.com/projectdiscovery/nuclei"
            )
        command[0] = resolved_executable
        redacted_command = redact_validation_command(
            command,
            target=target,
            resolved_target=target,
            target_type="url",
        )
        timeout_seconds = (
            int(policy.max_runtime_seconds)
            if policy is not None and getattr(policy, "max_runtime_seconds", None)
            else self.timeout_seconds
        )
        max_output_bytes = (
            int(policy.max_output_bytes)
            if policy is not None and getattr(policy, "max_output_bytes", None)
            else None
        )
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                async with asyncio.timeout(timeout_seconds):
                    (
                        stdout,
                        stderr,
                        output_limit_exceeded,
                    ) = await _communicate_with_output_cap(
                        proc,
                        max_stdout_bytes=max_output_bytes,
                    )
            except TimeoutError:
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
                return ValidationToolResult(
                    tool_name=self.name,
                    target=target,
                    returncode=-1,
                    timed_out=True,
                    command=redacted_command,
                    resolved_target=target,
                    output_sha256=_output_sha256(b""),
                )

            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            if proc.returncode != 0:
                return ValidationToolResult(
                    tool_name=self.name,
                    target=target,
                    returncode=proc.returncode or 1,
                    stderr=stderr_text,
                    command=redacted_command,
                    resolved_target=target,
                    stdout_bytes=len(stdout),
                    output_sha256=_output_sha256(stdout),
                    output_limit_exceeded=output_limit_exceeded,
                )
            if output_limit_exceeded:
                return ValidationToolResult(
                    tool_name=self.name,
                    target=target,
                    returncode=proc.returncode or 0,
                    stderr=stderr_text,
                    command=redacted_command,
                    resolved_target=target,
                    stdout_bytes=len(stdout),
                    output_sha256=_output_sha256(stdout),
                    output_limit_exceeded=True,
                )

            return ValidationToolResult(
                tool_name=self.name,
                target=target,
                findings=self.parse_output(target, stdout),
                returncode=proc.returncode or 0,
                stderr=stderr_text,
                command=redacted_command,
                resolved_target=target,
                stdout_bytes=len(stdout),
                output_sha256=_output_sha256(stdout),
            )
        except Exception:
            if proc is not None:
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
            raise


class _DormantValidationAdapter:
    name = ""
    deterministic = True
    active = True
    timeout_seconds = _DORMANT_TOOL_TIMEOUT
    executable = ""
    default_tags = ""
    success_returncodes = frozenset({0})

    def is_available(self) -> bool:
        return resolve_validation_executable(self.executable) is not None

    def parse_json_line(
        self,
        target: str,
        data: dict[str, Any],
    ) -> ValidationEvidence | None:
        findings = self.parse_json_document(target, data)
        return findings[0] if findings else None

    def parse_output(
        self,
        target: str,
        output: bytes | str,
    ) -> list[ValidationEvidence]:
        text = (
            output.decode("utf-8", errors="replace")
            if isinstance(output, bytes)
            else output
        )
        if not text.strip():
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict) and not isinstance(data, list):
            return []
        return self.parse_json_document(target, data)

    def parse_json_document(
        self,
        target: str,
        data: dict[str, Any] | list[Any],
    ) -> list[ValidationEvidence]:
        raise NotImplementedError

    def build_command(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
    ) -> list[str]:
        raise NotImplementedError

    async def run(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
        policy: Any | None = None,
        sandbox_runner: ValidationSandboxRunner | None = None,
    ) -> ValidationToolResult:
        del auth_headers
        if target_type is None or policy is None:
            raise ValidationToolUnavailable(
                f"{self.name} execution requires target_type and validation policy"
            )
        runner = sandbox_runner or ValidationSandboxRunner()
        command = self.build_command(
            target,
            template_tags=template_tags,
            target_type=target_type,
        )
        try:
            result = await runner.run(
                command,
                tool_name=self.name,
                executable=self.executable,
                target=target,
                target_type=target_type,
                timeout_seconds=policy.max_runtime_seconds,
                max_output_bytes=policy.max_output_bytes,
            )
        except ValidationSandboxError as exc:
            raise ValidationToolUnavailable(str(exc)) from exc

        if result.timed_out or result.output_limit_exceeded:
            return ValidationToolResult(
                tool_name=self.name,
                target=target,
                returncode=result.returncode,
                stderr=result.stderr,
                timed_out=result.timed_out,
                command=redact_validation_command(
                    result.command,
                    target=target,
                    resolved_target=result.resolved_target,
                    target_type=target_type,
                ),
                resolved_target=sanitize_validation_target_for_storage(
                    result.resolved_target,
                    target_type,
                ),
                stdout_bytes=len(result.stdout),
                output_sha256=_output_sha256(result.stdout),
                output_limit_exceeded=result.output_limit_exceeded,
                sandboxed=True,
                sandbox_mode=result.sandbox_mode,
                container_image=result.container_image,
                network_policy=result.network_policy,
                resource_limits=result.resource_limits or {},
            )

        returncode = (
            0 if result.returncode in self.success_returncodes else result.returncode
        )
        return ValidationToolResult(
            tool_name=self.name,
            target=target,
            findings=self.parse_output(target, result.stdout),
            returncode=returncode,
            stderr=result.stderr,
            command=redact_validation_command(
                result.command,
                target=target,
                resolved_target=result.resolved_target,
                target_type=target_type,
            ),
            resolved_target=sanitize_validation_target_for_storage(
                result.resolved_target,
                target_type,
            ),
            stdout_bytes=len(result.stdout),
            output_sha256=_output_sha256(result.stdout),
            output_limit_exceeded=result.output_limit_exceeded,
            sandboxed=True,
            sandbox_mode=result.sandbox_mode,
            container_image=result.container_image,
            network_policy=result.network_policy,
            resource_limits=result.resource_limits or {},
        )


class SemgrepValidationAdapter(_DormantValidationAdapter):
    """Dormant Semgrep adapter for future repository SAST validation."""

    name = SEMGREP_TOOL_NAME
    executable = "semgrep"
    default_tags = str(
        Path(__file__).resolve().parent / "validation_rules" / "semgrep-default.yml"
    )

    def _default_config_for_target(self, target: str, template_tags: str | None) -> str:
        if template_tags:
            return template_tags

        target_path = Path(target).expanduser()
        search_root = target_path if target_path.is_dir() else target_path.parent
        for filename in ("semgrep-rules.yml", ".semgrep.yml", ".semgrep.yaml"):
            candidate = search_root / filename
            if candidate.is_file():
                return str(candidate)
        return self.default_tags

    def _project_root_for_target(self, target: str) -> str | None:
        target_path = Path(target).expanduser()
        if target_path.is_dir():
            return str(target_path)
        if target_path.is_file():
            return str(target_path.parent)
        return None

    def build_command(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
    ) -> list[str]:
        del auth_headers, target_type
        command = [
            "semgrep",
            "scan",
            "--config",
            self._default_config_for_target(target, template_tags),
            "--json",
            "--metrics=off",
            "--quiet",
            "--no-git-ignore",
        ]
        project_root = self._project_root_for_target(target)
        if project_root:
            command.extend(["--novcs", "--project-root", project_root])
        command.append(target)
        return command

    def parse_json_document(
        self,
        target: str,
        data: dict[str, Any] | list[Any],
    ) -> list[ValidationEvidence]:
        if not isinstance(data, dict):
            return []
        findings: list[ValidationEvidence] = []
        for result in _iter_dicts(data.get("results")):
            check_id = str(result.get("check_id") or result.get("rule_id") or "")
            if not check_id:
                continue
            extra = _dict_or_empty(result.get("extra"))
            metadata = _dict_or_empty(extra.get("metadata"))
            path = str(result.get("path") or target)
            start = _dict_or_empty(result.get("start"))
            line = start.get("line")
            matched_url = f"{path}:{line}" if line else path
            message = str(extra.get("message") or check_id)
            severity = _normalize_severity(extra.get("severity"))
            cve_ids = _extract_cve_ids([metadata, result, message])
            tags = _compact_strings(
                [
                    *_normalize_tags(metadata.get("technology") or []),
                    *_normalize_tags(metadata.get("category") or []),
                    "semgrep",
                    "sast",
                    "code",
                    str(extra.get("severity") or "").lower(),
                ]
            )
            findings.append(
                ValidationEvidence(
                    tool_name=self.name,
                    target=target,
                    severity=severity,
                    finding_title=message,
                    cve_ids=cve_ids,
                    tags=tags,
                    matched_url=matched_url,
                    raw_output=result,
                    deterministic=self.deterministic,
                    template_id=check_id,
                    extracted_results=matched_url,
                )
            )
        return findings


class OSVScannerValidationAdapter(_DormantValidationAdapter):
    """Dormant OSV-Scanner adapter for future dependency CVE validation."""

    name = OSV_SCANNER_TOOL_NAME
    executable = "osv-scanner"
    success_returncodes = frozenset({0, 1})

    def build_command(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
    ) -> list[str]:
        del auth_headers, template_tags, target_type
        return ["osv-scanner", "scan", "--format", "json", target]

    def parse_json_document(
        self,
        target: str,
        data: dict[str, Any] | list[Any],
    ) -> list[ValidationEvidence]:
        if not isinstance(data, dict):
            return []
        findings: list[ValidationEvidence] = []
        for result in _iter_dicts(data.get("results")):
            source = _dict_or_empty(result.get("source"))
            source_path = str(source.get("path") or target)
            source_type = str(source.get("type") or "dependency")
            for package_result in _iter_dicts(result.get("packages")):
                package = _dict_or_empty(package_result.get("package"))
                package_name = str(package.get("name") or "unknown package")
                package_version = str(package.get("version") or "unknown version")
                ecosystem = str(package.get("ecosystem") or "unknown ecosystem")
                groups = list(_iter_dicts(package_result.get("groups")))
                group_by_id: dict[str, dict[str, Any]] = {}
                for group in groups:
                    for identifier in _normalize_string_list(group.get("ids") or []):
                        group_by_id[identifier] = group
                    for alias in _normalize_string_list(group.get("aliases") or []):
                        group_by_id[alias] = group
                emitted_ids: set[str] = set()
                for vulnerability in _iter_dicts(package_result.get("vulnerabilities")):
                    vuln_id = str(vulnerability.get("id") or "")
                    if not vuln_id:
                        continue
                    aliases = _normalize_string_list(vulnerability.get("aliases") or [])
                    cve_ids = _extract_cve_ids([vuln_id, aliases, vulnerability])
                    summary = str(vulnerability.get("summary") or vuln_id)
                    severity = _osv_severity(vulnerability)
                    if severity == "unknown":
                        group = group_by_id.get(vuln_id) or next(
                            (
                                group_by_id[alias]
                                for alias in aliases
                                if alias in group_by_id
                            ),
                            None,
                        )
                        if group is not None:
                            severity = _severity_from_numeric_score(
                                group.get("max_severity")
                            )
                    tags = _compact_strings(
                        [
                            "osv",
                            "dependency",
                            source_type,
                            ecosystem.lower(),
                            package_name,
                        ]
                    )
                    findings.append(
                        ValidationEvidence(
                            tool_name=self.name,
                            target=target,
                            severity=severity,
                            finding_title=f"{package_name}@{package_version}: {summary}",
                            cve_ids=cve_ids,
                            tags=tags,
                            matched_url=source_path,
                            raw_output={
                                "source": source,
                                "package": package,
                                "vulnerability": vulnerability,
                            },
                            deterministic=self.deterministic,
                            template_id=vuln_id,
                            extracted_results=f"{ecosystem}:{package_name}@{package_version}",
                        )
                    )
                    emitted_ids.add(vuln_id)
                    emitted_ids.update(aliases)
                for group in groups:
                    ids = _normalize_string_list(group.get("ids") or [])
                    aliases = _normalize_string_list(group.get("aliases") or [])
                    vuln_id = ids[0] if ids else (aliases[0] if aliases else "")
                    if not vuln_id:
                        continue
                    if vuln_id in emitted_ids or any(
                        alias in emitted_ids for alias in aliases
                    ):
                        continue
                    cve_ids = _extract_cve_ids([vuln_id, aliases, group])
                    severity = _severity_from_numeric_score(group.get("max_severity"))
                    findings.append(
                        ValidationEvidence(
                            tool_name=self.name,
                            target=target,
                            severity=severity,
                            finding_title=f"{package_name}@{package_version}: {vuln_id}",
                            cve_ids=cve_ids,
                            tags=_compact_strings(
                                [
                                    "osv",
                                    "dependency",
                                    source_type,
                                    ecosystem.lower(),
                                    package_name,
                                ]
                            ),
                            matched_url=source_path,
                            raw_output={
                                "source": source,
                                "package": package,
                                "vulnerability_group": group,
                            },
                            deterministic=self.deterministic,
                            template_id=vuln_id,
                            extracted_results=f"{ecosystem}:{package_name}@{package_version}",
                        )
                    )
        return findings


class TrivyValidationAdapter(_DormantValidationAdapter):
    """Dormant Trivy adapter for future filesystem/container evidence."""

    name = TRIVY_TOOL_NAME
    executable = "trivy"

    def build_command(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
    ) -> list[str]:
        del auth_headers
        if target_type == "container_image":
            return [
                "trivy",
                "image",
                "--format",
                "json",
                "--scanners",
                template_tags or "vuln",
                "--no-progress",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--skip-version-check",
                "--skip-vex-repo-update",
                "--offline-scan",
                target,
            ]
        scanners = template_tags or "misconfig"
        command = [
            "trivy",
            "fs",
            "--format",
            "json",
            "--scanners",
            scanners,
            "--no-progress",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--skip-version-check",
            "--skip-vex-repo-update",
            "--offline-scan",
            target,
        ]
        return command

    def parse_json_document(
        self,
        target: str,
        data: dict[str, Any] | list[Any],
    ) -> list[ValidationEvidence]:
        results = (
            data
            if isinstance(data, list)
            else data.get("Results")
            if isinstance(data, dict)
            else []
        )
        findings: list[ValidationEvidence] = []
        for result in _iter_dicts(results):
            result_target = str(result.get("Target") or target)
            result_type = str(result.get("Type") or result.get("Class") or "filesystem")
            findings.extend(
                self._parse_vulnerabilities(target, result_target, result_type, result)
            )
            findings.extend(
                self._parse_misconfigurations(
                    target, result_target, result_type, result
                )
            )
        return findings

    def _parse_vulnerabilities(
        self,
        target: str,
        result_target: str,
        result_type: str,
        result: dict[str, Any],
    ) -> list[ValidationEvidence]:
        findings: list[ValidationEvidence] = []
        for vulnerability in _iter_dicts(result.get("Vulnerabilities")):
            vuln_id = str(vulnerability.get("VulnerabilityID") or "")
            if not vuln_id:
                continue
            package = str(vulnerability.get("PkgName") or "unknown package")
            installed = str(vulnerability.get("InstalledVersion") or "unknown version")
            title = str(vulnerability.get("Title") or vuln_id)
            findings.append(
                ValidationEvidence(
                    tool_name=self.name,
                    target=target,
                    severity=_normalize_severity(vulnerability.get("Severity")),
                    finding_title=f"{package}@{installed}: {title}",
                    cve_ids=_extract_cve_ids([vuln_id, vulnerability]),
                    tags=_compact_strings(
                        ["trivy", "vulnerability", result_type, package]
                    ),
                    matched_url=result_target,
                    raw_output={
                        "result": _result_context(result),
                        "vulnerability": vulnerability,
                    },
                    deterministic=self.deterministic,
                    template_id=vuln_id,
                    extracted_results=f"{package}@{installed}",
                    cvss_score=_trivy_cvss_score(vulnerability),
                )
            )
        return findings

    def _parse_misconfigurations(
        self,
        target: str,
        result_target: str,
        result_type: str,
        result: dict[str, Any],
    ) -> list[ValidationEvidence]:
        findings: list[ValidationEvidence] = []
        for misconfig in _iter_dicts(result.get("Misconfigurations")):
            rule_id = str(misconfig.get("ID") or misconfig.get("AVDID") or "")
            if not rule_id:
                continue
            cause = _dict_or_empty(misconfig.get("CauseMetadata"))
            line = cause.get("StartLine")
            matched_url = f"{result_target}:{line}" if line else result_target
            title = str(misconfig.get("Title") or misconfig.get("Message") or rule_id)
            findings.append(
                ValidationEvidence(
                    tool_name=self.name,
                    target=target,
                    severity=_normalize_severity(misconfig.get("Severity")),
                    finding_title=title,
                    cve_ids=[],
                    tags=_compact_strings(
                        ["trivy", "misconfiguration", result_type, rule_id]
                    ),
                    matched_url=matched_url,
                    raw_output={
                        "result": _result_context(result),
                        "misconfiguration": misconfig,
                    },
                    deterministic=self.deterministic,
                    template_id=rule_id,
                    extracted_results=str(cause.get("Resource") or matched_url),
                )
            )
        return findings


class CheckovValidationAdapter(_DormantValidationAdapter):
    """Dormant Checkov adapter for future IaC misconfiguration validation."""

    name = CHECKOV_TOOL_NAME
    executable = "checkov"

    def build_command(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
    ) -> list[str]:
        del auth_headers, target_type
        command = [
            "checkov",
            "--directory",
            target,
            "--output",
            "json",
            "--quiet",
            "--skip-download",
            "--skip-results-upload",
            "--soft-fail",
        ]
        if template_tags:
            command.extend(["--check", template_tags])
        return command

    def parse_json_document(
        self,
        target: str,
        data: dict[str, Any] | list[Any],
    ) -> list[ValidationEvidence]:
        documents = data if isinstance(data, list) else [data]
        findings: list[ValidationEvidence] = []
        for document in _iter_dicts(documents):
            results = _dict_or_empty(document.get("results"))
            for check in _iter_dicts(results.get("failed_checks")):
                check_id = str(check.get("check_id") or "")
                if not check_id:
                    continue
                file_path = str(check.get("file_path") or target)
                line_range = check.get("file_line_range")
                line = (
                    line_range[0]
                    if isinstance(line_range, list) and line_range
                    else None
                )
                matched_url = f"{file_path}:{line}" if line else file_path
                severity = _normalize_severity(check.get("severity"))
                title = str(check.get("check_name") or check_id)
                check_text = " ".join(
                    [
                        title,
                        str(check.get("resource") or ""),
                        str(check.get("guideline") or ""),
                    ]
                ).lower()
                exposure_tag = (
                    "exposure"
                    if any(
                        phrase in check_text
                        for phrase in [
                            "public read",
                            "public access",
                            "publicly accessible",
                            "allows public",
                        ]
                    )
                    else ""
                )
                findings.append(
                    ValidationEvidence(
                        tool_name=self.name,
                        target=target,
                        severity=severity,
                        finding_title=title,
                        cve_ids=_extract_cve_ids([check]),
                        matched_url=matched_url,
                        raw_output=check,
                        deterministic=self.deterministic,
                        template_id=check_id,
                        extracted_results=str(check.get("resource") or matched_url),
                        tags=_compact_strings(
                            [
                                exposure_tag,
                                "checkov",
                                "iac",
                                "misconfiguration",
                                str(check.get("bc_check_id") or ""),
                                check_id,
                            ]
                        ),
                    )
                )
        return findings


class TrufflehogValidationAdapter:
    """TruffleHog adapter for offline filesystem secret scanning.

    Trufflehog emits NDJSON to stdout (one JSON object per line). Each line has the shape::

        {
          "SourceMetadata": {"Data": {"Git": {"file": "...", "commit": "...", "line": 42}}},
          "DetectorName": "AWS",
          "DetectorType": 2,
          "Verified": true,
          "Raw": "<credential blob>",
          "ExtraData": {"account": "..."},
          "SourceID": 1,
          "SourceType": 7,
          "SourceName": "trufflehog - git"
        }

    Verified findings (the secret was live-tested against the provider) map to severity
    "high"; unverified findings map to "low" because they may be examples or revoked.
    ThreatGenix's live command disables verification by default so the runner does
    not call provider APIs from the validation process.
    """

    name = TRUFFLEHOG_TOOL_NAME
    executable = "trufflehog"
    deterministic = True
    active = True
    timeout_seconds = _DORMANT_TOOL_TIMEOUT
    success_returncodes = frozenset({0, 183})

    def is_available(self) -> bool:
        return resolve_validation_executable("trufflehog") is not None

    def build_command(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
    ) -> list[str]:
        del auth_headers, template_tags, target_type
        return [
            "trufflehog",
            "filesystem",
            target,
            "--json",
            "--no-update",
            "--no-verification",
            "--results=verified,unknown,unverified",
            "--filter-unverified",
            "--force-skip-binaries",
            "--force-skip-archives",
        ]

    def parse_json_line(
        self,
        target: str,
        data: dict[str, Any],
    ) -> ValidationEvidence | None:
        detector = (
            data.get("DetectorName") or data.get("DetectorType") or "trufflehog-secret"
        )
        detector = str(detector)
        verified = bool(data.get("Verified"))
        severity = "high" if verified else "low"

        source_metadata = data.get("SourceMetadata") or {}
        if not isinstance(source_metadata, dict):
            source_metadata = {}
        source_data = source_metadata.get("Data") or {}
        if not isinstance(source_data, dict):
            source_data = {}
        git_meta = source_data.get("Git") or {}
        if not isinstance(git_meta, dict):
            git_meta = {}
        filesystem_meta = source_data.get("Filesystem") or {}
        if not isinstance(filesystem_meta, dict):
            filesystem_meta = {}

        file_path = str(
            git_meta.get("file")
            or git_meta.get("File")
            or filesystem_meta.get("file")
            or filesystem_meta.get("File")
            or target
        )
        line_number = (
            git_meta.get("line")
            or git_meta.get("Line")
            or filesystem_meta.get("line")
            or filesystem_meta.get("Line")
        )
        matched_url = f"{file_path}:{line_number}" if line_number else file_path
        commit = str(git_meta.get("commit") or git_meta.get("Commit") or "")

        title_prefix = "Verified secret" if verified else "Unverified secret"
        title = f"{title_prefix}: {detector}"

        tags = _compact_strings(
            [
                "trufflehog",
                "secret",
                "credential",
                detector.lower(),
                "verified" if verified else "unverified",
            ]
        )

        return ValidationEvidence(
            tool_name=self.name,
            target=target,
            severity=severity,
            finding_title=title,
            cve_ids=[],
            tags=tags,
            matched_url=matched_url,
            raw_output=data,
            deterministic=self.deterministic,
            template_id=f"trufflehog-{_slugify(detector) or 'secret'}",
            extracted_results=commit or matched_url,
        )

    def parse_output(
        self,
        target: str,
        output: bytes | str,
    ) -> list[ValidationEvidence]:
        text = (
            output.decode("utf-8", errors="replace")
            if isinstance(output, bytes)
            else output
        )
        findings: list[ValidationEvidence] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            finding = self.parse_json_line(target, data)
            if finding is not None:
                findings.append(finding)
        return findings

    async def run(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
        policy: Any | None = None,
        sandbox_runner: ValidationSandboxRunner | None = None,
    ) -> ValidationToolResult:
        del auth_headers
        if target_type is None or policy is None:
            raise ValidationToolUnavailable(
                f"{self.name} execution requires target_type and validation policy"
            )
        runner = sandbox_runner or ValidationSandboxRunner()
        command = self.build_command(
            target, template_tags=template_tags, target_type=target_type
        )
        try:
            result = await runner.run(
                command,
                tool_name=self.name,
                executable="trufflehog",
                target=target,
                target_type=target_type,
                timeout_seconds=policy.max_runtime_seconds,
                max_output_bytes=policy.max_output_bytes,
            )
        except ValidationSandboxError as exc:
            raise ValidationToolUnavailable(str(exc)) from exc

        redacted_command = redact_validation_command(
            result.command,
            target=target,
            resolved_target=result.resolved_target,
            target_type=target_type,
        )
        if result.timed_out or result.output_limit_exceeded:
            return ValidationToolResult(
                tool_name=self.name,
                target=target,
                returncode=result.returncode,
                stderr=result.stderr,
                timed_out=result.timed_out,
                command=redacted_command,
                resolved_target=sanitize_validation_target_for_storage(
                    result.resolved_target, target_type
                ),
                stdout_bytes=len(result.stdout),
                output_sha256=_output_sha256(result.stdout),
                output_limit_exceeded=result.output_limit_exceeded,
                sandboxed=True,
                sandbox_mode=result.sandbox_mode,
                container_image=result.container_image,
                network_policy=result.network_policy,
                resource_limits=result.resource_limits or {},
            )
        returncode = (
            0 if result.returncode in self.success_returncodes else result.returncode
        )
        return ValidationToolResult(
            tool_name=self.name,
            target=target,
            findings=self.parse_output(target, result.stdout),
            returncode=returncode,
            stderr=result.stderr,
            command=redacted_command,
            resolved_target=sanitize_validation_target_for_storage(
                result.resolved_target, target_type
            ),
            stdout_bytes=len(result.stdout),
            output_sha256=_output_sha256(result.stdout),
            sandboxed=True,
            sandbox_mode=result.sandbox_mode,
            container_image=result.container_image,
            network_policy=result.network_policy,
            resource_limits=result.resource_limits or {},
        )


class AiRedTeamValidationAdapter:
    """Deterministic AI-system red-team evidence parser and local spec evaluator.

    The adapter does not call a model provider. It normalizes evidence produced
    by approved AI red-team harnesses, including promptfoo-style output and
    ThreatGenix AI-system spec files with executed test cases.
    """

    name = AI_RED_TEAM_TOOL_NAME
    deterministic = True
    active = True
    timeout_seconds = 120

    def is_available(self) -> bool:
        return True

    def build_command(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
    ) -> list[str]:
        del auth_headers, template_tags, target_type
        return [self.name, "evaluate", target]

    def parse_json_line(
        self,
        target: str,
        data: dict[str, Any],
    ) -> ValidationEvidence | None:
        findings = self.parse_json_document(target, data)
        return findings[0] if findings else None

    def parse_output(
        self,
        target: str,
        output: bytes | str,
    ) -> list[ValidationEvidence]:
        text = (
            output.decode("utf-8", errors="replace")
            if isinstance(output, bytes)
            else output
        )
        if not text.strip():
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            findings: list[ValidationEvidence] = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    findings.extend(self.parse_json_document(target, item))
            return findings
        return self.parse_json_document(target, data)

    def parse_json_document(
        self,
        target: str,
        data: dict[str, Any] | list[Any],
    ) -> list[ValidationEvidence]:
        if isinstance(data, list):
            return self._parse_cases(target, data, system_context={})
        if not isinstance(data, dict):
            return []

        promptfoo_outputs = _promptfoo_outputs(data)
        if promptfoo_outputs is not None:
            return self._parse_promptfoo_outputs(target, promptfoo_outputs)

        cases = _ai_case_candidates(data)
        system_context = _dict_or_empty(data.get("system") or data.get("ai_system"))
        return self._parse_cases(target, cases, system_context=system_context)

    async def run(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
        policy: Any | None = None,
        sandbox_runner: ValidationSandboxRunner | None = None,
    ) -> ValidationToolResult:
        del auth_headers, template_tags, sandbox_runner
        if target_type != _AI_SYSTEM_TARGET_TYPE:
            raise ValidationToolUnavailable(
                f"{self.name} requires target_type={_AI_SYSTEM_TARGET_TYPE}"
            )
        max_output_bytes = (
            int(policy.max_output_bytes)
            if policy is not None and getattr(policy, "max_output_bytes", None)
            else 1_000_000
        )
        resolved_target = validate_validation_target_access(target, target_type)
        payload = Path(resolved_target).read_bytes()
        output_limit_exceeded = len(payload) > max_output_bytes
        if output_limit_exceeded:
            payload = payload[:max_output_bytes]
        findings = [] if output_limit_exceeded else self.parse_output(target, payload)
        return ValidationToolResult(
            tool_name=self.name,
            target=target,
            findings=findings,
            returncode=0 if not output_limit_exceeded else -1,
            stderr=(
                "AI-system evidence exceeded max_output_bytes"
                if output_limit_exceeded
                else ""
            ),
            command=self.build_command(target, target_type=target_type),
            resolved_target=resolved_target,
            stdout_bytes=len(payload),
            output_sha256=_output_sha256(payload),
            output_limit_exceeded=output_limit_exceeded,
            sandboxed=True,
            sandbox_mode="process",
            network_policy="none",
            resource_limits={
                "max_output_bytes": str(max_output_bytes),
                "network": "disabled",
            },
        )

    def _parse_promptfoo_outputs(
        self,
        target: str,
        outputs: list[dict[str, Any]],
    ) -> list[ValidationEvidence]:
        findings: list[ValidationEvidence] = []
        for index, output in enumerate(outputs, start=1):
            if not _promptfoo_output_is_failure(output):
                continue
            test_case = _dict_or_empty(output.get("testCase"))
            vars_payload = _dict_or_empty(test_case.get("vars"))
            plugin_id = _first_string(
                vars_payload.get("pluginId"),
                output.get("pluginId"),
                output.get("plugin"),
                "prompt-injection",
            )
            strategy_id = _first_string(
                vars_payload.get("strategyId"),
                output.get("strategyId"),
                output.get("strategy"),
            )
            grading = _dict_or_empty(output.get("gradingResult"))
            reason = _first_string(
                grading.get("reason"),
                output.get("reason"),
                output.get("error"),
                "AI red-team test failed",
            )
            case = {
                "id": _first_string(output.get("id"), f"promptfoo-{index}"),
                "plugin_id": plugin_id,
                "strategy_id": strategy_id,
                "category": plugin_id,
                "attack_success": True,
                "severity": _severity_for_ai_tags(
                    _ai_tags_for(plugin_id, strategy_id)
                ),
                "target": _first_string(output.get("provider"), target),
                "rationale": reason,
                "score": output.get("score"),
            }
            findings.append(self._case_to_evidence(target, case, system_context={}))
        return findings

    def _parse_cases(
        self,
        target: str,
        cases: list[dict[str, Any]],
        *,
        system_context: dict[str, Any],
    ) -> list[ValidationEvidence]:
        findings: list[ValidationEvidence] = []
        for case in cases:
            if not _ai_case_exploit_succeeded(case):
                continue
            findings.append(
                self._case_to_evidence(
                    target,
                    case,
                    system_context=system_context,
                )
            )
        return findings

    def _case_to_evidence(
        self,
        target: str,
        case: dict[str, Any],
        *,
        system_context: dict[str, Any],
    ) -> ValidationEvidence:
        category = _first_string(
            case.get("category"),
            case.get("plugin_id"),
            case.get("pluginId"),
            case.get("risk"),
            case.get("type"),
            "ai-red-team",
        )
        strategy = _first_string(
            case.get("strategy"),
            case.get("strategy_id"),
            case.get("strategyId"),
        )
        tags = _ai_tags_for(category, strategy)
        case_id = _first_string(
            case.get("id"),
            case.get("test_id"),
            case.get("name"),
            f"ai-red-team-{_slugify(category) or 'finding'}",
        )
        component = _first_string(
            case.get("target"),
            case.get("component"),
            case.get("agent"),
            case.get("endpoint"),
            system_context.get("name"),
            target,
        )
        title = f"AI red-team exploit demonstrated: {_humanize_ai_category(category)}"
        extracted_results = _ai_case_extracted_results(case, category, strategy)
        severity = _normalize_severity(case.get("severity"))
        if severity == "unknown":
            severity = _severity_for_ai_tags(tags)

        return ValidationEvidence(
            tool_name=self.name,
            target=target,
            severity=severity,
            finding_title=title,
            cve_ids=[],
            tags=tags,
            matched_url=component,
            raw_output=_ai_case_raw_output(case, system_context=system_context),
            deterministic=self.deterministic,
            template_id=f"ai-red-team-{_slugify(str(case_id)) or 'finding'}",
            extracted_results=extracted_results,
        )


class ProwlerValidationAdapter(_DormantValidationAdapter):
    """Stub Prowler adapter for future cloud posture scanning.

    Prowler emits OCSF (Open Cybersecurity Schema Framework) JSON output, e.g.::

        {
          "metadata": {"product": {"name": "Prowler"}},
          "finding_info": {"uid": "...", "title": "..."},
          "severity": "High",
          "resources": [{"type": "AWS::S3::Bucket", "uid": "..."}],
          "status_code": "FAIL",
          "remediation": {"desc": "..."}
        }

    This adapter is intentionally dormant: ``is_available()`` always returns False,
    the binary is not installed in the Docker image, and the registry exposes it as a
    placeholder so the tool inventory shows it as a known-but-unavailable scanner.
    Wire up ``parse_json_document`` and the Dockerfile install when this becomes active.
    """

    name = PROWLER_TOOL_NAME
    executable = "prowler"

    def is_available(self) -> bool:
        return False

    def build_command(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
    ) -> list[str]:
        del target, auth_headers, template_tags, target_type
        raise ValidationToolUnavailable(
            "Prowler adapter is a stub — cloud posture scanning is not yet enabled"
        )

    def parse_json_document(
        self,
        target: str,
        data: dict[str, Any] | list[Any],
    ) -> list[ValidationEvidence]:
        del target, data
        return []


class ExternalReportImportAdapter:
    """Parse imported output from external security tools without execution."""

    name = EXTERNAL_REPORT_TOOL_NAME
    deterministic = True
    active = False
    timeout_seconds = 0

    def is_available(self) -> bool:
        return True

    def build_command(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
    ) -> list[str]:
        del target, auth_headers, template_tags, target_type
        raise ValidationToolUnavailable(
            f"{self.name} is import-only and cannot execute"
        )

    def parse_json_line(
        self,
        target: str,
        data: dict[str, Any],
    ) -> ValidationEvidence | None:
        findings = _parse_external_document(
            target,
            data,
            tool_name=self.name,
            deterministic=self.deterministic,
        )
        return findings[0] if findings else None

    def parse_output(
        self,
        target: str,
        output: bytes | str,
    ) -> list[ValidationEvidence]:
        return _parse_external_report_output(
            target,
            output,
            tool_name=self.name,
            deterministic=self.deterministic,
        )

    async def run(
        self,
        target: str,
        *,
        auth_headers: list[str] | None = None,
        template_tags: str | None = None,
        target_type: str | None = None,
        policy: Any | None = None,
        sandbox_runner: ValidationSandboxRunner | None = None,
    ) -> ValidationToolResult:
        del target, auth_headers, template_tags, target_type, policy, sandbox_runner
        raise ValidationToolUnavailable(
            f"{self.name} is import-only and cannot execute"
        )


class PentestReportImportAdapter(ExternalReportImportAdapter):
    """Parse imported human pentest findings as non-deterministic evidence."""

    name = PENTEST_REPORT_TOOL_NAME
    deterministic = False


class ValidationToolRegistry:
    """In-process registry for validation tool adapters."""

    def __init__(self) -> None:
        self._adapters: dict[str, ValidationToolAdapter] = {}

    def register(self, adapter: ValidationToolAdapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> ValidationToolAdapter:
        return self._adapters[name]

    def list(self) -> list[ValidationToolAdapter]:
        return list(self._adapters.values())


def default_validation_tool_registry() -> ValidationToolRegistry:
    registry = ValidationToolRegistry()
    registry.register(NucleiValidationAdapter())
    registry.register(SemgrepValidationAdapter())
    registry.register(OSVScannerValidationAdapter())
    registry.register(TrivyValidationAdapter())
    registry.register(CheckovValidationAdapter())
    registry.register(TrufflehogValidationAdapter())
    registry.register(AiRedTeamValidationAdapter())
    return registry


def default_evidence_import_tool_registry() -> ValidationToolRegistry:
    registry = default_validation_tool_registry()
    registry.register(ExternalReportImportAdapter())
    registry.register(PentestReportImportAdapter())
    return registry


def redact_validation_command(
    command: list[str],
    *,
    target: str | None = None,
    resolved_target: str | None = None,
    target_type: str | None = None,
) -> list[str]:
    """Return a command safe to persist as execution metadata."""
    redacted: list[str] = []
    index = 0
    secret_next_flags = {
        "-H",
        "--header",
        "--token",
        "--password",
        "--username",
        "--cookie",
        "--api-key",
        "-proxy",
        "--proxy",
    }
    local_file_next_flags = {
        "-J",
        "-r",
        "-w",
        "-x",
        "-g",
        "-p",
        "-n",
        "-t",
        "-templates",
        "-it",
        "-include-templates",
        "-et",
        "-exclude-templates",
        "-w",
        "-workflows",
        "--hook",
        "--config",
        "--directory",
        "--project-root",
    }
    while index < len(command):
        arg = command[index]
        if _should_redact_target_arg(arg, target, resolved_target, target_type):
            redacted.append(_target_placeholder(arg, target_type))
            index += 1
            continue
        redacted.append(arg)
        if arg in secret_next_flags and index + 1 < len(command):
            value = command[index + 1]
            redacted.append(_redact_secret_arg(arg, value))
            index += 2
            continue
        if arg in local_file_next_flags and index + 1 < len(command):
            redacted.append("[local-file-redacted]")
            index += 2
            continue
        if any(
            token in arg.lower()
            for token in ["token=", "password=", "secret=", "apikey=", "api-key="]
        ):
            redacted[-1] = arg.split("=", 1)[0] + "=[redacted]"
        index += 1
    return redacted


def sanitize_validation_target_for_storage(
    target: str | None,
    target_type: str | None,
) -> str | None:
    """Avoid persisting full local filesystem paths as execution metadata."""
    if not target:
        return None
    if target_type not in _PATH_TARGET_TYPES:
        return target
    name = target.rstrip("/").split("/")[-1] or "path"
    return f"{name} (sha256:{_target_hash(target)})"


def _nuclei_template_selector_args(template_tags: str | None) -> list[str]:
    """Build Nuclei selector flags.

    By default ThreatGenix preserves the historical tag-based Nuclei behavior.
    Operators can set THREATGENIX_VALIDATION_NUCLEI_TEMPLATES to one or more
    approved template files for low-impact smoke checks or tightly-scoped labs.
    """
    configured_templates = _split_env_paths(
        validation_env_value(NUCLEI_TEMPLATES_ENV, "") or ""
    )
    if configured_templates:
        args: list[str] = []
        for template in configured_templates:
            args.extend(["-t", template])
        return args
    return ["-tags", template_tags or NUCLEI_TAGS_BASE]


def _split_env_paths(raw: str) -> list[str]:
    normalized = raw.replace(",", os.pathsep)
    return [entry.strip() for entry in normalized.split(os.pathsep) if entry.strip()]


def _promptfoo_outputs(data: dict[str, Any]) -> list[dict[str, Any]] | None:
    results = data.get("results")
    if not isinstance(results, dict):
        return None
    outputs = results.get("outputs")
    if not isinstance(outputs, list):
        return None
    return [item for item in outputs if isinstance(item, dict)]


def _promptfoo_output_is_failure(output: dict[str, Any]) -> bool:
    success = output.get("success")
    if success is False:
        return True
    score = _coerce_float(output.get("score"))
    if score is not None and score < 1:
        return True
    grading = _dict_or_empty(output.get("gradingResult"))
    pass_value = grading.get("pass")
    if pass_value is False:
        return True
    return False


def _ai_case_candidates(data: dict[str, Any]) -> list[dict[str, Any]]:
    for key in _AI_FINDING_LIST_KEYS:
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _ai_case_candidates(value)
            if nested:
                return nested
    return []


def _ai_case_exploit_succeeded(case: dict[str, Any]) -> bool:
    for key in (
        "attack_success",
        "exploit_success",
        "exploitable",
        "control_failed",
        "policy_bypassed",
        "vulnerable",
        "failed",
    ):
        value = case.get(key)
        if isinstance(value, bool):
            return value
    for key in ("blocked", "control_effective", "mitigated", "safe"):
        value = case.get(key)
        if isinstance(value, bool):
            return not value
    status = str(case.get("status") or case.get("result") or "").strip().lower()
    if status in {
        "exploitable",
        "vulnerable",
        "confirmed",
        "failed",
        "bypassed",
        "leaked",
        "exfiltrated",
    }:
        return True
    if status in {"blocked", "passed", "mitigated", "not_supported", "safe"}:
        return False
    score = _coerce_float(case.get("score"))
    if score is not None and score < 1:
        return True
    return False


def _ai_tags_for(category: str | None, strategy: str | None = None) -> list[str]:
    tags: list[Any] = ["ai-red-team", "owasp-llm"]
    for raw in (category, strategy):
        normalized = _slugify(str(raw or ""))
        if not normalized:
            continue
        tags.append(normalized)
        tags.extend(_AI_CATEGORY_TAGS.get(normalized, []))
    return _compact_strings(_normalize_tags(tags))


def _severity_for_ai_tags(tags: list[str]) -> str:
    tag_set = set(tags)
    if tag_set & _AI_HIGH_RISK_TAGS:
        return "high"
    if "model-dos" in tag_set:
        return "medium"
    return "medium"


def _ai_case_raw_output(
    case: dict[str, Any],
    *,
    system_context: dict[str, Any],
) -> dict[str, Any]:
    allowed_case_keys = {
        "id",
        "test_id",
        "name",
        "title",
        "category",
        "plugin_id",
        "pluginId",
        "strategy",
        "strategy_id",
        "strategyId",
        "target",
        "component",
        "agent",
        "endpoint",
        "severity",
        "status",
        "result",
        "score",
        "attack_success",
        "exploit_success",
        "control_failed",
        "policy_bypassed",
        "vulnerable",
        "failed",
        "blocked",
        "control_effective",
    }
    allowed_system_keys = {"name", "type", "provider", "model", "deployment"}
    sanitized_case = {
        key: _safe_evidence_value(value)
        for key, value in case.items()
        if key in allowed_case_keys
    }
    sanitized_system = {
        key: _safe_evidence_value(value)
        for key, value in system_context.items()
        if key in allowed_system_keys
    }
    return {
        "case": sanitized_case,
        "system": sanitized_system,
        "redaction": "prompts, completions, secrets, and tool payload bodies omitted",
    }


def _safe_evidence_value(value: Any) -> Any:
    if isinstance(value, str):
        return _truncate_text(_redact_ai_evidence_text(value), 2_000)
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, float):
        return value
    if isinstance(value, list):
        return [_safe_evidence_value(item) for item in value[:20]]
    if isinstance(value, dict):
        return {
            str(key): _safe_evidence_value(item)
            for key, item in list(value.items())[:20]
        }
    return str(value)


def _ai_case_extracted_results(
    case: dict[str, Any],
    category: str | None,
    strategy: str | None,
) -> str:
    result_markers = [
        key
        for key in (
            "attack_success",
            "exploit_success",
            "control_failed",
            "policy_bypassed",
            "vulnerable",
            "failed",
        )
        if case.get(key) is True
    ]
    blocked_markers = [
        key
        for key in ("blocked", "control_effective")
        if case.get(key) is True
    ]
    parts = [
        f"category={_slugify(str(category or 'ai-red-team')) or 'ai-red-team'}",
    ]
    strategy_slug = _slugify(str(strategy or ""))
    if strategy_slug:
        parts.append(f"strategy={strategy_slug}")
    if result_markers:
        parts.append(f"result={','.join(result_markers)}")
    if blocked_markers:
        parts.append(f"blocked_by={','.join(blocked_markers)}")
    score = case.get("score")
    if isinstance(score, (int, float)):
        parts.append(f"score={score}")
    return "; ".join(parts)


def _redact_ai_evidence_text(value: str) -> str:
    redacted = re.sub(
        r"(?i)(secret|token|api[_-]?key|password|credential)(\s*[=:]\s*)[^\s,;]+",
        r"\1\2[redacted]",
        value,
    )
    redacted = re.sub(
        r"(?i)(bearer\s+)[a-z0-9._~+/=-]{12,}",
        r"\1[redacted]",
        redacted,
    )
    return redacted


def _first_string(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _humanize_ai_category(category: str) -> str:
    return (_slugify(category) or "ai-system-risk").replace("-", " ")


def _coerce_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _truncate_text(value: str, limit: int) -> str:
    text = value.strip()
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)].rstrip() + "..."


def _normalize_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return []


def _redact_secret_arg(flag: str, value: str) -> str:
    if flag in {"-H", "--header"} and ":" in value:
        header_name = value.split(":", 1)[0].strip()
        return f"{header_name}: [redacted]"
    return "[redacted]"


def _should_redact_target_arg(
    arg: str,
    target: str | None,
    resolved_target: str | None,
    target_type: str | None,
) -> bool:
    if target_type not in _PATH_TARGET_TYPES:
        return False
    return bool(arg and arg in {target, resolved_target})


def _target_placeholder(arg: str, target_type: str | None) -> str:
    name = arg.rstrip("/").split("/")[-1] or "path"
    return f"[{target_type or 'target'}:{name}:sha256:{_target_hash(arg)}]"


def _target_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _output_sha256(value: bytes | str) -> str:
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(payload).hexdigest()


async def _read_stream_with_limit(
    stream: asyncio.StreamReader | None,
    max_bytes: int | None,
) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(8192)
        if not chunk:
            return b"".join(chunks), False
        if max_bytes is not None and total + len(chunk) > max_bytes:
            remaining = max(0, max_bytes - total)
            if remaining:
                chunks.append(chunk[:remaining])
            return b"".join(chunks), True
        chunks.append(chunk)
        total += len(chunk)


async def _communicate_with_output_cap(
    proc: asyncio.subprocess.Process,
    *,
    max_stdout_bytes: int | None,
    max_stderr_bytes: int = _STDERR_CAPTURE_LIMIT,
) -> tuple[bytes, bytes, bool]:
    stdout_task = asyncio.create_task(
        _read_stream_with_limit(proc.stdout, max_stdout_bytes)
    )
    stderr_task = asyncio.create_task(
        _read_stream_with_limit(proc.stderr, max_stderr_bytes)
    )
    wait_task = asyncio.create_task(proc.wait())
    stdout_limit_exceeded = False
    stderr_limit_exceeded = False

    try:
        while True:
            done, _ = await asyncio.wait(
                {stdout_task, stderr_task, wait_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if stdout_task in done:
                _, stdout_limit_exceeded = stdout_task.result()
            if stderr_task in done:
                _, stderr_limit_exceeded = stderr_task.result()
            if (
                stdout_limit_exceeded or stderr_limit_exceeded
            ) and proc.returncode is None:
                proc.kill()
            if wait_task in done:
                break
            if stdout_limit_exceeded or stderr_limit_exceeded:
                await wait_task
                break

        stdout, stdout_limit_exceeded = await stdout_task
        stderr, stderr_limit_exceeded = await stderr_task
        return stdout, stderr, stdout_limit_exceeded or stderr_limit_exceeded
    finally:
        for task in (stdout_task, stderr_task, wait_task):
            if not task.done():
                task.cancel()


def _normalize_tags(value: Any) -> list[str]:
    if isinstance(value, str):
        return [tag.strip() for tag in value.split(",") if tag.strip()]
    if isinstance(value, list):
        return [str(tag).strip() for tag in value if str(tag).strip()]
    return []


def _normalize_extracted_results(value: Any) -> str | None:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if value is None:
        return None
    return str(value)


def _normalize_cvss_score(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_severity(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    return _GENERIC_SEVERITY_MAP.get(value.strip().lower(), "unknown")


def _parse_external_report_output(
    target: str,
    output: bytes | str,
    *,
    tool_name: str,
    deterministic: bool,
) -> list[ValidationEvidence]:
    text = (
        output.decode("utf-8", errors="replace")
        if isinstance(output, bytes)
        else output
    )
    if not text.strip():
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, (dict, list)):
        findings = _parse_external_document(
            target,
            data,
            tool_name=tool_name,
            deterministic=deterministic,
        )
        if findings:
            return findings

    jsonl_findings: list[ValidationEvidence] = []
    parsed_jsonl = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            line_data = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed_jsonl = True
        if isinstance(line_data, dict):
            jsonl_findings.extend(
                _parse_external_document(
                    target,
                    line_data,
                    tool_name=tool_name,
                    deterministic=deterministic,
                )
            )
    if jsonl_findings or parsed_jsonl:
        return jsonl_findings

    return _parse_external_text_report(
        target,
        text,
        tool_name=tool_name,
        deterministic=deterministic,
    )


def _parse_external_document(
    target: str,
    data: dict[str, Any] | list[Any],
    *,
    tool_name: str,
    deterministic: bool,
) -> list[ValidationEvidence]:
    findings: list[ValidationEvidence] = []
    source_tool = _external_source_tool(data)
    for index, item in enumerate(_external_finding_dicts(data), start=1):
        finding = _external_finding_from_dict(
            target,
            item,
            index=index,
            tool_name=tool_name,
            deterministic=deterministic,
            source_tool=source_tool,
        )
        if finding is not None:
            findings.append(finding)
    return findings


def _parse_external_text_report(
    target: str,
    text: str,
    *,
    tool_name: str,
    deterministic: bool,
) -> list[ValidationEvidence]:
    chunks = [
        chunk.strip() for chunk in _TEXT_FINDING_SPLIT_RE.split(text) if chunk.strip()
    ]
    if not chunks:
        chunks = [text.strip()]
    findings: list[ValidationEvidence] = []
    for index, chunk in enumerate(chunks, start=1):
        title = _text_report_title(chunk, index=index, tool_name=tool_name)
        severity = _normalize_external_severity(chunk)
        tags = _external_keyword_tags(chunk)
        findings.append(
            ValidationEvidence(
                tool_name=tool_name,
                target=target,
                severity=severity,
                finding_title=title,
                cve_ids=_extract_cve_ids([chunk]),
                tags=_compact_strings([tool_name, "imported-report", *tags]),
                matched_url=target,
                raw_output={"text": chunk[:20_000]},
                deterministic=deterministic,
                template_id=f"{tool_name}-{index:03d}",
                extracted_results=chunk[:2_000],
            )
        )
    return findings


def _external_finding_dicts(data: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    for key in _EXTERNAL_FINDING_LIST_KEYS:
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _external_finding_dicts(value)
            if nested:
                return nested
    if _looks_like_external_finding(data):
        return [data]
    return []


def _looks_like_external_finding(value: dict[str, Any]) -> bool:
    keys = {str(key).lower() for key in value}
    return bool(
        keys.intersection(_EXTERNAL_TITLE_KEYS)
        or keys.intersection(_EXTERNAL_SEVERITY_KEYS)
        or keys.intersection(_EXTERNAL_DESCRIPTION_KEYS)
    )


def _external_finding_from_dict(
    target: str,
    item: dict[str, Any],
    *,
    index: int,
    tool_name: str,
    deterministic: bool,
    source_tool: str | None,
) -> ValidationEvidence | None:
    title = _first_external_text(item, _EXTERNAL_TITLE_KEYS)
    template_id = _first_external_text(item, _EXTERNAL_ID_KEYS)
    if not title and not template_id:
        return None
    if not title:
        title = template_id or f"Imported finding {index}"
    source = (
        _first_external_text(
            item, ("tool", "scanner", "source_tool", "source", "product")
        )
        or source_tool
    )
    if source and source.casefold() not in title.casefold():
        title = f"{source}: {title}"
    if not template_id:
        template_id = _external_template_id(tool_name, title, index)
    matched_url = _first_external_text(item, _EXTERNAL_TARGET_KEYS) or target
    description = _joined_external_text(item, _EXTERNAL_DESCRIPTION_KEYS)
    severity = _normalize_external_severity(
        _first_external_text(item, _EXTERNAL_SEVERITY_KEYS) or item
    )
    tags = _compact_strings(
        [
            tool_name,
            "imported-report",
            _slugify(source or ""),
            *_external_declared_tags(item),
            *_external_keyword_tags(
                "\n".join(
                    [title, description, matched_url, json.dumps(item, default=str)]
                )
            ),
        ]
    )
    return ValidationEvidence(
        tool_name=tool_name,
        target=target,
        severity=severity,
        finding_title=title,
        cve_ids=_extract_cve_ids([template_id, title, item]),
        tags=tags,
        matched_url=matched_url,
        raw_output=item,
        deterministic=deterministic,
        template_id=template_id[:200],
        extracted_results=description[:2_000] if description else matched_url,
        cvss_score=_normalize_cvss_score(
            _first_external_text(item, ("cvss", "cvss_score", "score"))
        ),
    )


def _external_source_tool(data: dict[str, Any] | list[Any]) -> str | None:
    if not isinstance(data, dict):
        return None
    return _first_external_text(
        data, ("tool", "scanner", "source_tool", "source", "product")
    )


def _first_external_text(data: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        if key not in data:
            continue
        value = data.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            if value.strip():
                return value.strip()
            continue
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, list):
            compact = _compact_strings(
                [_stringify_external_value(item) for item in value]
            )
            if compact:
                return ", ".join(compact)
            continue
        if isinstance(value, dict):
            nested = _first_external_text(value, keys)
            if nested:
                return nested
            text = _stringify_external_value(value)
            if text:
                return text
    return ""


def _joined_external_text(data: dict[str, Any], keys: tuple[str, ...]) -> str:
    return "\n".join(
        _compact_strings(
            [
                _stringify_external_value(data.get(key))
                for key in keys
                if data.get(key) is not None
            ]
        )
    )


def _stringify_external_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(
            _compact_strings([_stringify_external_value(item) for item in value])
        )
    if isinstance(value, dict):
        for key in ("name", "id", "title", "value", "description"):
            if key in value:
                nested = _stringify_external_value(value.get(key))
                if nested:
                    return nested
        return json.dumps(value, default=str)
    return str(value).strip()


def _external_declared_tags(item: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    for key in _EXTERNAL_TAG_KEYS:
        value = item.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            tags.extend(_normalize_tags(value))
        elif isinstance(value, list):
            tags.extend(_normalize_tags(value))
        else:
            text = _stringify_external_value(value)
            if text:
                tags.append(text)
    return [_slugify(tag) for tag in tags if _slugify(tag)]


def _external_keyword_tags(text: str) -> list[str]:
    lowered = text.casefold()
    tags: list[str] = []
    keyword_map = [
        (
            "auth-bypass",
            (
                "auth bypass",
                "authentication bypass",
                "authorization bypass",
                "bypass authentication",
            ),
        ),
        ("jwt", ("jwt", "json web token", "unsigned token")),
        (
            "idor",
            ("idor", "object reference", "broken object level authorization", "bola"),
        ),
        ("sqli", ("sql injection", "sqli")),
        ("xss", ("cross-site scripting", "cross site scripting", "xss")),
        (
            "ssrf",
            ("server-side request forgery", "server side request forgery", "ssrf"),
        ),
        (
            "rce",
            ("remote code execution", "command injection", "code execution", "rce"),
        ),
        ("csrf", ("csrf", "cross-site request forgery", "cross site request forgery")),
        ("xxe", ("xml external entity", "xxe")),
        ("lfi", ("local file inclusion", "lfi")),
        ("rfi", ("remote file inclusion", "rfi")),
        ("open-redirect", ("open redirect", "unvalidated redirect")),
        ("misconfig", ("misconfiguration", "misconfigured", "insecure configuration")),
        (
            "exposure",
            (
                "publicly accessible",
                "public access",
                "data exposure",
                "information disclosure",
            ),
        ),
        ("cookie", ("cookie", "session cookie")),
        ("dos", ("denial of service", "resource exhaustion", "dos")),
        ("audit", ("repudiation", "audit log", "logging gap")),
        ("spoofing", ("spoofing", "spoofed", "impersonation")),
        ("tampering", ("tampering", "modify data", "manipulate")),
        ("elevation-of-privilege", ("privilege escalation", "elevation of privilege")),
    ]
    for tag, phrases in keyword_map:
        if any(phrase in lowered for phrase in phrases):
            tags.append(tag)
    if _CVE_PATTERN.search(text):
        tags.append("cve")
    return tags


def _normalize_external_severity(value: Any) -> str:
    if not isinstance(value, str):
        text = json.dumps(value, default=str)
    else:
        text = value
    normalized = text.strip().casefold()
    if normalized in _GENERIC_SEVERITY_MAP:
        return _GENERIC_SEVERITY_MAP[normalized]
    if re.search(r"\bp0\b|\bcritical\b", normalized):
        return "critical"
    if re.search(r"\bp1\b|\bhigh\b|\bmajor\b", normalized):
        return "high"
    if re.search(r"\bp2\b|\bmedium\b|\bmoderate\b", normalized):
        return "medium"
    if re.search(r"\bp3\b|\blow\b|\bminor\b", normalized):
        return "low"
    if re.search(r"\bp4\b|\binfo(?:rmational)?\b", normalized):
        return "info"
    return "unknown"


def _external_template_id(tool_name: str, title: str, index: int) -> str:
    slug = _slugify(title)[:80] or f"finding-{index:03d}"
    return f"{tool_name}-{slug}"


def _slugify(value: str) -> str:
    tokens = re.findall(r"[a-z0-9]+", value.casefold())
    return "-".join(tokens)


def _text_report_title(text: str, *, index: int, tool_name: str) -> str:
    for line in text.splitlines():
        cleaned = line.strip().strip("#*- ")
        if cleaned:
            return re.sub(
                r"^(critical|high|medium|moderate|low|info|p[0-4])\s*[:\-]\s*",
                "",
                cleaned,
                flags=re.IGNORECASE,
            )[:500]
    return f"{tool_name} finding {index}"


def _iter_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _compact_strings(values: list[Any]) -> list[str]:
    compacted: list[str] = []
    for value in values:
        if not value:
            continue
        text = str(value).strip()
        if text and text not in compacted:
            compacted.append(text)
    return compacted


def _extract_cve_ids(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    cve_ids: list[str] = []
    for value in values:
        for match in _CVE_PATTERN.findall(json.dumps(value, default=str)):
            normalized = match.upper()
            if normalized in seen:
                continue
            seen.add(normalized)
            cve_ids.append(normalized)
    return cve_ids


def _osv_severity(vulnerability: dict[str, Any]) -> str:
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        severity = _normalize_severity(database_specific.get("severity"))
        if severity != "unknown":
            return severity

    score = _highest_cvss_score(vulnerability.get("severity"))
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _severity_from_numeric_score(value: Any) -> str:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _highest_cvss_score(severities: Any) -> float | None:
    scores: list[float] = []
    for severity in _iter_dicts(severities):
        score = severity.get("score")
        if not isinstance(score, str):
            continue
        first_token = score.split("/")[0].strip()
        try:
            scores.append(float(first_token))
        except ValueError:
            continue
    return max(scores) if scores else None


def _trivy_cvss_score(vulnerability: dict[str, Any]) -> float | None:
    cvss = vulnerability.get("CVSS")
    scores: list[float] = []
    if isinstance(cvss, dict):
        for vendor_score in cvss.values():
            if not isinstance(vendor_score, dict):
                continue
            score = _normalize_cvss_score(vendor_score.get("V3Score"))
            if score is not None:
                scores.append(score)
    return max(scores) if scores else None


def _result_context(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "Target": result.get("Target"),
        "Class": result.get("Class"),
        "Type": result.get("Type"),
    }

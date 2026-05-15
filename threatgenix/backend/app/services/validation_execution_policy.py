"""Execution policy for validation tools.

This module is intentionally policy-only. It does not execute scanners.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from app.services.validation_sandbox import (
    VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV,
    configured_validation_allowed_roots,
    validation_container_image,
    validation_container_image_present,
    validation_container_pull_policy,
    validation_container_runtime,
    validation_isolated_runner_ready_for,
    validation_process_sandbox_network_allowed,
    validation_sandbox_mode,
)
from app.services.validation_runtime import (
    RUNTIME_MANAGED,
    validation_runtime_mode,
    validation_run_submission_blocked_reason,
    validation_run_submission_enabled,
)
from app.services.validation_tools import (
    AI_RED_TEAM_TOOL_NAME,
    CHECKOV_TOOL_NAME,
    EXTERNAL_REPORT_TOOL_NAME,
    NUCLEI_TOOL_NAME,
    OSV_SCANNER_TOOL_NAME,
    PENTEST_REPORT_TOOL_NAME,
    SEMGREP_TOOL_NAME,
    TRUFFLEHOG_TOOL_NAME,
    TRIVY_TOOL_NAME,
    ValidationToolAdapter,
    ValidationToolRegistry,
    default_validation_tool_registry,
)

TARGET_URL = "url"
TARGET_REPOSITORY_PATH = "repository_path"
TARGET_LOCKFILE = "lockfile"
TARGET_CONTAINER_IMAGE = "container_image"
TARGET_IAC_DIRECTORY = "iac_directory"
TARGET_AI_SYSTEM = "ai_system"
CURRENT_VALIDATION_TARGET_TYPES = [
    TARGET_URL,
    TARGET_REPOSITORY_PATH,
    TARGET_LOCKFILE,
    TARGET_CONTAINER_IMAGE,
    TARGET_IAC_DIRECTORY,
    TARGET_AI_SYSTEM,
]

NETWORK_TARGET_ONLY = "target_only"
NETWORK_NONE = "none"
NETWORK_ADVISORY_DB = "advisory_db"
_PATH_TARGET_TYPES = {
    TARGET_REPOSITORY_PATH,
    TARGET_LOCKFILE,
    TARGET_IAC_DIRECTORY,
    TARGET_AI_SYSTEM,
}
_INSTALL_HINTS = {
    NUCLEI_TOOL_NAME: "brew install nuclei",
    SEMGREP_TOOL_NAME: "brew install semgrep",
    OSV_SCANNER_TOOL_NAME: "brew install osv-scanner",
    TRIVY_TOOL_NAME: "brew install aquasecurity/trivy/trivy",
    CHECKOV_TOOL_NAME: "pipx install checkov",
    TRUFFLEHOG_TOOL_NAME: "brew install trufflehog",
    AI_RED_TEAM_TOOL_NAME: None,
}


def _network_mode_for_tool_name(tool_name: str) -> str:
    if tool_name == NUCLEI_TOOL_NAME:
        return NETWORK_TARGET_ONLY
    if tool_name == OSV_SCANNER_TOOL_NAME:
        return NETWORK_ADVISORY_DB
    return NETWORK_NONE


def _env_flag(name: str, *, default: bool = False) -> bool:
    raw = os.getenv(f"THREATGENIX_{name}")
    if raw is None:
        raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _tool_execution_enabled(tool_slug: str, *, default: bool = False) -> bool:
    normalized = tool_slug.upper().replace("-", "_")
    return _env_flag(f"VALIDATION_{normalized}_ENABLED", default=default)


def managed_process_network_policy_blocked(
    network_mode: str,
    *,
    tool_name: str | None = None,
) -> bool:
    isolated_network_ready = (
        validation_isolated_runner_ready_for(tool_name, network_mode)
        if tool_name
        else False
    )
    return (
        validation_runtime_mode() == RUNTIME_MANAGED
        and validation_sandbox_mode() != "container"
        and network_mode != NETWORK_NONE
        and not isolated_network_ready
    )


@dataclass(frozen=True)
class ValidationPolicyDecision:
    tool_name: str
    target_type: str
    allowed: bool
    reason: str


@dataclass(frozen=True)
class ValidationExecutionPolicy:
    tool_name: str
    supported_targets: list[str]
    runs_in_sandbox_required: bool
    execution_enabled: bool
    network_mode: str
    max_runtime_seconds: int
    max_output_bytes: int
    artifact_capture_enabled: bool
    allowlist_required: bool = True
    category: str = "validation"
    proof_mode: str = "deterministic evidence"
    safety_boundary: str = "authorization required; bounded runtime and output"
    documentation_url: str = ""
    recommended_for: list[str] | None = None

    def evaluate(self, target_type: str, target: str) -> ValidationPolicyDecision:
        if not target.strip():
            return ValidationPolicyDecision(
                tool_name=self.tool_name,
                target_type=target_type,
                allowed=False,
                reason="target is required",
            )
        if target_type not in self.supported_targets:
            return ValidationPolicyDecision(
                tool_name=self.tool_name,
                target_type=target_type,
                allowed=False,
                reason=f"{self.tool_name} does not support target type {target_type}",
            )
        if not self.execution_enabled:
            return ValidationPolicyDecision(
                tool_name=self.tool_name,
                target_type=target_type,
                allowed=False,
                reason=f"{self.tool_name} execution is disabled until sandbox enforcement is enabled",
            )
        return ValidationPolicyDecision(
            tool_name=self.tool_name,
            target_type=target_type,
            allowed=True,
            reason="execution permitted by validation policy",
        )

    def evaluate_parse_only(self, target_type: str, target: str) -> ValidationPolicyDecision:
        """Evaluate pre-captured evidence ingestion without requiring execution enablement."""
        if not target.strip():
            return ValidationPolicyDecision(
                tool_name=self.tool_name,
                target_type=target_type,
                allowed=False,
                reason="target is required",
            )
        if target_type not in self.supported_targets:
            return ValidationPolicyDecision(
                tool_name=self.tool_name,
                target_type=target_type,
                allowed=False,
                reason=f"{self.tool_name} does not support target type {target_type}",
            )
        return ValidationPolicyDecision(
            tool_name=self.tool_name,
            target_type=target_type,
            allowed=True,
            reason="parse-only evidence ingestion permitted by validation policy",
        )


class ValidationExecutionPolicyRegistry:
    def __init__(self, policies: list[ValidationExecutionPolicy]) -> None:
        self._policies = {policy.tool_name: policy for policy in policies}

    def get(self, tool_name: str) -> ValidationExecutionPolicy:
        return self._policies[tool_name]

    def list(self) -> list[ValidationExecutionPolicy]:
        return list(self._policies.values())


@dataclass(frozen=True)
class ValidationToolInventoryItem:
    name: str
    active: bool
    available: bool
    deterministic: bool
    runtime_strategy: str
    runtime_detail: str
    readiness_status: str
    blocker_reasons: list[str]
    setup_actions: list[str]
    install_hint: str | None
    enablement_env: str | None
    local_allowlist_required: bool
    local_allowlist_configured: bool
    sandbox_mode: str
    container_runtime_available: bool
    container_image: str | None
    container_image_present: bool
    container_pull_policy: str
    supported_targets: list[str]
    runs_in_sandbox_required: bool
    execution_enabled: bool
    network_mode: str
    max_runtime_seconds: int
    max_output_bytes: int
    artifact_capture_enabled: bool
    category: str
    proof_mode: str
    safety_boundary: str
    documentation_url: str
    recommended_for: list[str]


@dataclass(frozen=True)
class ValidationToolRuntimeAvailability:
    available: bool
    strategy: str
    detail: str


@dataclass(frozen=True)
class RedTeamToolProfile:
    name: str
    label: str
    category: str
    status: str
    supported_targets: list[str]
    network_mode: str
    recommended_for: list[str]
    safety_boundary: str
    integration_notes: str
    documentation_url: str


def validation_tool_runtime_availability(
    adapter: ValidationToolAdapter,
) -> ValidationToolRuntimeAvailability:
    """Return whether a tool can be invoked by the configured runner.

    In container sandbox mode, the approved image is the tool host. The backend
    should not require scanner CLIs on the API host when Docker/Podman and an
    image are configured.
    """
    if adapter.name == AI_RED_TEAM_TOOL_NAME:
        return ValidationToolRuntimeAvailability(
            available=True,
            strategy="in_process",
            detail="Runs the deterministic AI-system evidence parser without external model or network calls.",
        )

    sandbox_mode = validation_sandbox_mode()
    container_image = validation_container_image(adapter.name)
    container_runtime_available = validation_container_runtime() is not None
    container_pull_policy = validation_container_pull_policy()
    if validation_runtime_mode() == RUNTIME_MANAGED and validation_isolated_runner_ready_for(
        adapter.name,
        _network_mode_for_tool_name(adapter.name),
    ):
        return ValidationToolRuntimeAvailability(
            available=True,
            strategy="isolated_runner",
            detail="Runs through the configured remote isolated validation runner.",
        )

    if sandbox_mode == "container":
        if container_image and container_runtime_available and validation_container_image_present(adapter.name):
            return ValidationToolRuntimeAvailability(
                available=True,
                strategy="container_image",
                detail=f"Runs from approved local container image {container_image}.",
            )
        if container_image and container_runtime_available and container_pull_policy != "never":
            return ValidationToolRuntimeAvailability(
                available=True,
                strategy="container_image",
                detail=(
                    f"Runs from approved container image {container_image}; "
                    f"runner may pull with policy {container_pull_policy}."
                ),
            )
        if container_image:
            if container_runtime_available:
                return ValidationToolRuntimeAvailability(
                    available=False,
                    strategy="container_image",
                    detail=(
                        f"Approved container image {container_image} is not present locally "
                        "and THREATGENIX_VALIDATION_CONTAINER_PULL=never."
                    ),
                )
            return ValidationToolRuntimeAvailability(
                available=False,
                strategy="container_image",
                detail="Container image is configured, but Docker/Podman is unavailable to the runner.",
            )
        return ValidationToolRuntimeAvailability(
            available=False,
            strategy="unavailable",
            detail="No approved container image is configured for this tool.",
        )

    if adapter.is_available():
        return ValidationToolRuntimeAvailability(
            available=True,
            strategy="host_cli",
            detail="Runs from a CLI installed on the validation runner host.",
        )

    return ValidationToolRuntimeAvailability(
        available=False,
        strategy="unavailable",
        detail=(
            f"{adapter.name} CLI is not installed or not on PATH. "
            "Set THREATGENIX_VALIDATION_SANDBOX_MODE=container to run from an approved image."
        ),
    )


def validation_tool_runtime_available(adapter: ValidationToolAdapter) -> bool:
    return validation_tool_runtime_availability(adapter).available


def default_validation_execution_policy_registry() -> ValidationExecutionPolicyRegistry:
    return ValidationExecutionPolicyRegistry(
        [
            ValidationExecutionPolicy(
                tool_name=NUCLEI_TOOL_NAME,
                supported_targets=[TARGET_URL],
                runs_in_sandbox_required=False,
                execution_enabled=_tool_execution_enabled("nuclei", default=True),
                network_mode=NETWORK_TARGET_ONLY,
                max_runtime_seconds=600,
                max_output_bytes=2_000_000,
                artifact_capture_enabled=True,
                category="dynamic_template_scan",
                proof_mode="HTTP proof of finding",
                safety_boundary="Explicit authorization gate; target-only network access; rate-limited Nuclei templates.",
                documentation_url="https://docs.projectdiscovery.io/tools/nuclei/overview",
                recommended_for=["external attack surface", "known CVEs", "HTTP misconfiguration"],
            ),
            ValidationExecutionPolicy(
                tool_name=SEMGREP_TOOL_NAME,
                supported_targets=[TARGET_REPOSITORY_PATH],
                runs_in_sandbox_required=True,
                execution_enabled=_tool_execution_enabled("semgrep", default=True),
                network_mode=NETWORK_NONE,
                max_runtime_seconds=600,
                max_output_bytes=5_000_000,
                artifact_capture_enabled=True,
                category="static_code_analysis",
                proof_mode="source-code evidence",
                safety_boundary="Local path allowlist; no network; metrics disabled; command and path redaction.",
                documentation_url="https://semgrep.dev/docs/getting-started/cli",
                recommended_for=["semantic code flaws", "insecure auth logic", "injection patterns"],
            ),
            ValidationExecutionPolicy(
                tool_name=OSV_SCANNER_TOOL_NAME,
                supported_targets=[TARGET_LOCKFILE, TARGET_REPOSITORY_PATH],
                runs_in_sandbox_required=True,
                execution_enabled=_tool_execution_enabled("osv-scanner", default=True),
                network_mode=NETWORK_ADVISORY_DB,
                max_runtime_seconds=600,
                max_output_bytes=5_000_000,
                artifact_capture_enabled=True,
                category="software_composition_analysis",
                proof_mode="dependency advisory match",
                safety_boundary="Local path allowlist; advisory database access only; no target exploitation.",
                documentation_url="https://google.github.io/osv-scanner/",
                recommended_for=["dependency CVEs", "lockfile validation", "supply-chain risk"],
            ),
            ValidationExecutionPolicy(
                tool_name=TRIVY_TOOL_NAME,
                supported_targets=[
                    TARGET_REPOSITORY_PATH,
                    TARGET_IAC_DIRECTORY,
                ],
                runs_in_sandbox_required=True,
                execution_enabled=_tool_execution_enabled("trivy", default=True),
                network_mode=NETWORK_NONE,
                max_runtime_seconds=900,
                max_output_bytes=10_000_000,
                artifact_capture_enabled=True,
                category="misconfiguration_scan",
                proof_mode="offline configuration evidence",
                safety_boundary=(
                    "Local path allowlist for filesystem scans; DB updates disabled by "
                    "default; bounded output."
                ),
                documentation_url="https://trivy.dev/latest/",
                recommended_for=[
                    "IaC misconfiguration",
                    "filesystem configuration drift",
                    "cloud exposure patterns",
                ],
            ),
            ValidationExecutionPolicy(
                tool_name=CHECKOV_TOOL_NAME,
                supported_targets=[TARGET_IAC_DIRECTORY, TARGET_REPOSITORY_PATH],
                runs_in_sandbox_required=True,
                execution_enabled=_tool_execution_enabled("checkov", default=True),
                network_mode=NETWORK_NONE,
                max_runtime_seconds=600,
                max_output_bytes=5_000_000,
                artifact_capture_enabled=True,
                category="iac_policy_scan",
                proof_mode="IaC policy failure",
                safety_boundary="Local path allowlist; skip-download and skip-results-upload enabled; no cloud mutations.",
                documentation_url="https://www.checkov.io/",
                recommended_for=["Terraform/Kubernetes drift", "public storage", "cloud control gaps"],
            ),
            ValidationExecutionPolicy(
                tool_name=TRUFFLEHOG_TOOL_NAME,
                supported_targets=[TARGET_REPOSITORY_PATH],
                runs_in_sandbox_required=True,
                execution_enabled=_tool_execution_enabled("trufflehog", default=True),
                network_mode=NETWORK_NONE,
                max_runtime_seconds=600,
                max_output_bytes=5_000_000,
                artifact_capture_enabled=True,
                category="secret_exposure_scan",
                proof_mode="offline secret-pattern evidence",
                safety_boundary="Local repository path allowlist; no network; provider verification disabled; command and path redaction.",
                documentation_url="https://github.com/trufflesecurity/trufflehog",
                recommended_for=["credential exposure", "secret leakage", "token hygiene"],
            ),
            ValidationExecutionPolicy(
                tool_name=AI_RED_TEAM_TOOL_NAME,
                supported_targets=[TARGET_AI_SYSTEM],
                runs_in_sandbox_required=True,
                execution_enabled=_tool_execution_enabled("ai-red-team", default=True),
                network_mode=NETWORK_NONE,
                max_runtime_seconds=120,
                max_output_bytes=2_000_000,
                artifact_capture_enabled=True,
                category="ai_system_red_team",
                proof_mode="executed AI red-team case evidence",
                safety_boundary=(
                    "Local AI-system evidence file allowlist; no model provider calls; "
                    "no network; prompts and completions redacted from stored metadata."
                ),
                documentation_url="",
                recommended_for=[
                    "prompt injection",
                    "RAG poisoning",
                    "sensitive data leakage",
                    "agent tool abuse",
                    "model denial of service",
                ],
            ),
        ]
    )


def default_evidence_ingest_policy_registry() -> ValidationExecutionPolicyRegistry:
    return ValidationExecutionPolicyRegistry(
        [
            *default_validation_execution_policy_registry().list(),
            ValidationExecutionPolicy(
                tool_name=EXTERNAL_REPORT_TOOL_NAME,
                supported_targets=CURRENT_VALIDATION_TARGET_TYPES,
                runs_in_sandbox_required=False,
                execution_enabled=False,
                network_mode=NETWORK_NONE,
                max_runtime_seconds=0,
                max_output_bytes=10_000_000,
                artifact_capture_enabled=True,
                allowlist_required=False,
                category="external_security_report",
                proof_mode="externally supplied security evidence",
                safety_boundary="Parse-only import; ThreatGenix does not execute the external tool.",
                recommended_for=["third-party scanner output", "BAS reports", "security platform exports"],
            ),
            ValidationExecutionPolicy(
                tool_name=PENTEST_REPORT_TOOL_NAME,
                supported_targets=CURRENT_VALIDATION_TARGET_TYPES,
                runs_in_sandbox_required=False,
                execution_enabled=False,
                network_mode=NETWORK_NONE,
                max_runtime_seconds=0,
                max_output_bytes=10_000_000,
                artifact_capture_enabled=True,
                allowlist_required=False,
                category="pentest_report",
                proof_mode="human pentest evidence",
                safety_boundary="Parse-only import; human evidence remains reviewable and non-deterministic.",
                recommended_for=["consultant pentest findings", "manual exploit notes", "attestation evidence"],
            ),
        ]
    )


def build_validation_tool_inventory(
    tool_registry: ValidationToolRegistry | None = None,
    policy_registry: ValidationExecutionPolicyRegistry | None = None,
) -> list[ValidationToolInventoryItem]:
    tool_registry = tool_registry or default_validation_tool_registry()
    policy_registry = policy_registry or default_validation_execution_policy_registry()

    inventory: list[ValidationToolInventoryItem] = []
    for adapter in tool_registry.list():
        try:
            policy = policy_registry.get(adapter.name)
        except KeyError:
            policy = ValidationExecutionPolicy(
                tool_name=adapter.name,
                supported_targets=[],
                runs_in_sandbox_required=True,
                execution_enabled=False,
                network_mode=NETWORK_NONE,
                max_runtime_seconds=0,
                max_output_bytes=0,
                artifact_capture_enabled=False,
                category="unconfigured_validation_tool",
                proof_mode="not configured",
                safety_boundary="Adapter is registered without an execution policy; execution is blocked.",
                recommended_for=[],
            )
        inventory.append(_inventory_item(adapter, policy))
    return inventory


def _inventory_item(
    adapter: ValidationToolAdapter,
    policy: ValidationExecutionPolicy,
) -> ValidationToolInventoryItem:
    enablement_env = f"THREATGENIX_VALIDATION_{adapter.name.upper().replace('-', '_')}_ENABLED"
    local_allowlist_required = any(
        target_type in _PATH_TARGET_TYPES for target_type in policy.supported_targets
    )
    local_allowlist_configured = bool(configured_validation_allowed_roots())
    sandbox_mode = validation_sandbox_mode()
    container_runtime_available = validation_container_runtime() is not None
    container_image = validation_container_image(adapter.name)
    container_image_present = validation_container_image_present(adapter.name)
    container_pull_policy = validation_container_pull_policy()
    runtime_availability = validation_tool_runtime_availability(adapter)
    tool_available = runtime_availability.available
    isolated_network_ready = validation_isolated_runner_ready_for(
        adapter.name,
        policy.network_mode,
    )
    blocker_reasons: list[str] = []
    setup_actions: list[str] = []
    install_hint = None
    run_submission_enabled = validation_run_submission_enabled()
    if not run_submission_enabled:
        blocker_reasons.append(validation_run_submission_blocked_reason())
        setup_actions.append("Use Try Sandbox or import captured scanner output in hosted SaaS mode.")
    if not tool_available:
        blocker_reasons.append(runtime_availability.detail)
        install_hint = _INSTALL_HINTS.get(adapter.name)
        if sandbox_mode == "container" and container_image:
            setup_actions.append(
                f"Pre-pull {container_image} or set THREATGENIX_VALIDATION_CONTAINER_PULL=missing for controlled pulls."
            )
        elif install_hint:
            setup_actions.append(install_hint)
    if not policy.execution_enabled:
        blocker_reasons.append(f"{adapter.name} execution is disabled by policy.")
        setup_actions.append(f"Set {enablement_env}=true after the tool is installed and approved.")
    if local_allowlist_required and not local_allowlist_configured:
        blocker_reasons.append("Local path allowlist is not configured.")
        setup_actions.append(
            "Set THREATGENIX_VALIDATION_ALLOWED_PATHS to the repository, lockfile, or IaC roots allowed for validation."
        )
    if (
        managed_process_network_policy_blocked(
            policy.network_mode,
            tool_name=policy.tool_name,
        )
        or (
            policy.runs_in_sandbox_required
            and sandbox_mode != "container"
            and policy.network_mode != NETWORK_NONE
            and not validation_process_sandbox_network_allowed(policy.network_mode)
            and not isolated_network_ready
        )
    ):
        blocker_reasons.append(
            f"{policy.network_mode} network policy requires an isolated network runner."
        )
        setup_actions.append(
            "Set THREATGENIX_VALIDATION_SANDBOX_MODE=container and start an approved container runtime before running this tool."
        )
    elif (
        policy.runs_in_sandbox_required
        and sandbox_mode != "container"
        and policy.network_mode != NETWORK_NONE
        and policy.network_mode == NETWORK_ADVISORY_DB
        and validation_process_sandbox_network_allowed(policy.network_mode)
    ):
        setup_actions.append(
            f"{VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV}=true allows local/dev advisory DB egress; use container mode before production."
        )
    elif isolated_network_ready:
        setup_actions.append(
            "Networked execution will run through the configured isolated validation runner."
        )
    if policy.runs_in_sandbox_required and sandbox_mode == "container" and not container_runtime_available:
        blocker_reasons.append("Container sandbox runtime is not available.")
        setup_actions.append(
            "Start Docker or set THREATGENIX_VALIDATION_CONTAINER_RUNTIME to an available container runtime."
        )
    if not blocker_reasons:
        readiness_status = "ready"
        setup_actions.append("Create or run a validation target with per-run authorization.")
    elif policy.execution_enabled and tool_available:
        readiness_status = "needs_configuration"
    elif not policy.execution_enabled:
        readiness_status = "policy_disabled"
    elif runtime_availability.strategy == "container_image":
        readiness_status = "needs_configuration"
    else:
        readiness_status = "cli_missing"

    return ValidationToolInventoryItem(
        name=adapter.name,
        active=adapter.active,
        available=tool_available,
        deterministic=adapter.deterministic,
        runtime_strategy=runtime_availability.strategy,
        runtime_detail=runtime_availability.detail,
        readiness_status=readiness_status,
        blocker_reasons=blocker_reasons,
        setup_actions=setup_actions,
        install_hint=install_hint,
        enablement_env=enablement_env,
        local_allowlist_required=local_allowlist_required,
        local_allowlist_configured=local_allowlist_configured,
        sandbox_mode=sandbox_mode,
        container_runtime_available=container_runtime_available,
        container_image=container_image,
        container_image_present=container_image_present,
        container_pull_policy=container_pull_policy,
        supported_targets=policy.supported_targets,
        runs_in_sandbox_required=policy.runs_in_sandbox_required,
        execution_enabled=policy.execution_enabled,
        network_mode=policy.network_mode,
        max_runtime_seconds=policy.max_runtime_seconds,
        max_output_bytes=policy.max_output_bytes,
        artifact_capture_enabled=policy.artifact_capture_enabled,
        category=policy.category,
        proof_mode=policy.proof_mode,
        safety_boundary=policy.safety_boundary,
        documentation_url=policy.documentation_url,
        recommended_for=policy.recommended_for or [],
    )


def build_red_team_tool_catalog() -> list[RedTeamToolProfile]:
    """Return optional non-current providers for the product surface.

    The current Validation Lab release intentionally exposes only the
    deterministic tools that ThreatGenix can run now.
    """
    return []

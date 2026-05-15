"""Deployment preflight checks for hosted validation execution."""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from app.services.validation_env import validation_env_aliases

STATUS_PASS = "pass"
STATUS_CONFIGURATION_NEEDED = "configuration_needed"
STATUS_FAIL = "fail"
_STATUS_ORDER = {
    STATUS_PASS: 0,
    STATUS_CONFIGURATION_NEEDED: 1,
    STATUS_FAIL: 2,
}
_TRUE_VALUES = {"1", "true", "yes", "on"}
_PRODUCTION_LIKE_ENVS = {"production", "staging"}
_GCP_CONFIG_CANDIDATES = (
    "cloudbuild.yaml",
    "cloudbuild.yml",
    "backend/cloudbuild.yaml",
    "backend/cloudbuild.yml",
    "deploy/gcp/cloud-run-api.yaml",
    "deploy/gcp/cloud-run-api.yml",
    "deploy/gcp/cloud-run-worker.yaml",
    "deploy/gcp/cloud-run-worker.yml",
    "gcp/cloud-run-api.yaml",
    "gcp/cloud-run-api.yml",
    "gcp/cloud-run-worker.yaml",
    "gcp/cloud-run-worker.yml",
)


@dataclass(frozen=True)
class DeploymentPreflightCheck:
    name: str
    status: str
    detail: str
    fix: str | None = None


@dataclass(frozen=True)
class DeploymentPreflightResult:
    provider: str
    status: str
    checks: list[DeploymentPreflightCheck]


def check_fly_deployment_config(
    fly_config_path: Path,
    *,
    environ: Mapping[str, str] | None = None,
) -> DeploymentPreflightResult:
    """Validate Fly deployment config without calling Fly.io."""
    env = os.environ if environ is None else environ
    checks: list[DeploymentPreflightCheck] = []
    if not fly_config_path.exists():
        checks.append(
            DeploymentPreflightCheck(
                name="fly config present",
                status=STATUS_CONFIGURATION_NEEDED,
                detail=f"Fly config is missing at {fly_config_path}.",
                fix="Add backend/fly.toml or provide the Fly config path used for deploys.",
            )
        )
        return _result("fly", checks)

    try:
        config = tomllib.loads(fly_config_path.read_text())
    except tomllib.TOMLDecodeError as exc:
        checks.append(
            DeploymentPreflightCheck(
                name="fly config parses",
                status=STATUS_FAIL,
                detail=f"Fly config is invalid TOML: {exc}.",
                fix="Fix backend/fly.toml before running a staging or production deploy.",
            )
        )
        return _result("fly", checks)

    processes = _string_mapping(config.get("processes"))
    checks.extend(_process_group_checks(processes))
    checks.extend(_fly_service_checks(config))

    deploy = config.get("deploy")
    release_command = (
        deploy.get("release_command") if isinstance(deploy, dict) else None
    )
    checks.append(
        _expect_contains(
            name="fly release migration",
            value=release_command,
            expected="scripts/migrate.sh",
            fix="Set [deploy].release_command to run scripts/migrate.sh.",
        )
    )

    configured_env = _string_mapping(config.get("env"))
    checks.extend(_hosted_validation_env_checks("fly", configured_env))
    checks.append(_fly_credentials_check(env))
    return _result("fly", checks)


def check_gcp_deployment_config(
    root: Path,
    *,
    environ: Mapping[str, str] | None = None,
) -> DeploymentPreflightResult:
    """Validate GCP deployment config shape without calling Google Cloud."""
    env = os.environ if environ is None else environ
    checks: list[DeploymentPreflightCheck] = []
    config_paths = [root / candidate for candidate in _GCP_CONFIG_CANDIDATES]
    existing_paths = [path for path in config_paths if path.exists()]
    if not existing_paths:
        checks.append(
            DeploymentPreflightCheck(
                name="gcp config present",
                status=STATUS_CONFIGURATION_NEEDED,
                detail=(
                    "No GCP deployment config was found under cloudbuild, deploy/gcp, "
                    "or gcp paths."
                ),
                fix=(
                    "Add checked-in GCP staging/production config for the API and "
                    "validation worker before claiming GCP readiness."
                ),
            )
        )
        return _result("gcp", checks)

    combined_text = "\n".join(path.read_text() for path in existing_paths)
    checks.append(
        DeploymentPreflightCheck(
            name="gcp config present",
            status=STATUS_PASS,
            detail=", ".join(str(path.relative_to(root)) for path in existing_paths),
        )
    )
    checks.append(
        _expect_text_contains(
            name="gcp api service command",
            text=combined_text,
            expected_patterns=(r"uvicorn\s+app\.main:app", r"app\.main:app"),
            fix="Declare the API service command in checked-in GCP deploy config.",
        )
    )
    checks.append(
        _expect_text_contains(
            name="gcp worker service command",
            text=combined_text,
            expected_patterns=(r"worker_main\.py",),
            fix="Declare a separate validation worker service/job that runs worker_main.py.",
        )
    )
    checks.extend(_hosted_validation_env_checks("gcp", _env_from_text(combined_text)))
    checks.append(_gcp_credentials_check(env))
    return _result("gcp", checks)


def _process_group_checks(
    processes: Mapping[str, str],
) -> list[DeploymentPreflightCheck]:
    return [
        _expect_contains(
            name="fly app process",
            value=processes.get("app"),
            expected="uvicorn app.main:app",
            fix="Set [processes].app to run uvicorn app.main:app.",
        ),
        _expect_contains(
            name="fly worker process",
            value=processes.get("worker"),
            expected="worker_main.py",
            fix="Set [processes].worker to run python worker_main.py.",
        ),
    ]


def _fly_service_checks(config: Mapping[str, object]) -> list[DeploymentPreflightCheck]:
    services = config.get("services")
    if not isinstance(services, list) or not services:
        return [
            DeploymentPreflightCheck(
                name="fly public service process",
                status=STATUS_CONFIGURATION_NEEDED,
                detail="Fly config does not declare a public service.",
                fix="Expose only the API app process in [[services]].processes.",
            )
        ]
    public_processes: list[str] = []
    for service in services:
        if isinstance(service, dict):
            service_processes = service.get("processes")
            if isinstance(service_processes, list):
                public_processes.extend(str(process) for process in service_processes)
    if public_processes == ["app"]:
        return [
            DeploymentPreflightCheck(
                name="fly public service process",
                status=STATUS_PASS,
                detail="Only the API app process is exposed by Fly services.",
            )
        ]
    return [
        DeploymentPreflightCheck(
            name="fly public service process",
            status=STATUS_FAIL,
            detail=f"Fly services expose processes {public_processes or 'none'}.",
            fix="Expose only the app process; keep the validation worker private.",
        )
    ]


def _hosted_validation_env_checks(
    provider: str,
    configured_env: Mapping[str, str],
) -> list[DeploymentPreflightCheck]:
    app_env = _env_value(configured_env, "APP_ENV", "THREATGENIX_APP_ENV")
    runtime_mode = _env_value(configured_env, "THREATGENIX_VALIDATION_RUNTIME_MODE")
    managed_runner = _env_value(
        configured_env, "THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED"
    )
    allowed_paths = _env_value(configured_env, "THREATGENIX_VALIDATION_ALLOWED_PATHS")
    nuclei_enabled = _env_flag_default_true(
        configured_env, "THREATGENIX_VALIDATION_NUCLEI_ENABLED"
    )
    osv_enabled = _env_flag(
        configured_env, "THREATGENIX_VALIDATION_OSV_SCANNER_ENABLED"
    )
    sandbox_mode = _env_value(configured_env, "THREATGENIX_VALIDATION_SANDBOX_MODE")
    process_advisory = _env_flag(
        configured_env,
        "THREATGENIX_VALIDATION_PROCESS_ADVISORY_DB_NETWORK",
    )
    container_runtime = _env_value(
        configured_env, "THREATGENIX_VALIDATION_CONTAINER_RUNTIME"
    )
    container_network = _env_value(
        configured_env, "THREATGENIX_VALIDATION_CONTAINER_NETWORK"
    )
    container_isolation_proof = _env_value(
        configured_env,
        "THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF",
    )
    isolated_backend = _env_value(
        configured_env,
        "THREATGENIX_VALIDATION_ISOLATED_RUNNER_BACKEND",
    )
    isolated_proxy = _env_value(
        configured_env,
        "THREATGENIX_VALIDATION_ISOLATED_EGRESS_PROXY_URL",
    )
    isolated_k8s_api_server = _env_value(
        configured_env,
        "THREATGENIX_VALIDATION_K8S_API_SERVER",
    )
    isolated_k8s_ca_cert = _env_value(
        configured_env,
        "THREATGENIX_VALIDATION_K8S_CA_CERT_B64",
    )
    isolated_nuclei_image = _env_value(
        configured_env,
        "THREATGENIX_VALIDATION_ISOLATED_IMAGE_NUCLEI",
    )
    isolated_osv_image = _env_value(
        configured_env,
        "THREATGENIX_VALIDATION_ISOLATED_IMAGE_OSV_SCANNER",
    )
    nuclei_target_verification_required = _env_value(
        configured_env,
        "THREATGENIX_VALIDATION_NUCLEI_REQUIRE_TARGET_VERIFICATION",
    )
    isolated_runner_configured = isolated_backend in {"gke", "kubernetes"}

    checks = [
        _expect_one_of(
            name=f"{provider} app environment",
            value=app_env,
            allowed=_PRODUCTION_LIKE_ENVS,
            fix="Set APP_ENV to production or staging in hosted deployment config.",
        ),
        _expect_equals(
            name=f"{provider} managed runtime mode",
            value=runtime_mode,
            expected="managed",
            fix="Set THREATGENIX_VALIDATION_RUNTIME_MODE=managed.",
        ),
        _expect_true(
            name=f"{provider} managed runner enabled",
            value=managed_runner,
            fix="Set THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED=true.",
        ),
        _expect_present(
            name=f"{provider} validation allowed paths",
            value=allowed_paths,
            fix="Set THREATGENIX_VALIDATION_ALLOWED_PATHS to mounted tenant artifacts.",
        ),
    ]
    if process_advisory and app_env in _PRODUCTION_LIKE_ENVS:
        checks.append(
            DeploymentPreflightCheck(
                name=f"{provider} process advisory DB egress",
                status=STATUS_FAIL,
                detail=(
                    "Process-sandbox advisory DB egress is enabled in a hosted "
                    f"{app_env} deployment."
                ),
                fix=(
                    "Remove THREATGENIX_VALIDATION_PROCESS_ADVISORY_DB_NETWORK and "
                    "use container sandbox egress for OSV."
                ),
            )
        )
    else:
        checks.append(
            DeploymentPreflightCheck(
                name=f"{provider} process advisory DB egress",
                status=STATUS_PASS,
                detail="Process-sandbox advisory DB egress is not enabled.",
            )
        )

    if nuclei_enabled:
        if isolated_runner_configured:
            checks.extend(
                [
                    _expect_one_of(
                        name=f"{provider} isolated runner backend",
                        value=isolated_backend,
                        allowed={"gke", "kubernetes"},
                        fix="Set THREATGENIX_VALIDATION_ISOLATED_RUNNER_BACKEND=gke.",
                    ),
                    _expect_present(
                        name=f"{provider} isolated egress proxy",
                        value=isolated_proxy,
                        fix="Set THREATGENIX_VALIDATION_ISOLATED_EGRESS_PROXY_URL.",
                    ),
                    _expect_present(
                        name=f"{provider} isolated Kubernetes API server",
                        value=isolated_k8s_api_server,
                        fix="Set THREATGENIX_VALIDATION_K8S_API_SERVER for Cloud Run job submission.",
                    ),
                    _expect_present(
                        name=f"{provider} isolated Kubernetes CA certificate",
                        value=isolated_k8s_ca_cert,
                        fix="Set THREATGENIX_VALIDATION_K8S_CA_CERT_B64 for TLS verification.",
                    ),
                    _expect_present(
                        name=f"{provider} Nuclei target-network isolation proof",
                        value=container_isolation_proof,
                        fix=(
                            "Set THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF "
                            "to the checked-in GKE runner/IaC proof."
                        ),
                    ),
                    _expect_digest_pinned_image(
                        name=f"{provider} Nuclei isolated image",
                        value=isolated_nuclei_image,
                        fix=(
                            "Set THREATGENIX_VALIDATION_ISOLATED_IMAGE_NUCLEI "
                            "to a digest-pinned scanner wrapper image."
                        ),
                    ),
                    _expect_true(
                        name=f"{provider} Nuclei target verification required",
                        value=nuclei_target_verification_required,
                        fix=(
                            "Set THREATGENIX_VALIDATION_NUCLEI_REQUIRE_TARGET_VERIFICATION=true."
                        ),
                    ),
                ]
            )
        else:
            checks.extend(
                [
                    _expect_equals(
                        name=f"{provider} Nuclei sandbox mode",
                        value=sandbox_mode,
                        expected="container",
                        fix=(
                            "Set THREATGENIX_VALIDATION_NUCLEI_ENABLED=false until "
                            "target-network egress is isolated, or configure "
                            "THREATGENIX_VALIDATION_ISOLATED_RUNNER_BACKEND=gke."
                        ),
                    ),
                    _expect_present(
                        name=f"{provider} Nuclei target-network isolation proof",
                        value=container_isolation_proof,
                        fix=(
                            "Set THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF to "
                            "the checked-in runner, IaC, or deployment artifact that "
                            "proves per-scan target-network isolation."
                        ),
                    ),
                ]
            )

    if osv_enabled:
        if isolated_runner_configured:
            checks.extend(
                [
                    _expect_one_of(
                        name=f"{provider} isolated runner backend",
                        value=isolated_backend,
                        allowed={"gke", "kubernetes"},
                        fix="Set THREATGENIX_VALIDATION_ISOLATED_RUNNER_BACKEND=gke.",
                    ),
                    _expect_present(
                        name=f"{provider} isolated egress proxy",
                        value=isolated_proxy,
                        fix="Set THREATGENIX_VALIDATION_ISOLATED_EGRESS_PROXY_URL.",
                    ),
                    _expect_present(
                        name=f"{provider} isolated Kubernetes API server",
                        value=isolated_k8s_api_server,
                        fix="Set THREATGENIX_VALIDATION_K8S_API_SERVER for Cloud Run job submission.",
                    ),
                    _expect_present(
                        name=f"{provider} isolated Kubernetes CA certificate",
                        value=isolated_k8s_ca_cert,
                        fix="Set THREATGENIX_VALIDATION_K8S_CA_CERT_B64 for TLS verification.",
                    ),
                    _expect_digest_pinned_image(
                        name=f"{provider} OSV isolated image",
                        value=isolated_osv_image,
                        fix=(
                            "Set THREATGENIX_VALIDATION_ISOLATED_IMAGE_OSV_SCANNER "
                            "to a digest-pinned scanner wrapper image."
                        ),
                    ),
                    _expect_present(
                        name=f"{provider} OSV isolation proof",
                        value=container_isolation_proof,
                        fix=(
                            "Set THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF to "
                            "the checked-in GKE runner/IaC proof."
                        ),
                    ),
                ]
            )
        else:
            checks.extend(
                [
                    _expect_equals(
                        name=f"{provider} OSV sandbox mode",
                        value=sandbox_mode,
                        expected="container",
                        fix=(
                            "Set THREATGENIX_VALIDATION_SANDBOX_MODE=container for OSV "
                            "or configure THREATGENIX_VALIDATION_ISOLATED_RUNNER_BACKEND=gke."
                        ),
                    ),
                    _expect_present(
                        name=f"{provider} container runtime",
                        value=container_runtime,
                        fix="Set THREATGENIX_VALIDATION_CONTAINER_RUNTIME to docker or podman.",
                    ),
                    _expect_present(
                        name=f"{provider} advisory DB container network",
                        value=container_network,
                        fix=(
                            "Set THREATGENIX_VALIDATION_CONTAINER_NETWORK to the "
                            "egress-controlled network used by OSV."
                        ),
                    ),
                    _expect_present(
                        name=f"{provider} OSV isolation proof",
                        value=container_isolation_proof,
                        fix=(
                            "Set THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF to "
                            "the checked-in runner, IaC, or deployment artifact that "
                            "proves per-scan isolation and advisory DB-only egress."
                        ),
                    ),
                ]
            )
    return checks


def _fly_credentials_check(environ: Mapping[str, str]) -> DeploymentPreflightCheck:
    if _env_value(environ, "FLY_API_TOKEN", "FLY_ACCESS_TOKEN"):
        return DeploymentPreflightCheck(
            name="fly deployment credentials",
            status=STATUS_PASS,
            detail="Fly deploy token is available in the preflight environment.",
        )
    return DeploymentPreflightCheck(
        name="fly deployment credentials",
        status=STATUS_CONFIGURATION_NEEDED,
        detail="FLY_API_TOKEN or FLY_ACCESS_TOKEN is not set.",
        fix="Provide a scoped Fly deploy token before running the deploy gate.",
    )


def _gcp_credentials_check(environ: Mapping[str, str]) -> DeploymentPreflightCheck:
    project = _env_value(
        environ, "GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GCLOUD_PROJECT"
    )
    credential = _env_value(
        environ,
        "GOOGLE_APPLICATION_CREDENTIALS",
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
        "GCP_SERVICE_ACCOUNT_KEY",
        "GOOGLE_OAUTH_ACCESS_TOKEN",
    )
    if project and credential:
        return DeploymentPreflightCheck(
            name="gcp deployment credentials",
            status=STATUS_PASS,
            detail="GCP project and deploy credentials are available in the preflight environment.",
        )
    missing = []
    if not project:
        missing.append("GOOGLE_CLOUD_PROJECT/GCP_PROJECT")
    if not credential:
        missing.append("GOOGLE_APPLICATION_CREDENTIALS or service-account token")
    return DeploymentPreflightCheck(
        name="gcp deployment credentials",
        status=STATUS_CONFIGURATION_NEEDED,
        detail=f"Missing GCP deploy configuration: {', '.join(missing)}.",
        fix="Provide GCP project and deploy credentials before running the deploy gate.",
    )


def _env_from_text(text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    keys = (
        "APP_ENV",
        "THREATGENIX_APP_ENV",
        "THREATGENIX_VALIDATION_RUNTIME_MODE",
        "THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED",
        "THREATGENIX_VALIDATION_ALLOWED_PATHS",
        "THREATGENIX_VALIDATION_NUCLEI_ENABLED",
        "THREATGENIX_VALIDATION_OSV_SCANNER_ENABLED",
        "THREATGENIX_VALIDATION_SANDBOX_MODE",
        "THREATGENIX_VALIDATION_PROCESS_ADVISORY_DB_NETWORK",
        "THREATGENIX_VALIDATION_CONTAINER_RUNTIME",
        "THREATGENIX_VALIDATION_CONTAINER_NETWORK",
        "THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF",
        "THREATGENIX_VALIDATION_ISOLATED_RUNNER_BACKEND",
        "THREATGENIX_VALIDATION_ISOLATED_EGRESS_PROXY_URL",
        "THREATGENIX_VALIDATION_K8S_API_SERVER",
        "THREATGENIX_VALIDATION_K8S_CA_CERT_B64",
        "THREATGENIX_VALIDATION_ISOLATED_IMAGE_NUCLEI",
        "THREATGENIX_VALIDATION_ISOLATED_IMAGE_OSV_SCANNER",
        "THREATGENIX_VALIDATION_NUCLEI_REQUIRE_TARGET_VERIFICATION",
    )
    for key in keys:
        for candidate in validation_env_aliases(key):
            match = re.search(rf"{candidate}\s*[:=]\s*[\"']?([^\"'\s,]+)", text)
            if match:
                env[candidate] = match.group(1)
                break
    return env


def _expect_contains(
    *,
    name: str,
    value: str | None,
    expected: str,
    fix: str,
) -> DeploymentPreflightCheck:
    if value and expected in value:
        return DeploymentPreflightCheck(name=name, status=STATUS_PASS, detail=value)
    status = STATUS_CONFIGURATION_NEEDED if not value else STATUS_FAIL
    return DeploymentPreflightCheck(
        name=name,
        status=status,
        detail=f"Expected {expected!r}, found {value!r}.",
        fix=fix,
    )


def _expect_text_contains(
    *,
    name: str,
    text: str,
    expected_patterns: tuple[str, ...],
    fix: str,
) -> DeploymentPreflightCheck:
    if any(re.search(pattern, text) for pattern in expected_patterns):
        return DeploymentPreflightCheck(
            name=name,
            status=STATUS_PASS,
            detail="Expected command marker is present.",
        )
    return DeploymentPreflightCheck(
        name=name,
        status=STATUS_CONFIGURATION_NEEDED,
        detail=f"None of {expected_patterns!r} were found.",
        fix=fix,
    )


def _expect_equals(
    *,
    name: str,
    value: str | None,
    expected: str,
    fix: str,
) -> DeploymentPreflightCheck:
    if value == expected:
        return DeploymentPreflightCheck(
            name=name, status=STATUS_PASS, detail=f"{name}={value}"
        )
    status = STATUS_CONFIGURATION_NEEDED if value is None else STATUS_FAIL
    return DeploymentPreflightCheck(
        name=name,
        status=status,
        detail=f"Expected {expected!r}, found {value!r}.",
        fix=fix,
    )


def _expect_one_of(
    *,
    name: str,
    value: str | None,
    allowed: set[str],
    fix: str,
) -> DeploymentPreflightCheck:
    if value in allowed:
        return DeploymentPreflightCheck(
            name=name, status=STATUS_PASS, detail=f"{name}={value}"
        )
    status = STATUS_CONFIGURATION_NEEDED if value is None else STATUS_FAIL
    return DeploymentPreflightCheck(
        name=name,
        status=status,
        detail=f"Expected one of {sorted(allowed)!r}, found {value!r}.",
        fix=fix,
    )


def _expect_present(
    *,
    name: str,
    value: str | None,
    fix: str,
) -> DeploymentPreflightCheck:
    if value:
        return DeploymentPreflightCheck(
            name=name, status=STATUS_PASS, detail=f"{name} is set."
        )
    return DeploymentPreflightCheck(
        name=name,
        status=STATUS_CONFIGURATION_NEEDED,
        detail=f"{name} is not set.",
        fix=fix,
    )


def _expect_digest_pinned_image(
    *,
    name: str,
    value: str | None,
    fix: str,
) -> DeploymentPreflightCheck:
    if value and "@sha256:" in value:
        return DeploymentPreflightCheck(
            name=name,
            status=STATUS_PASS,
            detail=f"{name} is digest pinned.",
        )
    status = STATUS_CONFIGURATION_NEEDED if value is None else STATUS_FAIL
    return DeploymentPreflightCheck(
        name=name,
        status=status,
        detail=f"Expected digest-pinned image, found {value!r}.",
        fix=fix,
    )


def _expect_true(
    *,
    name: str,
    value: str | None,
    fix: str,
) -> DeploymentPreflightCheck:
    if value and value.strip().lower() in _TRUE_VALUES:
        return DeploymentPreflightCheck(
            name=name, status=STATUS_PASS, detail=f"{name}=true"
        )
    status = STATUS_CONFIGURATION_NEEDED if value is None else STATUS_FAIL
    return DeploymentPreflightCheck(
        name=name,
        status=status,
        detail=f"Expected true, found {value!r}.",
        fix=fix,
    )


def _env_flag(env: Mapping[str, str], key: str) -> bool:
    raw = _env_value(env, key)
    return bool(raw and raw.strip().lower() in _TRUE_VALUES)


def _env_flag_default_true(env: Mapping[str, str], key: str) -> bool:
    raw = _env_value(env, key)
    if raw is None:
        return True
    return raw.strip().lower() in _TRUE_VALUES


def _env_value(env: Mapping[str, str], *keys: str) -> str | None:
    for key in keys:
        for candidate in validation_env_aliases(key):
            value = env.get(candidate)
            if value is not None and value.strip():
                return value.strip().lower()
    return None


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _result(
    provider: str, checks: list[DeploymentPreflightCheck]
) -> DeploymentPreflightResult:
    status = max(
        (check.status for check in checks), key=lambda item: _STATUS_ORDER[item]
    )
    return DeploymentPreflightResult(provider=provider, status=status, checks=checks)

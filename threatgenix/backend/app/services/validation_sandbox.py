"""Process-level sandbox boundary for deterministic validation tools."""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.services.validation_env import validation_env_flag, validation_env_value

VALIDATION_ALLOWED_PATHS_ENV = "THREATGENIX_VALIDATION_ALLOWED_PATHS"
VALIDATION_ALLOWED_PATHS_LEGACY_ENV = "VALIDATION_SCAN_ALLOWED_PATHS"
VALIDATION_SANDBOX_MODE_ENV = "THREATGENIX_VALIDATION_SANDBOX_MODE"
VALIDATION_CONTAINER_RUNTIME_ENV = "THREATGENIX_VALIDATION_CONTAINER_RUNTIME"
VALIDATION_CONTAINER_CPUS_ENV = "THREATGENIX_VALIDATION_CONTAINER_CPUS"
VALIDATION_CONTAINER_MEMORY_ENV = "THREATGENIX_VALIDATION_CONTAINER_MEMORY"
VALIDATION_CONTAINER_PIDS_ENV = "THREATGENIX_VALIDATION_CONTAINER_PIDS"
VALIDATION_CONTAINER_PULL_ENV = "THREATGENIX_VALIDATION_CONTAINER_PULL"
VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV = (
    "THREATGENIX_VALIDATION_PROCESS_ADVISORY_DB_NETWORK"
)
VALIDATION_ISOLATED_RUNNER_BACKEND_ENV = (
    "THREATGENIX_VALIDATION_ISOLATED_RUNNER_BACKEND"
)
VALIDATION_ISOLATED_RUNNER_EGRESS_PROXY_ENV = (
    "THREATGENIX_VALIDATION_ISOLATED_EGRESS_PROXY_URL"
)
VALIDATION_ISOLATED_RUNNER_PROOF_ENV = (
    "THREATGENIX_VALIDATION_CONTAINER_ISOLATION_PROOF"
)
VALIDATION_ISOLATED_K8S_API_SERVER_ENV = "THREATGENIX_VALIDATION_K8S_API_SERVER"
VALIDATION_ISOLATED_K8S_CA_CERT_B64_ENV = "THREATGENIX_VALIDATION_K8S_CA_CERT_B64"
VALIDATION_ISOLATED_ALLOW_UNPINNED_IMAGES_ENV = (
    "THREATGENIX_VALIDATION_ISOLATED_ALLOW_UNPINNED_IMAGES"
)
_PATH_TARGET_TYPES = {
    "repository_path",
    "lockfile",
    "iac_directory",
    "ai_system",
}
_PATH_TARGET_EXPECTATIONS = {
    "repository_path": "directory",
    "iac_directory": "directory",
    "lockfile": "file",
    "ai_system": "file",
}
_READ_CHUNK_BYTES = 64 * 1024
_SANDBOX_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
_SANDBOX_MODE_PROCESS = "process"
_SANDBOX_MODE_CONTAINER = "container"
_CONTAINER_WORKDIR = "/workspace"
_CONTAINER_TARGET_DIR = "/workspace/target"
_CONTAINER_ARTIFACTS_DIR = "/artifacts"
_DEFAULT_CONTAINER_IMAGES = {
    "nuclei": "projectdiscovery/nuclei:latest",
    "semgrep": "semgrep/semgrep:latest",
    "osv-scanner": "ghcr.io/google/osv-scanner:latest",
    "trivy": "aquasec/trivy:latest",
    "checkov": "bridgecrew/checkov:latest",
    "trufflehog": "trufflesecurity/trufflehog:latest",
    "prowler": "toniblyx/prowler:latest",
}
_NETWORK_NONE = "none"
_NETWORK_ADVISORY_DB = "advisory_db"
_NETWORK_TARGET_ONLY = "target_only"
_CONTAINER_PULL_POLICIES = {"always", "missing", "never"}
_ISOLATED_RUNNER_BACKENDS = {"gke", "kubernetes"}
_ISOLATED_NETWORK_MODES = {_NETWORK_ADVISORY_DB, _NETWORK_TARGET_ONLY}
_ISOLATED_RUNNER_TOOLS = {"nuclei", "osv-scanner"}


class ValidationSandboxError(RuntimeError):
    """Raised when a validation tool cannot be safely executed."""


class ValidationSandboxTargetError(ValidationSandboxError):
    """Raised when a target violates local path allowlist policy."""


class ValidationSandboxOutputLimitError(ValidationSandboxError):
    """Raised when a tool emits more output than policy permits."""


@dataclass(frozen=True)
class ValidationSandboxMount:
    source: str
    destination: str
    readonly: bool = True


@dataclass(frozen=True)
class ValidationSandboxResult:
    command: list[str]
    target: str
    resolved_target: str
    returncode: int
    stdout: bytes
    stderr: str
    timed_out: bool = False
    output_limit_exceeded: bool = False
    sandbox_mode: str = _SANDBOX_MODE_PROCESS
    container_image: str | None = None
    network_policy: str | None = None
    resource_limits: dict[str, str] | None = None


def configured_validation_allowed_roots() -> list[str]:
    """Return configured local roots for repository/IaC/lockfile validation."""
    raw = validation_env_value(VALIDATION_ALLOWED_PATHS_ENV)
    raw = raw or os.getenv(VALIDATION_ALLOWED_PATHS_LEGACY_ENV) or ""
    normalized = raw.replace(",", os.pathsep)
    roots: list[str] = []
    for entry in normalized.split(os.pathsep):
        entry = entry.strip()
        if entry:
            roots.append(entry)
    return roots


def validation_sandbox_mode() -> str:
    """Return the configured sandbox backend."""
    raw = validation_env_value(VALIDATION_SANDBOX_MODE_ENV, _SANDBOX_MODE_PROCESS)
    raw = (raw or _SANDBOX_MODE_PROCESS).strip().lower()
    if raw in {_SANDBOX_MODE_PROCESS, _SANDBOX_MODE_CONTAINER}:
        return raw
    return _SANDBOX_MODE_PROCESS


def resolve_validation_executable(executable: str) -> str | None:
    """Resolve a validation executable using ThreatGenix's fixed runner PATH."""
    if Path(executable).name != executable:
        return None
    return shutil.which(executable, path=_SANDBOX_PATH)


def validation_container_runtime() -> str | None:
    raw = validation_env_value(VALIDATION_CONTAINER_RUNTIME_ENV, "docker")
    runtime = (raw or "docker").strip() or "docker"
    return shutil.which(runtime, path=_SANDBOX_PATH)


def validation_container_image(tool_name: str) -> str | None:
    normalized = tool_name.upper().replace("-", "_")
    raw = validation_env_value(f"THREATGENIX_VALIDATION_IMAGE_{normalized}")
    if raw and raw.strip():
        return raw.strip()
    return _DEFAULT_CONTAINER_IMAGES.get(tool_name)


def validation_container_pull_policy() -> str:
    raw = validation_env_value(VALIDATION_CONTAINER_PULL_ENV, "never")
    raw = (raw or "never").strip().lower()
    if raw in _CONTAINER_PULL_POLICIES:
        return raw
    return "never"


def validation_container_image_present(tool_name: str) -> bool:
    runtime = validation_container_runtime()
    image = validation_container_image(tool_name)
    if runtime is None or not image:
        return False
    try:
        result = subprocess.run(
            [runtime, "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def validation_container_available() -> bool:
    return (
        validation_sandbox_mode() == _SANDBOX_MODE_CONTAINER
        and validation_container_runtime() is not None
    )


def validation_isolated_runner_backend() -> str | None:
    """Return the configured remote isolated-runner backend, if any."""
    raw = validation_env_value(VALIDATION_ISOLATED_RUNNER_BACKEND_ENV, "")
    raw = (raw or "").strip().lower()
    return raw if raw in _ISOLATED_RUNNER_BACKENDS else None


def validation_isolated_runner_tool_image(tool_name: str) -> str | None:
    normalized = tool_name.upper().replace("-", "_")
    raw = validation_env_value(
        f"THREATGENIX_VALIDATION_ISOLATED_IMAGE_{normalized}", ""
    )
    return raw.strip() or None


def validation_isolated_runner_image_pinned(image: str | None) -> bool:
    return bool(image and "@sha256:" in image)


def validation_isolated_runner_ready_for(
    tool_name: str,
    network_mode: str | None = None,
) -> bool:
    """Return whether a remote runner can enforce this tool's network policy.

    This is intentionally stricter than a plain feature flag: hosted SaaS may
    only route networked scanners away from the process worker when there is a
    named backend, an egress proxy, isolation proof, and a digest-pinned scanner
    image. Local development can opt out of digest pinning, but staging/prod
    never can.
    """
    normalized_tool = tool_name.strip().lower()
    normalized_network = (network_mode or _NETWORK_NONE).strip().lower()
    if normalized_tool not in _ISOLATED_RUNNER_TOOLS:
        return False
    if normalized_network not in _ISOLATED_NETWORK_MODES:
        return False
    backend = validation_isolated_runner_backend()
    if backend is None:
        return False
    if backend == "gke" and (
        not (
            validation_env_value(VALIDATION_ISOLATED_K8S_API_SERVER_ENV, "") or ""
        ).strip()
        or not (
            validation_env_value(VALIDATION_ISOLATED_K8S_CA_CERT_B64_ENV, "") or ""
        ).strip()
    ):
        return False
    if not (
        validation_env_value(VALIDATION_ISOLATED_RUNNER_EGRESS_PROXY_ENV, "") or ""
    ).strip():
        return False
    if not (
        validation_env_value(VALIDATION_ISOLATED_RUNNER_PROOF_ENV, "") or ""
    ).strip():
        return False
    image = validation_isolated_runner_tool_image(normalized_tool)
    if validation_isolated_runner_image_pinned(image):
        return True
    if _production_like_app_env():
        return False
    return validation_env_flag(VALIDATION_ISOLATED_ALLOW_UNPINNED_IMAGES_ENV)


def validation_process_sandbox_network_allowed(network_mode: str | None = None) -> bool:
    """Return whether the process runner may use the requested network policy.

    The process runner cannot enforce egress boundaries. The advisory DB opt-in is
    only for local/dev OSV E2E proof where container isolation is unavailable.
    """
    requested = (network_mode or _NETWORK_NONE).strip().lower()
    if requested == _NETWORK_NONE:
        return True
    if requested == _NETWORK_ADVISORY_DB:
        if _production_like_app_env():
            return False
        return validation_env_flag(VALIDATION_PROCESS_ADVISORY_DB_NETWORK_ENV)
    return False


def create_validation_sandbox_runner(
    *, network_mode: str | None = None
) -> "ValidationSandboxRunner":
    """Return the configured runner for sandbox-required validation tools."""
    if validation_sandbox_mode() == _SANDBOX_MODE_CONTAINER:
        return ContainerValidationSandboxRunner(network_mode=network_mode)
    return ValidationSandboxRunner(network_mode=network_mode)


def validate_validation_target_access(
    target: str,
    target_type: str,
    *,
    allowed_roots: list[str] | None = None,
) -> str:
    """Resolve a target through the same local allowlist checks used at runtime."""
    return ValidationSandboxRunner(allowed_roots=allowed_roots)._resolve_target(
        target,
        target_type,
    )


def validate_validation_target_reference(
    target: str,
    target_type: str,
    *,
    allowed_roots: list[str] | None = None,
) -> str:
    """Validate a managed-runner target reference without requiring local access.

    The API process is only the control plane in managed mode. It may not share a
    filesystem with the worker, so it should enforce target-root policy without
    requiring the target path to exist locally. The worker still calls
    ``validate_validation_target_access`` before executing the scanner.
    """
    stripped = target.strip()
    if not stripped:
        raise ValidationSandboxTargetError("target is required")
    if target_type not in _PATH_TARGET_TYPES:
        return stripped

    configured_roots = (
        configured_validation_allowed_roots()
        if allowed_roots is None
        else allowed_roots
    )
    if not configured_roots:
        raise ValidationSandboxTargetError(
            f"{VALIDATION_ALLOWED_PATHS_ENV} must allow at least one local validation root"
        )

    target_path = Path(stripped).expanduser()
    if not target_path.is_absolute():
        raise ValidationSandboxTargetError(
            f"{target_type} validation target must be an absolute path in managed mode: {stripped}"
        )
    resolved_target = target_path.resolve(strict=False)

    policy_roots: list[Path] = []
    for root in configured_roots:
        root_path = Path(root.strip()).expanduser()
        if not root_path.is_absolute():
            continue
        policy_roots.append(root_path.resolve(strict=False))

    if not policy_roots:
        raise ValidationSandboxTargetError(
            "no absolute validation allowed roots are configured"
        )

    if _path_within_allowed_roots(resolved_target, policy_roots):
        return str(resolved_target)
    raise ValidationSandboxTargetError(
        f"validation target is outside configured allowed roots: {stripped}"
    )


class ValidationSandboxRunner:
    """Run a deterministic validation command with local safety constraints.

    This is the process-level execution boundary: no shell, executable
    allowlist, path-root allowlist, runtime timeout, bounded stdout/stderr,
    and sanitized environment. Set THREATGENIX_VALIDATION_SANDBOX_MODE=container
    to run sandbox-required tools through the Docker/Podman boundary below.
    """

    def __init__(
        self,
        *,
        allowed_roots: list[str] | None = None,
        env: dict[str, str] | None = None,
        network_mode: str | None = None,
    ) -> None:
        self.allowed_roots = (
            configured_validation_allowed_roots()
            if allowed_roots is None
            else allowed_roots
        )
        self.env = env
        self.network_mode = network_mode or _NETWORK_NONE

    async def run(
        self,
        command: list[str],
        *,
        tool_name: str,
        executable: str,
        target: str,
        target_type: str,
        timeout_seconds: int,
        max_output_bytes: int,
    ) -> ValidationSandboxResult:
        if not validation_process_sandbox_network_allowed(self.network_mode):
            raise ValidationSandboxError(
                f"{self.network_mode} network policy requires an isolated network runner"
            )
        resolved_command = self._resolve_command(command, executable)
        resolved_target = self._resolve_target(target, target_type)
        resolved_command = [
            resolved_target if arg == target else arg for arg in resolved_command
        ]
        stdout, stderr, returncode, timed_out, output_limited = await self._run_process(
            resolved_command,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        return ValidationSandboxResult(
            command=resolved_command,
            target=target,
            resolved_target=resolved_target,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            output_limit_exceeded=output_limited,
            sandbox_mode=_SANDBOX_MODE_PROCESS,
            network_policy="host_process",
            resource_limits={
                "timeout_seconds": str(timeout_seconds),
                "max_output_bytes": str(max_output_bytes),
            },
        )

    def _resolve_command(self, command: list[str], executable: str) -> list[str]:
        if not command:
            raise ValidationSandboxError("validation command is empty")
        command_executable = command[0]
        if Path(command_executable).name != command_executable:
            raise ValidationSandboxError(
                "validation command executable must be an approved basename"
            )
        if command_executable != executable:
            raise ValidationSandboxError(
                f"{command_executable} is not allowed for validation executable {executable}"
            )
        resolved_executable = resolve_validation_executable(command_executable)
        if resolved_executable is None:
            raise ValidationSandboxError(
                f"{executable} CLI not installed or unavailable"
            )
        return [resolved_executable, *command[1:]]

    def _resolve_target(self, target: str, target_type: str) -> str:
        stripped = target.strip()
        if not stripped:
            raise ValidationSandboxTargetError("target is required")
        if target_type not in _PATH_TARGET_TYPES:
            return stripped

        if not self.allowed_roots:
            raise ValidationSandboxTargetError(
                f"{VALIDATION_ALLOWED_PATHS_ENV} must allow at least one local validation root"
            )

        try:
            resolved_target = Path(stripped).expanduser().resolve(strict=True)
        except FileNotFoundError as exc:
            raise ValidationSandboxTargetError(
                f"validation target does not exist: {stripped}"
            ) from exc

        expected_shape = _PATH_TARGET_EXPECTATIONS.get(target_type)
        if expected_shape == "directory" and not resolved_target.is_dir():
            raise ValidationSandboxTargetError(
                f"{target_type} validation target must be a directory: {stripped}"
            )
        if expected_shape == "file" and not resolved_target.is_file():
            raise ValidationSandboxTargetError(
                f"{target_type} validation target must be a file: {stripped}"
            )

        allowed_roots: list[Path] = []
        for root in self.allowed_roots:
            try:
                allowed_roots.append(Path(root).expanduser().resolve(strict=True))
            except FileNotFoundError:
                continue

        if not allowed_roots:
            raise ValidationSandboxTargetError(
                "no configured validation allowed roots exist"
            )

        for root in allowed_roots:
            if _path_within_allowed_roots(resolved_target, [root]):
                if expected_shape == "directory":
                    _reject_external_symlink_descendants(
                        resolved_target,
                        allowed_roots,
                    )
                return str(resolved_target)

        raise ValidationSandboxTargetError(
            f"validation target is outside configured allowed roots: {stripped}"
        )

    async def _run_process(
        self,
        command: list[str],
        *,
        timeout_seconds: int,
        max_output_bytes: int,
    ) -> tuple[bytes, str, int, bool, bool]:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._process_env(),
            start_new_session=True,
        )
        stdout_task = asyncio.create_task(_read_capped(proc.stdout, max_output_bytes))
        stderr_task = asyncio.create_task(
            _read_capped(proc.stderr, min(max_output_bytes, 256 * 1024))
        )
        wait_task = asyncio.create_task(proc.wait())
        try:
            await asyncio.wait_for(wait_task, timeout=timeout_seconds)
            stdout = await stdout_task
            stderr = await stderr_task
            return (
                stdout,
                stderr.decode("utf-8", errors="replace").strip(),
                proc.returncode or 0,
                False,
                False,
            )
        except TimeoutError:
            await self._kill(proc)
            stdout_task.cancel()
            stderr_task.cancel()
            return b"", "", -1, True, False
        except ValidationSandboxOutputLimitError:
            await self._kill(proc)
            stdout_task.cancel()
            stderr_task.cancel()
            return (
                b"",
                "validation tool output exceeded max_output_bytes",
                -1,
                False,
                True,
            )

    def _process_env(self) -> dict[str, str]:
        base_env = {
            "PATH": _SANDBOX_PATH,
            "HOME": "/tmp",
            "LANG": os.getenv("LANG", "C.UTF-8"),
            "LC_ALL": os.getenv("LC_ALL", "C.UTF-8"),
            "SEMGREP_SEND_METRICS": "off",
            "CHECKOV_DISABLE_VERSION_CHECK": "1",
            "TRIVY_NO_PROGRESS": "true",
            "TRIVY_SKIP_DB_UPDATE": "true",
            "TRIVY_SKIP_JAVA_DB_UPDATE": "true",
            "TRIVY_SKIP_CHECK_UPDATE": "true",
            "TRIVY_SKIP_VERSION_CHECK": "true",
            "TRIVY_SKIP_VEX_REPO_UPDATE": "true",
            "TRIVY_OFFLINE_SCAN": "true",
        }
        if self.env is None:
            return base_env
        sanitized_overrides = {
            key: value for key, value in self.env.items() if key not in {"PATH", "HOME"}
        }
        return {**base_env, **sanitized_overrides}

    async def _kill(self, proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        try:
            await proc.wait()
        except ProcessLookupError:
            pass


class ContainerValidationSandboxRunner(ValidationSandboxRunner):
    """Run validation tools inside Docker/Podman with defensive defaults."""

    def __init__(
        self,
        *,
        allowed_roots: list[str] | None = None,
        env: dict[str, str] | None = None,
        runtime_path: str | None = None,
        network_mode: str | None = None,
    ) -> None:
        super().__init__(
            allowed_roots=allowed_roots, env=env, network_mode=network_mode
        )
        self.runtime_path = runtime_path or validation_container_runtime()
        self.network_mode = network_mode or _NETWORK_NONE

    async def run(
        self,
        command: list[str],
        *,
        tool_name: str,
        executable: str,
        target: str,
        target_type: str,
        timeout_seconds: int,
        max_output_bytes: int,
    ) -> ValidationSandboxResult:
        if self.runtime_path is None:
            raise ValidationSandboxError(
                f"{VALIDATION_CONTAINER_RUNTIME_ENV} runtime is not installed or unavailable"
            )
        if not command:
            command_name = "empty"
        elif Path(command[0]).name != command[0]:
            command_name = command[0]
        else:
            command_name = command[0]
        if not command or command_name != executable:
            raise ValidationSandboxError(
                f"{command_name} is not allowed for validation executable {executable}"
            )
        resolved_target = self._resolve_target(target, target_type)
        image = validation_container_image(tool_name)
        if not image:
            raise ValidationSandboxError(
                f"No container image is configured for {tool_name}"
            )

        with tempfile.TemporaryDirectory(
            prefix="tg-validation-artifacts-"
        ) as artifacts_dir:
            container_command, network_policy, limits = self.build_container_command(
                command,
                image=image,
                target=target,
                resolved_target=resolved_target,
                target_type=target_type,
                artifacts_dir=artifacts_dir,
            )
            (
                stdout,
                stderr,
                returncode,
                timed_out,
                output_limited,
            ) = await self._run_process(
                container_command,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
        return ValidationSandboxResult(
            command=container_command,
            target=target,
            resolved_target=resolved_target,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            output_limit_exceeded=output_limited,
            sandbox_mode=_SANDBOX_MODE_CONTAINER,
            container_image=image,
            network_policy=network_policy,
            resource_limits=limits,
        )

    def build_container_command(
        self,
        command: list[str],
        *,
        image: str,
        target: str,
        resolved_target: str,
        target_type: str,
        artifacts_dir: str,
    ) -> tuple[list[str], str, dict[str, str]]:
        if self.runtime_path is None:
            raise ValidationSandboxError(
                f"{VALIDATION_CONTAINER_RUNTIME_ENV} runtime is not installed or unavailable"
            )
        mounts, mapped_command = self._container_mounts_and_command(
            command,
            target=target,
            resolved_target=resolved_target,
            target_type=target_type,
            artifacts_dir=artifacts_dir,
        )
        entrypoint = Path(mapped_command[0]).name
        network_policy = self._container_network_policy()
        limits = self._container_resource_limits()
        container_name = f"tg-validation-{uuid.uuid4().hex[:12]}"
        runtime_command = [
            self.runtime_path,
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            network_policy,
            "--cpus",
            limits["cpus"],
            "--memory",
            limits["memory"],
            "--pids-limit",
            limits["pids"],
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=256m",
            "--workdir",
            _CONTAINER_WORKDIR,
            "--entrypoint",
            entrypoint,
            "--pull",
            validation_container_pull_policy(),
        ]
        for mount in mounts:
            readonly = ",readonly" if mount.readonly else ""
            runtime_command.extend(
                [
                    "--mount",
                    f"type=bind,source={mount.source},target={mount.destination}{readonly}",
                ]
            )
        for key, value in self._process_env().items():
            runtime_command.extend(["--env", f"{key}={value}"])
        runtime_command.extend([image, *mapped_command[1:]])
        return runtime_command, network_policy, limits

    def _container_mounts_and_command(
        self,
        command: list[str],
        *,
        target: str,
        resolved_target: str,
        target_type: str,
        artifacts_dir: str,
    ) -> tuple[list[ValidationSandboxMount], list[str]]:
        mounts = [
            ValidationSandboxMount(
                source=str(Path(artifacts_dir).resolve()),
                destination=_CONTAINER_ARTIFACTS_DIR,
                readonly=False,
            )
        ]
        path_map: dict[str, str] = {
            str(Path(artifacts_dir).resolve()): _CONTAINER_ARTIFACTS_DIR
        }
        if target_type in _PATH_TARGET_TYPES:
            target_path = Path(resolved_target)
            mount_source = target_path if target_path.is_dir() else target_path.parent
            mounts.append(
                ValidationSandboxMount(
                    source=str(mount_source),
                    destination=_CONTAINER_TARGET_DIR,
                    readonly=True,
                )
            )
            path_map[str(mount_source)] = _CONTAINER_TARGET_DIR
            if target_path.is_dir():
                path_map[resolved_target] = _CONTAINER_TARGET_DIR
            else:
                path_map[resolved_target] = (
                    f"{_CONTAINER_TARGET_DIR}/{target_path.name}"
                )
            path_map[target] = path_map[resolved_target]

        mapped_command: list[str] = []
        extra_mount_index = 0
        for arg in command:
            mapped = _mapped_container_path(arg, path_map)
            if mapped is not None:
                mapped_command.append(mapped)
                continue
            existing_path = _existing_absolute_path(arg)
            if existing_path is not None:
                destination = f"/tool-inputs/{extra_mount_index}"
                extra_mount_index += 1
                if existing_path.is_file():
                    mounts.append(
                        ValidationSandboxMount(
                            source=str(existing_path.parent),
                            destination=destination,
                            readonly=True,
                        )
                    )
                    mapped_command.append(f"{destination}/{existing_path.name}")
                else:
                    mounts.append(
                        ValidationSandboxMount(
                            source=str(existing_path),
                            destination=destination,
                            readonly=True,
                        )
                    )
                    mapped_command.append(destination)
                continue
            mapped_command.append(arg)
        return mounts, mapped_command

    def _container_network_policy(self) -> str:
        if self.network_mode == _NETWORK_NONE:
            return "none"
        configured_network = (
            validation_env_value("THREATGENIX_VALIDATION_CONTAINER_NETWORK", "") or ""
        ).strip()
        if configured_network:
            return configured_network
        raise ValidationSandboxError(
            f"{self.network_mode} network policy requires an explicitly configured container network"
        )

    def _container_resource_limits(self) -> dict[str, str]:
        return {
            "cpus": validation_env_value(VALIDATION_CONTAINER_CPUS_ENV, "1") or "1",
            "memory": validation_env_value(VALIDATION_CONTAINER_MEMORY_ENV, "1g")
            or "1g",
            "pids": validation_env_value(VALIDATION_CONTAINER_PIDS_ENV, "256") or "256",
        }


def _mapped_container_path(arg: str, path_map: dict[str, str]) -> str | None:
    if not arg:
        return None
    for host_path, container_path in sorted(
        path_map.items(), key=lambda item: len(item[0]), reverse=True
    ):
        if arg == host_path:
            return container_path
        prefix = f"{host_path.rstrip('/')}/"
        if arg.startswith(prefix):
            suffix = arg[len(prefix) :]
            return f"{container_path.rstrip('/')}/{suffix}"
    return None


def _existing_absolute_path(value: str) -> Path | None:
    if not value or not value.startswith("/"):
        return None
    try:
        return Path(value).expanduser().resolve(strict=True)
    except (FileNotFoundError, OSError):
        return None


def _path_within_allowed_roots(path: Path, allowed_roots: list[Path]) -> bool:
    return any(path == root or root in path.parents for root in allowed_roots)


def _production_like_app_env() -> bool:
    raw = os.getenv("APP_ENV") or os.getenv("THREATGENIX_APP_ENV") or ""
    return raw.strip().lower() in {"production", "staging"}


def _reject_external_symlink_descendants(
    target_root: Path,
    allowed_roots: list[Path],
) -> None:
    """Reject directory targets that contain symlinks escaping allowed roots."""
    try:
        iterator = target_root.rglob("*")
        for candidate in iterator:
            if not candidate.is_symlink():
                continue
            try:
                resolved = candidate.resolve(strict=True)
            except FileNotFoundError as exc:
                raise ValidationSandboxTargetError(
                    f"validation target contains broken symlink: {candidate}"
                ) from exc
            except (OSError, RuntimeError) as exc:
                raise ValidationSandboxTargetError(
                    f"validation target contains unsafe symlink: {candidate}"
                ) from exc
            if not _path_within_allowed_roots(resolved, allowed_roots):
                raise ValidationSandboxTargetError(
                    "validation target contains symlink outside configured "
                    f"allowed roots: {candidate}"
                )
    except PermissionError as exc:
        raise ValidationSandboxTargetError(
            f"validation target contains unreadable path: {target_root}"
        ) from exc


async def _read_capped(
    stream: asyncio.StreamReader | None,
    max_bytes: int,
) -> bytes:
    if stream is None:
        return b""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValidationSandboxOutputLimitError(
                "validation tool output exceeded max_output_bytes"
            )
        chunks.append(chunk)
    return b"".join(chunks)

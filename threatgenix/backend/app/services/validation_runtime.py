"""Runtime mode controls for validation execution.

Hosted SaaS must not execute tenant-provided scanner targets in the API
process. The API is the control plane: it may accept and queue validation work
only when a trusted execution plane exists. The scanner worker is the execution
plane and must explicitly identify itself before managed-mode jobs can run.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.validation_env import validation_env_flag, validation_env_value

VALIDATION_RUNTIME_MODE_ENV = "THREATGENIX_VALIDATION_RUNTIME_MODE"
VALIDATION_MANAGED_RUNNER_ENABLED_ENV = "THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED"
VALIDATION_EXECUTION_CONTEXT_ENV = "THREATGENIX_VALIDATION_EXECUTION_CONTEXT"
RUNTIME_TRY_SANDBOX = "try_sandbox"
RUNTIME_SELF_HOSTED = "self_hosted"
RUNTIME_MANAGED = "managed"
_VALID_RUNTIME_MODES = {RUNTIME_TRY_SANDBOX, RUNTIME_SELF_HOSTED, RUNTIME_MANAGED}
EXECUTION_CONTEXT_API = "api"
EXECUTION_CONTEXT_WORKER = "worker"
_VALID_EXECUTION_CONTEXTS = {EXECUTION_CONTEXT_API, EXECUTION_CONTEXT_WORKER}


@dataclass(frozen=True)
class ValidationRuntimeState:
    mode: str
    run_submission_enabled: bool
    live_execution_enabled: bool
    inline_execution_enabled: bool
    worker_execution_enabled: bool
    managed_runner_enabled: bool
    try_sandbox_enabled: bool
    title: str
    detail: str


def _env_flag(name: str, *, default: bool = False) -> bool:
    return validation_env_flag(name, default=default)


def validation_runtime_mode() -> str:
    """Return the active validation runtime mode.

    The safe hosted default is try_sandbox. Self-hosted operators can opt into
    live tool execution with THREATGENIX_VALIDATION_RUNTIME_MODE=self_hosted.
    """
    raw = validation_env_value(VALIDATION_RUNTIME_MODE_ENV, RUNTIME_TRY_SANDBOX)
    raw = (raw or RUNTIME_TRY_SANDBOX).strip().lower()
    if raw in _VALID_RUNTIME_MODES:
        return raw
    return RUNTIME_TRY_SANDBOX


def validation_execution_context() -> str:
    raw = validation_env_value(VALIDATION_EXECUTION_CONTEXT_ENV, EXECUTION_CONTEXT_API)
    raw = (raw or EXECUTION_CONTEXT_API).strip().lower()
    if raw in _VALID_EXECUTION_CONTEXTS:
        return raw
    return EXECUTION_CONTEXT_API


def managed_validation_runner_enabled() -> bool:
    return validation_runtime_mode() == RUNTIME_MANAGED and _env_flag(
        VALIDATION_MANAGED_RUNNER_ENABLED_ENV
    )


def validation_run_submission_enabled() -> bool:
    """Return whether the API may accept and queue live validation work."""
    mode = validation_runtime_mode()
    return mode == RUNTIME_SELF_HOSTED or managed_validation_runner_enabled()


def inline_validation_execution_enabled() -> bool:
    """Return whether the API process may execute scanner jobs inline."""
    return validation_runtime_mode() == RUNTIME_SELF_HOSTED


def validation_worker_execution_enabled() -> bool:
    """Return whether this process may execute scanner jobs."""
    mode = validation_runtime_mode()
    if mode == RUNTIME_SELF_HOSTED:
        return True
    return (
        mode == RUNTIME_MANAGED
        and managed_validation_runner_enabled()
        and validation_execution_context() == EXECUTION_CONTEXT_WORKER
    )


def live_validation_execution_enabled() -> bool:
    """Backward-compatible alias for API-local execution.

    Use ``validation_run_submission_enabled`` when deciding whether the API can
    queue a run, and ``validation_worker_execution_enabled`` when deciding
    whether a process can run scanners.
    """
    return inline_validation_execution_enabled()


def validation_runtime_state() -> ValidationRuntimeState:
    mode = validation_runtime_mode()
    managed_runner = managed_validation_runner_enabled()
    worker_execution = validation_worker_execution_enabled()
    if mode == RUNTIME_SELF_HOSTED:
        return ValidationRuntimeState(
            mode=mode,
            run_submission_enabled=True,
            live_execution_enabled=True,
            inline_execution_enabled=True,
            worker_execution_enabled=True,
            managed_runner_enabled=False,
            try_sandbox_enabled=True,
            title="Self-hosted validation runner",
            detail=(
                "Live validation can execute approved tools against authorized "
                "targets in this trusted deployment."
            ),
        )
    if mode == RUNTIME_MANAGED and managed_runner:
        return ValidationRuntimeState(
            mode=mode,
            run_submission_enabled=True,
            live_execution_enabled=False,
            inline_execution_enabled=False,
            worker_execution_enabled=worker_execution,
            managed_runner_enabled=True,
            try_sandbox_enabled=True,
            title="Managed isolated runner",
            detail=(
                "Live validation requests are queued to a dedicated validation "
                "worker. The API server remains a control plane and does not "
                "execute scanner processes."
            ),
        )
    if mode == RUNTIME_MANAGED:
        return ValidationRuntimeState(
            mode=mode,
            run_submission_enabled=False,
            live_execution_enabled=False,
            inline_execution_enabled=False,
            worker_execution_enabled=False,
            managed_runner_enabled=False,
            try_sandbox_enabled=True,
            title="Managed isolated runner pending",
            detail=(
                "Managed runner mode is configured, but API-local scanner execution "
                "is disabled until a dedicated isolated worker is connected."
            ),
        )
    return ValidationRuntimeState(
        mode=RUNTIME_TRY_SANDBOX,
        run_submission_enabled=False,
        live_execution_enabled=False,
        inline_execution_enabled=False,
        worker_execution_enabled=False,
        managed_runner_enabled=False,
        try_sandbox_enabled=True,
        title="SaaS try sandbox",
        detail=(
            "Hosted tenants can run curated demo evidence and import captured "
            "scanner output. Live tool execution is disabled until a managed "
            "isolated runner is connected."
        ),
    )


def validation_run_submission_blocked_reason() -> str:
    if validation_runtime_mode() == RUNTIME_MANAGED:
        return (
            "Managed validation runner is not enabled. Set "
            f"{VALIDATION_MANAGED_RUNNER_ENABLED_ENV}=true and run a dedicated "
            "validation worker before accepting live scanner jobs."
        )
    return (
        "Live validation submission is disabled in this runtime. Use Try Sandbox "
        "or import pre-captured evidence; enable self_hosted mode or connect the "
        "managed isolated runner before accepting scanner runs."
    )


def validation_worker_execution_blocked_reason() -> str:
    if validation_runtime_mode() == RUNTIME_MANAGED:
        if not managed_validation_runner_enabled():
            return validation_run_submission_blocked_reason()
        return (
            "Managed validation execution is restricted to the dedicated worker "
            f"process. Set {VALIDATION_EXECUTION_CONTEXT_ENV}=worker for the "
            "runner and keep API processes in the default api context."
        )
    return live_execution_blocked_reason()


def live_execution_blocked_reason() -> str:
    return (
        "Live validation execution is disabled in this runtime. Use Try Sandbox "
        "or import pre-captured evidence; connect a managed isolated runner or "
        "switch a trusted deployment to self_hosted before enabling scanner runs."
    )

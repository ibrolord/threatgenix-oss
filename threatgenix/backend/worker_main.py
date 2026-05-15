"""Managed validation runner entry point.

Run as a background worker alongside the API service (same Docker image, different CMD):

    CMD ["python", "worker_main.py"]

The worker shares the same DATABASE_URL as the API service.  It polls for
pending ScanJobs, executes them using the local process sandbox (tools must be
installed in the container), then writes results back to the database.

Required env vars (same as the API service):
    DATABASE_URL                        — shared Postgres connection
    THREATGENIX_VALIDATION_RUNTIME_MODE — "managed" for SaaS worker or "self_hosted"
    THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED — true when mode is "managed"
    THREATGENIX_VALIDATION_SANDBOX_MODE — "process" (default) or "container"
    THREATGENIX_VALIDATION_ALLOWED_PATHS — colon/comma-separated paths the scanner may read

Optional tuning:
    VALIDATION_WORKER_POLL_INTERVAL     — seconds between polls when busy (default 5)
    VALIDATION_WORKER_IDLE_BACKOFF_MAX  — max seconds between polls when idle (default 30)
    VALIDATION_WORKER_HEARTBEAT_INTERVAL — seconds between runner heartbeats while executing (default 10)
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Bootstrap logging before importing app modules so first-log lines are visible.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("threatgenix.worker")


class _HealthHandler(BaseHTTPRequestHandler):
    server_version = "ThreatGenixWorkerHealth/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler method name
        if self.path not in {"/", "/health", "/api/health"}:
            self.send_response(404)
            self.end_headers()
            return
        body = b'{"status":"ok","service":"validation-worker"}\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        logger.debug("validation_worker_health_http " + format, *args)


def _start_health_server() -> ThreadingHTTPServer | None:
    """Expose the Cloud Run port while the worker loop runs in-process."""
    port_raw = os.getenv("PORT")
    if not port_raw:
        return None
    try:
        port = int(port_raw)
    except ValueError:
        logger.warning("validation_worker_health_disabled invalid_port=%s", port_raw)
        return None

    server = ThreadingHTTPServer(("0.0.0.0", port), _HealthHandler)
    thread = threading.Thread(target=server.serve_forever, name="worker-health", daemon=True)
    thread.start()
    logger.info("validation_worker_health_listening port=%s", port)
    return server


def _validate_env() -> None:
    """Abort early with a clear message if critical env vars are missing."""
    os.environ["THREATGENIX_VALIDATION_EXECUTION_CONTEXT"] = "worker"

    # Importing settings here gives local development the same .env fallback as
    # the API process, while still requiring an explicit database secret in
    # production-like deployments.
    from app.config import settings  # noqa: PLC0415

    database_url_from_env = os.getenv("DATABASE_URL")
    production_like = settings.app_env in {"production", "staging"}
    if production_like and not database_url_from_env:
        logger.error(
            "validation_worker_env_error missing_vars=%s — cannot start",
            ["DATABASE_URL"],
        )
        sys.exit(1)

    runtime_mode = os.getenv("THREATGENIX_VALIDATION_RUNTIME_MODE", "try_sandbox")
    managed_runner_enabled = os.getenv(
        "THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED", ""
    ).strip().lower() in {"1", "true", "yes", "on"}
    if runtime_mode not in {"managed", "self_hosted"}:
        logger.warning(
            "validation_worker_runtime_mode_warning mode=%s — "
            "live execution requires THREATGENIX_VALIDATION_RUNTIME_MODE=managed or self_hosted",
            runtime_mode,
        )
    if runtime_mode == "managed" and not managed_runner_enabled:
        logger.error(
            "validation_worker_env_error %s must be true in managed mode",
            "THREATGENIX_VALIDATION_MANAGED_RUNNER_ENABLED",
        )
        sys.exit(1)


async def _main() -> None:
    _validate_env()
    _start_health_server()

    # Import deferred so logging is configured first and env validation runs.
    from app.services.scan_worker import run_polling_loop  # noqa: PLC0415

    poll_interval = float(os.getenv("VALIDATION_WORKER_POLL_INTERVAL", "5"))
    idle_backoff_max = float(os.getenv("VALIDATION_WORKER_IDLE_BACKOFF_MAX", "30"))
    heartbeat_interval = float(os.getenv("VALIDATION_WORKER_HEARTBEAT_INTERVAL", "10"))

    logger.info(
        "validation_worker_boot poll_interval=%.1f idle_backoff_max=%.1f heartbeat_interval=%.1f",
        poll_interval,
        idle_backoff_max,
        heartbeat_interval,
    )

    await run_polling_loop(
        poll_interval_seconds=poll_interval,
        idle_backoff_max=idle_backoff_max,
        heartbeat_interval_seconds=heartbeat_interval,
    )


if __name__ == "__main__":
    asyncio.run(_main())

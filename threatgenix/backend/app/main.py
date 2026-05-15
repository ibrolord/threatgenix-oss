from contextlib import asynccontextmanager
import logging
import os
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler  # type: ignore[import-not-found]
from slowapi.errors import RateLimitExceeded  # type: ignore[import-not-found]
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.limiter import limiter

from app.api.auth import router as auth_router
from app.api.application_reviews import router as application_reviews_router
from app.api.github_integration import router as github_integration_router
from app.api.review_agent import router as review_agent_router
from app.api.assistant import router as assistant_router
from app.api.dfd import router as dfd_router
from app.api.documents import router as documents_router
from app.api.evidence import router as evidence_router
from app.api.environment import router as environment_router
from app.api.orchestration import router as orchestration_router
from app.api.threat_models import router as threat_models_router
from app.api.compliance import router as compliance_router
from app.api.threats import router as threats_router
from app.api.threat_agent_orchestration import router as threat_agent_orchestration_router
from app.api.llm import router as llm_router
from app.api.dashboard import router as dashboard_router
from app.api.threat_intel import router as threat_intel_router
from app.api.threat_catalog import catalog_router, manual_router
from app.api.scans import router as scans_router
from app.api.scan_credentials import router as scan_credentials_router
from app.api.validation_tools import router as validation_tools_router
from app.api.validation_lab import router as validation_lab_router
from app.config import settings
from app.database import engine

logger = logging.getLogger("threatgenix.api")
REQUIRED_ALEMBIC_REVISION = "084"
PRODUCTION_LIKE_ENVS = {"production", "staging"}
DEFAULT_DEV_SECRET_KEY = "dev-secret-change-in-production"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

REQUIRED_SCHEMA_COLUMNS = {
    "threat_models": {
        "analyst_attestation",
        "analyst_name",
        "archived_at",
        "last_analyze_requested_at",
        "next_review_date",
        "organization_id",
        "out_of_scope_statement",
        "report_logo_base64",
        "report_template",
        "report_templates",
        "report_watermark_text",
        "review_state",
    },
    "threats": {
        "qualification_note",
        "qualification_score",
    },
    "users": {
        "email_verified",
        "organization_id",
        "report_template_library",
    },
    "organizations": {
        "is_active",
        "subscription_tier",
    },
    "email_verifications": {
        "code_hash",
        "expires_at",
        "user_id",
    },
    "password_reset_tokens": {
        "expires_at",
        "token_hash",
        "user_id",
    },
    "evidence_sources": {
        "source_type",
        "stable_key",
        "threat_model_id",
    },
    "evidence_items": {
        "confidence_label",
        "item_type",
        "source_id",
        "stable_key",
        "threat_model_id",
    },
    "evidence_entities": {
        "canonical_key",
        "entity_type",
        "threat_model_id",
    },
    "evidence_observations": {
        "evidence_item_id",
        "predicate",
        "subject_entity_id",
        "threat_model_id",
    },
    "evidence_relationships": {
        "from_entity_id",
        "relationship_type",
        "stable_key",
        "threat_model_id",
        "to_entity_id",
    },
    "evidence_findings": {
        "finding_key",
        "finding_kind",
        "threat_model_id",
    },
    "evidence_finding_links": {
        "evidence_item_id",
        "finding_id",
        "link_type",
        "threat_model_id",
    },
    "orchestration_jobs": {
        "idempotency_key",
        "job_kind",
        "owner_id",
        "status",
        "threat_model_id",
    },
    "orchestration_tasks": {
        "job_id",
        "status",
        "task_kind",
        "threat_model_id",
    },
    "orchestration_events": {
        "event_type",
        "job_id",
        "threat_model_id",
    },
    "threat_validation_runs": {
        "agent_type",
        "conclusion",
        "deterministic_fallback_used",
        "evidence_refs",
        "exploitability",
        "model_output_hash",
        "orchestration_job_id",
        "status",
        "threat_id",
        "threat_model_id",
    },
    "threat_remediation_runs": {
        "agent_type",
        "deterministic_fallback_used",
        "evidence_refs",
        "external_ticket_id",
        "model_output_hash",
        "orchestration_job_id",
        "status",
        "threat_id",
        "validation_run_id",
    },
    "scan_jobs": {
        "attempt_count",
        "claimed_at",
        "failure_code",
        "heartbeat_at",
        "lease_expires_at",
        "max_attempts",
        "runner_id",
    },
    "validation_artifact_bundles": {
        "byte_size",
        "filename",
        "sha256",
        "status",
        "threat_model_id",
    },
    "validation_artifact_bundle_items": {
        "bundle_id",
        "raw_output_sha256",
        "scan_job_id",
        "source_path",
        "tool_name",
    },
    "validation_target_bundles": {
        "archive_bytes",
        "byte_size",
        "filename",
        "owner_id",
        "sha256",
        "status",
        "storage_backend",
        "threat_model_id",
    },
    "scan_target_authorizations": {
        "expires_at",
        "normalized_host",
        "owner_id",
        "proof_method",
        "status",
        "threat_model_id",
        "verified_at",
    },
    "remediation_webhook_nonces": {
        "expires_at",
        "nonce_hash",
        "received_at",
        "scope",
    },
    "validation_worker_heartbeats": {
        "current_scan_job_id",
        "last_seen_at",
        "runner_id",
        "runtime_mode",
        "sandbox_mode",
        "status",
        "version",
    },
    "application_security_reviews": {
        "app_name",
        "bundle_hash",
        "commit_sha",
        "context",
        "decision",
        "idempotency_key",
        "input_kind",
        "invocation_surface",
        "owner_id",
        "policy",
        "requested_tools",
        "review_lineage_id",
        "scope",
        "scope_fingerprint",
        "status",
        "tenant_key",
    },
    "application_review_bundles": {
        "bundle_kind",
        "byte_size",
        "content_hash",
        "file_count",
        "manifest",
        "owner_id",
        "review_id",
        "source",
        "status",
        "tenant_key",
    },
    "application_review_context_entries": {
        "body",
        "content_hash",
        "facets",
        "item_type",
        "keywords",
        "owner_id",
        "retrieval_text",
        "review_id",
        "source_refs",
        "source_type",
        "stale_reason",
        "status",
        "tenant_key",
        "title",
    },
    "github_repository_links": {
        "id",
        "tenant_key",
        "owner_id",
        "installation_id",
        "repository_id",
        "repository_full_name",
        "requested_tools",
        "status",
    },
    "application_risk_acceptances": {
        "id",
        "tenant_key",
        "app_name",
        "review_id",
        "scope_type",
        "scope_value",
        "justification",
        "approver_id",
        "approved_at",
        "expires_at",
        "status",
        "audit_events",
    },
}


def _csv_values(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [value.strip() for value in raw.split(",") if value.strip()]


def _is_production_like() -> bool:
    return settings.app_env.strip().lower() in PRODUCTION_LIKE_ENVS


def _origin_host(origin: str) -> str:
    parsed = urlparse(origin)
    return (parsed.hostname or "").lower()


def _host_without_port(host: str) -> str:
    if host.startswith("[") and "]" in host:
        return host[1 : host.index("]")].lower()
    return host.rsplit(":", 1)[0].lower()


def _database_host(database_url: str) -> str:
    return (urlparse(database_url).hostname or "").lower()


def validate_runtime_configuration() -> list[str]:
    """Return production/staging configuration errors that must block startup."""

    if not _is_production_like():
        return []

    errors: list[str] = []
    secret_key = settings.secret_key.strip()
    if secret_key == DEFAULT_DEV_SECRET_KEY or len(secret_key) < 32:
        errors.append("SECRET_KEY must be a non-default value with at least 32 characters")

    db_host = _database_host(settings.database_url)
    if db_host in LOOPBACK_HOSTS or db_host == "db":
        errors.append("DATABASE_URL must point to a production database, not a local Compose host")

    origins = _csv_values(settings.allowed_origins)
    if not origins:
        errors.append("ALLOWED_ORIGINS must include the public HTTPS frontend origin")
    for origin in origins:
        parsed = urlparse(origin)
        host = _origin_host(origin)
        if "*" in origin or parsed.scheme == "*" or "*" in host:
            errors.append("ALLOWED_ORIGINS cannot use wildcards in production")
        if parsed.scheme != "https":
            errors.append(f"ALLOWED_ORIGINS entry must use https: {origin}")
        if host in LOOPBACK_HOSTS:
            errors.append(f"ALLOWED_ORIGINS entry cannot be loopback in production: {origin}")

    trusted_hosts = _csv_values(settings.trusted_hosts)
    if not trusted_hosts:
        errors.append("TRUSTED_HOSTS must include the public API host in production")
    for host in trusted_hosts:
        normalized = _host_without_port(host)
        if "*" in host or "*" in normalized:
            errors.append("TRUSTED_HOSTS cannot use wildcards in production")
        if normalized in LOOPBACK_HOSTS:
            errors.append(f"TRUSTED_HOSTS entry cannot be loopback in production: {host}")

    if settings.auth_expose_dev_tokens:
        errors.append("AUTH_EXPOSE_DEV_TOKENS must be false in production")

    return errors


async def get_missing_required_schema() -> list[str]:
    def _inspect_schema(sync_conn) -> list[str]:
        inspector = inspect(sync_conn)
        missing: list[str] = []
        available_tables = set(inspector.get_table_names())

        for table_name, required_columns in REQUIRED_SCHEMA_COLUMNS.items():
            if table_name not in available_tables:
                missing.append(table_name)
                continue
            available_columns = {
                column["name"] for column in inspector.get_columns(table_name)
            }
            for column_name in sorted(required_columns - available_columns):
                missing.append(f"{table_name}.{column_name}")

        return missing

    async with engine.begin() as conn:
        return await conn.run_sync(_inspect_schema)


async def get_current_alembic_revision() -> str | None:
    async with engine.begin() as conn:
        has_table = await conn.run_sync(
            lambda sync_conn: "alembic_version" in inspect(sync_conn).get_table_names()
        )
        if not has_table:
            return None
        result = await conn.execute(text("SELECT version_num FROM alembic_version"))
        revisions = [str(value) for value in result.scalars().all()]
        if len(revisions) != 1:
            return ", ".join(sorted(revisions)) if revisions else None
        return revisions[0]


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio

    logger = logging.getLogger("threatgenix.startup")
    cleanup_task = None
    app.state.schema_ready = False
    app.state.schema_error = None
    startup_failures: list[str] = []

    runtime_config_errors = validate_runtime_configuration()
    if runtime_config_errors:
        raise RuntimeError("SECURITY: " + "; ".join(runtime_config_errors))

    if settings.secret_key == DEFAULT_DEV_SECRET_KEY:
        logger.warning(
            "SECURITY: SECRET_KEY is set to the default dev value — "
            "this is only acceptable in local development"
        )
    if _is_production_like():
        try:
            current_revision = await get_current_alembic_revision()
        except Exception as exc:
            startup_failures.append(f"alembic revision check failed: {exc}")
        else:
            if current_revision != REQUIRED_ALEMBIC_REVISION:
                startup_failures.append(
                    "database migration revision is "
                    f"{current_revision or 'missing'}, expected {REQUIRED_ALEMBIC_REVISION}. "
                    "Run `alembic upgrade head` before starting production."
                )
        if startup_failures:
            app.state.schema_error = "; ".join(startup_failures)
            logger.error("Startup schema readiness failed: %s", app.state.schema_error)
            raise RuntimeError(app.state.schema_error)
    try:
        from app.seed import seed

        await seed()
    except Exception as exc:
        logger.warning("Startup DB init failed (will retry on first request): %s", exc)
        startup_failures.append(f"database bootstrap failed: {exc}")
    if settings.app_env not in {"production", "staging"}:
        try:
            from app.seed_demo import seed_demo

            await seed_demo()
        except Exception as exc:
            logger.warning("Demo seed failed (non-critical): %s", exc)

    # F-03: Start ephemeral document cleanup loop (purges raw_text after 24hr)
    try:
        from app.services.doc_cleanup import cleanup_loop, purge_expired_documents

        await purge_expired_documents()  # Run once at startup
        cleanup_task = asyncio.create_task(cleanup_loop(interval_seconds=3600))
    except Exception as exc:
        logger.warning("Document cleanup startup skipped (non-critical): %s", exc)

    try:
        missing_schema = await get_missing_required_schema()
    except Exception as exc:
        startup_failures.append(f"runtime schema check failed: {exc}")
    else:
        if missing_schema:
            startup_failures.append(
                "missing required database columns: "
                + ", ".join(missing_schema)
                + ". Run `alembic upgrade head`."
            )

    if startup_failures:
        app.state.schema_error = "; ".join(startup_failures)
        logger.error("Startup schema readiness failed: %s", app.state.schema_error)
        if cleanup_task is not None:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass
        raise RuntimeError(app.state.schema_error)

    app.state.schema_ready = True

    yield

    # Shutdown: cancel cleanup loop
    if cleanup_task is not None:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


_is_production = _is_production_like()
app = FastAPI(
    title=settings.api_title,
    version="0.1.0",
    lifespan=lifespan,
    # Disable interactive API docs in production — they expose internal schema
    docs_url=None if _is_production else "/docs",
    redoc_url=None if _is_production else "/redoc",
    openapi_url=None if _is_production else "/openapi.json",
)
app.state.schema_ready = True
app.state.schema_error = None
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(
    request: Request, exc: SQLAlchemyError
) -> JSONResponse:
    logger.exception(
        "Unhandled database error during %s %s", request.method, request.url.path
    )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.add_middleware(
    CORSMiddleware,
    allow_origins=_csv_values(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_trusted_hosts = _csv_values(settings.trusted_hosts)
if _trusted_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_trusted_hosts)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; object-src 'none'"
    )
    # HSTS is set at the reverse proxy (Render/Vercel) but we add it here as defense-in-depth
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains"
        )
    return response


app.include_router(auth_router)
app.include_router(application_reviews_router)
app.include_router(github_integration_router)
app.include_router(review_agent_router)
app.include_router(assistant_router)
app.include_router(threat_models_router)
app.include_router(documents_router)
app.include_router(evidence_router)
app.include_router(environment_router)
app.include_router(orchestration_router)
app.include_router(dfd_router)
app.include_router(threats_router)
app.include_router(threat_agent_orchestration_router)
app.include_router(compliance_router)
app.include_router(llm_router)
app.include_router(dashboard_router)
app.include_router(threat_intel_router)
app.include_router(catalog_router)
app.include_router(manual_router)
app.include_router(scans_router)
app.include_router(scan_credentials_router)
app.include_router(validation_tools_router)
app.include_router(validation_lab_router)


@app.get("/api/health")
async def health_check(response: Response, deep: bool = False):
    if not getattr(app.state, "schema_ready", True):
        response.status_code = 503
        return {
            "status": "degraded",
            "detail": getattr(
                app.state, "schema_error", "Database schema is not ready"
            ),
        }

    result: dict = {
        "status": "ok",
        "version": app.version,
        "api_title": settings.api_title,
        "runtime_name": settings.runtime_name,
        "deployment_profile": settings.deployment_profile,
        "source_version": os.getenv("SOURCE_VERSION"),
        "region": settings.bedrock_region,
        "environment": settings.app_env,
    }

    # Deep health: verify DB is reachable (opt-in via ?deep=true)
    if deep:
        try:
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            result["database"] = "connected"
            result["alembic_revision"] = await get_current_alembic_revision()
        except Exception:
            response.status_code = 503
            return {"status": "degraded", "detail": "Database unreachable"}
        try:
            from app.database import async_session
            from app.services.validation_runner_observability import (
                get_runner_queue_status,
            )
            from app.services.validation_runtime import (
                managed_validation_runner_enabled,
            )

            async with async_session() as db:
                runner_status = await get_runner_queue_status(db)
            result["validation_runner"] = {
                "status": runner_status.status,
                "pending_count": runner_status.pending_count,
                "running_count": runner_status.running_count,
                "active_worker_count": runner_status.active_worker_count,
                "last_heartbeat_at": (
                    runner_status.last_heartbeat_at.isoformat()
                    if runner_status.last_heartbeat_at
                    else None
                ),
            }
            if (
                managed_validation_runner_enabled()
                and runner_status.active_worker_count == 0
            ):
                response.status_code = 503
                result["status"] = "degraded"
                result["detail"] = runner_status.detail
        except Exception:
            logger.exception("Deep validation runner health check failed")
            response.status_code = 503
            return {
                "status": "degraded",
                "detail": "Validation runner health unavailable",
            }

    return result

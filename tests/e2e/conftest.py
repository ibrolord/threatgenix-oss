"""E2E test fixtures -- real Postgres, real HTTP, real server.

Uses sync httpx plus a small asyncpg-backed DB adapter to avoid async test-loop
coupling. The backend server runs as a subprocess (async internally), but all test
interactions are synchronous.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import quote_plus

import asyncpg
import httpx
import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
E2E_DB_USER = os.getenv("THREATGENIX_E2E_DB_USER", "test")
E2E_DB_PASSWORD = os.getenv("THREATGENIX_E2E_DB_PASSWORD", "test")
E2E_DB_HOST = os.getenv("THREATGENIX_E2E_DB_HOST", "localhost")
E2E_DB_PORT = os.getenv("THREATGENIX_E2E_DB_PORT", "55433")
E2E_DB_NAME = os.getenv("THREATGENIX_E2E_DB_NAME", "threatgenix_test")
E2E_AUTH_EMAIL = os.getenv("THREATGENIX_E2E_AUTH_EMAIL", "qa-e2e@example.test")
E2E_AUTH_PASSWORD = os.getenv("THREATGENIX_E2E_AUTH_PASSWORD", "ThreatGenixE2E2026!")


def _database_url(driver: str) -> str:
    env_name = (
        "THREATGENIX_E2E_DATABASE_URL_ASYNC"
        if driver
        else "THREATGENIX_E2E_DATABASE_URL_SYNC"
    )
    if override := os.getenv(env_name):
        return override
    user = quote_plus(E2E_DB_USER)
    password = quote_plus(E2E_DB_PASSWORD)
    return (
        f"postgresql{driver}://{user}:{password}"
        f"@{E2E_DB_HOST}:{E2E_DB_PORT}/{E2E_DB_NAME}"
    )


TEST_DB_URL_ASYNC = _database_url("+asyncpg")
TEST_DB_URL_SYNC = _database_url("")
BACKEND_PORT = int(os.getenv("THREATGENIX_E2E_BACKEND_PORT", "8099"))
BACKEND_BASE = f"http://localhost:{BACKEND_PORT}"
FRONTEND_PORT = int(os.getenv("THREATGENIX_E2E_FRONTEND_PORT", "5174"))
FRONTEND_BASE = f"http://localhost:{FRONTEND_PORT}"
PROJECT_ROOT = Path(__file__).resolve().parents[2]  # tests/e2e/../../ = project root
BACKEND_DIR = PROJECT_ROOT / "threatgenix" / "backend"
FRONTEND_DIR = PROJECT_ROOT / "threatgenix" / "frontend"
FIXTURES_DIR = Path(__file__).parent / "fixtures"
BASELINE_PATH = Path(__file__).parent / "baseline.json"


# ---------------------------------------------------------------------------
# Session-scoped: create DB schema using SQLAlchemy async (one-shot)
# ---------------------------------------------------------------------------
def _setup_schema_and_seed():
    """Use asyncio to set up schema and seed data once, then return."""
    import asyncio

    sys.path.insert(0, str(BACKEND_DIR))
    os.environ["DATABASE_URL"] = TEST_DB_URL_ASYNC

    async def _do():
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
        from sqlalchemy import text

        from app.database import Base
        from app.models import (  # noqa: F401
            ComplianceMapping,
            DFDEdge,
            DFDNode,
            Document,
            Organization,
            Threat,
            ThreatModel,
            TrustBoundary,
            User,
        )
        from app.seed import SEED_DATA
        from app.services.auth import hash_password

        engine = create_async_engine(TEST_DB_URL_ASYNC, echo=False)
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            await conn.run_sync(Base.metadata.create_all)

        # Seed compliance mappings
        sf = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with sf() as session:
            result = await session.execute(text("SELECT COUNT(*) FROM compliance_mappings"))
            count = result.scalar()
            if count == 0:
                from app.models.compliance import ComplianceMapping as CM
                seen_mappings: set[tuple[str, str, str, str]] = set()
                for stride_cat, subtype, framework, control_id, control_name in SEED_DATA:
                    key = (stride_cat, subtype, framework, control_id)
                    if key in seen_mappings:
                        continue
                    seen_mappings.add(key)
                    session.add(CM(
                        stride_category=stride_cat,
                        threat_subtype=subtype,
                        framework=framework,
                        control_id=control_id,
                        control_name=control_name,
                    ))
            session.add(Organization(
                name="ThreatGenix E2E Organization",
                users=[
                    User(
                        email=E2E_AUTH_EMAIL,
                        hashed_password=hash_password(E2E_AUTH_PASSWORD),
                        full_name="ThreatGenix E2E",
                        role="admin",
                        is_active=True,
                        email_verified=True,
                    )
                ],
            ))
            await session.commit()

        await engine.dispose()

    asyncio.run(_do())


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """One-shot schema creation and seeding before any tests run."""
    _setup_schema_and_seed()


# ---------------------------------------------------------------------------
# Session-scoped: sync-style asyncpg connection for direct DB checks
# ---------------------------------------------------------------------------
class SyncAsyncpgCursor:
    def __init__(self, dsn: str):
        self._dsn = dsn
        self._rows: list[tuple] = []

    def _convert_placeholders(self, query: str, params: tuple) -> str:
        if not params:
            return query
        converted = query
        for index in range(1, len(params) + 1):
            converted = converted.replace("%s", f"${index}", 1)
        return converted

    def _coerce_params(self, params: tuple) -> tuple:
        coerced = []
        for value in params:
            if isinstance(value, str):
                try:
                    coerced.append(uuid.UUID(value))
                    continue
                except ValueError:
                    pass
            coerced.append(value)
        return tuple(coerced)

    async def _run(self, query: str, params: tuple = ()) -> list[tuple]:
        conn = await asyncpg.connect(self._dsn)
        try:
            query = self._convert_placeholders(query, params)
            params = self._coerce_params(params)
            if query.lstrip().upper().startswith("SELECT"):
                records = await conn.fetch(query, *params)
                return [tuple(record) for record in records]
            await conn.execute(query, *params)
            return []
        finally:
            await conn.close()

    def execute(self, query: str, params: tuple = ()) -> None:
        self._rows = asyncio.run(self._run(query, params))

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows

    def close(self) -> None:
        return None


class SyncAsyncpgConnection:
    def __init__(self, dsn: str):
        self._dsn = dsn

    def cursor(self) -> SyncAsyncpgCursor:
        return SyncAsyncpgCursor(self._dsn)

    def close(self) -> None:
        return None


@pytest.fixture(scope="session")
def db_conn(setup_database):
    """Sync-style connection for direct DB queries in tests."""
    conn = SyncAsyncpgConnection(TEST_DB_URL_SYNC)
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Session-scoped: backend server process
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def backend_server(setup_database):
    """Start uvicorn as a subprocess, wait for health, yield, kill."""
    env = os.environ.copy()
    env["DATABASE_URL"] = TEST_DB_URL_ASYNC
    env["ALLOWED_ORIGINS"] = "*"
    env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:" + env.get("PATH", "")

    # Use test_app module which patches Bedrock before importing the real app
    test_e2e_dir = Path(__file__).parent
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "test_app:app",
            "--host", "0.0.0.0",
            "--port", str(BACKEND_PORT),
        ],
        cwd=str(test_e2e_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait for server to be ready (max 15s)
    for _ in range(30):
        try:
            r = httpx.get(f"{BACKEND_BASE}/api/health", timeout=1)
            if r.status_code == 200:
                break
        except httpx.ConnectError:
            time.sleep(0.5)
    else:
        proc.kill()
        stdout, stderr = proc.communicate()
        pytest.fail(
            f"Backend failed to start within 15s.\n"
            f"STDOUT: {stdout.decode()}\nSTDERR: {stderr.decode()}"
        )
    yield proc
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ---------------------------------------------------------------------------
# Session-scoped: sync HTTP client
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def auth_headers(setup_database) -> dict[str, str]:
    """Return a bearer token for the seeded e2e user without consuming /login quota."""
    sys.path.insert(0, str(BACKEND_DIR))
    from app.services.auth import create_access_token

    async def _fetch_user_id() -> uuid.UUID:
        conn = await asyncpg.connect(TEST_DB_URL_SYNC)
        try:
            user_id = await conn.fetchval(
                "SELECT id FROM users WHERE email = $1",
                E2E_AUTH_EMAIL,
            )
            assert user_id is not None, f"Missing seeded e2e user {E2E_AUTH_EMAIL}"
            return user_id
        finally:
            await conn.close()

    token = create_access_token(asyncio.run(_fetch_user_id()))
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def client(backend_server, auth_headers) -> httpx.Client:
    with httpx.Client(base_url=BACKEND_BASE, timeout=30, headers=auth_headers) as c:
        yield c


# ---------------------------------------------------------------------------
# Table truncation between tests (sync via psycopg2)
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def clean_tables(db_conn):
    """Truncate all tables after each test for isolation."""
    yield
    cur = db_conn.cursor()
    for table in [
        "threats", "dfd_edges", "dfd_nodes", "trust_boundaries",
        "documents", "threat_models",
    ]:
        cur.execute(f"TRUNCATE TABLE {table} CASCADE")
    cur.close()


# ---------------------------------------------------------------------------
# Factory functions -- create test data at each level of the chain
# ---------------------------------------------------------------------------
class Factories:
    """Test data factories that use the real API (sync httpx)."""

    def __init__(self, client: httpx.Client):
        self.client = client
        self.model_id: str | None = None

    def create_threat_model(
        self,
        system_name: str = "Northstar Bank Mobile App",
        description: str = "QA test model",
        data_classification: str = "Confidential",
    ) -> dict:
        resp = self.client.post("/api/threat-models", json={
            "system_name": system_name,
            "description": description,
            "data_classification": data_classification,
        })
        assert resp.status_code == 201, f"Factory create_threat_model failed: {resp.status_code} {resp.text}"
        data = resp.json()
        self.model_id = data["id"]
        return data

    def upload_pdf(self, threat_model_id: str | None = None) -> dict:
        mid = threat_model_id or self.model_id
        assert mid, "Call create_threat_model first or pass threat_model_id"
        pdf_path = FIXTURES_DIR / "test_banking_app.pdf"
        assert pdf_path.exists(), f"Test PDF not found at {pdf_path}"
        with open(pdf_path, "rb") as f:
            resp = self.client.post(
                f"/api/threat-models/{mid}/documents",
                files={"file": ("test_banking_app.pdf", f, "application/pdf")},
            )
        assert resp.status_code == 201, f"Factory upload_pdf failed: {resp.status_code} {resp.text}"
        return resp.json()

    def create_report_ready_model(
        self,
        system_name: str = "Northstar Bank Report-Ready App",
    ) -> dict:
        """Create a model with a connected DFD that passes report blocking gates."""
        model = self.create_threat_model(
            system_name=system_name,
            description="Report-ready e2e model",
            data_classification="Confidential",
        )
        customer_id = str(uuid.uuid4())
        api_id = str(uuid.uuid4())
        database_id = str(uuid.uuid4())
        resp = self.client.put(f"/api/threat-models/{model['id']}/dfd", json={
            "nodes": [
                {
                    "id": customer_id,
                    "node_type": "external_entity",
                    "name": "Mobile Banking Customer",
                    "position_x": 0,
                    "position_y": 100,
                    "properties": {
                        "data_classification": "Public",
                        "authentication_type": "oauth2",
                        "network_exposure": "internet",
                        "privilege_level": "standard",
                        "entity_scope": "external",
                        "entity_kind": "human",
                        "trust_level": "untrusted",
                    },
                },
                {
                    "id": api_id,
                    "node_type": "process",
                    "name": "Authenticated Banking API",
                    "position_x": 250,
                    "position_y": 100,
                    "properties": {
                        "data_classification": "Confidential",
                        "authentication_type": "oauth2",
                        "network_exposure": "internet",
                        "privilege_level": "standard",
                        "runtime_type": "container",
                        "input_validation": "strict",
                        "logging_level": "audit",
                    },
                },
                {
                    "id": database_id,
                    "node_type": "data_store",
                    "name": "Account Ledger Database",
                    "position_x": 500,
                    "position_y": 100,
                    "properties": {
                        "data_classification": "Confidential",
                        "authentication_type": "mtls",
                        "network_exposure": "vpc_private",
                        "privilege_level": "restricted",
                        "store_type": "relational",
                        "store_purpose": "account ledger",
                        "encryption_at_rest": "transparent",
                        "backup_strategy": "geo_redundant",
                    },
                },
            ],
            "edges": [
                {
                    "source_node_id": customer_id,
                    "target_node_id": api_id,
                    "label": "HTTPS authenticated account request",
                    "properties": {
                        "data_payload": "session token and account query",
                        "data_classification": "Confidential",
                    },
                },
                {
                    "source_node_id": api_id,
                    "target_node_id": database_id,
                    "label": "Account balance lookup",
                    "properties": {
                        "data_payload": "account balance and transaction history",
                        "data_classification": "Confidential",
                    },
                },
            ],
            "trust_boundaries": [],
        })
        assert resp.status_code == 200, (
            f"Factory create_report_ready_model failed: {resp.status_code} {resp.text}"
        )
        return model

    def generate_threats(self, threat_model_id: str | None = None, rules_only: bool = True) -> list:
        mid = threat_model_id or self.model_id
        # Use threats/generate (which hardcodes source='Rules') instead of
        # analyze (which has a source mismatch bug).
        resp = self.client.post(f"/api/threat-models/{mid}/threats/generate")
        assert resp.status_code == 200, f"Factory generate_threats failed: {resp.status_code} {resp.text}"
        # generate returns RuleEngineOutput {threats: [...], ...}
        # We need the threats list, then re-fetch via the list endpoint
        list_resp = self.client.get(f"/api/threat-models/{mid}/threats")
        assert list_resp.status_code == 200
        return list_resp.json()

    def full_demo_chain(self) -> dict:
        """Run the entire Priya demo flow, return all IDs."""
        model = self.create_threat_model()
        doc = self.upload_pdf()
        threats = self.generate_threats(rules_only=True)
        return {
            "model_id": model["id"],
            "document_id": doc["document_id"],
            "threats": threats,
        }


@pytest.fixture
def factories(client) -> Factories:
    return Factories(client)


# ---------------------------------------------------------------------------
# Regression baseline helpers
# ---------------------------------------------------------------------------
def load_baseline() -> dict:
    if BASELINE_PATH.exists():
        return json.loads(BASELINE_PATH.read_text())
    return {}


def save_baseline(results: dict) -> None:
    BASELINE_PATH.write_text(json.dumps(results, indent=2))

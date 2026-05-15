"""E2E test fixtures -- real Postgres, real HTTP, real server.

Uses SYNC httpx and psycopg2 to avoid async event loop issues with pytest.
The backend server runs as a subprocess (async internally), but all test
interactions are synchronous.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx
import psycopg2
import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TEST_DB_URL_ASYNC = "postgresql+asyncpg://test:test@localhost:5433/threatgenix_test"
TEST_DB_URL_SYNC = "postgresql://test:test@localhost:5433/threatgenix_test"
BACKEND_PORT = 8099
BACKEND_BASE = f"http://localhost:{BACKEND_PORT}"
FRONTEND_PORT = 5174
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
            Threat,
            ThreatModel,
            TrustBoundary,
        )
        from app.seed import SEED_DATA

        engine = create_async_engine(TEST_DB_URL_ASYNC, echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

        # Seed compliance mappings
        sf = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with sf() as session:
            result = await session.execute(text("SELECT COUNT(*) FROM compliance_mappings"))
            count = result.scalar()
            if count == 0:
                from app.models.compliance import ComplianceMapping as CM
                for stride_cat, subtype, control_id, control_name in SEED_DATA:
                    session.add(CM(
                        stride_category=stride_cat,
                        threat_subtype=subtype,
                        nist_control_id=control_id,
                        nist_control_name=control_name,
                    ))
                await session.commit()

        await engine.dispose()

    asyncio.run(_do())


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """One-shot schema creation and seeding before any tests run."""
    _setup_schema_and_seed()


# ---------------------------------------------------------------------------
# Session-scoped: sync psycopg2 connection for direct DB checks
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def db_conn(setup_database):
    """Sync psycopg2 connection for direct DB queries in tests."""
    conn = psycopg2.connect(TEST_DB_URL_SYNC)
    conn.autocommit = True
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
def client(backend_server) -> httpx.Client:
    with httpx.Client(base_url=BACKEND_BASE, timeout=30) as c:
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

    def generate_threats(self, threat_model_id: str | None = None, rules_only: bool = True) -> list:
        mid = threat_model_id or self.model_id
        # Use threats/generate (which hardcodes source='Rules') instead of
        # analyze (which has a source mismatch bug).
        resp = self.client.post(f"/api/threat-models/{mid}/threats/generate")
        assert resp.status_code == 200, f"Factory generate_threats failed: {resp.status_code} {resp.text}"
        data = resp.json()
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

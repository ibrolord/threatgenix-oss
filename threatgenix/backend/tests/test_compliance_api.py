"""Tests for compliance API endpoints (Block B16)."""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import Integer, String, UniqueConstraint
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.database import get_db
from app.main import app


# ---------------------------------------------------------------------------
# Standalone SQLite-compatible model
# ---------------------------------------------------------------------------

class SQLiteBase(DeclarativeBase):
    pass


class ComplianceMappingSQLite(SQLiteBase):
    __tablename__ = "compliance_mappings"
    __table_args__ = (
        UniqueConstraint("stride_category", "threat_subtype", "framework", "control_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    stride_category: Mapped[str] = mapped_column(String(20), nullable=False)
    threat_subtype: Mapped[str] = mapped_column(String(100), nullable=False)
    framework: Mapped[str] = mapped_column(String(50), nullable=False, default="NIST 800-53")
    control_id: Mapped[str] = mapped_column(String(20), nullable=False)
    control_name: Mapped[str] = mapped_column(String(255), nullable=False)


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

SEED_ROWS = [
    ("Spoofing", "trust_boundary_identity_spoofing", "NIST 800-53", "IA-2", "Identification and Authentication (Organizational Users)"),
    ("Spoofing", "trust_boundary_identity_spoofing", "NIST 800-53", "IA-8", "Identification and Authentication (Non-Organizational Users)"),
    ("Spoofing", "service_spoofing", "NIST 800-53", "IA-3", "Device Identification and Authentication"),
    ("Tampering", "unencrypted_cross_boundary_flow", "NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ("Tampering", "unencrypted_cross_boundary_flow", "NIST 800-53", "SC-13", "Cryptographic Protection"),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def test_client():
    """Create a test client with an in-memory SQLite database for compliance mappings."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(SQLiteBase.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Seed data
    async with session_factory() as session:
        for sc, st, fw, cid, cname in SEED_ROWS:
            session.add(ComplianceMappingSQLite(
                stride_category=sc,
                threat_subtype=st,
                framework=fw,
                control_id=cid,
                control_name=cname,
            ))
        await session.commit()

    # Override get_db dependency
    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.pop(get_db, None)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_compliance_mappings_returns_list(test_client: AsyncClient):
    """GET /api/compliance-mappings returns all seeded mappings."""
    response = await test_client.get("/api/compliance-mappings")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 5
    # Verify structure of each item
    for item in data:
        assert "stride_category" in item
        assert "threat_subtype" in item
        assert "framework" in item
        assert "control_id" in item
        assert "control_name" in item


@pytest.mark.asyncio
async def test_compliance_mappings_by_stride_spoofing(test_client: AsyncClient):
    """GET /api/compliance-mappings/by-stride/Spoofing returns filtered results."""
    response = await test_client.get("/api/compliance-mappings/by-stride/Spoofing")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 3
    for item in data:
        assert item["stride_category"] == "Spoofing"


@pytest.mark.asyncio
async def test_compliance_mappings_by_stride_tampering(test_client: AsyncClient):
    """GET /api/compliance-mappings/by-stride/Tampering returns filtered results."""
    response = await test_client.get("/api/compliance-mappings/by-stride/Tampering")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2
    for item in data:
        assert item["stride_category"] == "Tampering"


@pytest.mark.asyncio
async def test_compliance_mappings_by_stride_unknown(test_client: AsyncClient):
    """GET /api/compliance-mappings/by-stride/Unknown returns empty list."""
    response = await test_client.get("/api/compliance-mappings/by-stride/Unknown")
    assert response.status_code == 200
    data = response.json()
    assert data == []

"""Tests for compliance_service (Block B15)."""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import Integer, String, UniqueConstraint
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.schemas.threat import ComplianceControlRef


# ---------------------------------------------------------------------------
# Standalone SQLite-compatible model (avoids importing Postgres-specific Base)
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
# Seed data (subset from app.seed)
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
async def db_session():
    """Create an async SQLite in-memory session with seeded compliance data."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(SQLiteBase.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

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
        yield session

    await engine.dispose()


# ---------------------------------------------------------------------------
# Fake Threat object (mimics the DB model with optional threat_subtype)
# ---------------------------------------------------------------------------

class FakeThreat:
    def __init__(
        self,
        threat_id: uuid.UUID | None = None,
        stride_category: str = "Spoofing",
        threat_subtype: str | None = None,
    ):
        self.id = threat_id or uuid.uuid4()
        self.stride_category = stride_category
        self.threat_subtype = threat_subtype


# ---------------------------------------------------------------------------
# Import the service functions (they use app.models.compliance.ComplianceMapping
# which maps to the same table name, but here we rely on the raw SQL going to
# our SQLite table with the same schema).
# ---------------------------------------------------------------------------

from app.services.compliance_service import lookup_controls, lookup_controls_batch  # noqa: E402


# ---------------------------------------------------------------------------
# Tests: lookup_controls
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lookup_controls_returns_correct_controls(db_session: AsyncSession):
    """Known stride_category + threat_subtype returns matching controls."""
    controls = await lookup_controls(
        db_session,
        stride_category="Spoofing",
        threat_subtype="trust_boundary_identity_spoofing",
    )
    assert len(controls) == 2
    ids = {c.control_id for c in controls}
    assert ids == {"IA-2", "IA-8"}
    for c in controls:
        assert isinstance(c, ComplianceControlRef)
        assert c.framework == "NIST 800-53"


@pytest.mark.asyncio
async def test_lookup_controls_returns_empty_for_unknown(db_session: AsyncSession):
    """Unknown combination returns empty list."""
    controls = await lookup_controls(
        db_session,
        stride_category="Spoofing",
        threat_subtype="nonexistent_subtype",
    )
    assert controls == []


@pytest.mark.asyncio
async def test_lookup_controls_returns_empty_for_none_subtype(db_session: AsyncSession):
    """None threat_subtype returns empty list."""
    controls = await lookup_controls(db_session, stride_category="Spoofing", threat_subtype=None)
    assert controls == []


@pytest.mark.asyncio
async def test_lookup_controls_returns_empty_for_empty_string_subtype(db_session: AsyncSession):
    """Empty-string threat_subtype returns empty list."""
    controls = await lookup_controls(db_session, stride_category="Spoofing", threat_subtype="")
    assert controls == []


# ---------------------------------------------------------------------------
# Tests: lookup_controls_batch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_batch_lookup_returns_correct_mapping(db_session: AsyncSession):
    """Batch lookup returns controls keyed by threat.id."""
    t1 = FakeThreat(stride_category="Spoofing", threat_subtype="trust_boundary_identity_spoofing")
    t2 = FakeThreat(stride_category="Tampering", threat_subtype="unencrypted_cross_boundary_flow")
    t3 = FakeThreat(stride_category="Spoofing", threat_subtype="service_spoofing")

    result = await lookup_controls_batch(db_session, [t1, t2, t3])

    assert len(result) == 3
    assert {c.control_id for c in result[t1.id]} == {"IA-2", "IA-8"}
    assert {c.control_id for c in result[t2.id]} == {"SC-8", "SC-13"}
    assert {c.control_id for c in result[t3.id]} == {"IA-3"}


@pytest.mark.asyncio
async def test_batch_lookup_handles_missing_threat_subtype(db_session: AsyncSession):
    """Threats without threat_subtype get empty list."""
    t_with = FakeThreat(stride_category="Spoofing", threat_subtype="trust_boundary_identity_spoofing")
    t_none = FakeThreat(stride_category="Spoofing", threat_subtype=None)
    t_empty = FakeThreat(stride_category="Spoofing", threat_subtype="")

    result = await lookup_controls_batch(db_session, [t_with, t_none, t_empty])

    assert len(result) == 3
    assert len(result[t_with.id]) == 2
    assert result[t_none.id] == []
    assert result[t_empty.id] == []


@pytest.mark.asyncio
async def test_batch_lookup_handles_no_attr_threat_subtype(db_session: AsyncSession):
    """Threats whose object has no threat_subtype attr at all get empty list."""

    class ThreatNoSubtype:
        def __init__(self):
            self.id = uuid.uuid4()
            self.stride_category = "Spoofing"

    t = ThreatNoSubtype()
    result = await lookup_controls_batch(db_session, [t])
    assert result[t.id] == []


@pytest.mark.asyncio
async def test_batch_lookup_empty_list(db_session: AsyncSession):
    """Empty threats list returns empty dict."""
    result = await lookup_controls_batch(db_session, [])
    assert result == {}


@pytest.mark.asyncio
async def test_batch_lookup_unknown_subtype(db_session: AsyncSession):
    """Threat with unknown subtype returns empty list for that threat."""
    t = FakeThreat(stride_category="Spoofing", threat_subtype="does_not_exist")
    result = await lookup_controls_batch(db_session, [t])
    assert result[t.id] == []

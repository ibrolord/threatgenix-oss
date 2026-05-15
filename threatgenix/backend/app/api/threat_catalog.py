"""Threat catalog: browse STRIDE rules and manually add threats."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query
from pathlib import Path
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.threat import Threat
from app.models.user import User
from app.schemas.threat import ManualThreatCreate, ThreatCatalogEntry, ThreatResponse
from app.services.auth import get_current_user
from app.services.compliance_service import lookup_controls_batch
from app.services.model_collaboration import require_model_permission
from app.services.threat_model import get_threat_model

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Catalog router (no auth — reference data)
# ---------------------------------------------------------------------------
catalog_router = APIRouter(prefix="/api", tags=["threat-catalog"])

# Cache loaded catalog entries at module level
_catalog_cache: list[ThreatCatalogEntry] | None = None


def _load_catalog() -> list[ThreatCatalogEntry]:
    global _catalog_cache
    if _catalog_cache is not None:
        return _catalog_cache

    yaml_path = Path(__file__).parent.parent / "services" / "rules" / "rule_definitions.yaml"
    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    entries: list[ThreatCatalogEntry] = []
    for rule in data["rules"]:
        entries.append(
            ThreatCatalogEntry(
                rule_id=rule["rule_id"],
                stride_category=rule["stride_category"],
                threat_subtype=rule["threat_subtype"],
                severity=rule["severity"],
                description_template=rule["description_template"],
                condition_type=rule["condition_type"],
            )
        )
    _catalog_cache = entries
    return entries


@catalog_router.get("/threat-catalog", response_model=list[ThreatCatalogEntry])
async def get_threat_catalog(
    q: Optional[str] = Query(None, description="Text search across subtype + description"),
    stride: Optional[str] = Query(None, description="Filter by STRIDE category"),
) -> list[ThreatCatalogEntry]:
    """Return all 41 rule definitions as a browseable catalog."""
    entries = _load_catalog()

    if stride:
        entries = [e for e in entries if e.stride_category.lower() == stride.lower()]

    if q:
        q_lower = q.lower()
        entries = [
            e
            for e in entries
            if q_lower in e.threat_subtype.lower()
            or q_lower in e.description_template.lower()
        ]

    return entries


# ---------------------------------------------------------------------------
# Manual threat creation router (requires auth + ownership)
# ---------------------------------------------------------------------------
manual_router = APIRouter(
    prefix="/api/threat-models/{threat_model_id}",
    tags=["threats"],
)


async def _require_owner(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> User:
    """Verify threat model exists and belongs to current user."""
    require_model_permission(
        await get_threat_model(db, threat_model_id),
        current_user,
        "write",
    )
    return current_user


@manual_router.post("/threats/manual", response_model=ThreatResponse)
async def create_manual_threat(
    threat_model_id: UUID,
    body: ManualThreatCreate,
    db: AsyncSession = Depends(get_db),
    _owner: User = Depends(_require_owner),
) -> ThreatResponse:
    """Create a threat manually — from catalog rule or fully custom."""
    stored_rule_id = (body.rule_id or "").strip() or None

    # Look up the catalog entry (optional — custom rule_ids are allowed)
    catalog = _load_catalog()
    entry = next((e for e in catalog if stored_rule_id and e.rule_id == stored_rule_id), None)

    # Calculate next display_id for this threat model
    await db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": threat_model_id.int % (2**63)},
    )
    result = await db.execute(
        select(Threat)
        .where(Threat.threat_model_id == threat_model_id)
        .order_by(Threat.display_id.desc())
    )
    existing = result.scalars().all()

    max_num = 0
    for t in existing:
        try:
            parts = t.display_id.rsplit("-", 1)
            if len(parts) == 2:
                max_num = max(max_num, int(parts[1]))
        except (ValueError, IndexError):
            pass

    display_id = f"T-{max_num + 1:03d}"

    # Use overrides, catalog defaults, or require description for custom threats
    if entry:
        description = body.description or entry.description_template
        severity = body.severity or entry.severity
        stride_category = entry.stride_category
        threat_subtype = entry.threat_subtype
    else:
        # Fully custom threat — description is required
        if not body.description:
            raise HTTPException(status_code=400, detail="Description required for custom threats")
        description = body.description
        severity = body.severity or "Medium"
        stride_category = body.stride_category or "Tampering"
        threat_subtype = (
            (body.threat_subtype or "Custom threat").strip()
            or "Custom threat"
        )

    # Validate severity
    if severity not in ("Critical", "High", "Medium", "Low"):
        raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")

    try:
        affected_node_ids = [UUID(nid) for nid in body.affected_node_ids]
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail="affected_node_ids must contain valid UUID values",
        ) from exc
    threat_id = uuid4()
    now = datetime.now(timezone.utc)

    threat = Threat(
        id=threat_id,
        threat_model_id=threat_model_id,
        display_id=display_id,
        description=description,
        stride_category=stride_category,
        threat_subtype=threat_subtype,
        severity=severity,
        source="Manual",
        status="Open",
        rule_id=stored_rule_id,
        ai_enhanced=False,
        affected_node_ids=affected_node_ids,
        affected_edge_ids=[],
    )
    db.add(threat)
    await db.commit()
    await db.refresh(threat)

    # Auto-populate compliance controls for manual threats
    controls_map = await lookup_controls_batch(db, [threat])
    compliance_controls = controls_map.get(threat_id, [])

    return ThreatResponse(
        id=threat_id,
        display_id=display_id,
        description=description,
        stride_category=stride_category,
        threat_subtype=threat_subtype,
        severity=severity,
        source="Manual",
        status="Open",
        dismiss_reason=None,
        rule_id=stored_rule_id,
        ai_enhanced=False,
        original_rule_threat_id=None,
        affected_node_ids=affected_node_ids,
        affected_edge_ids=[],
        relevance_rationale=None,
        compliance_controls=compliance_controls,
        created_at=now,
    )

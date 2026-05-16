"""Ingest MITRE ATT&CK Enterprise techniques from STIX 2.1 JSON.

Source: https://github.com/mitre-attack/attack-stix-data/
Format: STIX 2.1 bundle JSON
Update frequency: ~2x/year (major releases)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intel import AttackTechnique, ThreatIntelSync
from app.services.threat_intel.embeddings import (
    build_embedding_text_attack,
    generate_embeddings_batch,
)

logger = logging.getLogger(__name__)

# STIX 2.1 Enterprise ATT&CK bundle
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def _extract_technique_id(external_references: list[dict]) -> str | None:
    """Extract ATT&CK technique ID (e.g., T1234) from STIX external_references."""
    for ref in external_references:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_url(external_references: list[dict]) -> str | None:
    """Extract ATT&CK URL from STIX external_references."""
    for ref in external_references:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def _extract_tactic(kill_chain_phases: list[dict]) -> str:
    """Extract the first tactic from kill_chain_phases."""
    for phase in kill_chain_phases:
        if phase.get("kill_chain_name") == "mitre-attack":
            return phase.get("phase_name", "unknown")
    return "unknown"


async def ingest_attack(db: AsyncSession, with_embeddings: bool = True) -> int:
    """Download and ingest ATT&CK Enterprise techniques.

    Args:
        db: Async database session.
        with_embeddings: Whether to generate embeddings with the configured provider.

    Returns:
        Number of techniques ingested.
    """
    # Update sync status
    sync_record = await _get_or_create_sync(db, "attack")
    sync_record.status = "syncing"
    await db.commit()

    try:
        # Download STIX bundle
        logger.info("Downloading ATT&CK STIX bundle from GitHub...")
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.get(ATTACK_STIX_URL)
            resp.raise_for_status()
        bundle = resp.json()

        # Parse attack-pattern objects (techniques)
        techniques_data: list[dict] = []
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            ext_refs = obj.get("external_references", [])
            technique_id = _extract_technique_id(ext_refs)
            if not technique_id:
                continue

            name = obj.get("name", "")
            description = obj.get("description", "")
            tactic = _extract_tactic(obj.get("kill_chain_phases", []))
            is_sub = obj.get("x_mitre_is_subtechnique", False)
            parent_id = technique_id.split(".")[0] if is_sub and "." in technique_id else None
            platforms = obj.get("x_mitre_platforms", [])

            techniques_data.append({
                "technique_id": technique_id,
                "name": name,
                "description": description,
                "tactic": tactic,
                "is_subtechnique": is_sub,
                "parent_id": parent_id,
                "platforms": platforms,
                "url": _extract_url(ext_refs),
                "stix_id": obj.get("id"),
                "version": bundle.get("spec_version", "2.1"),
            })

        logger.info("Parsed %d ATT&CK techniques from STIX bundle", len(techniques_data))

        # Generate embeddings if requested
        embeddings: list[list[float]] | None = None
        if with_embeddings and techniques_data:
            logger.info("Generating embeddings for %d techniques...", len(techniques_data))
            texts = [
                build_embedding_text_attack(
                    t["technique_id"], t["name"], t["description"], t["tactic"]
                )
                for t in techniques_data
            ]
            embeddings = generate_embeddings_batch(texts)

        # Upsert into database
        count = 0
        for i, data in enumerate(techniques_data):
            existing = await db.execute(
                select(AttackTechnique).where(
                    AttackTechnique.technique_id == data["technique_id"]
                )
            )
            row = existing.scalars().first()

            embedding = embeddings[i] if embeddings else None

            if row:
                row.name = data["name"]
                row.description = data["description"]
                row.tactic = data["tactic"]
                row.is_subtechnique = data["is_subtechnique"]
                row.parent_id = data["parent_id"]
                row.platforms = data["platforms"]
                row.url = data["url"]
                row.stix_id = data["stix_id"]
                row.version = data["version"]
                if embedding:
                    row.embedding = embedding
            else:
                db.add(AttackTechnique(
                    **data,
                    embedding=embedding,
                ))
            count += 1

        await db.commit()

        # Update sync metadata
        sync_record.status = "complete"
        sync_record.last_sync_at = datetime.now(timezone.utc)
        sync_record.record_count = count
        sync_record.error_message = None
        await db.commit()

        logger.info("ATT&CK ingestion complete: %d techniques", count)
        return count

    except Exception as exc:
        sync_record.status = "error"
        sync_record.error_message = str(exc)[:500]
        await db.commit()
        logger.error("ATT&CK ingestion failed: %s", exc)
        raise


async def _get_or_create_sync(db: AsyncSession, source_name: str) -> ThreatIntelSync:
    """Get or create a ThreatIntelSync record."""
    result = await db.execute(
        select(ThreatIntelSync).where(ThreatIntelSync.source_name == source_name)
    )
    sync = result.scalars().first()
    if not sync:
        sync = ThreatIntelSync(source_name=source_name)
        db.add(sync)
        await db.commit()
        await db.refresh(sync)
    return sync

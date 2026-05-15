"""Ingest CAPEC attack patterns from XML.

Source: https://capec.mitre.org/data/xml/capec_latest.xml
Format: XML
Update frequency: Quarterly
"""

from __future__ import annotations

import logging
import defusedxml.ElementTree as ET
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intel import AttackPattern
from app.services.threat_intel.embeddings import (
    build_embedding_text_capec,
    generate_embeddings_batch,
)

logger = logging.getLogger(__name__)

CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

# CAPEC XML namespace
NS = {"capec": "http://capec.mitre.org/capec-3"}


def _text_content(element: ET.Element | None) -> str:
    """Extract all text content from an element and its children."""
    if element is None:
        return ""
    parts = []
    for text in element.itertext():
        stripped = text.strip()
        if stripped:
            parts.append(stripped)
    return " ".join(parts)


def _parse_capec_xml(xml_bytes: bytes) -> list[dict]:
    """Parse CAPEC XML into a list of attack pattern dicts."""
    root = ET.fromstring(xml_bytes)
    patterns: list[dict] = []

    for ap in root.findall(".//capec:Attack_Pattern", NS):
        capec_id_num = ap.get("ID", "")
        status = ap.get("Status", "")

        # Skip deprecated/obsolete patterns
        if status in ("Deprecated", "Obsolete"):
            continue

        capec_id = f"CAPEC-{capec_id_num}"
        name = ap.get("Name", "")
        description = _text_content(ap.find("capec:Description", NS))
        likelihood = ap.findtext("capec:Likelihood_Of_Attack", default="", namespaces=NS)
        severity = ap.findtext("capec:Typical_Severity", default="", namespaces=NS)
        prerequisites = _text_content(ap.find("capec:Prerequisites", NS))

        # Extract related CWE IDs
        related_cwes: list[str] = []
        for weakness in ap.findall(".//capec:Related_Weakness", NS):
            cwe_num = weakness.get("CWE_ID", "")
            if cwe_num:
                related_cwes.append(f"CWE-{cwe_num}")

        # Extract related ATT&CK technique IDs
        related_attacks: list[str] = []
        for taxonomy_mapping in ap.findall(".//capec:Taxonomy_Mapping", NS):
            taxonomy_name = taxonomy_mapping.get("Taxonomy_Name", "")
            if "ATT&CK" in taxonomy_name:
                entry_id = taxonomy_mapping.findtext("capec:Entry_ID", default="", namespaces=NS)
                if entry_id:
                    related_attacks.append(entry_id)

        patterns.append({
            "capec_id": capec_id,
            "name": name,
            "description": description[:5000],
            "likelihood": likelihood or None,
            "severity": severity or None,
            "prerequisites": prerequisites[:2000] if prerequisites else None,
            "related_cwe_ids": related_cwes,
            "related_attack_ids": related_attacks,
        })

    return patterns


async def ingest_capec(db: AsyncSession, with_embeddings: bool = True) -> int:
    """Download and ingest CAPEC attack patterns.

    Args:
        db: Async database session.
        with_embeddings: Whether to generate embeddings.

    Returns:
        Number of patterns ingested.
    """
    from app.services.threat_intel.ingest_attack import _get_or_create_sync

    sync_record = await _get_or_create_sync(db, "capec")
    sync_record.status = "syncing"
    await db.commit()

    try:
        logger.info("Downloading CAPEC XML...")
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.get(CAPEC_XML_URL)
            resp.raise_for_status()

        patterns = _parse_capec_xml(resp.content)
        logger.info("Parsed %d CAPEC attack patterns", len(patterns))

        # Generate embeddings
        embeddings: list[list[float]] | None = None
        if with_embeddings and patterns:
            logger.info("Generating embeddings for %d patterns...", len(patterns))
            texts = [
                build_embedding_text_capec(p["capec_id"], p["name"], p["description"])
                for p in patterns
            ]
            embeddings = generate_embeddings_batch(texts)

        # Upsert
        count = 0
        for i, data in enumerate(patterns):
            existing = await db.execute(
                select(AttackPattern).where(AttackPattern.capec_id == data["capec_id"])
            )
            row = existing.scalars().first()
            embedding = embeddings[i] if embeddings else None

            if row:
                row.name = data["name"]
                row.description = data["description"]
                row.likelihood = data["likelihood"]
                row.severity = data["severity"]
                row.prerequisites = data["prerequisites"]
                row.related_cwe_ids = data["related_cwe_ids"]
                row.related_attack_ids = data["related_attack_ids"]
                if embedding:
                    row.embedding = embedding
            else:
                db.add(AttackPattern(**data, embedding=embedding))
            count += 1

        await db.commit()

        sync_record.status = "complete"
        sync_record.last_sync_at = datetime.now(timezone.utc)
        sync_record.record_count = count
        sync_record.error_message = None
        await db.commit()

        logger.info("CAPEC ingestion complete: %d patterns", count)
        return count

    except Exception as exc:
        sync_record.status = "error"
        sync_record.error_message = str(exc)[:500]
        await db.commit()
        logger.error("CAPEC ingestion failed: %s", exc)
        raise

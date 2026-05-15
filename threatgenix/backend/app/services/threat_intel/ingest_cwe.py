"""Ingest CWE weaknesses from XML.

Source: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
Format: XML (zipped)
Update frequency: Quarterly

We focus on CWE Top 25 2025 + financial-sector-relevant weaknesses (~200 total).
"""

from __future__ import annotations

import io
import logging
import defusedxml.ElementTree as ET
import zipfile
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intel import WeaknessEntry
from app.services.threat_intel.embeddings import (
    build_embedding_text_cwe,
    generate_embeddings_batch,
)

logger = logging.getLogger(__name__)

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

NS = {"cwe": "http://cwe.mitre.org/cwe-7"}

# CWE Top 25 2025 (most dangerous software weaknesses)
CWE_TOP_25_2025 = {
    "CWE-79", "CWE-89", "CWE-352", "CWE-22", "CWE-125", "CWE-78",
    "CWE-416", "CWE-787", "CWE-20", "CWE-200", "CWE-862", "CWE-77",
    "CWE-306", "CWE-269", "CWE-434", "CWE-502", "CWE-190", "CWE-863",
    "CWE-476", "CWE-287", "CWE-798", "CWE-119", "CWE-918", "CWE-611",
    "CWE-94",
}

# Additional CWEs relevant to financial/banking applications
FINANCIAL_RELEVANT_CWES = {
    "CWE-256",  # Plaintext Storage of a Password
    "CWE-257",  # Storing Passwords in a Recoverable Format
    "CWE-261",  # Weak Encoding for Password
    "CWE-284",  # Improper Access Control
    "CWE-285",  # Improper Authorization
    "CWE-311",  # Missing Encryption of Sensitive Data
    "CWE-312",  # Cleartext Storage of Sensitive Information
    "CWE-319",  # Cleartext Transmission of Sensitive Information
    "CWE-326",  # Inadequate Encryption Strength
    "CWE-327",  # Use of a Broken or Risky Cryptographic Algorithm
    "CWE-330",  # Use of Insufficiently Random Values
    "CWE-346",  # Origin Validation Error
    "CWE-347",  # Improper Verification of Cryptographic Signature
    "CWE-362",  # Concurrent Execution using Shared Resource with Improper Synchronization
    "CWE-384",  # Session Fixation
    "CWE-400",  # Uncontrolled Resource Consumption
    "CWE-522",  # Insufficiently Protected Credentials
    "CWE-532",  # Insertion of Sensitive Information into Log File
    "CWE-601",  # URL Redirection to Untrusted Site
    "CWE-613",  # Insufficient Session Expiration
    "CWE-640",  # Weak Password Recovery Mechanism for Forgotten Password
    "CWE-732",  # Incorrect Permission Assignment for Critical Resource
    "CWE-770",  # Allocation of Resources Without Limits or Throttling
    "CWE-776",  # Improper Restriction of Recursive Entity References in DTDs
    "CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
    "CWE-942",  # Permissive Cross-domain Policy with Untrusted Domains
    "CWE-1021", # Improper Restriction of Rendered UI Layers or Frames
}

PRIORITY_CWE_IDS = CWE_TOP_25_2025 | FINANCIAL_RELEVANT_CWES


def _text_content(element: ET.Element | None) -> str:
    if element is None:
        return ""
    parts = []
    for text in element.itertext():
        stripped = text.strip()
        if stripped:
            parts.append(stripped)
    return " ".join(parts)


def _parse_cwe_xml(xml_bytes: bytes) -> list[dict]:
    """Parse CWE XML, extracting priority weaknesses."""
    root = ET.fromstring(xml_bytes)
    weaknesses: list[dict] = []

    for weakness in root.findall(".//cwe:Weakness", NS):
        cwe_num = weakness.get("ID", "")
        cwe_id = f"CWE-{cwe_num}"
        status = weakness.get("Status", "")

        if status in ("Deprecated", "Obsolete"):
            continue

        # Only ingest priority CWEs (Top 25 + financial-relevant)
        if cwe_id not in PRIORITY_CWE_IDS:
            continue

        name = weakness.get("Name", "")
        description = _text_content(weakness.find("cwe:Description", NS))
        extended = _text_content(weakness.find("cwe:Extended_Description", NS))

        # Extract consequences
        consequences_parts: list[str] = []
        for consequence in weakness.findall(".//cwe:Consequence", NS):
            scope = consequence.findtext("cwe:Scope", default="", namespaces=NS)
            impact = consequence.findtext("cwe:Impact", default="", namespaces=NS)
            if scope and impact:
                consequences_parts.append(f"{scope}: {impact}")
        consequences = "; ".join(consequences_parts) if consequences_parts else None

        # Extract mitigations
        mitigations_parts: list[str] = []
        for mitigation in weakness.findall(".//cwe:Potential_Mitigation", NS):
            phase = mitigation.findtext("cwe:Phase", default="", namespaces=NS)
            desc = _text_content(mitigation.find("cwe:Description", NS))
            if desc:
                prefix = f"[{phase}] " if phase else ""
                mitigations_parts.append(f"{prefix}{desc[:500]}")
        mitigations = " | ".join(mitigations_parts[:5]) if mitigations_parts else None

        # Extract related CAPEC IDs
        related_capecs: list[str] = []
        for related in weakness.findall(".//cwe:Related_Attack_Pattern", NS):
            capec_num = related.get("CAPEC_ID", "")
            if capec_num:
                related_capecs.append(f"CAPEC-{capec_num}")

        weaknesses.append({
            "cwe_id": cwe_id,
            "name": name,
            "description": description[:5000],
            "extended_description": extended[:3000] if extended else None,
            "consequences": consequences[:2000] if consequences else None,
            "mitigations": mitigations[:3000] if mitigations else None,
            "related_capec_ids": related_capecs,
            "is_top_25": cwe_id in CWE_TOP_25_2025,
        })

    return weaknesses


async def ingest_cwe(db: AsyncSession, with_embeddings: bool = True) -> int:
    """Download and ingest CWE weaknesses (Top 25 + financial-relevant).

    Args:
        db: Async database session.
        with_embeddings: Whether to generate embeddings.

    Returns:
        Number of weaknesses ingested.
    """
    from app.services.threat_intel.ingest_attack import _get_or_create_sync

    sync_record = await _get_or_create_sync(db, "cwe")
    sync_record.status = "syncing"
    await db.commit()

    try:
        logger.info("Downloading CWE XML (zipped)...")
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.get(CWE_ZIP_URL)
            resp.raise_for_status()

        # Unzip
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            xml_filename = [n for n in zf.namelist() if n.endswith(".xml")][0]
            xml_bytes = zf.read(xml_filename)

        weaknesses = _parse_cwe_xml(xml_bytes)
        logger.info("Parsed %d priority CWE weaknesses", len(weaknesses))

        # Generate embeddings
        embeddings: list[list[float]] | None = None
        if with_embeddings and weaknesses:
            logger.info("Generating embeddings for %d weaknesses...", len(weaknesses))
            texts = [
                build_embedding_text_cwe(w["cwe_id"], w["name"], w["description"])
                for w in weaknesses
            ]
            embeddings = generate_embeddings_batch(texts)

        # Upsert
        count = 0
        for i, data in enumerate(weaknesses):
            existing = await db.execute(
                select(WeaknessEntry).where(WeaknessEntry.cwe_id == data["cwe_id"])
            )
            row = existing.scalars().first()
            embedding = embeddings[i] if embeddings else None

            if row:
                row.name = data["name"]
                row.description = data["description"]
                row.extended_description = data["extended_description"]
                row.consequences = data["consequences"]
                row.mitigations = data["mitigations"]
                row.related_capec_ids = data["related_capec_ids"]
                row.is_top_25 = data["is_top_25"]
                if embedding:
                    row.embedding = embedding
            else:
                db.add(WeaknessEntry(**data, embedding=embedding))
            count += 1

        await db.commit()

        sync_record.status = "complete"
        sync_record.last_sync_at = datetime.now(timezone.utc)
        sync_record.record_count = count
        sync_record.error_message = None
        await db.commit()

        logger.info("CWE ingestion complete: %d weaknesses", count)
        return count

    except Exception as exc:
        sync_record.status = "error"
        sync_record.error_message = str(exc)[:500]
        await db.commit()
        logger.error("CWE ingestion failed: %s", exc)
        raise

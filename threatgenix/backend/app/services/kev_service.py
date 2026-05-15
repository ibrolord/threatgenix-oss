"""CISA KEV lookup service — Layer 3 active exploitation context.

Given technology keywords or CVE IDs from a threat model, returns
KEV entries indicating active exploitation in the wild.

This directly affects risk scoring: an actively exploited vulnerability
should increase the likelihood score in the 5x5 risk matrix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intel import KEVEntry


@dataclass
class KEVRef:
    """A CISA KEV entry reference."""
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    known_ransomware_use: str | None
    date_added: str | None  # ISO format


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


def extract_cve_ids(text_content: str) -> list[str]:
    """Extract CVE IDs from text."""
    return list(set(CVE_PATTERN.findall(text_content)))


async def lookup_kev_by_cve(
    db: AsyncSession,
    cve_ids: list[str],
) -> list[KEVRef]:
    """Look up KEV entries by CVE ID.

    Args:
        db: Async database session.
        cve_ids: List of CVE IDs (e.g., ["CVE-2024-12345"]).

    Returns:
        List of KEV entries (actively exploited vulnerabilities).
    """
    if not cve_ids:
        return []

    result = await db.execute(
        select(KEVEntry).where(KEVEntry.cve_id.in_(cve_ids))
    )
    rows = result.scalars().all()

    return [
        KEVRef(
            cve_id=row.cve_id,
            vendor_project=row.vendor_project,
            product=row.product,
            vulnerability_name=row.vulnerability_name,
            known_ransomware_use=row.known_ransomware_use,
            date_added=row.date_added.isoformat() if row.date_added else None,
        )
        for row in rows
    ]


async def lookup_kev_by_technology(
    db: AsyncSession,
    technology_keywords: list[str],
) -> list[KEVRef]:
    """Look up KEV entries matching technology keywords.

    Searches vendor_project and product fields using ILIKE.

    Args:
        db: Async database session.
        technology_keywords: List of technology names to search for.

    Returns:
        List of matching KEV entries.
    """
    if not technology_keywords:
        return []

    conditions = []
    params = {}
    for i, keyword in enumerate(technology_keywords[:10]):
        param_name = f"kw_{i}"
        conditions.append(
            f"(LOWER(vendor_project) LIKE :{param_name} OR LOWER(product) LIKE :{param_name})"
        )
        params[param_name] = f"%{keyword.lower()}%"

    if not conditions:
        return []

    query = f"""
        SELECT cve_id, vendor_project, product, vulnerability_name,
               known_ransomware_use, date_added
        FROM kev_entries
        WHERE {" OR ".join(conditions)}
        ORDER BY date_added DESC NULLS LAST
        LIMIT 20
    """

    result = await db.execute(text(query), params)
    return [
        KEVRef(
            cve_id=row.cve_id,
            vendor_project=row.vendor_project,
            product=row.product,
            vulnerability_name=row.vulnerability_name,
            known_ransomware_use=row.known_ransomware_use,
            date_added=row.date_added.isoformat() if row.date_added else None,
        )
        for row in result
    ]

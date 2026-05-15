"""Semantic retrieval service for threat intelligence.

Given a threat description or DFD context, retrieves the most relevant:
- ATT&CK techniques (TTPs)
- CAPEC attack patterns
- CWE weaknesses
- CCCS advisories

Uses pgvector cosine similarity search over pre-computed embeddings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.threat_intel import (
    CRIMapping,
)
from app.services.threat_intel.embeddings import generate_embedding

logger = logging.getLogger(__name__)
VECTOR_SEARCH_TABLES = (
    "attack_techniques",
    "attack_patterns",
    "weakness_entries",
    "cccs_advisories",
)


@dataclass
class ThreatIntelContext:
    """Retrieved threat intelligence context for AI enhancement."""

    attack_techniques: list[dict]  # Top-K ATT&CK techniques
    attack_patterns: list[dict]  # Top-K CAPEC patterns
    weaknesses: list[dict]  # Top-K CWE weaknesses
    advisories: list[dict]  # Top-K CCCS advisories
    kev_matches: list[dict]  # KEV entries matching technologies
    cri_controls: list[dict]  # CRI controls for matched ATT&CK techniques
    unavailable_reason: str | None = None

    def to_prompt_context(self) -> str:
        """Format as text for injection into AI enhancement prompt."""
        sections: list[str] = []

        if self.attack_techniques:
            lines = ["## Relevant MITRE ATT&CK Techniques"]
            for t in self.attack_techniques:
                lines.append(
                    f"- **{t['technique_id']}** ({t['tactic']}): {t['name']} — "
                    f"{t['description'][:200]}"
                )
            sections.append("\n".join(lines))

        if self.attack_patterns:
            lines = ["## Relevant CAPEC Attack Patterns"]
            for p in self.attack_patterns:
                cwe_refs = ", ".join(p.get("related_cwe_ids", [])[:3])
                lines.append(
                    f"- **{p['capec_id']}**: {p['name']} "
                    f"(severity: {p.get('severity', 'N/A')}, "
                    f"related CWEs: {cwe_refs or 'none'}) — "
                    f"{p['description'][:200]}"
                )
            sections.append("\n".join(lines))

        if self.weaknesses:
            lines = ["## Relevant CWE Weaknesses"]
            for w in self.weaknesses:
                top25 = " [TOP 25]" if w.get("is_top_25") else ""
                lines.append(
                    f"- **{w['cwe_id']}**: {w['name']}{top25} — "
                    f"{w['description'][:200]}"
                )
            sections.append("\n".join(lines))

        if self.advisories:
            lines = ["## Recent CCCS Advisories"]
            for a in self.advisories:
                cves = ", ".join(a.get("referenced_cves", [])[:3])
                lines.append(
                    f"- **{a['advisory_id']}**: {a['title']} "
                    f"(CVEs: {cves or 'none'}) — "
                    f"{(a.get('summary') or '')[:150]}"
                )
            sections.append("\n".join(lines))

        if self.kev_matches:
            lines = ["## Actively Exploited Vulnerabilities (CISA KEV)"]
            for k in self.kev_matches:
                ransomware = (
                    " [RANSOMWARE]" if k.get("known_ransomware_use") == "Known" else ""
                )
                lines.append(
                    f"- **{k['cve_id']}**: {k['vulnerability_name']}{ransomware} "
                    f"({k['vendor_project']}/{k['product']})"
                )
            sections.append("\n".join(lines))

        if self.cri_controls:
            lines = ["## CRI Profile Controls (Financial Sector)"]
            for c in self.cri_controls:
                lines.append(
                    f"- **{c['cri_control_id']}** ({c['cri_function']}): "
                    f"{c['cri_control_name']} — "
                    f"{c['mapping_type']}s {c['attack_technique_id']}"
                )
            sections.append("\n".join(lines))

        if not sections:
            return ""

        return (
            "\n\n---\n\n## Threat Intelligence Context\n"
            "The following threat intelligence is retrieved from authoritative sources. "
            "Use it to ground your threat analysis with specific technique IDs, "
            "attack patterns, and weakness references. CITE these IDs in your threats.\n\n"
            + "\n\n".join(sections)
        )


def _empty_threat_intel_context(
    unavailable_reason: str | None = None,
) -> ThreatIntelContext:
    return ThreatIntelContext(
        attack_techniques=[],
        attack_patterns=[],
        weaknesses=[],
        advisories=[],
        kev_matches=[],
        cri_controls=[],
        unavailable_reason=unavailable_reason,
    )


async def _vector_search_available(db: AsyncSession) -> tuple[bool, str | None]:
    """Return whether vector-backed retrieval can safely run."""
    try:
        vector_type_result = await db.execute(
            text("SELECT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'vector')")
        )
        if not bool(vector_type_result.scalar()):
            return False, "pgvector type unavailable"

        missing_tables: list[str] = []
        for table_name in VECTOR_SEARCH_TABLES:
            table_result = await db.execute(
                text("SELECT to_regclass(:table_name)"),
                {"table_name": table_name},
            )
            if table_result.scalar() is None:
                missing_tables.append(table_name)

        if missing_tables:
            return False, f"missing vector-backed tables: {', '.join(missing_tables)}"
        return True, None
    except Exception as exc:
        return False, f"availability probe failed: {exc}"


async def retrieve_threat_intel(
    db: AsyncSession,
    query_text: str,
    *,
    top_k_attack: int = 8,
    top_k_capec: int = 5,
    top_k_cwe: int = 5,
    top_k_advisory: int = 3,
    technology_keywords: list[str] | None = None,
) -> ThreatIntelContext:
    """Retrieve relevant threat intelligence for a given context.

    Args:
        db: Async database session.
        query_text: The text to search against (DFD summary + threat descriptions).
        top_k_attack: Number of ATT&CK techniques to retrieve.
        top_k_capec: Number of CAPEC patterns to retrieve.
        top_k_cwe: Number of CWE weaknesses to retrieve.
        top_k_advisory: Number of CCCS advisories to retrieve.
        technology_keywords: Optional list of technology names for KEV lookup.

    Returns:
        ThreatIntelContext with retrieved intelligence.
    """
    if settings.audit_disable_threat_intel:
        logger.warning("audit_disable_threat_intel enabled")
        return _empty_threat_intel_context("audit toggle enabled")

    vector_available, unavailable_reason = await _vector_search_available(db)
    if not vector_available:
        logger.warning(
            "Threat intel unavailable, skipping retrieval: %s", unavailable_reason
        )
        return _empty_threat_intel_context(unavailable_reason)

    # The availability probes above are read-only. End that transaction before
    # the synchronous Bedrock call so slow or degraded embedding providers do
    # not tie up a pooled database connection. Sessions are configured with
    # expire_on_commit=False, so loaded review inputs remain usable afterward.
    await db.commit()

    # Generate query embedding
    try:
        query_embedding = generate_embedding(query_text)
    except Exception as exc:
        logger.warning("Failed to generate query embedding: %s", exc)
        return _empty_threat_intel_context(
            f"embedding generation failed: {type(exc).__name__}"
        )

    embedding_str = "[" + ",".join(str(x) for x in query_embedding) + "]"

    # Parallel semantic searches using pgvector cosine distance
    attack_techniques = await _search_attack(db, embedding_str, top_k_attack)
    attack_patterns = await _search_capec(db, embedding_str, top_k_capec)
    weaknesses = await _search_cwe(db, embedding_str, top_k_cwe)
    advisories = await _search_cccs(db, embedding_str, top_k_advisory)

    # KEV lookup by technology keywords
    kev_matches: list[dict] = []
    if technology_keywords:
        kev_matches = await _lookup_kev(db, technology_keywords)

    # CRI control lookup for matched ATT&CK techniques
    technique_ids = [t["technique_id"] for t in attack_techniques]
    cri_controls = await _lookup_cri(db, technique_ids)

    return ThreatIntelContext(
        attack_techniques=attack_techniques,
        attack_patterns=attack_patterns,
        weaknesses=weaknesses,
        advisories=advisories,
        kev_matches=kev_matches,
        cri_controls=cri_controls,
    )


# Cosine distance threshold: entries with distance >= this value are too
# dissimilar to the query and should not be returned as semantic matches.
# Cosine distance is in [0, 2]; 0 = identical, 1 = orthogonal, 2 = opposite.
# 0.45 corresponds to cosine similarity ~0.55 — a reasonable relevance floor.
_SIMILARITY_DISTANCE_THRESHOLD = 0.45


async def _search_attack(
    db: AsyncSession, embedding_str: str, top_k: int
) -> list[dict]:
    """Semantic search over ATT&CK techniques."""
    result = await db.execute(
        text("""
            SELECT technique_id, name, description, tactic, url,
                   embedding <=> CAST(:embedding AS vector) AS distance
            FROM attack_techniques
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> CAST(:embedding AS vector)
            LIMIT :limit
        """),
        {"embedding": embedding_str, "limit": top_k},
    )
    return [
        {
            "technique_id": row.technique_id,
            "name": row.name,
            "description": row.description,
            "tactic": row.tactic,
            "url": row.url,
            "distance": row.distance,
        }
        for row in result
        if row.distance is not None and row.distance < _SIMILARITY_DISTANCE_THRESHOLD
    ]


async def _search_capec(db: AsyncSession, embedding_str: str, top_k: int) -> list[dict]:
    """Semantic search over CAPEC attack patterns."""
    result = await db.execute(
        text("""
            SELECT capec_id, name, description, likelihood, severity,
                   related_cwe_ids, related_attack_ids,
                   embedding <=> CAST(:embedding AS vector) AS distance
            FROM attack_patterns
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> CAST(:embedding AS vector)
            LIMIT :limit
        """),
        {"embedding": embedding_str, "limit": top_k},
    )
    return [
        {
            "capec_id": row.capec_id,
            "name": row.name,
            "description": row.description,
            "likelihood": row.likelihood,
            "severity": row.severity,
            "related_cwe_ids": row.related_cwe_ids or [],
            "related_attack_ids": row.related_attack_ids or [],
            "distance": row.distance,
        }
        for row in result
        if row.distance is not None and row.distance < _SIMILARITY_DISTANCE_THRESHOLD
    ]


async def _search_cwe(db: AsyncSession, embedding_str: str, top_k: int) -> list[dict]:
    """Semantic search over CWE weaknesses."""
    result = await db.execute(
        text("""
            SELECT cwe_id, name, description, is_top_25, consequences,
                   embedding <=> CAST(:embedding AS vector) AS distance
            FROM weakness_entries
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> CAST(:embedding AS vector)
            LIMIT :limit
        """),
        {"embedding": embedding_str, "limit": top_k},
    )
    return [
        {
            "cwe_id": row.cwe_id,
            "name": row.name,
            "description": row.description,
            "is_top_25": row.is_top_25,
            "consequences": row.consequences,
            "distance": row.distance,
        }
        for row in result
        if row.distance is not None and row.distance < _SIMILARITY_DISTANCE_THRESHOLD
    ]


async def _search_cccs(db: AsyncSession, embedding_str: str, top_k: int) -> list[dict]:
    """Semantic search over CCCS advisories."""
    result = await db.execute(
        text("""
            SELECT advisory_id, title, summary, severity, published_date, url,
                   referenced_cves, referenced_attack_ids,
                   embedding <=> CAST(:embedding AS vector) AS distance
            FROM cccs_advisories
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> CAST(:embedding AS vector)
            LIMIT :limit
        """),
        {"embedding": embedding_str, "limit": top_k},
    )
    return [
        {
            "advisory_id": row.advisory_id,
            "title": row.title,
            "summary": row.summary,
            "severity": row.severity,
            "published_date": row.published_date.isoformat()
            if row.published_date
            else None,
            "url": row.url,
            "referenced_cves": row.referenced_cves or [],
            "referenced_attack_ids": row.referenced_attack_ids or [],
            "distance": row.distance,
        }
        for row in result
        if row.distance is not None and row.distance < _SIMILARITY_DISTANCE_THRESHOLD
    ]


async def _lookup_kev(db: AsyncSession, technology_keywords: list[str]) -> list[dict]:
    """Look up KEV entries matching technology keywords."""
    if not technology_keywords:
        return []

    # Build ILIKE conditions for each keyword
    conditions = []
    params = {}
    for i, keyword in enumerate(technology_keywords[:10]):  # Limit to 10 keywords
        param_name = f"kw_{i}"
        conditions.append(
            f"(LOWER(vendor_project) LIKE :{param_name} OR LOWER(product) LIKE :{param_name})"
        )
        params[param_name] = f"%{keyword.lower()}%"

    if not conditions:
        return []

    query = f"""
        SELECT cve_id, vendor_project, product, vulnerability_name,
               date_added, short_description, known_ransomware_use
        FROM kev_entries
        WHERE {" OR ".join(conditions)}
        ORDER BY date_added DESC NULLS LAST
        LIMIT 10
    """

    result = await db.execute(text(query), params)
    return [
        {
            "cve_id": row.cve_id,
            "vendor_project": row.vendor_project,
            "product": row.product,
            "vulnerability_name": row.vulnerability_name,
            "date_added": row.date_added.isoformat() if row.date_added else None,
            "short_description": row.short_description,
            "known_ransomware_use": row.known_ransomware_use,
        }
        for row in result
    ]


async def _lookup_cri(db: AsyncSession, technique_ids: list[str]) -> list[dict]:
    """Look up CRI Profile controls for given ATT&CK technique IDs."""
    if not technique_ids:
        return []

    result = await db.execute(
        select(CRIMapping).where(CRIMapping.attack_technique_id.in_(technique_ids))
    )
    rows = result.scalars().all()

    return [
        {
            "cri_control_id": row.cri_control_id,
            "cri_control_name": row.cri_control_name,
            "cri_function": row.cri_function,
            "attack_technique_id": row.attack_technique_id,
            "mapping_type": row.mapping_type,
        }
        for row in rows
    ]

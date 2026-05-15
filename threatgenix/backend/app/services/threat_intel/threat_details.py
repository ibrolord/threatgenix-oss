"""Per-threat threat intelligence enrichment.

Builds a focused threat-intel payload for a single persisted threat by combining:
- exact references already cited in the threat text
- exact CVE matches from scan evidence
- semantic matches from the local threat-intel store

The response is intentionally additive. It does not override the threat's stored
severity; it exposes external severity signals beside the local severity.
"""

from __future__ import annotations

import logging
import re
from typing import Callable, Iterable, Sequence, TypeVar

from sqlalchemy import or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dfd import DFDNode
from app.models.scan import ScanThreatResult
from app.models.threat import Threat
from app.models.threat_intel import (
    AttackPattern,
    AttackTechnique,
    CCSCAdvisory,
    WeaknessEntry,
)
from app.schemas.threat import (
    ThreatIntelAdvisoryRef,
    ThreatIntelCriControlRef,
    ThreatIntelKevRef,
    ThreatIntelPatternRef,
    ThreatIntelResponse,
    ThreatIntelSeveritySignal,
    ThreatIntelTechniqueRef,
    ThreatIntelWeaknessRef,
)
from app.services.cri_service import (
    extract_attack_ids_from_description,
    lookup_cri_controls,
)
from app.services.kev_service import extract_cve_ids, lookup_kev_by_cve
from app.services.threat_intel.retrieval import retrieve_threat_intel

_CAPEC_ID_RE = re.compile(r"\bCAPEC-\d+\b", re.IGNORECASE)
_CWE_ID_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}
_ItemT = TypeVar("_ItemT")
logger = logging.getLogger(__name__)


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        candidate = value.strip()
        if not candidate:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)
    return deduped


def _extract_capec_ids(text: str) -> list[str]:
    return _dedupe_strings(match.upper() for match in _CAPEC_ID_RE.findall(text))


def _extract_cwe_ids(text: str) -> list[str]:
    return _dedupe_strings(match.upper() for match in _CWE_ID_RE.findall(text))


def _normalize_external_severity(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().casefold()
    if not normalized:
        return None
    if "critical" in normalized or normalized == "very high":
        return "Critical"
    if "high" in normalized:
        return "High"
    if "medium" in normalized or "moderate" in normalized:
        return "Medium"
    if "low" in normalized or normalized == "minor":
        return "Low"
    return None


def _highest_external_severity(
    signals: Sequence[ThreatIntelSeveritySignal],
) -> str | None:
    ranked = [
        signal.normalized_severity
        for signal in signals
        if signal.normalized_severity in _SEVERITY_ORDER
    ]
    if not ranked:
        return None
    return max(ranked, key=lambda value: _SEVERITY_ORDER[value])


def _merge_by_key(
    exact_items: Sequence[_ItemT],
    semantic_items: Sequence[_ItemT],
    key_fn: Callable[[_ItemT], str],
) -> tuple[list[_ItemT], bool]:
    merged: list[_ItemT] = []
    seen: set[str] = set()
    inferred = False

    for item in exact_items:
        key = key_fn(item)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)

    for item in semantic_items:
        key = key_fn(item)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
        inferred = True

    return merged, inferred


async def _load_node_names(db: AsyncSession, threat: Threat) -> list[str]:
    if not threat.affected_node_ids:
        return []
    result = await db.execute(
        select(DFDNode).where(DFDNode.id.in_(threat.affected_node_ids))
    )
    return [node.name for node in result.scalars().all() if getattr(node, "name", None)]


async def _latest_scan_result(db: AsyncSession, threat_id) -> ScanThreatResult | None:
    result = await db.execute(
        select(ScanThreatResult)
        .where(ScanThreatResult.threat_id == threat_id)
        .order_by(
            ScanThreatResult.updated_at.desc(), ScanThreatResult.created_at.desc()
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _fetch_attack_techniques(
    db: AsyncSession,
    technique_ids: Sequence[str],
    *,
    match_type: str,
) -> list[ThreatIntelTechniqueRef]:
    if not technique_ids:
        return []
    try:
        result = await db.execute(
            select(AttackTechnique).where(
                AttackTechnique.technique_id.in_(technique_ids)
            )
        )
    except SQLAlchemyError:
        logger.warning(
            "Failed to fetch ATT&CK techniques for threat intel.", exc_info=True
        )
        return []
    rows = {row.technique_id: row for row in result.scalars().all()}
    return [
        ThreatIntelTechniqueRef(
            technique_id=technique_id,
            name=rows[technique_id].name,
            tactic=rows[technique_id].tactic,
            description=rows[technique_id].description,
            url=rows[technique_id].url,
            match_type=match_type,
        )
        for technique_id in technique_ids
        if technique_id in rows
    ]


async def _fetch_attack_patterns(
    db: AsyncSession,
    capec_ids: Sequence[str],
    *,
    match_type: str,
) -> list[ThreatIntelPatternRef]:
    if not capec_ids:
        return []
    try:
        result = await db.execute(
            select(AttackPattern).where(AttackPattern.capec_id.in_(capec_ids))
        )
    except SQLAlchemyError:
        logger.warning(
            "Failed to fetch CAPEC patterns for threat intel.", exc_info=True
        )
        return []
    rows = {row.capec_id: row for row in result.scalars().all()}
    return [
        ThreatIntelPatternRef(
            capec_id=capec_id,
            name=rows[capec_id].name,
            description=rows[capec_id].description,
            severity=rows[capec_id].severity,
            likelihood=rows[capec_id].likelihood,
            related_cwe_ids=rows[capec_id].related_cwe_ids or [],
            related_attack_ids=rows[capec_id].related_attack_ids or [],
            match_type=match_type,
        )
        for capec_id in capec_ids
        if capec_id in rows
    ]


async def _fetch_weaknesses(
    db: AsyncSession,
    cwe_ids: Sequence[str],
    *,
    match_type: str,
) -> list[ThreatIntelWeaknessRef]:
    if not cwe_ids:
        return []
    try:
        result = await db.execute(
            select(WeaknessEntry).where(WeaknessEntry.cwe_id.in_(cwe_ids))
        )
    except SQLAlchemyError:
        logger.warning(
            "Failed to fetch CWE weaknesses for threat intel.", exc_info=True
        )
        return []
    rows = {row.cwe_id: row for row in result.scalars().all()}
    return [
        ThreatIntelWeaknessRef(
            cwe_id=cwe_id,
            name=rows[cwe_id].name,
            description=rows[cwe_id].description,
            consequences=rows[cwe_id].consequences,
            is_top_25=bool(rows[cwe_id].is_top_25),
            match_type=match_type,
        )
        for cwe_id in cwe_ids
        if cwe_id in rows
    ]


async def _fetch_advisories(
    db: AsyncSession,
    *,
    cve_ids: Sequence[str],
    attack_ids: Sequence[str],
    match_type: str,
) -> list[ThreatIntelAdvisoryRef]:
    conditions = []
    if cve_ids:
        conditions.append(CCSCAdvisory.referenced_cves.overlap(list(cve_ids)))
    if attack_ids:
        conditions.append(CCSCAdvisory.referenced_attack_ids.overlap(list(attack_ids)))
    if not conditions:
        return []

    try:
        result = await db.execute(
            select(CCSCAdvisory)
            .where(or_(*conditions))
            .order_by(CCSCAdvisory.published_date.desc().nullslast())
        )
    except SQLAlchemyError:
        logger.warning(
            "Failed to fetch CCSC advisories for threat intel.", exc_info=True
        )
        return []
    advisories = result.scalars().all()
    return [
        ThreatIntelAdvisoryRef(
            advisory_id=row.advisory_id,
            title=row.title,
            summary=row.summary,
            severity=row.severity,
            url=row.url,
            published_date=row.published_date.isoformat()
            if row.published_date
            else None,
            referenced_cves=row.referenced_cves or [],
            referenced_attack_ids=row.referenced_attack_ids or [],
            match_type=match_type,
        )
        for row in advisories
    ]


def _semantic_attack_refs(rows: Sequence[dict]) -> list[ThreatIntelTechniqueRef]:
    return [
        ThreatIntelTechniqueRef(
            technique_id=row["technique_id"],
            name=row["name"],
            tactic=row["tactic"],
            description=row.get("description"),
            url=row.get("url"),
            match_type="semantic",
        )
        for row in rows
    ]


def _semantic_pattern_refs(rows: Sequence[dict]) -> list[ThreatIntelPatternRef]:
    return [
        ThreatIntelPatternRef(
            capec_id=row["capec_id"],
            name=row["name"],
            description=row.get("description"),
            severity=row.get("severity"),
            likelihood=row.get("likelihood"),
            related_cwe_ids=row.get("related_cwe_ids", []),
            related_attack_ids=row.get("related_attack_ids", []),
            match_type="semantic",
        )
        for row in rows
    ]


def _semantic_weakness_refs(rows: Sequence[dict]) -> list[ThreatIntelWeaknessRef]:
    return [
        ThreatIntelWeaknessRef(
            cwe_id=row["cwe_id"],
            name=row["name"],
            description=row.get("description"),
            consequences=row.get("consequences"),
            is_top_25=bool(row.get("is_top_25")),
            match_type="semantic",
        )
        for row in rows
    ]


def _semantic_advisory_refs(rows: Sequence[dict]) -> list[ThreatIntelAdvisoryRef]:
    return [
        ThreatIntelAdvisoryRef(
            advisory_id=row["advisory_id"],
            title=row["title"],
            summary=row.get("summary"),
            severity=row.get("severity"),
            url=row.get("url"),
            published_date=row.get("published_date"),
            referenced_cves=row.get("referenced_cves", []),
            referenced_attack_ids=row.get("referenced_attack_ids", []),
            match_type="semantic",
        )
        for row in rows
    ]


def _semantic_kev_refs(rows: Sequence[dict]) -> list[ThreatIntelKevRef]:
    return [
        ThreatIntelKevRef(
            cve_id=row["cve_id"],
            vendor_project=row["vendor_project"],
            product=row["product"],
            vulnerability_name=row["vulnerability_name"],
            known_ransomware_use=row.get("known_ransomware_use"),
            date_added=row.get("date_added"),
            match_type="technology_keyword",
        )
        for row in rows
    ]


def _cri_refs(rows: Sequence[dict]) -> list[ThreatIntelCriControlRef]:
    return [
        ThreatIntelCriControlRef(
            cri_control_id=row["cri_control_id"],
            cri_control_name=row["cri_control_name"],
            cri_function=row.get("cri_function") or "",
            mapping_type=row.get("mapping_type") or "",
            attack_technique_id=row["attack_technique_id"],
        )
        for row in rows
    ]


def _build_severity_signals(
    patterns: Sequence[ThreatIntelPatternRef],
    advisories: Sequence[ThreatIntelAdvisoryRef],
    kev_entries: Sequence[ThreatIntelKevRef],
) -> list[ThreatIntelSeveritySignal]:
    signals: list[ThreatIntelSeveritySignal] = []

    for pattern in patterns:
        if not pattern.severity:
            continue
        signals.append(
            ThreatIntelSeveritySignal(
                source="CAPEC",
                label="Typical Severity",
                reference_id=pattern.capec_id,
                value=pattern.severity,
                normalized_severity=_normalize_external_severity(pattern.severity),
                note=f"Likelihood: {pattern.likelihood}"
                if pattern.likelihood
                else None,
            )
        )

    for advisory in advisories:
        if not advisory.severity:
            continue
        signals.append(
            ThreatIntelSeveritySignal(
                source="CCCS",
                label="Advisory Severity",
                reference_id=advisory.advisory_id,
                value=advisory.severity,
                normalized_severity=_normalize_external_severity(advisory.severity),
                note=advisory.title,
            )
        )

    for kev in kev_entries:
        kev_value = (
            "Known exploited and linked to ransomware activity"
            if kev.known_ransomware_use == "Known"
            else "Known exploited in the wild"
        )
        signals.append(
            ThreatIntelSeveritySignal(
                source="CISA KEV",
                label="Active Exploitation",
                reference_id=kev.cve_id,
                value=kev_value,
                normalized_severity=None,
                note=f"{kev.vendor_project} / {kev.product}",
            )
        )

    return signals


async def build_threat_intel_response(
    db: AsyncSession,
    threat: Threat,
    *,
    system_name: str = "",
    system_description: str = "",
    include_semantic_retrieval: bool = True,
) -> ThreatIntelResponse:
    text_parts = [
        threat.threat_subtype or "",
        threat.description or "",
        threat.relevance_rationale or "",
        threat.mitigation_notes or "",
    ]
    combined_text = " ".join(part for part in text_parts if part).strip()

    attack_ids = extract_attack_ids_from_description(combined_text)
    capec_ids = _extract_capec_ids(combined_text)
    cwe_ids = _extract_cwe_ids(combined_text)
    cited_cve_ids = extract_cve_ids(combined_text)

    node_names = await _load_node_names(db, threat)
    scan_result = await _latest_scan_result(db, threat.id)
    scan_cve_ids = _dedupe_strings((scan_result.cve_ids if scan_result else []) or [])
    exact_cve_ids = _dedupe_strings([*scan_cve_ids, *cited_cve_ids])

    exact_attack_refs = await _fetch_attack_techniques(
        db, attack_ids, match_type="exact"
    )
    exact_pattern_refs = await _fetch_attack_patterns(db, capec_ids, match_type="exact")
    exact_weakness_refs = await _fetch_weaknesses(db, cwe_ids, match_type="exact")
    exact_advisory_refs = await _fetch_advisories(
        db,
        cve_ids=exact_cve_ids,
        attack_ids=attack_ids,
        match_type="exact",
    )

    exact_kev_refs = [
        ThreatIntelKevRef(
            cve_id=entry.cve_id,
            vendor_project=entry.vendor_project,
            product=entry.product,
            vulnerability_name=entry.vulnerability_name,
            known_ransomware_use=entry.known_ransomware_use,
            date_added=entry.date_added,
            match_type="scan_cve" if entry.cve_id in scan_cve_ids else "threat_text",
        )
        for entry in await lookup_kev_by_cve(db, exact_cve_ids)
    ]

    semantic_attack_refs: list[ThreatIntelTechniqueRef] = []
    semantic_pattern_refs: list[ThreatIntelPatternRef] = []
    semantic_weakness_refs: list[ThreatIntelWeaknessRef] = []
    semantic_advisory_refs: list[ThreatIntelAdvisoryRef] = []
    semantic_kev_refs: list[ThreatIntelKevRef] = []
    cri_refs: list[ThreatIntelCriControlRef] = []
    unavailable_reason: str | None = None

    # Put threat-specific content first so pgvector retrieval is dominated by the
    # actual threat context, not the shared system name/description that is
    # identical across all threats in a model (which causes every threat to return
    # the same top-K semantic matches).
    stride_prefix = (
        f"STRIDE category: {threat.stride_category}. "
        if threat.stride_category
        else ""
    )
    threat_core = f"{stride_prefix}{combined_text}".strip()
    system_context = " ".join(
        part for part in [system_name, system_description] if part
    )
    query_text = " ".join(
        part
        for part in [
            threat_core,
            *node_names,
            system_context,
        ]
        if part
    )[:3000]

    if query_text and include_semantic_retrieval:
        intel_ctx = await retrieve_threat_intel(
            db,
            query_text,
            top_k_attack=3,
            top_k_capec=3,
            top_k_cwe=3,
            top_k_advisory=3,
            technology_keywords=node_names,
        )
        unavailable_reason = intel_ctx.unavailable_reason
        semantic_attack_refs = _semantic_attack_refs(intel_ctx.attack_techniques)
        semantic_pattern_refs = _semantic_pattern_refs(intel_ctx.attack_patterns)
        semantic_weakness_refs = _semantic_weakness_refs(intel_ctx.weaknesses)
        semantic_advisory_refs = _semantic_advisory_refs(intel_ctx.advisories)
        semantic_kev_refs = _semantic_kev_refs(intel_ctx.kev_matches)
        cri_refs = _cri_refs(intel_ctx.cri_controls)

    if not cri_refs:
        attack_ids_for_cri = _dedupe_strings(
            [*attack_ids, *(ref.technique_id for ref in exact_attack_refs)]
        )
        cri_refs = [
            ThreatIntelCriControlRef(
                cri_control_id=entry.cri_control_id,
                cri_control_name=entry.cri_control_name,
                cri_function=entry.cri_function,
                mapping_type=entry.mapping_type,
                attack_technique_id=entry.attack_technique_id,
            )
            for entry in await lookup_cri_controls(db, attack_ids_for_cri)
        ]

    attack_refs, inferred_attack = _merge_by_key(
        exact_attack_refs,
        semantic_attack_refs,
        lambda item: item.technique_id,
    )
    pattern_refs, inferred_patterns = _merge_by_key(
        exact_pattern_refs,
        semantic_pattern_refs,
        lambda item: item.capec_id,
    )
    weakness_refs, inferred_weaknesses = _merge_by_key(
        exact_weakness_refs,
        semantic_weakness_refs,
        lambda item: item.cwe_id,
    )
    advisory_refs, inferred_advisories = _merge_by_key(
        exact_advisory_refs,
        semantic_advisory_refs,
        lambda item: item.advisory_id,
    )
    kev_refs, inferred_kev = _merge_by_key(
        exact_kev_refs,
        semantic_kev_refs,
        lambda item: item.cve_id,
    )

    severity_signals = _build_severity_signals(pattern_refs, advisory_refs, kev_refs)

    return ThreatIntelResponse(
        local_severity=threat.severity,
        highest_external_severity=_highest_external_severity(severity_signals),
        semantic_matches_inferred=any(
            [
                inferred_attack,
                inferred_patterns,
                inferred_weaknesses,
                inferred_advisories,
                inferred_kev,
            ]
        ),
        unavailable_reason=unavailable_reason,
        scan_cve_ids=scan_cve_ids,
        severity_signals=severity_signals,
        attack_techniques=attack_refs,
        attack_patterns=pattern_refs,
        weaknesses=weakness_refs,
        advisories=advisory_refs,
        kev_entries=kev_refs,
        cri_controls=cri_refs,
    )

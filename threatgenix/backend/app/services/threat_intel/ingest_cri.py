"""Ingest CRI Profile v2.1 → ATT&CK technique mappings.

Source: MITRE Center for Threat-Informed Defense Mappings Explorer
Format: JSON (machine-readable mapping data)
Update frequency: On new CRI Profile / ATT&CK releases

This is the competitive differentiator: no other threat modeling tool maps
threats to CRI Profile controls used by Canadian financial institutions.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intel import CRIMapping

logger = logging.getLogger(__name__)

# MITRE CTID Mappings Explorer data endpoint for CRI Profile
# The mapping data is hosted on the CTID GitHub pages
CRI_MAPPINGS_BASE_URL = (
    "https://center-for-threat-informed-defense.github.io/"
    "mappings-explorer/external/cri_profile/"
)

# Hardcoded seed data for CRI Profile → ATT&CK mappings
# These are the highest-priority mappings for Canadian banking threat models.
# Source: MITRE CTID CRI Profile to ATT&CK v16.1 mapping (June 2025)
#
# Full dataset should be loaded from the CTID API when available.
# For now, we seed the most critical mappings that ThreatGenix needs.
CRI_SEED_MAPPINGS: list[tuple[str, str, str, str, str]] = [
    # (cri_control_id, cri_control_name, cri_function, attack_technique_id, mapping_type)

    # Identity & Access Management
    ("GV.ID-01", "Asset inventory is maintained", "Govern", "T1078", "mitigates"),
    ("GV.ID-01", "Asset inventory is maintained", "Govern", "T1133", "mitigates"),
    ("PR.AA-01", "Identities and credentials are managed", "Protect", "T1078", "mitigates"),
    ("PR.AA-01", "Identities and credentials are managed", "Protect", "T1110", "mitigates"),
    ("PR.AA-01", "Identities and credentials are managed", "Protect", "T1556", "mitigates"),
    ("PR.AA-02", "Access is managed and protected", "Protect", "T1078", "mitigates"),
    ("PR.AA-02", "Access is managed and protected", "Protect", "T1021", "mitigates"),
    ("PR.AA-03", "Identity proofing is performed", "Protect", "T1078", "mitigates"),
    ("PR.AA-03", "Identity proofing is performed", "Protect", "T1566", "mitigates"),
    ("PR.AA-05", "Access permissions are managed", "Protect", "T1098", "mitigates"),
    ("PR.AA-05", "Access permissions are managed", "Protect", "T1548", "mitigates"),

    # Data Security
    ("PR.DS-01", "Data-at-rest is protected", "Protect", "T1005", "mitigates"),
    ("PR.DS-01", "Data-at-rest is protected", "Protect", "T1530", "mitigates"),
    ("PR.DS-01", "Data-at-rest is protected", "Protect", "T1565", "mitigates"),
    ("PR.DS-02", "Data-in-transit is protected", "Protect", "T1557", "mitigates"),
    ("PR.DS-02", "Data-in-transit is protected", "Protect", "T1040", "mitigates"),
    ("PR.DS-10", "Data confidentiality is maintained", "Protect", "T1048", "mitigates"),
    ("PR.DS-10", "Data confidentiality is maintained", "Protect", "T1567", "mitigates"),

    # Platform Security
    ("PR.PS-01", "Configuration management practices are established", "Protect", "T1574", "mitigates"),
    ("PR.PS-01", "Configuration management practices are established", "Protect", "T1195", "mitigates"),
    ("PR.PS-02", "Software is maintained and replaced", "Protect", "T1190", "mitigates"),
    ("PR.PS-02", "Software is maintained and replaced", "Protect", "T1203", "mitigates"),
    ("PR.PS-04", "Log records are generated and available", "Protect", "T1070", "detects"),
    ("PR.PS-04", "Log records are generated and available", "Protect", "T1562", "detects"),

    # Technology Infrastructure Resilience
    ("PR.IR-01", "Networks and environments are protected", "Protect", "T1046", "mitigates"),
    ("PR.IR-01", "Networks and environments are protected", "Protect", "T1570", "mitigates"),
    ("PR.IR-01", "Networks and environments are protected", "Protect", "T1071", "mitigates"),
    ("PR.IR-04", "Adequate resource capacity is maintained", "Protect", "T1498", "mitigates"),
    ("PR.IR-04", "Adequate resource capacity is maintained", "Protect", "T1499", "mitigates"),

    # Detection & Monitoring
    ("DE.CM-01", "Networks are monitored for threats", "Detect", "T1071", "detects"),
    ("DE.CM-01", "Networks are monitored for threats", "Detect", "T1572", "detects"),
    ("DE.CM-01", "Networks are monitored for threats", "Detect", "T1090", "detects"),
    ("DE.CM-02", "Physical environment is monitored", "Detect", "T1200", "detects"),
    ("DE.CM-03", "Personnel activity is monitored", "Detect", "T1078", "detects"),
    ("DE.CM-03", "Personnel activity is monitored", "Detect", "T1098", "detects"),
    ("DE.CM-06", "External service provider activities are monitored", "Detect", "T1199", "detects"),
    ("DE.CM-09", "Computing hardware and software are monitored", "Detect", "T1204", "detects"),
    ("DE.CM-09", "Computing hardware and software are monitored", "Detect", "T1059", "detects"),

    # Adverse Event Analysis
    ("DE.AE-02", "Potentially adverse events are analyzed", "Detect", "T1486", "detects"),
    ("DE.AE-02", "Potentially adverse events are analyzed", "Detect", "T1490", "detects"),
    ("DE.AE-03", "Events are correlated from multiple sources", "Detect", "T1562", "detects"),

    # Incident Response
    ("RS.MA-01", "Incident response plan is executed", "Respond", "T1486", "mitigates"),
    ("RS.AN-03", "Analysis is performed to establish impact", "Respond", "T1657", "detects"),
    ("RS.AN-03", "Analysis is performed to establish impact", "Respond", "T1531", "detects"),

    # Recovery
    ("RC.RP-01", "Recovery plan is executed", "Recover", "T1486", "mitigates"),
    ("RC.RP-01", "Recovery plan is executed", "Recover", "T1490", "mitigates"),
    ("RC.RP-03", "Integrity of backups and assets is verified", "Recover", "T1490", "mitigates"),

    # Financial-sector specific ATT&CK techniques
    ("PR.AA-01", "Identities and credentials are managed", "Protect", "T1657", "mitigates"),
    ("DE.CM-01", "Networks are monitored for threats", "Detect", "T1657", "detects"),
    ("PR.DS-02", "Data-in-transit is protected", "Protect", "T1657", "mitigates"),

    # Supply chain
    ("GV.SC-01", "Cyber supply chain risk management is established", "Govern", "T1195", "mitigates"),
    ("GV.SC-02", "Suppliers are assessed and prioritized", "Govern", "T1199", "mitigates"),
    ("GV.SC-05", "Supply chain requirements are integrated into contracts", "Govern", "T1195", "mitigates"),

    # Risk Assessment
    ("GV.RM-01", "Risk management strategy is established", "Govern", "T1190", "mitigates"),
    ("GV.RM-02", "Risk appetite and tolerance are established", "Govern", "T1190", "mitigates"),
    ("ID.RA-01", "Vulnerabilities in assets are identified", "Identify", "T1190", "detects"),
    ("ID.RA-01", "Vulnerabilities in assets are identified", "Identify", "T1203", "detects"),
    ("ID.RA-02", "Threat intelligence is received", "Identify", "T1595", "detects"),
    ("ID.RA-02", "Threat intelligence is received", "Identify", "T1592", "detects"),
]


async def ingest_cri(db: AsyncSession) -> int:
    """Ingest CRI Profile → ATT&CK mappings.

    Currently uses seed data. Will be updated to pull from CTID API
    when machine-readable endpoint is available.

    Args:
        db: Async database session.

    Returns:
        Number of mappings ingested.
    """
    from app.services.threat_intel.ingest_attack import _get_or_create_sync

    sync_record = await _get_or_create_sync(db, "cri")
    sync_record.status = "syncing"
    await db.commit()

    try:
        count = 0
        for cri_id, cri_name, cri_func, attack_id, map_type in CRI_SEED_MAPPINGS:
            existing = await db.execute(
                select(CRIMapping).where(
                    CRIMapping.cri_control_id == cri_id,
                    CRIMapping.attack_technique_id == attack_id,
                )
            )
            row = existing.scalars().first()

            if row:
                row.cri_control_name = cri_name
                row.cri_function = cri_func
                row.mapping_type = map_type
            else:
                db.add(CRIMapping(
                    cri_control_id=cri_id,
                    cri_control_name=cri_name,
                    cri_function=cri_func,
                    attack_technique_id=attack_id,
                    mapping_type=map_type,
                ))
            count += 1

        await db.commit()

        sync_record.status = "complete"
        sync_record.last_sync_at = datetime.now(timezone.utc)
        sync_record.record_count = count
        sync_record.version = "CRI Profile v2.1 / ATT&CK v16.1"
        sync_record.error_message = None
        await db.commit()

        logger.info("CRI Profile ingestion complete: %d mappings", count)
        return count

    except Exception as exc:
        sync_record.status = "error"
        sync_record.error_message = str(exc)[:500]
        await db.commit()
        logger.error("CRI Profile ingestion failed: %s", exc)
        raise

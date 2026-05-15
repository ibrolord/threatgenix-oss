"""CRI Profile lookup service — Layer 3 deterministic compliance mapping.

Given ATT&CK technique IDs from a threat's citations, returns the
CRI Profile controls that mitigate/detect those techniques.

This is what makes ThreatGenix unique for Canadian financial institutions:
no other threat modeling tool maps threats to CRI Profile controls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intel import CRIMapping


@dataclass
class CRIControlRef:
    """A CRI Profile control reference."""
    cri_control_id: str
    cri_control_name: str
    cri_function: str  # Govern, Identify, Protect, Detect, Respond, Recover
    mapping_type: str  # mitigates, detects
    attack_technique_id: str


# Regex to extract ATT&CK technique IDs from threat descriptions
ATTACK_ID_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")


def extract_attack_ids_from_description(description: str) -> list[str]:
    """Extract ATT&CK technique IDs mentioned in a threat description."""
    return list(set(ATTACK_ID_PATTERN.findall(description)))


async def lookup_cri_controls(
    db: AsyncSession,
    attack_technique_ids: list[str],
) -> list[CRIControlRef]:
    """Look up CRI Profile controls for given ATT&CK technique IDs.

    Args:
        db: Async database session.
        attack_technique_ids: List of ATT&CK technique IDs (e.g., ["T1657", "T1078"]).

    Returns:
        List of CRI controls that mitigate/detect the given techniques.
    """
    if not attack_technique_ids:
        return []

    result = await db.execute(
        select(CRIMapping).where(
            CRIMapping.attack_technique_id.in_(attack_technique_ids)
        )
    )
    rows = result.scalars().all()

    return [
        CRIControlRef(
            cri_control_id=row.cri_control_id,
            cri_control_name=row.cri_control_name,
            cri_function=row.cri_function or "",
            mapping_type=row.mapping_type or "",
            attack_technique_id=row.attack_technique_id,
        )
        for row in rows
    ]


async def lookup_cri_controls_for_threat(
    db: AsyncSession,
    threat_description: str,
) -> list[CRIControlRef]:
    """Extract ATT&CK IDs from a threat description and look up CRI controls.

    This is the convenience function used during PDF report generation
    and compliance coverage endpoints.
    """
    attack_ids = extract_attack_ids_from_description(threat_description)
    if not attack_ids:
        return []
    return await lookup_cri_controls(db, attack_ids)

"""Threat qualification scorer (v2).

Computes a 0-100 integer score per GeneratedThreat that reflects how much
attention the threat deserves given the system context. Higher = investigate first.

Score formula (additive, clamped to 100):
    severity_pts          Critical=40, High=30, Medium=20, Low=10
    data_class_pts        Restricted=+20, Confidential=+10, Internal=+5, Public=0
    boundary_pts          crosses trust boundary=+15
    node_type_pts         best node type across affected nodes:
                              data_store=+10, process=+5, external_entity=0
    source_pts            AI+Rules=+5, AI=+3, Rules=0
    stride_pts            InfoDisclosure=+5, Repudiation=+5, EoP=+3,
                              Tampering=+3, Spoofing=+2, DoS=0
    subtype_pts           description contains banking-regulated keyword=+10
                              (only applied when source is Rules/AI+Rules to avoid
                               noisy free-text AI prose triggering false bonuses)

v2 additions (F-06 node properties + scan/intel signals):
    node_property_pts     F-06 property signals (see _node_property_pts)
    scan_pts              scan_status=confirmed=+15, mitigated=-10
    kev_pts               KEV active exploitation=+12
    controls_pts          zero compliance controls mapped=+5

Max theoretical before clamp: 40+20+15+10+5+5+10+28+15+12+5 = 165 → clamped to 100.
"""

from __future__ import annotations

from app.schemas.dfd import DFDResponse
from app.schemas.rules import GeneratedThreat

# ── Lookup tables ────────────────────────────────────────────────────────────

_SEVERITY_PTS: dict[str, int] = {
    "Critical": 40,
    "High": 30,
    "Medium": 20,
    "Low": 10,
}

_DATA_CLASS_PTS: dict[str, int] = {
    "Restricted": 20,
    "Confidential": 10,
    "Internal": 5,
    "Public": 0,
}

_NODE_TYPE_PTS: dict[str, int] = {
    "data_store": 10,
    "process": 5,
    "external_entity": 0,
}

_SOURCE_PTS: dict[str, int] = {
    "AI+Rules": 5,
    "AI": 3,
    "Rules": 0,
}

_STRIDE_PTS: dict[str, int] = {
    "Information Disclosure": 5,
    "Repudiation": 5,
    "Elevation of Privilege": 3,
    "Tampering": 3,
    "Spoofing": 2,
    "Denial of Service": 0,
}

# Keywords that indicate a threat touches a regulated banking asset.
# Only applied when threat source is Rules or AI+Rules (controlled threat_subtype).
_REGULATED_KEYWORDS = frozenset([
    "pci", "osfi", "cardholder", "cde", "pipeda", "fintrac", "swift",
    "financial", "payment", "transaction", "aml", "kyc",
])


def _best_node_type_pts(affected_node_ids: list[str], dfd: DFDResponse) -> int:
    """Return the highest node_type score across all affected nodes.

    Falls back to 0 if no affected nodes or none are found in the DFD.
    """
    if not affected_node_ids:
        return 0
    node_map = {str(n.id): n for n in dfd.nodes}
    best = 0
    for nid in affected_node_ids:
        node = node_map.get(nid)
        if node is not None:
            pts = _NODE_TYPE_PTS.get(node.node_type, 0)
            if pts > best:
                best = pts
    return best


def _crosses_boundary(threat: GeneratedThreat, dfd: DFDResponse) -> bool:
    """Determine if a threat crosses a trust boundary.

    For rule threats: use the pre-computed flag on GeneratedThreat.
    For AI threats (crosses_trust_boundary=False by default): compute from
    DFD topology — check if any edge between affected nodes crosses a boundary.
    """
    if threat.crosses_trust_boundary:
        return True

    # AI threats: infer from DFD topology
    if not threat.affected_node_ids or not dfd.trust_boundaries:
        return False

    affected_set = set(threat.affected_node_ids)
    for boundary in dfd.trust_boundaries:
        boundary_ids = {str(nid) for nid in boundary.node_ids}
        for edge in dfd.edges:
            src = str(edge.source_node_id)
            tgt = str(edge.target_node_id)
            if src in affected_set and tgt in affected_set:
                # edge connects two of this threat's nodes
                if (src in boundary_ids) != (tgt in boundary_ids):
                    return True
    return False


def _regulated_keyword_pts(threat: GeneratedThreat) -> int:
    """Return +10 if the threat description mentions a regulated banking keyword.

    Only applied to Rules and AI+Rules threats where threat_subtype is a
    controlled value. Pure AI threats use free-form prose that can incidentally
    contain words like 'payment' or 'transaction', producing false +10 swings.
    """
    if threat.source not in ("Rules", "AI+Rules"):
        return 0
    desc_lower = threat.description.lower()
    subtype_lower = (threat.threat_subtype or "").lower()
    combined = desc_lower + " " + subtype_lower
    for kw in _REGULATED_KEYWORDS:
        if kw in combined:
            return 10
    return 0


def _node_property_pts(affected_node_ids: list[str], dfd: DFDResponse) -> int:
    """Score adjustments based on F-06 element properties.

    Uses the normalized property keys that the DFD API actually materializes:
      uses_auth, validates_input, encrypted_at_rest, internet_facing,
      handles_sensitive_data, stores_credentials.

    A node with no properties dict (None or empty) contributes 0 — we don't
    penalise threats where the analyst hasn't set properties yet.

    Suppression credit: if every affected node has both uses_auth=True AND
    validates_input=True, deduct 5 pts (analyst asserted controls are present).
    """
    if not affected_node_ids:
        return 0

    node_map = {str(n.id): n for n in dfd.nodes}
    pts = 0
    internet_facing_counted = False
    all_have_auth = True
    all_have_validation = True
    any_node_found = False

    for nid in affected_node_ids:
        node = node_map.get(nid)
        if node is None:
            continue
        props: dict = node.properties or {}
        if not props:
            # No properties set — skip suppression tracking for this node
            all_have_auth = False
            all_have_validation = False
            continue

        any_node_found = True

        # internet_facing: only count once (avoid double-counting multi-node threats)
        if not internet_facing_counted and props.get("internet_facing") is True:
            pts += 7
            internet_facing_counted = True

        # stores_credentials: always additive per node (each store is a risk)
        if props.get("stores_credentials") is True:
            pts += 8

        # uses_auth: False means no auth on this node
        auth_val = props.get("uses_auth")
        if auth_val is False:
            pts += 8
            all_have_auth = False
        elif auth_val is not True:
            # Not set — don't grant suppression credit
            all_have_auth = False

        # validates_input: False means no input validation
        validation_val = props.get("validates_input")
        if validation_val is False:
            pts += 5
            all_have_validation = False
        elif validation_val is not True:
            all_have_validation = False

        # No encryption on a node that handles sensitive data
        if props.get("handles_sensitive_data") is True and props.get("encrypted_at_rest") is False:
            pts += 5

    # Suppression credit: analyst confirmed auth + validation across all found nodes
    if any_node_found and all_have_auth and all_have_validation:
        pts -= 5

    return pts


def blend_scores(auto_score: int, analyst_score: int) -> int:
    """Blend auto and analyst scores: 40% auto, 60% analyst, clamped 0-100."""
    return min(100, max(0, round(auto_score * 0.4 + analyst_score * 0.6)))


def compute_qualification_score(
    threat: GeneratedThreat,
    data_classification: str,
    dfd: DFDResponse,
    scan_status: str | None = None,
    has_kev: bool = False,
    has_compliance_controls: bool = True,
) -> int:
    """Compute and return the 0-100 auto qualification score for a single threat.

    Args:
        threat: The generated threat (from rules engine or AI merger).
        data_classification: The threat model's data classification string.
        dfd: The full DFD, used to resolve node types and boundary topology
             for AI threats that lack structured attribution.
        scan_status: Latest scan result status for this threat ('confirmed',
                     'potential', 'mitigated', or None if no scan data).
        has_kev: True if this threat has matching KEV entries (active exploitation).
        has_compliance_controls: False if no NIST/OSFI/PCI/ISO controls are
                                 mapped to this threat's STRIDE+subtype.

    Returns:
        Integer score 0-100. Higher = investigate first.
        This is the auto_score; qualification_score = blend(auto_score, analyst_score).
    """
    score = 0
    score += _SEVERITY_PTS.get(threat.severity, 0)
    score += _DATA_CLASS_PTS.get(data_classification, 0)
    score += 15 if _crosses_boundary(threat, dfd) else 0
    score += _best_node_type_pts(threat.affected_node_ids, dfd)
    score += _SOURCE_PTS.get(threat.source, 0)
    score += _STRIDE_PTS.get(threat.stride_category, 0)
    score += _regulated_keyword_pts(threat)

    # v2: F-06 node property signals
    score += _node_property_pts(threat.affected_node_ids, dfd)

    # v2: Scan confirmation signals — use latest scan result
    if scan_status == "confirmed":
        score += 15
    elif scan_status == "mitigated":
        score -= 10

    # v2: Active exploitation in the wild
    if has_kev:
        score += 12

    # v2: No regulatory controls mapped = uncontrolled risk
    if not has_compliance_controls:
        score += 5

    return min(max(score, 0), 100)

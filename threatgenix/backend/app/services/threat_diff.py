"""Pure-function threat diff engine for Copilot Seed (C-01).

Compares two lists of threat dicts (baseline vs current) and returns
added/removed summaries keyed by threat identity.

Threat identity = (rule_id, tuple(sorted(affected_node_ids)))
"""

from __future__ import annotations


def _threat_key(threat: dict) -> tuple[str, tuple[str, ...]]:
    """Return the identity key for a threat dict."""
    rule_id = threat.get("rule_id", "")
    node_ids = threat.get("affected_node_ids", [])
    return (rule_id, tuple(sorted(str(nid) for nid in node_ids)))


def _summarize(threat: dict) -> dict:
    """Return a compact summary of a threat for the diff response."""
    description = threat.get("description", "")
    return {
        "rule_id": threat.get("rule_id", ""),
        "stride_category": threat.get("stride_category", ""),
        "severity": threat.get("severity", ""),
        "description_snippet": description[:80],
    }


def diff_threat_lists(
    baseline: list[dict],
    current: list[dict],
) -> dict:
    """Compare baseline (last /analyze snapshot) to current rule-engine output.

    Parameters
    ----------
    baseline : list[dict]
        Serialized GeneratedThreat dicts from last analysis.
    current : list[dict]
        Serialized GeneratedThreat dicts from current rule-engine run.

    Returns
    -------
    dict with keys:
        added   - list of summary dicts for threats in current but not baseline
        removed - list of summary dicts for threats in baseline but not current
        counts  - {"added": N, "removed": N, "total_before": N, "total_after": N}
    """
    baseline_keys = {_threat_key(t) for t in baseline}
    current_keys = {_threat_key(t) for t in current}

    # Map keys back to their threat dicts for summary extraction
    current_by_key = {_threat_key(t): t for t in current}
    baseline_by_key = {_threat_key(t): t for t in baseline}

    added_keys = current_keys - baseline_keys
    removed_keys = baseline_keys - current_keys

    added = [_summarize(current_by_key[k]) for k in sorted(added_keys)]
    removed = [_summarize(baseline_by_key[k]) for k in sorted(removed_keys)]

    return {
        "added": added,
        "removed": removed,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "total_before": len(baseline),
            "total_after": len(current),
        },
    }

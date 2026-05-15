"""Unit tests for the threat diff engine (C-01)."""

from __future__ import annotations


from app.services.threat_diff import diff_threat_lists


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_threat(
    rule_id: str,
    node_ids: list[str],
    *,
    stride_category: str = "Spoofing",
    severity: str = "High",
    description: str = "Some threat description that is fairly long and should be truncated in the snippet",
    threat_subtype: str = "subtype",
    edge_ids: list[str] | None = None,
) -> dict:
    return {
        "rule_id": rule_id,
        "stride_category": stride_category,
        "severity": severity,
        "description": description,
        "threat_subtype": threat_subtype,
        "affected_node_ids": node_ids,
        "affected_edge_ids": edge_ids or [],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDiffThreatLists:
    def test_empty_baseline(self):
        """First analysis: all threats are 'added', none removed."""
        current = [
            _make_threat("R-001", ["node-a"]),
            _make_threat("R-002", ["node-b", "node-c"]),
        ]
        result = diff_threat_lists([], current)

        assert result["counts"]["added"] == 2
        assert result["counts"]["removed"] == 0
        assert result["counts"]["total_before"] == 0
        assert result["counts"]["total_after"] == 2
        assert len(result["added"]) == 2
        assert len(result["removed"]) == 0

    def test_identical_lists(self):
        """No changes when baseline and current are identical."""
        threats = [
            _make_threat("R-001", ["node-a"]),
            _make_threat("R-002", ["node-b", "node-c"]),
        ]
        result = diff_threat_lists(threats, threats)

        assert result["counts"]["added"] == 0
        assert result["counts"]["removed"] == 0
        assert result["counts"]["total_before"] == 2
        assert result["counts"]["total_after"] == 2
        assert result["added"] == []
        assert result["removed"] == []

    def test_added_threats(self):
        """New node creates new threats that appear in 'added'."""
        baseline = [
            _make_threat("R-001", ["node-a"]),
        ]
        current = [
            _make_threat("R-001", ["node-a"]),
            _make_threat("R-001", ["node-a", "node-new"]),
            _make_threat("R-003", ["node-new"]),
        ]
        result = diff_threat_lists(baseline, current)

        assert result["counts"]["added"] == 2
        assert result["counts"]["removed"] == 0
        assert result["counts"]["total_before"] == 1
        assert result["counts"]["total_after"] == 3
        added_rule_ids = {t["rule_id"] for t in result["added"]}
        assert "R-001" in added_rule_ids
        assert "R-003" in added_rule_ids

    def test_removed_threats(self):
        """Deleted node removes threats that appear in 'removed'."""
        baseline = [
            _make_threat("R-001", ["node-a"]),
            _make_threat("R-002", ["node-b"]),
            _make_threat("R-003", ["node-c"]),
        ]
        current = [
            _make_threat("R-001", ["node-a"]),
        ]
        result = diff_threat_lists(baseline, current)

        assert result["counts"]["added"] == 0
        assert result["counts"]["removed"] == 2
        assert result["counts"]["total_before"] == 3
        assert result["counts"]["total_after"] == 1
        removed_rule_ids = {t["rule_id"] for t in result["removed"]}
        assert "R-002" in removed_rule_ids
        assert "R-003" in removed_rule_ids

    def test_mixed_changes(self):
        """Some threats added, some removed, some unchanged."""
        baseline = [
            _make_threat("R-001", ["node-a"]),
            _make_threat("R-002", ["node-b"]),
            _make_threat("R-003", ["node-c"]),
        ]
        current = [
            _make_threat("R-001", ["node-a"]),  # unchanged
            _make_threat("R-003", ["node-c"]),  # unchanged
            _make_threat("R-004", ["node-d"]),  # added
            _make_threat("R-005", ["node-a", "node-d"]),  # added
        ]
        result = diff_threat_lists(baseline, current)

        assert result["counts"]["added"] == 2
        assert result["counts"]["removed"] == 1
        assert result["counts"]["total_before"] == 3
        assert result["counts"]["total_after"] == 4

        added_rule_ids = {t["rule_id"] for t in result["added"]}
        assert added_rule_ids == {"R-004", "R-005"}

        removed_rule_ids = {t["rule_id"] for t in result["removed"]}
        assert removed_rule_ids == {"R-002"}

    def test_property_change_mitigates(self):
        """Setting uses_auth on a node removes its auth-related threat.

        Simulates a scenario where a node property change causes the rules
        engine to no longer fire a specific rule for that node, so the
        threat disappears from the current list.
        """
        # Baseline: node without auth generates an auth threat
        baseline = [
            _make_threat("R-AUTH-001", ["node-api-gateway"], stride_category="Spoofing"),
            _make_threat("R-DOS-001", ["node-api-gateway"], stride_category="Denial of Service"),
        ]
        # After user sets uses_auth=true, the auth threat no longer fires
        current = [
            _make_threat("R-DOS-001", ["node-api-gateway"], stride_category="Denial of Service"),
        ]
        result = diff_threat_lists(baseline, current)

        assert result["counts"]["added"] == 0
        assert result["counts"]["removed"] == 1
        assert result["counts"]["total_before"] == 2
        assert result["counts"]["total_after"] == 1

        assert len(result["removed"]) == 1
        assert result["removed"][0]["rule_id"] == "R-AUTH-001"
        assert result["removed"][0]["stride_category"] == "Spoofing"

    def test_description_snippet_truncated(self):
        """Description in summary is truncated to 80 chars."""
        long_desc = "A" * 200
        current = [_make_threat("R-001", ["node-a"], description=long_desc)]
        result = diff_threat_lists([], current)

        assert len(result["added"]) == 1
        assert len(result["added"][0]["description_snippet"]) == 80

    def test_node_id_order_irrelevant(self):
        """Threat identity ignores the order of affected_node_ids."""
        baseline = [_make_threat("R-001", ["node-b", "node-a"])]
        current = [_make_threat("R-001", ["node-a", "node-b"])]
        result = diff_threat_lists(baseline, current)

        assert result["counts"]["added"] == 0
        assert result["counts"]["removed"] == 0

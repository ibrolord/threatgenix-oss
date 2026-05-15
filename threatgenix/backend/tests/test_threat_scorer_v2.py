"""Tests for threat_scorer.py v2 — F-06 property signals, scan/KEV boosts, blend."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock


from app.services.threat_scorer import (
    blend_scores,
    compute_qualification_score,
    _node_property_pts,
)
from app.schemas.rules import GeneratedThreat


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_node(node_id: str, node_type: str = "process", properties: dict | None = None):
    node = MagicMock()
    node.id = uuid.UUID(node_id)
    node.node_type = node_type
    node.properties = properties or {}
    return node


def _make_dfd(nodes=None, edges=None, trust_boundaries=None):
    dfd = MagicMock()
    dfd.nodes = nodes or []
    dfd.edges = edges or []
    dfd.trust_boundaries = trust_boundaries or []
    return dfd


def _make_threat(
    severity="High",
    stride_category="Information Disclosure",
    source="Rules",
    threat_subtype="SQL Injection",
    affected_node_ids=None,
    affected_edge_ids=None,
    crosses_trust_boundary=False,
    description="Test threat description",
):
    t = MagicMock(spec=GeneratedThreat)
    t.severity = severity
    t.stride_category = stride_category
    t.source = source
    t.threat_subtype = threat_subtype
    t.affected_node_ids = affected_node_ids or []
    t.affected_edge_ids = affected_edge_ids or []
    t.crosses_trust_boundary = crosses_trust_boundary
    t.description = description
    return t


NODE_ID = "00000000-0000-0000-0000-000000000001"


# ── blend_scores ─────────────────────────────────────────────────────────────

class TestBlendScores:
    def test_pure_auto_no_analyst(self):
        # Without analyst score, caller uses auto directly
        assert blend_scores(75, 0) == 30  # 75*0.4 + 0*0.6 = 30

    def test_equal_weight(self):
        assert blend_scores(50, 50) == 50

    def test_analyst_dominates(self):
        # 40*0.4 + 80*0.6 = 16 + 48 = 64
        assert blend_scores(40, 80) == 64

    def test_clamp_max(self):
        assert blend_scores(100, 100) == 100

    def test_clamp_min(self):
        assert blend_scores(0, 0) == 0

    def test_rounding(self):
        # 33*0.4 + 50*0.6 = 13.2 + 30 = 43.2 → rounds to 43
        assert blend_scores(33, 50) == 43


# ── _node_property_pts ───────────────────────────────────────────────────────

class TestNodePropertyPts:
    def test_no_nodes_returns_zero(self):
        dfd = _make_dfd()
        assert _node_property_pts([], dfd) == 0

    def test_node_not_in_dfd_returns_zero(self):
        dfd = _make_dfd(nodes=[])
        assert _node_property_pts([NODE_ID], dfd) == 0

    def test_internet_facing_adds_7(self):
        node = _make_node(NODE_ID, properties={"internet_facing": True, "uses_auth": True, "validates_input": True})
        dfd = _make_dfd(nodes=[node])
        pts = _node_property_pts([NODE_ID], dfd)
        # internet_facing=7, suppression credit=-5 (all auth+validation) = 2
        assert pts == 2

    def test_internet_facing_counted_once_across_multiple_nodes(self):
        n1 = _make_node(NODE_ID, properties={"internet_facing": True})
        n2_id = "00000000-0000-0000-0000-000000000002"
        n2 = _make_node(n2_id, properties={"internet_facing": True})
        dfd = _make_dfd(nodes=[n1, n2])
        pts = _node_property_pts([NODE_ID, n2_id], dfd)
        # Only 7 once, no auth/validation so no suppression
        assert pts == 7

    def test_stores_credentials_adds_8(self):
        node = _make_node(NODE_ID, "data_store", properties={"stores_credentials": True})
        dfd = _make_dfd(nodes=[node])
        assert _node_property_pts([NODE_ID], dfd) == 8

    def test_no_auth_adds_8(self):
        node = _make_node(NODE_ID, properties={"uses_auth": False})
        dfd = _make_dfd(nodes=[node])
        assert _node_property_pts([NODE_ID], dfd) == 8

    def test_no_validation_adds_5(self):
        node = _make_node(NODE_ID, properties={"validates_input": False})
        dfd = _make_dfd(nodes=[node])
        assert _node_property_pts([NODE_ID], dfd) == 5

    def test_sensitive_data_no_encryption_adds_5(self):
        node = _make_node(NODE_ID, properties={
            "handles_sensitive_data": True,
            "encrypted_at_rest": False,
        })
        dfd = _make_dfd(nodes=[node])
        assert _node_property_pts([NODE_ID], dfd) == 5

    def test_suppression_credit_when_all_secured(self):
        node = _make_node(NODE_ID, properties={
            "uses_auth": True,
            "validates_input": True,
        })
        dfd = _make_dfd(nodes=[node])
        assert _node_property_pts([NODE_ID], dfd) == -5

    def test_no_suppression_credit_when_properties_absent(self):
        # Empty properties dict → no suppression (analyst hasn't set anything)
        node = _make_node(NODE_ID, properties={})
        dfd = _make_dfd(nodes=[node])
        assert _node_property_pts([NODE_ID], dfd) == 0

    def test_mixed_nodes_no_suppression(self):
        # One node has auth, other doesn't → no suppression credit
        n2_id = "00000000-0000-0000-0000-000000000002"
        n1 = _make_node(NODE_ID, properties={"uses_auth": True, "validates_input": True})
        n2 = _make_node(n2_id, properties={"uses_auth": False, "validates_input": True})
        dfd = _make_dfd(nodes=[n1, n2])
        pts = _node_property_pts([NODE_ID, n2_id], dfd)
        # n2 no auth = +8, no suppression
        assert pts == 8


# ── compute_qualification_score (v2 signals) ─────────────────────────────────

class TestComputeQualificationScoreV2:
    def _base_threat(self):
        return _make_threat(severity="High", stride_category="Information Disclosure", source="Rules")

    def _empty_dfd(self):
        return _make_dfd()

    def test_scan_confirmed_adds_15(self):
        t = self._base_threat()
        dfd = self._empty_dfd()
        base = compute_qualification_score(t, "Confidential", dfd)
        with_scan = compute_qualification_score(t, "Confidential", dfd, scan_status="confirmed")
        assert with_scan == min(base + 15, 100)

    def test_scan_mitigated_subtracts_10(self):
        t = self._base_threat()
        dfd = self._empty_dfd()
        base = compute_qualification_score(t, "Confidential", dfd)
        with_scan = compute_qualification_score(t, "Confidential", dfd, scan_status="mitigated")
        assert with_scan == max(base - 10, 0)

    def test_kev_adds_12(self):
        t = self._base_threat()
        dfd = self._empty_dfd()
        base = compute_qualification_score(t, "Confidential", dfd)
        with_kev = compute_qualification_score(t, "Confidential", dfd, has_kev=True)
        assert with_kev == min(base + 12, 100)

    def test_zero_controls_adds_5(self):
        t = self._base_threat()
        dfd = self._empty_dfd()
        base = compute_qualification_score(t, "Confidential", dfd)
        no_controls = compute_qualification_score(t, "Confidential", dfd, has_compliance_controls=False)
        assert no_controls == min(base + 5, 100)

    def test_all_signals_stacked_clamped_to_100(self):
        t = _make_threat(severity="Critical", stride_category="Information Disclosure", source="AI+Rules",
                         threat_subtype="payment fraud", crosses_trust_boundary=True)
        node = _make_node(NODE_ID, "data_store", properties={
            "internet_facing": True,
            "stores_credentials": True,
            "uses_auth": False,
            "validates_input": False,
            "handles_sensitive_data": True,
            "encrypted_at_rest": False,
        })
        dfd = _make_dfd(nodes=[node])
        score = compute_qualification_score(
            t, "Restricted", dfd,
            scan_status="confirmed",
            has_kev=True,
            has_compliance_controls=False,
        )
        assert score == 100

    def test_score_never_below_zero(self):
        t = _make_threat(severity="Low", stride_category="Denial of Service", source="Rules")
        dfd = _make_dfd()
        node = _make_node(NODE_ID, properties={"uses_auth": True, "validates_input": True})
        dfd.nodes = [node]
        score = compute_qualification_score(
            t, "Public", dfd, scan_status="mitigated"
        )
        assert score >= 0

    def test_backward_compat_no_new_args(self):
        """Old callers that pass only 3 args still work — new params default safely."""
        t = self._base_threat()
        dfd = self._empty_dfd()
        score = compute_qualification_score(t, "Internal", dfd)
        assert 0 <= score <= 100

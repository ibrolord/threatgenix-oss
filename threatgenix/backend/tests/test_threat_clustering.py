"""Tests for ThreatClusteringService — 3-pass deterministic clustering."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

from app.schemas.dfd import DFDNodeResponse, DFDResponse
from app.services.threat_clustering import compute_clusters


# ── Helpers ──────────────────────────────────────────────────────────────────

def _uid(n: int) -> uuid.UUID:
    return uuid.UUID(f"00000000-0000-0000-0000-{n:012d}")


def _make_node(node_id: uuid.UUID, label: str, node_type: str = "process"):
    n = MagicMock()
    n.id = node_id
    n.label = label
    n.node_type = node_type
    return n


def _make_edge(edge_id: uuid.UUID, src: uuid.UUID, tgt: uuid.UUID):
    e = MagicMock()
    e.id = edge_id
    e.source_node_id = src
    e.target_node_id = tgt
    return e


def _make_threat(
    tid: uuid.UUID,
    stride: str,
    node_ids: list[uuid.UUID] | None = None,
    edge_ids: list[uuid.UUID] | None = None,
    subtype: str | None = None,
    display_id: str = "T-001",
    auto_score: int | None = None,
):
    t = MagicMock()
    t.id = tid
    t.stride_category = stride
    t.affected_node_ids = node_ids or []
    t.affected_edge_ids = edge_ids or []
    t.threat_subtype = subtype
    t.display_id = display_id
    t.auto_score = auto_score
    t.qualification_score = None
    return t


def _make_dfd(nodes=None, edges=None):
    dfd = MagicMock()
    dfd.nodes = nodes or []
    dfd.edges = edges or []
    dfd.trust_boundaries = []
    return dfd


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestComputeClusters:
    def test_empty_threats_returns_empty(self):
        assert compute_clusters([], _make_dfd()) == []

    def test_single_threat_no_cluster(self):
        t = _make_threat(_uid(1), "Spoofing", node_ids=[_uid(10)])
        result = compute_clusters([t], _make_dfd())
        assert result == []

    # ── Pass 1: same node + same STRIDE ─────────────────────────────────────

    def test_pass1_two_threats_same_node_same_stride(self):
        node = _make_node(_uid(10), "API Gateway")
        dfd = _make_dfd(nodes=[node])
        t1 = _make_threat(_uid(1), "Spoofing", node_ids=[_uid(10)], display_id="T-001")
        t2 = _make_threat(_uid(2), "Spoofing", node_ids=[_uid(10)], display_id="T-002")
        results = compute_clusters([t1, t2], dfd)
        assert len(results) == 1
        assert results[0].reason == "same_node_stride"
        assert results[0].label == "Spoofing on API Gateway"
        assert set(results[0].threat_ids) == {_uid(1), _uid(2)}

    def test_pass1_uses_real_dfd_node_name_schema(self):
        dfd = DFDResponse(
            nodes=[
                DFDNodeResponse(
                    id=_uid(10),
                    node_type="process",
                    name="API Gateway",
                    position_x=0,
                    position_y=0,
                    trust_boundary_id=None,
                    properties={},
                )
            ],
            edges=[],
            trust_boundaries=[],
        )
        t1 = _make_threat(_uid(1), "Spoofing", node_ids=[_uid(10)], display_id="T-001")
        t2 = _make_threat(_uid(2), "Spoofing", node_ids=[_uid(10)], display_id="T-002")

        results = compute_clusters([t1, t2], dfd)

        assert len(results) == 1
        assert results[0].label == "Spoofing on API Gateway"

    def test_pass1_different_stride_no_cluster(self):
        node = _make_node(_uid(10), "API Gateway")
        dfd = _make_dfd(nodes=[node])
        t1 = _make_threat(_uid(1), "Spoofing", node_ids=[_uid(10)])
        t2 = _make_threat(_uid(2), "Tampering", node_ids=[_uid(10)])
        results = compute_clusters([t1, t2], dfd)
        assert results == []

    def test_pass1_different_node_no_cluster(self):
        n1 = _make_node(_uid(10), "Node A")
        n2 = _make_node(_uid(11), "Node B")
        dfd = _make_dfd(nodes=[n1, n2])
        t1 = _make_threat(_uid(1), "Spoofing", node_ids=[_uid(10)])
        t2 = _make_threat(_uid(2), "Spoofing", node_ids=[_uid(11)])
        results = compute_clusters([t1, t2], dfd)
        assert results == []

    def test_pass1_three_threats_same_group(self):
        node = _make_node(_uid(10), "DB")
        dfd = _make_dfd(nodes=[node])
        threats = [
            _make_threat(_uid(i), "Information Disclosure", node_ids=[_uid(10)])
            for i in range(1, 4)
        ]
        results = compute_clusters(threats, dfd)
        assert len(results) == 1
        assert len(results[0].threat_ids) == 3

    # ── Pass 2: same primary edge ────────────────────────────────────────────

    def test_pass2_same_edge(self):
        edge = _make_edge(_uid(20), _uid(10), _uid(11))
        n1 = _make_node(_uid(10), "Frontend")
        n2 = _make_node(_uid(11), "Backend")
        dfd = _make_dfd(nodes=[n1, n2], edges=[edge])
        t1 = _make_threat(_uid(1), "Tampering", edge_ids=[_uid(20)])
        t2 = _make_threat(_uid(2), "Information Disclosure", edge_ids=[_uid(20)])
        results = compute_clusters([t1, t2], dfd)
        assert len(results) == 1
        assert results[0].reason == "same_edge"
        assert "Frontend" in results[0].label
        assert "Backend" in results[0].label

    def test_pass2_threats_already_assigned_in_pass1_skipped(self):
        node = _make_node(_uid(10), "API")
        edge = _make_edge(_uid(20), _uid(10), _uid(11))
        n2 = _make_node(_uid(11), "DB")
        dfd = _make_dfd(nodes=[node, n2], edges=[edge])
        # t1 and t2 will cluster in pass1 (same node + stride)
        t1 = _make_threat(_uid(1), "Spoofing", node_ids=[_uid(10)], edge_ids=[_uid(20)])
        t2 = _make_threat(_uid(2), "Spoofing", node_ids=[_uid(10)], edge_ids=[_uid(20)])
        # t3 only has the edge and different stride — would be pass2 candidate with t1/t2
        # but t1/t2 are already assigned, so t3 alone won't form a cluster
        t3 = _make_threat(_uid(3), "Tampering", edge_ids=[_uid(20)])
        results = compute_clusters([t1, t2, t3], dfd)
        # Only pass1 cluster forms (t1+t2); t3 is alone in pass2
        assert len(results) == 1
        assert results[0].reason == "same_node_stride"

    # ── Pass 3: same subtype + same node type ────────────────────────────────

    def test_pass3_same_subtype_same_node_type(self):
        n1 = _make_node(_uid(10), "DB 1", node_type="data_store")
        n2 = _make_node(_uid(11), "DB 2", node_type="data_store")
        dfd = _make_dfd(nodes=[n1, n2])
        t1 = _make_threat(_uid(1), "Tampering", node_ids=[_uid(10)], subtype="SQL Injection")
        t2 = _make_threat(_uid(2), "Tampering", node_ids=[_uid(11)], subtype="SQL Injection")
        results = compute_clusters([t1, t2], dfd)
        assert len(results) == 1
        assert results[0].reason == "same_subtype_node"
        assert "SQL Injection" in results[0].label

    def test_pass3_no_subtype_skipped(self):
        n1 = _make_node(_uid(10), "A", "process")
        n2 = _make_node(_uid(11), "B", "process")
        dfd = _make_dfd(nodes=[n1, n2])
        t1 = _make_threat(_uid(1), "Spoofing", node_ids=[_uid(10)], subtype=None)
        t2 = _make_threat(_uid(2), "Spoofing", node_ids=[_uid(11)], subtype=None)
        results = compute_clusters([t1, t2], dfd)
        assert results == []

    # ── Representative selection ─────────────────────────────────────────────

    def test_representative_is_highest_auto_score(self):
        node = _make_node(_uid(10), "DB")
        dfd = _make_dfd(nodes=[node])
        t1 = _make_threat(_uid(1), "Spoofing", node_ids=[_uid(10)], auto_score=80, display_id="T-001")
        t2 = _make_threat(_uid(2), "Spoofing", node_ids=[_uid(10)], auto_score=40, display_id="T-002")
        results = compute_clusters([t1, t2], dfd)
        assert results[0].representative_threat_id == _uid(1)

    def test_representative_alphabetical_tiebreak(self):
        node = _make_node(_uid(10), "DB")
        dfd = _make_dfd(nodes=[node])
        t1 = _make_threat(_uid(1), "Spoofing", node_ids=[_uid(10)], auto_score=50, display_id="T-002")
        t2 = _make_threat(_uid(2), "Spoofing", node_ids=[_uid(10)], auto_score=50, display_id="T-001")
        results = compute_clusters([t1, t2], dfd)
        # "T-001" sorts before "T-002" alphabetically → t2 is representative
        assert results[0].representative_threat_id == _uid(2)

    # ── Idempotency ──────────────────────────────────────────────────────────

    def test_recompute_is_idempotent(self):
        node = _make_node(_uid(10), "API")
        dfd = _make_dfd(nodes=[node])
        threats = [
            _make_threat(_uid(i), "Information Disclosure", node_ids=[_uid(10)], display_id=f"T-{i:03d}")
            for i in range(1, 5)
        ]
        r1 = compute_clusters(threats, dfd)
        r2 = compute_clusters(threats, dfd)
        assert len(r1) == len(r2) == 1
        assert set(r1[0].threat_ids) == set(r2[0].threat_ids)
        assert r1[0].representative_threat_id == r2[0].representative_threat_id

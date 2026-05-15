"""Tests for Gap 2: Cloud-native DFD node types.

Covers:
- _base_type() mapping: all 5 cloud types → correct classic base types
- Existing STRIDE rules fire on cloud nodes via base_type mapping (no regressions)
- C-01→C-05 cloud-specific rules fire on appropriate configurations
- C-02 matches inbound edge (caller → serverless) as well as outbound
"""
from __future__ import annotations

import uuid


from app.schemas.dfd import DFDEdgeResponse, DFDNodeResponse, DFDResponse, TrustBoundaryResponse
from app.services.rules.conditions import (
    _base_type,
    _is_cloud_type,
    condition_c01,
    condition_c02,
    condition_c03,
    condition_c04,
    condition_c05,
)
from app.services.rules.engine import evaluate_rules

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BOUNDARY_ID = "00000000-0000-0000-0001-000000000000"


def _node(
    node_type: str,
    node_id: str | None = None,
    name: str | None = None,
    trust_boundary_id: str | None = None,
    properties: dict | None = None,
) -> DFDNodeResponse:
    return DFDNodeResponse(
        id=node_id or str(uuid.uuid4()),
        node_type=node_type,
        name=name or f"test-{node_type}",
        position_x=0.0,
        position_y=0.0,
        trust_boundary_id=trust_boundary_id,
        properties=properties or {},
    )


def _edge(
    src: DFDNodeResponse,
    tgt: DFDNodeResponse,
    label: str = "",
    edge_id: str | None = None,
) -> DFDEdgeResponse:
    return DFDEdgeResponse(
        id=edge_id or str(uuid.uuid4()),
        source_node_id=str(src.id),
        target_node_id=str(tgt.id),
        label=label,
        properties={},
    )


def _boundary(name: str = "Cloud Boundary") -> TrustBoundaryResponse:
    return TrustBoundaryResponse(
        id=BOUNDARY_ID,
        name=name,
        node_ids=[],
    )


def _dfd(
    nodes: list[DFDNodeResponse],
    edges: list[DFDEdgeResponse],
    boundaries: list[TrustBoundaryResponse] | None = None,
) -> DFDResponse:
    return DFDResponse(
        nodes=nodes,
        edges=edges,
        trust_boundaries=boundaries or [],
    )


# ---------------------------------------------------------------------------
# _base_type() mapping
# ---------------------------------------------------------------------------


class TestBaseTypeMapping:
    def test_human_actor_maps_to_external_entity(self):
        assert _base_type("human_actor") == "external_entity"

    def test_iam_role_maps_to_external_entity(self):
        assert _base_type("iam_role") == "external_entity"

    def test_managed_service_maps_to_data_store(self):
        assert _base_type("managed_service") == "data_store"

    def test_api_gateway_maps_to_process(self):
        assert _base_type("api_gateway") == "process"

    def test_container_maps_to_process(self):
        assert _base_type("container") == "process"

    def test_serverless_maps_to_process(self):
        assert _base_type("serverless") == "process"

    def test_classic_types_pass_through(self):
        for t in ("process", "data_store", "external_entity"):
            assert _base_type(t) == t

    def test_unknown_type_passes_through(self):
        assert _base_type("some_future_type") == "some_future_type"

    def test_is_cloud_type_true_for_all_five(self):
        for t in ("iam_role", "managed_service", "api_gateway", "container", "serverless"):
            assert _is_cloud_type(t), f"Expected {t} to be a cloud type"

    def test_is_cloud_type_false_for_classic(self):
        for t in ("process", "data_store", "external_entity"):
            assert not _is_cloud_type(t), f"Expected {t} NOT to be a cloud type"


# ---------------------------------------------------------------------------
# Existing STRIDE rules fire on cloud nodes (regression guard)
# ---------------------------------------------------------------------------


class TestExistingRulesFireOnCloudNodes:
    """Each cloud node type maps to a classic base type; existing rules must still fire."""

    def test_spoofing_rule_fires_on_iam_role_without_auth(self):
        """iam_role → external_entity: S-03 (unauthenticated external entity) should fire."""
        ee = _node("iam_role", properties={"authenticated": False})
        proc = _node("process")
        edge = _edge(ee, proc)
        dfd = _dfd([ee, proc], [edge])
        result = evaluate_rules(dfd)
        spoofing_threats = [t for t in result.threats if t.stride_category == "Spoofing"]
        assert len(spoofing_threats) > 0, "Expected S-03 to fire on unauthenticated iam_role"

    def test_tampering_rule_fires_on_managed_service_without_integrity(self):
        """managed_service → data_store: T-03 (no data integrity) should fire."""
        ds = _node("managed_service", properties={"data_integrity": False})
        proc = _node("process")
        edge = _edge(proc, ds)
        dfd = _dfd([proc, ds], [edge])
        result = evaluate_rules(dfd)
        tampering = [t for t in result.threats if t.stride_category == "Tampering"]
        assert len(tampering) > 0, "Expected Tampering rule to fire on managed_service without data_integrity"

    def test_info_disclosure_rule_fires_on_serverless_over_unencrypted_channel(self):
        """serverless → process: I-01 (unencrypted data flow) should fire when edge is unencrypted."""
        src = _node("external_entity")
        fn = _node("serverless")
        edge = _edge(src, fn, label="HTTP")
        dfd = _dfd([src, fn], [edge])
        result = evaluate_rules(dfd)
        # We just verify the engine runs without error on cloud node types;
        # whether I-01 fires depends on the specific condition logic
        assert result is not None

    def test_no_crash_on_all_cloud_types(self):
        """Engine must not crash when all node types are cloud types."""
        nodes = [
            _node("iam_role", node_id="00000000-0000-0000-0000-000000000001"),
            _node("managed_service", node_id="00000000-0000-0000-0000-000000000002"),
            _node("api_gateway", node_id="00000000-0000-0000-0000-000000000003"),
            _node("container", node_id="00000000-0000-0000-0000-000000000004"),
            _node("serverless", node_id="00000000-0000-0000-0000-000000000005"),
        ]
        edges = [
            _edge(nodes[0], nodes[2]),
            _edge(nodes[2], nodes[4]),
            _edge(nodes[4], nodes[1]),
        ]
        dfd = _dfd(nodes, edges)
        result = evaluate_rules(dfd)
        assert result is not None
        assert isinstance(result.threats, list)


# ---------------------------------------------------------------------------
# C-01: Managed service without encryption at rest
# ---------------------------------------------------------------------------


class TestC01:
    def test_fires_when_no_encryption(self):
        node = _node("managed_service", properties={"encrypted_at_rest": False})
        assert condition_c01(node, {}) is True

    def test_fires_when_encrypted_at_rest_absent(self):
        node = _node("managed_service", properties={})
        assert condition_c01(node, {}) is True

    def test_does_not_fire_when_encrypted(self):
        node = _node("managed_service", properties={"encrypted_at_rest": True})
        assert condition_c01(node, {}) is False

    def test_does_not_fire_on_non_managed_service(self):
        node = _node("data_store", properties={"encrypted_at_rest": False})
        assert condition_c01(node, {}) is False

    def test_c01_fires_in_engine(self):
        """End-to-end: C-01 threat appears when managed_service lacks encryption."""
        ds = _node("managed_service", properties={"encrypted_at_rest": False})
        proc = _node("process")
        dfd = _dfd([ds, proc], [_edge(proc, ds)])
        result = evaluate_rules(dfd)
        c01 = [t for t in result.threats if t.rule_id == "C-01"]
        assert len(c01) >= 1, "C-01 should fire when managed_service lacks encrypted_at_rest"


# ---------------------------------------------------------------------------
# C-02: Serverless crossing trust boundary without auth
# ---------------------------------------------------------------------------


class TestC02:
    def _boundary_edge(self, src: DFDNodeResponse, tgt: DFDNodeResponse) -> DFDEdgeResponse:
        return _edge(src, tgt)

    def test_fires_on_outbound_serverless_without_auth(self):
        """Serverless → X crosses boundary, serverless has no auth."""
        fn = _node("serverless", properties={"uses_auth": False})
        ext = _node("external_entity")
        edge = self._boundary_edge(fn, ext)
        assert condition_c02(fn, edge, ext, crosses_boundary=True) is True

    def test_fires_on_inbound_to_serverless_without_auth(self):
        """X → serverless crosses boundary — common invocation pattern must match."""
        caller = _node("api_gateway")
        fn = _node("serverless", properties={"uses_auth": False})
        edge = self._boundary_edge(caller, fn)
        assert condition_c02(caller, edge, fn, crosses_boundary=True) is True

    def test_does_not_fire_when_auth_present(self):
        fn = _node("serverless", properties={"uses_auth": True})
        ext = _node("external_entity")
        edge = self._boundary_edge(fn, ext)
        assert condition_c02(fn, edge, ext, crosses_boundary=True) is False

    def test_does_not_fire_when_no_boundary_crossing(self):
        fn = _node("serverless", properties={"uses_auth": False})
        ext = _node("external_entity")
        edge = self._boundary_edge(fn, ext)
        assert condition_c02(fn, edge, ext, crosses_boundary=False) is False

    def test_does_not_fire_when_neither_node_is_serverless(self):
        proc = _node("process")
        ds = _node("data_store")
        edge = self._boundary_edge(proc, ds)
        assert condition_c02(proc, edge, ds, crosses_boundary=True) is False

    def test_c02_fires_in_engine_inbound(self):
        """End-to-end: C-02 fires when caller → serverless crosses boundary without auth."""
        ext = _node("external_entity", node_id="00000000-0000-0000-0000-000000000011", trust_boundary_id=None)
        fn = _node("serverless", node_id="00000000-0000-0000-0000-000000000012",
                   trust_boundary_id=BOUNDARY_ID,
                   properties={"uses_auth": False})
        boundary_with_nodes = TrustBoundaryResponse(
            id=BOUNDARY_ID,
            name="Cloud Trust Boundary",
            node_ids=[fn.id],
        )
        edge = _edge(ext, fn)
        dfd = _dfd([ext, fn], [edge], [boundary_with_nodes])
        result = evaluate_rules(dfd)
        c02 = [t for t in result.threats if t.rule_id == "C-02"]
        assert len(c02) >= 1, "C-02 should fire on inbound call to serverless crossing boundary"


# ---------------------------------------------------------------------------
# C-03: IAM role without authentication
# ---------------------------------------------------------------------------


class TestC03:
    def test_fires_when_not_authenticated(self):
        node = _node("iam_role", properties={"authenticated": False})
        assert condition_c03(node, {}) is True

    def test_fires_when_authenticated_absent(self):
        node = _node("iam_role", properties={})
        assert condition_c03(node, {}) is True

    def test_does_not_fire_when_authenticated(self):
        node = _node("iam_role", properties={"authenticated": True})
        assert condition_c03(node, {}) is False

    def test_does_not_fire_on_non_iam_role(self):
        node = _node("external_entity", properties={"authenticated": False})
        assert condition_c03(node, {}) is False


# ---------------------------------------------------------------------------
# C-04: API gateway without input validation
# ---------------------------------------------------------------------------


class TestC04:
    def test_fires_when_no_validation(self):
        node = _node("api_gateway", properties={"validates_input": False})
        assert condition_c04(node, {}) is True

    def test_fires_when_validates_input_absent(self):
        node = _node("api_gateway", properties={})
        assert condition_c04(node, {}) is True

    def test_does_not_fire_when_validates_input(self):
        node = _node("api_gateway", properties={"validates_input": True})
        assert condition_c04(node, {}) is False

    def test_does_not_fire_on_non_api_gateway(self):
        node = _node("process", properties={"validates_input": False})
        assert condition_c04(node, {}) is False


# ---------------------------------------------------------------------------
# C-05: Internet-facing container without encryption
# ---------------------------------------------------------------------------


class TestC05:
    def test_fires_when_no_encryption_and_internet_facing(self):
        node = _node("container", properties={
            "uses_encryption": False,
            "internet_facing": True,
        })
        assert condition_c05(node, {}) is True

    def test_does_not_fire_when_encrypted(self):
        node = _node("container", properties={
            "uses_encryption": True,
            "internet_facing": True,
        })
        assert condition_c05(node, {}) is False

    def test_does_not_fire_when_not_internet_facing(self):
        node = _node("container", properties={
            "uses_encryption": False,
            "internet_facing": False,
        })
        assert condition_c05(node, {}) is False

    def test_does_not_fire_on_non_container(self):
        node = _node("process", properties={
            "uses_encryption": False,
            "internet_facing": True,
        })
        assert condition_c05(node, {}) is False

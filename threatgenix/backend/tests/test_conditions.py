from __future__ import annotations

import uuid


from app.schemas.dfd import DFDEdgeResponse, DFDNodeResponse, TrustBoundaryResponse
from app.services.rules.conditions import (
    _prop,
    condition_d01,
    condition_d02,
    condition_d03,
    condition_e01,
    condition_e02,
    condition_e03,
    condition_i01,
    condition_i02,
    condition_i03,
    condition_i04,
    condition_r01,
    condition_r02,
    condition_r03,
    condition_s01,
    condition_s02,
    condition_s03,
    condition_t01,
    condition_t02,
    condition_t03,
    condition_t04,
    condition_t_tls_01,
    condition_t_tls_02,
    condition_i_tls_01,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _node(
    node_type: str,
    node_id: uuid.UUID | None = None,
    properties: dict | None = None,
) -> DFDNodeResponse:
    return DFDNodeResponse(
        id=node_id or uuid.uuid4(),
        node_type=node_type,
        name=f"test-{node_type}",
        position_x=0,
        position_y=0,
        trust_boundary_id=None,
        properties=properties or {},
    )


def _edge(
    source: DFDNodeResponse,
    target: DFDNodeResponse,
    label: str = "",
) -> DFDEdgeResponse:
    return DFDEdgeResponse(
        id=uuid.uuid4(),
        source_node_id=source.id,
        target_node_id=target.id,
        label=label,
        properties={},
    )


def _boundary(node_ids: list[uuid.UUID] | None = None) -> TrustBoundaryResponse:
    return TrustBoundaryResponse(
        id=uuid.uuid4(),
        name="test-boundary",
        node_ids=node_ids or [],
    )


# Reusable fixtures
EXT = _node("external_entity")
PROC = _node("process")
DS = _node("data_store")
EDGE = _edge(EXT, PROC)


# ===========================================================================
# _prop helper — strict identity check
# ===========================================================================


class TestPropHelper:
    def test_true_returns_true(self):
        node = _node("process", properties={"uses_auth": True})
        assert _prop(node, "uses_auth") is True

    def test_false_returns_false(self):
        node = _node("process", properties={"uses_auth": False})
        assert _prop(node, "uses_auth") is False

    def test_missing_returns_false(self):
        node = _node("process", properties={})
        assert _prop(node, "uses_auth") is False

    def test_none_returns_false(self):
        node = _node("process", properties={"uses_auth": None})
        assert _prop(node, "uses_auth") is False

    def test_truthy_non_bool_returns_false(self):
        node = _node("process", properties={"uses_auth": "yes"})
        assert _prop(node, "uses_auth") is False

    def test_custom_authentication_type_counts_as_auth_present(self):
        node = _node("process", properties={"authentication_type": "fido2"})
        assert _prop(node, "uses_auth") is True

    def test_custom_sensitive_classification_counts_as_sensitive(self):
        node = _node("data_store", properties={"data_classification": "Highly Restricted"})
        assert _prop(node, "handles_sensitive_data") is True


# ===========================================================================
# Spoofing
# ===========================================================================


class TestConditionS01:
    def test_positive(self):
        assert condition_s01(EXT, EDGE, PROC, crosses_boundary=True) is True

    def test_negative_no_boundary(self):
        assert condition_s01(EXT, EDGE, PROC, crosses_boundary=False) is False

    def test_negative_wrong_source(self):
        assert condition_s01(PROC, EDGE, PROC, crosses_boundary=True) is False

    def test_suppressed_by_authenticated(self):
        ext_auth = _node("external_entity", properties={"authenticated": True})
        edge = _edge(ext_auth, PROC)
        assert condition_s01(ext_auth, edge, PROC, crosses_boundary=True) is False


class TestConditionS02:
    def test_positive(self):
        assert condition_s02(EXT, EDGE, PROC, crosses_boundary=True) is True

    def test_negative(self):
        assert condition_s02(EXT, EDGE, PROC, crosses_boundary=False) is False

    def test_suppressed_by_uses_auth(self):
        proc_auth = _node("process", properties={"uses_auth": True})
        edge = _edge(EXT, proc_auth)
        assert condition_s02(EXT, edge, proc_auth, crosses_boundary=True) is False


class TestConditionS03:
    def test_positive_operator_node(self):
        """Named operator/treasury actor is a high-value external entity."""
        operator = DFDNodeResponse(
            id=uuid.uuid4(), node_type="external_entity", name="Treasury Operator",
            position_x=0, position_y=0, trust_boundary_id=None, properties={},
        )
        assert condition_s03(operator, {}) is True

    def test_positive_payment_node(self):
        """Payment gateway external entity matches high-value pattern."""
        pg = DFDNodeResponse(
            id=uuid.uuid4(), node_type="external_entity", name="Payment Gateway",
            position_x=0, position_y=0, trust_boundary_id=None, properties={},
        )
        assert condition_s03(pg, {}) is True

    def test_positive_connected_to_financial_flow(self):
        """Generic external entity connected to a payment flow is still high-value."""
        generic_ext = DFDNodeResponse(
            id=uuid.uuid4(), node_type="external_entity", name="Partner",
            position_x=0, position_y=0, trust_boundary_id=None, properties={},
        )
        payment_edge = _edge(generic_ext, PROC, label="payment callback")
        context = {"all_edges": [payment_edge], "all_nodes": [generic_ext, PROC]}
        assert condition_s03(generic_ext, context) is True

    def test_negative_plain_external_entity(self):
        """Generic external entity with no high-value signal should NOT fire."""
        assert condition_s03(EXT, {}) is False

    def test_negative_process(self):
        assert condition_s03(PROC, {}) is False

    def test_suppressed_by_authenticated(self):
        ext_auth = DFDNodeResponse(
            id=uuid.uuid4(), node_type="external_entity", name="Treasury Operator",
            position_x=0, position_y=0, trust_boundary_id=None, properties={"authenticated": True},
        )
        assert condition_s03(ext_auth, {}) is False


# ===========================================================================
# Tampering
# ===========================================================================


class TestConditionT01:
    def test_positive(self):
        assert condition_t01(EXT, EDGE, PROC, crosses_boundary=True) is True

    def test_negative(self):
        assert condition_t01(EXT, EDGE, PROC, crosses_boundary=False) is False

    def test_suppressed_by_source_encryption(self):
        ext_enc = _node("external_entity", properties={"uses_encryption": True})
        edge = _edge(ext_enc, PROC)
        assert condition_t01(ext_enc, edge, PROC, crosses_boundary=True) is False

    def test_suppressed_by_target_encryption(self):
        proc_enc = _node("process", properties={"uses_encryption": True})
        edge = _edge(EXT, proc_enc)
        assert condition_t01(EXT, edge, proc_enc, crosses_boundary=True) is False


class TestConditionT02:
    def test_positive(self):
        e = _edge(EXT, DS)
        assert condition_t02(EXT, e, DS, crosses_boundary=False) is True

    def test_negative(self):
        assert condition_t02(PROC, EDGE, DS, crosses_boundary=False) is False


class TestConditionT03:
    def test_positive(self):
        e = _edge(PROC, DS)
        assert condition_t03(PROC, e, DS, crosses_boundary=False) is True

    def test_negative(self):
        assert condition_t03(EXT, EDGE, PROC, crosses_boundary=False) is False

    def test_suppressed_by_encrypted_at_rest(self):
        ds_enc = _node("data_store", properties={"encrypted_at_rest": True})
        e = _edge(PROC, ds_enc)
        assert condition_t03(PROC, e, ds_enc, crosses_boundary=False) is False


class TestConditionT04:
    def test_positive(self):
        e = _edge(EXT, DS)
        assert condition_t04(EXT, e, DS, crosses_boundary=True) is True

    def test_negative_no_boundary(self):
        e = _edge(EXT, DS)
        assert condition_t04(EXT, e, DS, crosses_boundary=False) is False

    def test_negative_wrong_target(self):
        assert condition_t04(EXT, EDGE, PROC, crosses_boundary=True) is False


# ===========================================================================
# Repudiation
# ===========================================================================


class TestConditionR01:
    def test_positive_source(self):
        assert condition_r01(EXT, EDGE, PROC, crosses_boundary=False) is True

    def test_positive_target(self):
        e = _edge(PROC, EXT)
        assert condition_r01(PROC, e, EXT, crosses_boundary=False) is True

    def test_negative(self):
        e = _edge(PROC, DS)
        assert condition_r01(PROC, e, DS, crosses_boundary=False) is False


class TestConditionR02:
    def test_positive_financial_flow(self):
        """Process involved in a payment flow triggers R-02."""
        e = _edge(PROC, DS, label="payment approval")
        assert condition_r02(PROC, e, DS, crosses_boundary=False) is True

    def test_positive_privileged_flow(self):
        """Process involved in a privileged override flow triggers R-02."""
        e = _edge(EXT, PROC, label="admin override command")
        assert condition_r02(EXT, e, PROC, crosses_boundary=False) is True

    def test_positive_sensitive_data_node(self):
        """Process handling sensitive data triggers R-02 even without keyword flow."""
        sensitive_proc = _node("process", properties={"handles_sensitive_data": True})
        e = _edge(sensitive_proc, DS)
        assert condition_r02(sensitive_proc, e, DS, crosses_boundary=False) is True

    def test_negative_generic_process_flow(self):
        """Generic process edge with no financial/privileged signal does NOT fire."""
        e = _edge(PROC, DS)
        assert condition_r02(PROC, e, DS, crosses_boundary=False) is False

    def test_negative_no_process_involved(self):
        """Edge with no process endpoint cannot fire."""
        e = _edge(EXT, DS)
        assert condition_r02(EXT, e, DS, crosses_boundary=False) is False


class TestConditionR03:
    def test_positive(self):
        e = _edge(PROC, DS)
        assert condition_r03(PROC, e, DS, crosses_boundary=False) is True

    def test_negative(self):
        assert condition_r03(EXT, EDGE, PROC, crosses_boundary=False) is False


# ===========================================================================
# Information Disclosure
# ===========================================================================


class TestConditionI01:
    def test_positive(self):
        assert condition_i01(EXT, EDGE, PROC, crosses_boundary=True) is True

    def test_negative(self):
        assert condition_i01(EXT, EDGE, PROC, crosses_boundary=False) is False

    def test_suppressed_by_source_encryption(self):
        ext_enc = _node("external_entity", properties={"uses_encryption": True})
        edge = _edge(ext_enc, PROC)
        assert condition_i01(ext_enc, edge, PROC, crosses_boundary=True) is False

    def test_suppressed_by_target_encryption(self):
        proc_enc = _node("process", properties={"uses_encryption": True})
        edge = _edge(EXT, proc_enc)
        assert condition_i01(EXT, edge, proc_enc, crosses_boundary=True) is False


class TestConditionI02:
    def test_positive(self):
        e = _edge(DS, EXT)
        assert condition_i02(DS, e, EXT, crosses_boundary=False) is True

    def test_negative(self):
        e = _edge(DS, PROC)
        assert condition_i02(DS, e, PROC, crosses_boundary=False) is False


class TestConditionI03:
    def test_positive(self):
        e = _edge(DS, PROC)
        assert condition_i03(DS, e, PROC, crosses_boundary=True) is True

    def test_negative_no_boundary(self):
        e = _edge(DS, PROC)
        assert condition_i03(DS, e, PROC, crosses_boundary=False) is False

    def test_negative_wrong_source(self):
        assert condition_i03(EXT, EDGE, PROC, crosses_boundary=True) is False


class TestConditionI04:
    def test_positive_password(self):
        e = _edge(EXT, PROC, label="Send Password Reset")
        assert condition_i04(EXT, e, PROC, crosses_boundary=False) is True

    def test_positive_token_case_insensitive(self):
        e = _edge(EXT, PROC, label="JWT TOKEN exchange")
        assert condition_i04(EXT, e, PROC, crosses_boundary=False) is True

    def test_negative_no_keyword(self):
        e = _edge(EXT, PROC, label="Get user profile")
        assert condition_i04(EXT, e, PROC, crosses_boundary=False) is False

    def test_negative_empty_label(self):
        e = _edge(EXT, PROC, label="")
        assert condition_i04(EXT, e, PROC, crosses_boundary=False) is False

    def test_suppressed_by_source_encryption(self):
        ext_enc = _node("external_entity", properties={"uses_encryption": True})
        e = _edge(ext_enc, PROC, label="Send Password Reset")
        assert condition_i04(ext_enc, e, PROC, crosses_boundary=False) is False


# ===========================================================================
# Denial of Service
# ===========================================================================


class TestConditionD01:
    def test_positive(self):
        assert condition_d01(EXT, EDGE, PROC, crosses_boundary=False) is True

    def test_negative(self):
        e = _edge(PROC, DS)
        assert condition_d01(PROC, e, DS, crosses_boundary=False) is False

    def test_suppressed_by_validates_input(self):
        proc_val = _node("process", properties={"validates_input": True})
        edge = _edge(EXT, proc_val)
        assert condition_d01(EXT, edge, proc_val, crosses_boundary=False) is False


class TestConditionD02:
    def test_positive_internet_facing(self):
        """Internet-facing process is an exhaustion target."""
        proc_internet = _node("process", properties={"internet_facing": True})
        assert condition_d02(proc_internet, {}) is True

    def test_positive_two_connections(self):
        """Process with degree >= 2 is a non-trivial dependency exhaustion target."""
        hub = _node("process")
        a = _node("external_entity")
        b = _node("data_store")
        edges = [_edge(a, hub), _edge(hub, b)]
        ctx = {"all_edges": edges}
        assert condition_d02(hub, ctx) is True

    def test_negative_isolated_process(self):
        """Internal process with degree < 2 (no connections) should NOT fire."""
        assert condition_d02(PROC, {}) is False

    def test_negative_single_edge_process(self):
        """Process with only 1 connection is not a cascading risk."""
        solo = _node("process")
        edge = _edge(EXT, solo)
        ctx = {"all_edges": [edge]}
        assert condition_d02(solo, ctx) is False

    def test_negative_external_entity(self):
        assert condition_d02(EXT, {}) is False


class TestConditionD03:
    def test_positive_high_degree(self):
        # Create a hub node with 4 connections
        hub = _node("process")
        others = [_node("external_entity") for _ in range(4)]
        edges = [_edge(o, hub) for o in others]
        ctx = {"all_edges": edges}
        assert condition_d03(hub, ctx) is True

    def test_negative_low_degree(self):
        hub = _node("process")
        others = [_node("external_entity") for _ in range(2)]
        edges = [_edge(o, hub) for o in others]
        ctx = {"all_edges": edges}
        assert condition_d03(hub, ctx) is False

    def test_counts_both_directions(self):
        hub = _node("process")
        n1 = _node("external_entity")
        n2 = _node("data_store")
        edges = [_edge(n1, hub), _edge(n2, hub), _edge(hub, n1), _edge(hub, n2)]
        ctx = {"all_edges": edges}
        assert condition_d03(hub, ctx) is True


# ===========================================================================
# Elevation of Privilege
# ===========================================================================


class TestConditionE01:
    def test_positive(self):
        assert condition_e01(EXT, EDGE, PROC, crosses_boundary=True) is True

    def test_negative_no_boundary(self):
        assert condition_e01(EXT, EDGE, PROC, crosses_boundary=False) is False

    def test_negative_wrong_types(self):
        e = _edge(PROC, DS)
        assert condition_e01(PROC, e, DS, crosses_boundary=True) is False

    def test_suppressed_by_both_auth_properties(self):
        ext_auth = _node("external_entity", properties={"authenticated": True})
        proc_auth = _node("process", properties={"uses_auth": True})
        edge = _edge(ext_auth, proc_auth)
        assert condition_e01(ext_auth, edge, proc_auth, crosses_boundary=True) is False

    def test_not_suppressed_by_only_source_auth(self):
        ext_auth = _node("external_entity", properties={"authenticated": True})
        edge = _edge(ext_auth, PROC)
        assert condition_e01(ext_auth, edge, PROC, crosses_boundary=True) is True

    def test_not_suppressed_by_only_target_auth(self):
        proc_auth = _node("process", properties={"uses_auth": True})
        edge = _edge(EXT, proc_auth)
        assert condition_e01(EXT, edge, proc_auth, crosses_boundary=True) is True


class TestConditionE02:
    def test_positive(self):
        assert condition_e02(EXT, EDGE, PROC, crosses_boundary=True) is True

    def test_negative_no_crossing(self):
        assert condition_e02(EXT, EDGE, PROC, crosses_boundary=False) is False

    def test_suppressed_auth_and_encrypted(self):
        """Source has uses_auth AND edge has encryption_in_transit — suppress."""
        src = _node("external_entity", properties={"uses_auth": True})
        encrypted_edge = DFDEdgeResponse(
            id=uuid.uuid4(),
            source_node_id=src.id,
            target_node_id=PROC.id,
            label="",
            properties={"encryption_in_transit": True},
        )
        assert condition_e02(src, encrypted_edge, PROC, crosses_boundary=True) is False

    def test_not_suppressed_auth_without_encryption(self):
        """Source has uses_auth but edge is NOT encrypted — still fires."""
        src = _node("external_entity", properties={"uses_auth": True})
        plain_edge = _edge(src, PROC)
        assert condition_e02(src, plain_edge, PROC, crosses_boundary=True) is True

    def test_suppressed_both_ends_authenticated(self):
        """Source.authenticated AND target.uses_auth — suppress."""
        src = _node("external_entity", properties={"authenticated": True})
        tgt = _node("process", properties={"uses_auth": True})
        assert condition_e02(src, EDGE, tgt, crosses_boundary=True) is False

    def test_not_suppressed_partial_auth(self):
        """Only one end authenticated (target.uses_auth alone) — still fires."""
        tgt = _node("process", properties={"uses_auth": True})
        assert condition_e02(EXT, EDGE, tgt, crosses_boundary=True) is True

    def test_not_suppressed_null_edge_properties(self):
        """Edge with no properties set — fires (unencrypted by default)."""
        assert condition_e02(EXT, EDGE, PROC, crosses_boundary=True) is True


class TestConditionE03:
    def test_positive(self):
        b = _boundary()
        assert condition_e03(b, entry_count=3) is True

    def test_positive_exact_threshold(self):
        b = _boundary()
        assert condition_e03(b, entry_count=2) is True

    def test_negative(self):
        b = _boundary()
        assert condition_e03(b, entry_count=1) is False


# ===========================================================================
# TLS Version Rules
# ===========================================================================


def _edge_with_tls(source, target, tls_version: str, **extra_props) -> DFDEdgeResponse:
    return DFDEdgeResponse(
        id=uuid.uuid4(),
        source_node_id=source.id,
        target_node_id=target.id,
        label="data flow",
        properties={"tls_version": tls_version, **extra_props},
    )


class TestConditionTTLS01:
    """T-TLS-01: deprecated TLS 1.0."""

    def test_fires_on_tls_1_0(self):
        edge = _edge_with_tls(PROC, DS, "tls_1_0")
        assert condition_t_tls_01(PROC, edge, DS, crosses_boundary=False) is True

    def test_does_not_fire_on_tls_1_1(self):
        edge = _edge_with_tls(PROC, DS, "tls_1_1")
        assert condition_t_tls_01(PROC, edge, DS, crosses_boundary=False) is False

    def test_does_not_fire_on_tls_1_2(self):
        edge = _edge_with_tls(PROC, DS, "tls_1_2")
        assert condition_t_tls_01(PROC, edge, DS, crosses_boundary=False) is False

    def test_does_not_fire_on_tls_1_3(self):
        edge = _edge_with_tls(PROC, DS, "tls_1_3")
        assert condition_t_tls_01(PROC, edge, DS, crosses_boundary=False) is False

    def test_does_not_fire_when_no_tls_version(self):
        edge = _edge(PROC, DS)
        assert condition_t_tls_01(PROC, edge, DS, crosses_boundary=False) is False

    def test_fires_on_custom_tls_1_0_label(self):
        edge = _edge_with_tls(PROC, DS, "TLS 1.0")
        assert condition_t_tls_01(PROC, edge, DS, crosses_boundary=False) is True


class TestConditionTTLS02:
    """T-TLS-02: deprecated TLS 1.1."""

    def test_fires_on_tls_1_1(self):
        edge = _edge_with_tls(PROC, DS, "tls_1_1")
        assert condition_t_tls_02(PROC, edge, DS, crosses_boundary=False) is True

    def test_does_not_fire_on_tls_1_0(self):
        edge = _edge_with_tls(PROC, DS, "tls_1_0")
        assert condition_t_tls_02(PROC, edge, DS, crosses_boundary=False) is False

    def test_does_not_fire_on_tls_1_2(self):
        edge = _edge_with_tls(PROC, DS, "tls_1_2")
        assert condition_t_tls_02(PROC, edge, DS, crosses_boundary=False) is False

    def test_fires_on_custom_tls_1_1_label(self):
        edge = _edge_with_tls(PROC, DS, "TLS 1.1")
        assert condition_t_tls_02(PROC, edge, DS, crosses_boundary=False) is True


class TestConditionITLS01:
    """I-TLS-01: sensitive data with no TLS."""

    def test_fires_on_pii_with_no_tls(self):
        edge = _edge_with_tls(EXT, PROC, "none", carries_pii=True)
        assert condition_i_tls_01(EXT, edge, PROC, crosses_boundary=False) is True

    def test_fires_on_credentials_with_no_tls(self):
        edge = _edge_with_tls(EXT, PROC, "none", carries_credentials=True)
        assert condition_i_tls_01(EXT, edge, PROC, crosses_boundary=False) is True

    def test_fires_on_financial_data_with_no_tls(self):
        edge = _edge_with_tls(EXT, PROC, "none", carries_financial_data=True)
        assert condition_i_tls_01(EXT, edge, PROC, crosses_boundary=False) is True

    def test_fires_on_secrets_with_no_tls(self):
        edge = _edge_with_tls(EXT, PROC, "none", carries_secrets=True)
        assert condition_i_tls_01(EXT, edge, PROC, crosses_boundary=False) is True

    def test_does_not_fire_when_tls_present_and_sensitive(self):
        edge = _edge_with_tls(EXT, PROC, "tls_1_3", carries_pii=True)
        assert condition_i_tls_01(EXT, edge, PROC, crosses_boundary=False) is False

    def test_does_not_fire_when_no_tls_but_no_sensitive_data(self):
        edge = _edge_with_tls(EXT, PROC, "none")
        assert condition_i_tls_01(EXT, edge, PROC, crosses_boundary=False) is False

    def test_does_not_fire_when_no_tls_version_set_and_no_sensitive_data(self):
        edge = _edge(EXT, PROC)
        assert condition_i_tls_01(EXT, edge, PROC, crosses_boundary=False) is False

    def test_fires_on_sensitive_data_with_plaintext_label(self):
        edge = _edge_with_tls(EXT, PROC, "plaintext", carries_pii=True)
        assert condition_i_tls_01(EXT, edge, PROC, crosses_boundary=False) is True

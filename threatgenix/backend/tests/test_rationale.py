"""Comprehensive unit tests for the rationale module.

Tests cover _classify_data_flow, _describe_security_posture,
build_rationale_tuple, build_rationale_standalone, and build_rationale_boundary.
"""

from __future__ import annotations

import pytest

from app.schemas.dfd import DFDEdgeResponse, DFDNodeResponse, TrustBoundaryResponse
from app.services.rules.rationale import (
    _classify_data_flow,
    _describe_security_posture,
    build_rationale_boundary,
    build_rationale_standalone,
    build_rationale_tuple,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NODE_ID1 = "00000000-0000-0000-0000-000000000001"
NODE_ID2 = "00000000-0000-0000-0000-000000000002"
NODE_ID3 = "00000000-0000-0000-0000-000000000003"
EDGE_ID1 = "00000000-0000-0000-0000-0000000000e1"
BOUNDARY_ID1 = "00000000-0000-0000-0000-0000000000b1"


def _make_node(
    node_id: str = NODE_ID1,
    node_type: str = "process",
    name: str = "TestNode",
    trust_boundary_id: str | None = None,
    properties: dict | None = None,
) -> DFDNodeResponse:
    return DFDNodeResponse(
        id=node_id,
        node_type=node_type,
        name=name,
        position_x=0.0,
        position_y=0.0,
        trust_boundary_id=trust_boundary_id,
        properties=properties or {},
    )


def _make_edge(
    edge_id: str = EDGE_ID1,
    source_node_id: str = NODE_ID1,
    target_node_id: str = NODE_ID2,
    label: str = "",
) -> DFDEdgeResponse:
    return DFDEdgeResponse(
        id=edge_id,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        label=label,
        properties={},
    )


def _make_boundary(
    boundary_id: str = BOUNDARY_ID1,
    name: str = "DMZ",
    node_ids: list[str] | None = None,
) -> TrustBoundaryResponse:
    return TrustBoundaryResponse(
        id=boundary_id,
        name=name,
        node_ids=node_ids or [],
    )


# ===================================================================
# 1. _classify_data_flow
# ===================================================================


class TestClassifyDataFlow:
    """Tests for _classify_data_flow(label)."""

    # --- Financial data keywords ---

    @pytest.mark.parametrize(
        "label",
        [
            "payment request",
            "transaction log",
            "wire transfer",
            "balance inquiry",
            "account_balance",
            "cardholder data",
            "card number",
            "debit request",
            "credit report",
            "fund allocation",
            "deposit receipt",
            "withdraw funds",
        ],
    )
    def test_financial_keywords(self, label: str) -> None:
        result = _classify_data_flow(label)
        assert "financial data" in result

    # --- Credential keywords ---

    @pytest.mark.parametrize(
        "label",
        [
            "password hash",
            "user credentials",
            "credential store",
            "access token",
            "secret key",
            "api_key",
            "api key",
            "auth header",
            "authentication request",
            "jwt payload",
            "session_id",
            "session id",
            "oauth flow",
            "bearer token",
        ],
    )
    def test_credential_keywords(self, label: str) -> None:
        result = _classify_data_flow(label)
        assert "credentials/secrets" in result

    # --- PII keywords ---

    @pytest.mark.parametrize(
        "label",
        [
            "ssn lookup",
            "social insurance number",
            "sin number",
            "full_name",
            "first name",
            "last_name",
            "home address",
            "home_address",
            "mailing address",
            "email address",
            "email notification",
            "phone number",
            "phone_number",
            "dob field",
            "date_of_birth",
            "date of birth",
        ],
    )
    def test_pii_keywords(self, label: str) -> None:
        result = _classify_data_flow(label)
        assert "personally identifiable information" in result

    # --- Empty / None ---

    def test_empty_string(self) -> None:
        assert _classify_data_flow("") == []

    def test_none_label(self) -> None:
        assert _classify_data_flow(None) == []

    # --- False positive prevention ---

    @pytest.mark.parametrize(
        "label",
        [
            "filename",
            "hostname",
            "processing",
            "service_name",
            "single sign-on",
            "business_info",
            "column_name",
        ],
    )
    def test_false_positives_should_not_match(self, label: str) -> None:
        result = _classify_data_flow(label)
        assert result == [], f"'{label}' should not match any category but got {result}"

    # --- Multiple categories ---

    def test_multiple_categories_financial_and_credentials(self) -> None:
        result = _classify_data_flow("payment credentials")
        assert "financial data" in result
        assert "credentials/secrets" in result

    def test_multiple_categories_all_three(self) -> None:
        result = _classify_data_flow("payment token with email address")
        assert "financial data" in result
        assert "credentials/secrets" in result
        assert "personally identifiable information" in result

    def test_no_match_generic_label(self) -> None:
        result = _classify_data_flow("status update")
        assert result == []

    # --- Case insensitivity ---

    def test_case_insensitive_financial(self) -> None:
        result = _classify_data_flow("PAYMENT Request")
        assert "financial data" in result

    def test_case_insensitive_credential(self) -> None:
        result = _classify_data_flow("JWT Token")
        assert "credentials/secrets" in result


# ===================================================================
# 2. _describe_security_posture
# ===================================================================


class TestDescribeSecurityPosture:
    """Tests for _describe_security_posture(node)."""

    # --- Process nodes ---

    def test_process_all_gaps(self) -> None:
        node = _make_node(
            node_type="process",
            properties={
                "internet_facing": True,
                "uses_auth": False,
                "validates_input": False,
                "uses_encryption": False,
                "handles_sensitive_data": True,
            },
        )
        gaps = _describe_security_posture(node)
        assert "internet-exposed without authentication" in gaps
        assert "no input validation" in gaps
        assert "no encryption" in gaps
        assert "handles sensitive data" in gaps

    def test_process_all_controls_set(self) -> None:
        node = _make_node(
            node_type="process",
            properties={
                "internet_facing": True,
                "uses_auth": True,
                "validates_input": True,
                "uses_encryption": True,
                "handles_sensitive_data": False,
            },
        )
        gaps = _describe_security_posture(node)
        assert gaps == []

    def test_process_no_auth_not_internet_facing(self) -> None:
        """Non-internet-facing without auth says 'no authentication', not 'internet-exposed'."""
        node = _make_node(
            node_type="process",
            properties={
                "internet_facing": False,
                "uses_auth": False,
            },
        )
        gaps = _describe_security_posture(node)
        assert "no authentication" in gaps
        assert "internet-exposed without authentication" not in gaps

    def test_process_internet_facing_with_auth(self) -> None:
        """Internet-facing with auth should not report auth gap."""
        node = _make_node(
            node_type="process",
            properties={
                "internet_facing": True,
                "uses_auth": True,
                "validates_input": True,
                "uses_encryption": True,
            },
        )
        gaps = _describe_security_posture(node)
        assert "internet-exposed without authentication" not in gaps
        assert "no authentication" not in gaps

    # --- Data store nodes ---

    def test_data_store_all_gaps(self) -> None:
        node = _make_node(
            node_type="data_store",
            name="UserDB",
            properties={
                "encrypted_at_rest": False,
                "stores_credentials": True,
                "has_backup": False,
                "internet_facing": True,
            },
        )
        gaps = _describe_security_posture(node)
        assert "not encrypted at rest" in gaps
        assert "stores credentials" in gaps
        assert "no backup" in gaps
        assert "directly internet-exposed" in gaps

    def test_data_store_fully_secured(self) -> None:
        node = _make_node(
            node_type="data_store",
            name="SecureDB",
            properties={
                "encrypted_at_rest": True,
                "stores_credentials": False,
                "has_backup": True,
                "internet_facing": False,
            },
        )
        gaps = _describe_security_posture(node)
        assert gaps == []

    # --- External entity nodes ---

    def test_external_entity_untrusted_unauthenticated(self) -> None:
        node = _make_node(
            node_type="external_entity",
            name="PublicUser",
            properties={"trusted": False, "authenticated": False},
        )
        gaps = _describe_security_posture(node)
        assert "untrusted" in gaps
        assert "unauthenticated" in gaps

    def test_external_entity_trusted_authenticated(self) -> None:
        node = _make_node(
            node_type="external_entity",
            name="AdminUser",
            properties={"trusted": True, "authenticated": True},
        )
        gaps = _describe_security_posture(node)
        assert gaps == []

    def test_external_entity_trusted_not_authenticated(self) -> None:
        node = _make_node(
            node_type="external_entity",
            name="Partner",
            properties={"trusted": True, "authenticated": False},
        )
        gaps = _describe_security_posture(node)
        assert "untrusted" not in gaps
        assert "unauthenticated" in gaps

    # --- Empty properties ---

    def test_empty_properties_process(self) -> None:
        node = _make_node(node_type="process", properties={})
        gaps = _describe_security_posture(node)
        assert gaps == []

    def test_empty_properties_data_store(self) -> None:
        node = _make_node(node_type="data_store", properties={})
        gaps = _describe_security_posture(node)
        assert gaps == []

    def test_empty_properties_external_entity(self) -> None:
        node = _make_node(node_type="external_entity", properties={})
        gaps = _describe_security_posture(node)
        assert gaps == []


# ===================================================================
# 3. build_rationale_tuple
# ===================================================================


class TestBuildRationaleTuple:
    """Tests for build_rationale_tuple()."""

    def test_rich_rationale_sensitive_data_boundary_gaps(self) -> None:
        """Edge with sensitive label + boundary crossing + security gaps."""
        source = _make_node(
            node_id=NODE_ID1,
            node_type="external_entity",
            name="PublicUser",
            properties={"trusted": False, "authenticated": False},
        )
        target = _make_node(
            node_id=NODE_ID2,
            node_type="process",
            name="PaymentService",
            properties={
                "internet_facing": True,
                "uses_auth": False,
                "validates_input": False,
                "uses_encryption": False,
            },
        )
        edge = _make_edge(label="payment credentials")

        result = build_rationale_tuple(
            rule_id="STRIDE-01",
            source=source,
            edge=edge,
            target=target,
            crosses_boundary=True,
            boundary_name="DMZ",
        )

        assert "financial data" in result
        assert "credentials/secrets" in result
        assert "high-impact" in result
        assert "PublicUser" in result
        assert "untrusted" in result
        assert "PaymentService" in result
        assert "internet-exposed without authentication" in result
        assert 'DMZ' in result
        assert "trust boundary" in result

    def test_fallback_rationale_no_keywords_no_boundary(self) -> None:
        """Edge with no special keywords and no boundary crossing → fallback."""
        source = _make_node(
            node_id=NODE_ID1,
            node_type="process",
            name="ServiceA",
            properties={
                "uses_auth": True,
                "validates_input": True,
                "uses_encryption": True,
            },
        )
        target = _make_node(
            node_id=NODE_ID2,
            node_type="process",
            name="ServiceB",
            properties={
                "uses_auth": True,
                "validates_input": True,
                "uses_encryption": True,
            },
        )
        edge = _make_edge(label="status update")

        result = build_rationale_tuple(
            rule_id="STRIDE-02",
            source=source,
            edge=edge,
            target=target,
            crosses_boundary=False,
            boundary_name=None,
        )

        # Should get fallback text
        assert "ServiceA" in result
        assert "ServiceB" in result
        assert "attack surface" in result

    def test_only_source_has_gaps(self) -> None:
        """Edge where only source has security gaps."""
        source = _make_node(
            node_id=NODE_ID1,
            node_type="external_entity",
            name="UntrustedClient",
            properties={"trusted": False, "authenticated": False},
        )
        target = _make_node(
            node_id=NODE_ID2,
            node_type="process",
            name="SecureAPI",
            properties={
                "uses_auth": True,
                "validates_input": True,
                "uses_encryption": True,
            },
        )
        edge = _make_edge(label="request data")

        result = build_rationale_tuple(
            rule_id="STRIDE-03",
            source=source,
            edge=edge,
            target=target,
            crosses_boundary=False,
            boundary_name=None,
        )

        assert "UntrustedClient" in result
        assert "untrusted" in result
        assert "SecureAPI" not in result or "vulnerable" not in result

    def test_only_target_has_gaps(self) -> None:
        """Edge where only target has security gaps."""
        source = _make_node(
            node_id=NODE_ID1,
            node_type="external_entity",
            name="TrustedAdmin",
            properties={"trusted": True, "authenticated": True},
        )
        target = _make_node(
            node_id=NODE_ID2,
            node_type="data_store",
            name="LegacyDB",
            properties={
                "encrypted_at_rest": False,
                "stores_credentials": True,
                "has_backup": False,
            },
        )
        edge = _make_edge(label="query results")

        result = build_rationale_tuple(
            rule_id="STRIDE-04",
            source=source,
            edge=edge,
            target=target,
            crosses_boundary=False,
            boundary_name=None,
        )

        assert "LegacyDB" in result
        assert "not encrypted at rest" in result
        assert "TrustedAdmin" not in result or "untrusted" not in result

    def test_boundary_crossing_without_name(self) -> None:
        """crosses_boundary=True but boundary_name=None → no boundary text."""
        source = _make_node(node_id=NODE_ID1, node_type="process", name="A")
        target = _make_node(node_id=NODE_ID2, node_type="process", name="B")
        edge = _make_edge(label="token exchange")

        result = build_rationale_tuple(
            rule_id="STRIDE-05",
            source=source,
            edge=edge,
            target=target,
            crosses_boundary=True,
            boundary_name=None,
        )

        assert "trust boundary" not in result

    def test_edge_label_with_financial_data(self) -> None:
        """Verify financial data classification appears in rationale."""
        source = _make_node(node_id=NODE_ID1, node_type="process", name="CheckoutSvc")
        target = _make_node(node_id=NODE_ID2, node_type="data_store", name="TxnDB")
        edge = _make_edge(label="transaction record")

        result = build_rationale_tuple(
            rule_id="STRIDE-06",
            source=source,
            edge=edge,
            target=target,
            crosses_boundary=False,
            boundary_name=None,
        )

        assert "financial data" in result
        assert "transaction record" in result


# ===================================================================
# 4. build_rationale_standalone
# ===================================================================


class TestBuildRationaleStandalone:
    """Tests for build_rationale_standalone()."""

    def test_node_with_gaps_and_sensitive_flows(self) -> None:
        """Node with security gaps + sensitive data flows."""
        node = _make_node(
            node_id=NODE_ID1,
            node_type="process",
            name="AuthService",
            properties={
                "internet_facing": True,
                "uses_auth": False,
                "validates_input": False,
                "uses_encryption": False,
                "handles_sensitive_data": True,
            },
        )
        edges = [
            _make_edge(
                source_node_id=NODE_ID2,
                target_node_id=NODE_ID1,
                label="password hash",
            ),
            _make_edge(
                edge_id="00000000-0000-0000-0000-0000000000e2",
                source_node_id=NODE_ID1,
                target_node_id=NODE_ID2,
                label="jwt token",
            ),
        ]
        context = {"all_edges": edges, "boundaries": []}

        result = build_rationale_standalone(
            rule_id="STANDALONE-01",
            node=node,
            context=context,
        )

        assert "internet-exposed without authentication" in result
        assert "no input validation" in result
        assert "credentials/secrets" in result
        assert "sensitive operations" in result

    def test_isolated_node_no_edges(self) -> None:
        """Node with no edges (isolated)."""
        node = _make_node(
            node_id=NODE_ID1,
            node_type="process",
            name="OrphanService",
            properties={
                "uses_auth": True,
                "validates_input": True,
                "uses_encryption": True,
            },
        )
        context = {"all_edges": [], "boundaries": []}

        result = build_rationale_standalone(
            rule_id="STANDALONE-02",
            node=node,
            context=context,
        )

        # No gaps and no edges → fallback
        assert "OrphanService" in result
        assert "evaluated" in result

    def test_node_in_trust_boundary(self) -> None:
        """Node located in a trust boundary."""
        node = _make_node(
            node_id=NODE_ID1,
            node_type="data_store",
            name="InternalDB",
            properties={"encrypted_at_rest": False, "has_backup": False},
        )
        boundary = _make_boundary(
            name="Internal Network",
            node_ids=[NODE_ID1],
        )
        context = {"all_edges": [], "boundaries": [boundary]}

        result = build_rationale_standalone(
            rule_id="STANDALONE-03",
            node=node,
            context=context,
        )

        assert "Internal Network" in result
        assert "trust boundary" in result

    def test_high_connectivity_node(self) -> None:
        """Node with 4+ flows → high-connectivity message."""
        node = _make_node(
            node_id=NODE_ID1,
            node_type="process",
            name="APIGateway",
            properties={},
        )
        edges = [
            _make_edge(
                edge_id=f"00000000-0000-0000-0000-0000000000e{i}",
                source_node_id=NODE_ID2 if i % 2 == 0 else NODE_ID1,
                target_node_id=NODE_ID1 if i % 2 == 0 else NODE_ID2,
                label=f"flow_{i}",
            )
            for i in range(1, 6)
        ]
        context = {"all_edges": edges, "boundaries": []}

        result = build_rationale_standalone(
            rule_id="STANDALONE-04",
            node=node,
            context=context,
        )

        assert "high-connectivity" in result
        assert "inbound" in result
        assert "outbound" in result

    def test_node_no_gaps_no_sensitive_data_fallback(self) -> None:
        """Fully secured node with non-sensitive edges → fallback."""
        node = _make_node(
            node_id=NODE_ID1,
            node_type="process",
            name="LoggingService",
            properties={
                "uses_auth": True,
                "validates_input": True,
                "uses_encryption": True,
            },
        )
        edges = [
            _make_edge(
                source_node_id=NODE_ID2,
                target_node_id=NODE_ID1,
                label="log entry",
            ),
        ]
        context = {"all_edges": edges, "boundaries": []}

        result = build_rationale_standalone(
            rule_id="STANDALONE-05",
            node=node,
            context=context,
        )

        # No gaps, no sensitive data, < 4 flows, no boundary → fallback
        assert "LoggingService" in result
        assert "evaluated" in result

    def test_data_classification_from_edges(self) -> None:
        """Verify data classifications are collected from inbound + outbound edges."""
        node = _make_node(
            node_id=NODE_ID1,
            node_type="process",
            name="UserService",
            properties={},
        )
        edges = [
            _make_edge(
                source_node_id=NODE_ID2,
                target_node_id=NODE_ID1,
                label="email address lookup",
            ),
            _make_edge(
                edge_id="00000000-0000-0000-0000-0000000000e2",
                source_node_id=NODE_ID1,
                target_node_id=NODE_ID2,
                label="payment confirmation",
            ),
        ]
        context = {"all_edges": edges, "boundaries": []}

        result = build_rationale_standalone(
            rule_id="STANDALONE-06",
            node=node,
            context=context,
        )

        assert "financial data" in result
        assert "personally identifiable information" in result


# ===================================================================
# 5. build_rationale_boundary
# ===================================================================


class TestBuildRationaleBoundary:
    """Tests for build_rationale_boundary()."""

    def test_basic_output_format(self) -> None:
        result = build_rationale_boundary(
            rule_id="BOUNDARY-01",
            boundary_name="DMZ",
            entry_count=3,
            node_count=5,
        )

        assert '"DMZ"' in result
        assert "3 entry points" in result
        assert "5 internal components" in result
        assert "attack vector" in result

    def test_single_entry_single_node(self) -> None:
        result = build_rationale_boundary(
            rule_id="BOUNDARY-02",
            boundary_name="Secure Zone",
            entry_count=1,
            node_count=1,
        )

        assert '"Secure Zone"' in result
        assert "1 entry points" in result
        assert "1 internal components" in result

    def test_large_counts(self) -> None:
        result = build_rationale_boundary(
            rule_id="BOUNDARY-03",
            boundary_name="Cloud VPC",
            entry_count=15,
            node_count=42,
        )

        assert "15 entry points" in result
        assert "42 internal components" in result
        assert "security controls" in result

    def test_zero_entries(self) -> None:
        """Boundary with zero entry points still produces valid output."""
        result = build_rationale_boundary(
            rule_id="BOUNDARY-04",
            boundary_name="Isolated Zone",
            entry_count=0,
            node_count=3,
        )

        assert '"Isolated Zone"' in result
        assert "0 entry points" in result

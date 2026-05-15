import uuid

from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.services.dfd_quality_gates import evaluate_quality_gates
from app.services.dfd_views import build_default_views, sync_default_views


def _sample_dfd() -> DFDResponse:
    external_id = uuid.uuid4()
    gateway_id = uuid.uuid4()
    store_id = uuid.uuid4()
    edge_id = uuid.uuid4()
    boundary_id = uuid.uuid4()

    return DFDResponse(
        nodes=[
            DFDNodeResponse(
                id=external_id,
                node_type="external_entity",
                name="Customer Mobile App",
                position_x=0,
                position_y=0,
                trust_boundary_id=None,
                properties={
                    "data_classification": "Internal",
                    "authentication_type": "jwt",
                    "network_exposure": "internet",
                    "privilege_level": "standard",
                    "entity_scope": "external",
                    "entity_kind": "device",
                    "trust_level": "semi_trusted",
                },
            ),
            DFDNodeResponse(
                id=gateway_id,
                node_type="api_gateway",
                name="API Gateway",
                position_x=200,
                position_y=0,
                trust_boundary_id=boundary_id,
                properties={
                    "data_classification": "Restricted",
                    "authentication_type": "oauth2",
                    "network_exposure": "dmz",
                    "privilege_level": "elevated",
                    "runtime_type": "gateway",
                    "input_validation": "strict",
                    "logging_level": "audit",
                },
            ),
            DFDNodeResponse(
                id=store_id,
                node_type="data_store",
                name="Customer Profile DB",
                position_x=420,
                position_y=0,
                trust_boundary_id=boundary_id,
                properties={
                    "data_classification": "Restricted",
                    "authentication_type": "mtls",
                    "network_exposure": "internal",
                    "privilege_level": "privileged",
                    "store_type": "PostgreSQL",
                    "store_purpose": "Customer profiles",
                    "encryption_at_rest": "transparent",
                    "backup_strategy": "geo_redundant",
                },
            ),
        ],
        edges=[
            DFDEdgeResponse(
                id=edge_id,
                source_node_id=external_id,
                target_node_id=gateway_id,
                label="Customer profile request",
                properties={
                    "protocol": "HTTPS",
                    "data_payload": "Customer profile request",
                    "data_classification": "Restricted",
                    "encryption_in_transit": True,
                    "carries_pii": True,
                },
            )
        ],
        trust_boundaries=[
            TrustBoundaryResponse(
                id=boundary_id,
                name="DMZ",
                node_ids=[gateway_id, store_id],
                position_x=150,
                position_y=-40,
                width=420,
                height=220,
            )
        ],
    )


def test_build_default_views_returns_context_container_and_deep_dive():
    dfd = _sample_dfd()

    views = build_default_views(dfd)

    assert [view.view_type for view in views] == ["context", "container", "deep_dive", "data_lifecycle"]
    context_view = views[0]
    container_view = views[1]
    deep_dive_view = views[2]
    lifecycle_view = views[3]

    assert len(container_view.node_ids) == 3
    assert container_view.name == "System View"
    assert len(container_view.edge_ids) == 1
    assert len(context_view.node_ids) >= 2
    assert len(deep_dive_view.edge_ids) == 1
    assert len(lifecycle_view.edge_ids) == 1
    assert len(lifecycle_view.node_ids) >= 2


def test_build_default_views_migrates_legacy_container_view_name():
    dfd = _sample_dfd()
    existing_views = build_default_views(dfd)
    legacy_system_view = existing_views[1].model_copy(update={"name": "Container View"})

    synced = build_default_views(dfd, [existing_views[0], legacy_system_view, existing_views[2], existing_views[3]])

    assert synced[1].name == "System View"


def test_evaluate_quality_gates_blocks_empty_dfd_even_with_default_views():
    dfd = DFDResponse(nodes=[], edges=[], trust_boundaries=[])

    summary = evaluate_quality_gates(dfd, views=build_default_views(dfd))

    gate_ids = {result.gate_id for result in summary.results}
    assert summary.blocking_count >= 1
    assert "missing_dfd" in gate_ids


def test_evaluate_quality_gates_flags_missing_metadata_and_bad_structure():
    external_id = uuid.uuid4()
    store_a_id = uuid.uuid4()
    store_b_id = uuid.uuid4()
    edge_id = uuid.uuid4()

    dfd = DFDResponse(
        nodes=[
            DFDNodeResponse(
                id=external_id,
                node_type="external_entity",
                name="System",
                position_x=0,
                position_y=0,
                trust_boundary_id=None,
                properties={},
            ),
            DFDNodeResponse(
                id=store_a_id,
                node_type="data_store",
                name="Primary DB",
                position_x=220,
                position_y=0,
                trust_boundary_id=None,
                properties={},
            ),
            DFDNodeResponse(
                id=store_b_id,
                node_type="data_store",
                name="Replica DB",
                position_x=440,
                position_y=0,
                trust_boundary_id=None,
                properties={},
            ),
        ],
        edges=[
            DFDEdgeResponse(
                id=edge_id,
                source_node_id=store_a_id,
                target_node_id=store_b_id,
                label="payload",
                properties={"data_payload": "replication stream", "carries_secrets": True},
            )
        ],
        trust_boundaries=[],
    )

    summary = evaluate_quality_gates(dfd, views=[])

    gate_ids = {result.gate_id for result in summary.results}
    assert summary.blocking_count >= 2
    assert "missing_context_view" in gate_ids
    assert "unclassified_data_stores" in gate_ids
    assert "store_to_store_flows" in gate_ids
    assert "generic_flow_labels" in gate_ids
    assert "missing_security_metadata" in gate_ids


def test_evaluate_quality_gates_flags_missing_lifecycle_stage_for_sensitive_flow():
    dfd = _sample_dfd()
    dfd.edges[0].properties = {
        "protocol": "HTTPS",
        "data_payload": "Customer profile request",
        "data_classification": "Highly Restricted",
        "encryption_in_transit": True,
        "carries_pii": True,
    }

    summary = evaluate_quality_gates(dfd, views=build_default_views(dfd))

    gate_ids = {result.gate_id for result in summary.results}
    assert "sensitive_flows_missing_lifecycle_stage" in gate_ids


def test_build_default_views_treats_custom_public_exposure_as_context_node():
    dfd = _sample_dfd()
    dfd.nodes[1].properties["network_exposure"] = "public edge partner"

    views = build_default_views(dfd)
    context_view = views[0]

    assert dfd.nodes[1].id in context_view.node_ids


def test_quality_gate_does_not_flag_custom_auth_on_public_process():
    dfd = _sample_dfd()
    dfd.nodes[1].properties["network_exposure"] = "public edge partner"
    dfd.nodes[1].properties["authentication_type"] = "fido2"

    summary = evaluate_quality_gates(dfd, views=build_default_views(dfd))

    gate_ids = {result.gate_id for result in summary.results}
    assert "internet_process_without_auth" not in gate_ids


def test_sync_default_views_preserves_valid_decomposition_view():
    dfd = _sample_dfd()
    defaults = build_default_views(dfd)
    container_view = defaults[1]
    parent_node_id = dfd.nodes[1].id
    decomposition_id = uuid.uuid4()
    child_process_id = uuid.uuid4()

    raw_views = [
        *(view.model_dump(mode="json") for view in defaults),
        {
            "id": str(decomposition_id),
            "view_type": "decomposition",
            "name": "API Gateway Decomposition",
            "node_ids": [],
            "edge_ids": [],
            "boundary_ids": [],
            "layout_snapshot": {"nodes": [], "boundaries": []},
            "parent_view_id": str(container_view.id),
            "parent_node_id": str(parent_node_id),
            "graph": {
                "nodes": [
                    {
                        "id": str(child_process_id),
                        "node_type": "process",
                        "name": "Gateway Handler",
                        "position_x": 120,
                        "position_y": 140,
                        "trust_boundary_id": None,
                        "properties": {},
                    }
                ],
                "edges": [],
                "trust_boundaries": [],
            },
            "is_auto_generated": False,
        },
    ]

    synced = sync_default_views(raw_views, dfd)

    synced_decomposition = next(
        view for view in synced if view["view_type"] == "decomposition"
    )
    assert synced_decomposition["id"] == str(decomposition_id)
    assert synced_decomposition["parent_view_id"] == str(container_view.id)
    assert synced_decomposition["parent_node_id"] == str(parent_node_id)
    assert synced_decomposition["graph"]["nodes"][0]["name"] == "Gateway Handler"


def test_sync_default_views_preserves_custom_workspace_view():
    dfd = _sample_dfd()
    defaults = build_default_views(dfd)
    workspace_id = uuid.uuid4()
    workspace_node_id = uuid.uuid4()

    raw_views = [
        *(view.model_dump(mode="json") for view in defaults),
        {
            "id": str(workspace_id),
            "view_type": "workspace",
            "name": "Settlement Flow",
            "node_ids": [],
            "edge_ids": [],
            "boundary_ids": [],
            "layout_snapshot": {"nodes": [], "boundaries": []},
            "parent_view_id": None,
            "parent_node_id": None,
            "graph": {
                "nodes": [
                    {
                        "id": str(workspace_node_id),
                        "node_type": "process",
                        "name": "Settlement Worker",
                        "position_x": 120,
                        "position_y": 140,
                        "trust_boundary_id": None,
                        "properties": {},
                    }
                ],
                "edges": [],
                "trust_boundaries": [],
            },
            "is_auto_generated": False,
        },
    ]

    synced = sync_default_views(raw_views, dfd)

    synced_workspace = next(
        view for view in synced if view["view_type"] == "workspace"
    )
    assert synced_workspace["id"] == str(workspace_id)
    assert synced_workspace["name"] == "Settlement Flow"
    assert synced_workspace["graph"]["nodes"][0]["name"] == "Settlement Worker"


# ===========================================================================
# New quality gates (added in 017 DFD quality improvements)
# ===========================================================================


def _make_node(node_type: str, name: str = "Node", boundary_id=None, **props) -> DFDNodeResponse:
    return DFDNodeResponse(
        id=uuid.uuid4(),
        node_type=node_type,
        name=name,
        position_x=0,
        position_y=0,
        trust_boundary_id=boundary_id,
        properties=props,
    )


def _make_edge(source: DFDNodeResponse, target: DFDNodeResponse, label: str = "flow", **props) -> DFDEdgeResponse:
    return DFDEdgeResponse(
        id=uuid.uuid4(),
        source_node_id=source.id,
        target_node_id=target.id,
        label=label,
        properties=props,
    )


class TestMissingExternalBoundaryGate:
    def test_fires_when_internet_facing_node_has_no_boundary(self):
        node = _make_node("api_gateway", "Public API", internet_facing=True)
        ext = _make_node("external_entity", "Customer")
        edge = _make_edge(ext, node, "request")
        dfd = DFDResponse(nodes=[node, ext], edges=[edge], trust_boundaries=[])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "missing_external_boundary" in gate_ids

    def test_does_not_fire_when_internet_facing_node_is_in_boundary(self):
        boundary_id = uuid.uuid4()
        node = _make_node("api_gateway", "Public API", boundary_id=boundary_id, internet_facing=True)
        ext = _make_node("external_entity", "Customer")
        edge = _make_edge(ext, node, "request")
        boundary = TrustBoundaryResponse(
            id=boundary_id, name="DMZ", node_ids=[node.id],
            position_x=0, position_y=0, width=200, height=100,
        )
        dfd = DFDResponse(nodes=[node, ext], edges=[edge], trust_boundaries=[boundary])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "missing_external_boundary" not in gate_ids


class TestNoLoggingPathGate:
    def test_fires_when_sensitive_node_but_no_log_destination(self):
        sensitive = _make_node("data_store", "Customer DB", handles_pii=True,
                               data_classification="Restricted")
        proc = _make_node("process", "API Service")
        edge = _make_edge(proc, sensitive, "write PII")
        dfd = DFDResponse(nodes=[sensitive, proc], edges=[edge], trust_boundaries=[])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "no_logging_path" in gate_ids

    def test_does_not_fire_when_log_node_with_incoming_edge_exists(self):
        sensitive = _make_node("data_store", "Customer DB", handles_pii=True,
                               data_classification="Restricted")
        proc = _make_node("process", "API Service")
        siem = _make_node("data_store", "Splunk SIEM")
        data_edge = _make_edge(proc, sensitive, "write PII")
        log_edge = _make_edge(proc, siem, "audit log")
        dfd = DFDResponse(nodes=[sensitive, proc, siem], edges=[data_edge, log_edge], trust_boundaries=[])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "no_logging_path" not in gate_ids


class TestCDEIsolationGate:
    def test_fires_when_financial_node_but_no_cde_boundary(self):
        fin_node = _make_node("data_store", "Payment DB", handles_financial_data=True,
                              data_classification="Restricted")
        proc = _make_node("process", "Payment Service")
        edge = _make_edge(proc, fin_node, "store PAN")
        boundary = TrustBoundaryResponse(
            id=uuid.uuid4(), name="Internal Network", node_ids=[fin_node.id, proc.id],
            position_x=0, position_y=0, width=200, height=100,
        )
        dfd = DFDResponse(nodes=[fin_node, proc], edges=[edge], trust_boundaries=[boundary])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "cde_isolation" in gate_ids

    def test_does_not_fire_when_cde_boundary_exists(self):
        fin_node = _make_node("data_store", "Payment DB", handles_financial_data=True,
                              data_classification="Restricted")
        proc = _make_node("process", "Payment Service")
        edge = _make_edge(proc, fin_node, "store PAN")
        boundary = TrustBoundaryResponse(
            id=uuid.uuid4(), name="PCI CDE Zone", node_ids=[fin_node.id, proc.id],
            position_x=0, position_y=0, width=200, height=100,
        )
        dfd = DFDResponse(nodes=[fin_node, proc], edges=[edge], trust_boundaries=[boundary])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "cde_isolation" not in gate_ids

    def test_fires_on_stores_credentials_node_without_cde_boundary(self):
        cred_node = _make_node("data_store", "Auth DB", stores_credentials=True)
        proc = _make_node("process", "Auth Service")
        edge = _make_edge(proc, cred_node, "store creds")
        dfd = DFDResponse(nodes=[cred_node, proc], edges=[edge], trust_boundaries=[])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "cde_isolation" in gate_ids


class TestThirdPartyBoundaryGate:
    def test_fires_when_external_service_has_no_boundary(self):
        ext_svc = _make_node("external_entity", "Stripe Payment API")
        proc = _make_node("process", "Payment Service")
        edge = _make_edge(proc, ext_svc, "charge card")
        dfd = DFDResponse(nodes=[ext_svc, proc], edges=[edge], trust_boundaries=[])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "third_party_boundary" in gate_ids

    def test_does_not_fire_for_human_customer_node(self):
        customer = _make_node("external_entity", "Customer Browser")
        proc = _make_node("process", "Web App")
        edge = _make_edge(customer, proc, "HTTP request")
        dfd = DFDResponse(nodes=[customer, proc], edges=[edge], trust_boundaries=[])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "third_party_boundary" not in gate_ids

    def test_does_not_fire_when_service_in_boundary(self):
        boundary_id = uuid.uuid4()
        ext_svc = _make_node("external_entity", "Stripe Payment API", boundary_id=boundary_id)
        proc = _make_node("process", "Payment Service")
        edge = _make_edge(proc, ext_svc, "charge card")
        boundary = TrustBoundaryResponse(
            id=boundary_id, name="Third-Party APIs", node_ids=[ext_svc.id],
            position_x=0, position_y=0, width=200, height=100,
        )
        dfd = DFDResponse(nodes=[ext_svc, proc], edges=[edge], trust_boundaries=[boundary])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "third_party_boundary" not in gate_ids


class TestKeyColocationGate:
    def test_fires_when_vault_and_protected_data_in_same_boundary(self):
        boundary_id = uuid.uuid4()
        vault = _make_node("data_store", "HashiCorp Vault", boundary_id=boundary_id,
                           stores_secrets=True)
        pii_db = _make_node("data_store", "Customer PII DB", boundary_id=boundary_id,
                            handles_pii=True, data_classification="Restricted")
        proc = _make_node("process", "App Server")
        edge1 = _make_edge(proc, vault, "get key")
        edge2 = _make_edge(proc, pii_db, "read PII")
        boundary = TrustBoundaryResponse(
            id=boundary_id, name="Internal", node_ids=[vault.id, pii_db.id, proc.id],
            position_x=0, position_y=0, width=300, height=150,
        )
        dfd = DFDResponse(nodes=[vault, pii_db, proc], edges=[edge1, edge2], trust_boundaries=[boundary])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "key_colocation" in gate_ids

    def test_does_not_fire_when_vault_in_separate_boundary(self):
        vault_boundary_id = uuid.uuid4()
        data_boundary_id = uuid.uuid4()
        vault = _make_node("data_store", "HashiCorp Vault", boundary_id=vault_boundary_id,
                           stores_secrets=True)
        pii_db = _make_node("data_store", "Customer PII DB", boundary_id=data_boundary_id,
                            handles_pii=True, data_classification="Restricted")
        proc = _make_node("process", "App Server")
        edge1 = _make_edge(proc, vault, "get key")
        edge2 = _make_edge(proc, pii_db, "read PII")
        b1 = TrustBoundaryResponse(
            id=vault_boundary_id, name="KMS Zone", node_ids=[vault.id],
            position_x=0, position_y=0, width=200, height=100,
        )
        b2 = TrustBoundaryResponse(
            id=data_boundary_id, name="Data Zone", node_ids=[pii_db.id, proc.id],
            position_x=300, position_y=0, width=200, height=100,
        )
        dfd = DFDResponse(nodes=[vault, pii_db, proc], edges=[edge1, edge2], trust_boundaries=[b1, b2])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "key_colocation" not in gate_ids


class TestAdminPathUnmarkedGate:
    def test_fires_when_admin_node_but_no_admin_boundary(self):
        admin_node = _make_node("process", "Admin Console", privilege_level="admin",
                                data_classification="Restricted")
        proc = _make_node("process", "API Service")
        edge = _make_edge(proc, admin_node, "admin call")
        boundary = TrustBoundaryResponse(
            id=uuid.uuid4(), name="Internal Network", node_ids=[admin_node.id, proc.id],
            position_x=0, position_y=0, width=200, height=100,
        )
        dfd = DFDResponse(nodes=[admin_node, proc], edges=[edge], trust_boundaries=[boundary])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "admin_path_unmarked" in gate_ids

    def test_fires_for_system_and_privileged_level_too(self):
        sys_node = _make_node("process", "DB Replication Job", privilege_level="system",
                              data_classification="Restricted")
        proc = _make_node("process", "Scheduler")
        edge = _make_edge(proc, sys_node, "trigger")
        dfd = DFDResponse(nodes=[sys_node, proc], edges=[edge], trust_boundaries=[])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "admin_path_unmarked" in gate_ids

    def test_does_not_fire_when_management_boundary_exists(self):
        admin_node = _make_node("process", "Admin Console", privilege_level="admin",
                                data_classification="Restricted")
        proc = _make_node("process", "API Service")
        edge = _make_edge(proc, admin_node, "admin call")
        boundary = TrustBoundaryResponse(
            id=uuid.uuid4(), name="Admin / Management Plane", node_ids=[admin_node.id, proc.id],
            position_x=0, position_y=0, width=200, height=100,
        )
        dfd = DFDResponse(nodes=[admin_node, proc], edges=[edge], trust_boundaries=[boundary])
        summary = evaluate_quality_gates(dfd, views=[])
        gate_ids = {r.gate_id for r in summary.results}
        assert "admin_path_unmarked" not in gate_ids

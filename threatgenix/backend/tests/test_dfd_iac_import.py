from __future__ import annotations

import uuid

from app.schemas.dfd import DFDNodeResponse, DFDResponse, TrustBoundaryResponse
from app.schemas.environment_evidence import IacEvidence
from app.services.dfd_iac_import import (
    DATA_BOUNDARY_NAME,
    EDGE_BOUNDARY_NAME,
    build_iac_import_draft,
    merge_iac_import_into_dfd,
)


def _iac_evidence() -> IacEvidence:
    return IacEvidence(
        source_type="archive",
        filename="infra.zip",
        reference="prod/payments",
        resource_count=6,
        resource_types=[
            "Deployment",
            "Service",
            "aws_db_instance",
            "aws_iam_role",
            "aws_security_group",
        ],
        resource_names=[
            "Deployment:payments-api",
            "Service:payments-public",
            "aws_db_instance.payments",
            "aws_iam_role.app_role",
            "aws_security_group.public_api",
        ],
        public_exposure=["deployment.yaml:payments-public: public load balancer or public service"],
        iam_bindings=["main.tf: IAM role, policy, or trust binding"],
        network_paths=["deployment.yaml:payments-public: network entry or routing component"],
        secret_refs=["main.tf: secret or key reference"],
        warnings=[],
        parsed_at="2026-04-16T00:00:00Z",
    )


def test_build_iac_import_draft_generates_nodes_edges_and_boundaries():
    draft = build_iac_import_draft(_iac_evidence())

    assert draft.imported_resource_count == 6
    assert draft.semantic_resource_count == 4
    node_names = {node.name for node in draft.dfd.nodes}
    assert "Internet" in node_names
    assert "payments-public" in node_names
    assert "payments-api" in node_names
    assert "payments" in node_names
    assert "app-role" in node_names

    boundary_names = {boundary.name for boundary in draft.dfd.trust_boundaries}
    assert EDGE_BOUNDARY_NAME in boundary_names
    assert DATA_BOUNDARY_NAME in boundary_names
    assert draft.dfd.edges


def test_merge_iac_import_into_existing_dfd_updates_matching_nodes():
    existing_boundary_id = uuid.uuid4()
    existing_node_id = uuid.uuid4()
    current = DFDResponse(
        nodes=[
            DFDNodeResponse(
                id=existing_node_id,
                node_type="process",
                name="payments-api",
                position_x=100,
                position_y=50,
                trust_boundary_id=existing_boundary_id,
                scan_target_url=None,
                scan_target_ports=None,
                properties={"internet_facing": False},
                security_controls=[],
            )
        ],
        edges=[],
        trust_boundaries=[
            TrustBoundaryResponse(
                id=existing_boundary_id,
                name="Existing Boundary",
                node_ids=[existing_node_id],
                position_x=40,
                position_y=20,
                width=260,
                height=160,
                boundary_type="network",
                parent_boundary_id=None,
            )
        ],
    )

    merged, summary = merge_iac_import_into_dfd(current, build_iac_import_draft(_iac_evidence(), x_offset=380))

    assert summary.matched_existing_nodes >= 1
    assert summary.created_nodes >= 1
    payments_api = next(node for node in merged.nodes if node.id == existing_node_id)
    assert payments_api.node_type == "container"
    assert payments_api.trust_boundary_id == existing_boundary_id
    assert any(boundary.name == EDGE_BOUNDARY_NAME for boundary in merged.trust_boundaries)
    assert merged.edges

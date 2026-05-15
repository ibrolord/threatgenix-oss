"""DFD API contract coverage for release-critical modeling flows."""

from __future__ import annotations

import json
import uuid


def _create_threat_model(client, name: str) -> str:
    response = client.post(
        "/api/threat-models",
        json={
            "system_name": name,
            "description": "DFD contract regression harness.",
            "data_classification": "Internal",
            "deployment_model": "cloud",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _repository_seed_evidence() -> dict:
    return {
        "source_type": "archive",
        "filename": "repo.zip",
        "file_count": 4,
        "dfd_seed_suggestions": [
            {
                "id": "repo-seed-api-layer",
                "node_type": "process",
                "label": "API layer",
                "rationale": "Repository route definitions indicate an API surface.",
                "source_refs": ["GET /api/reviews"],
                "confidence": 0.82,
            },
            {
                "id": "repo-seed-postgresql",
                "node_type": "data_store",
                "label": "PostgreSQL",
                "rationale": "Repository dependency hints indicate a data store.",
                "source_refs": ["PostgreSQL"],
                "confidence": 0.72,
            },
            {
                "id": "repo-seed-sqs",
                "node_type": "queue",
                "label": "Amazon SQS",
                "rationale": "Repository publisher hints indicate asynchronous flow.",
                "source_refs": ["Amazon SQS"],
                "confidence": 0.7,
            },
        ],
        "dfd_seed_flow_suggestions": [
            {
                "id": "repo-flow-api-postgresql",
                "source_seed_id": "repo-seed-api-layer",
                "target_seed_id": "repo-seed-postgresql",
                "label": "reads/writes persisted data",
                "rationale": "Repository data-store hints indicate persisted application state.",
                "source_refs": ["POST /payments/charge"],
                "confidence": 0.68,
                "directionality": "request",
                "transfer_mode": "synchronous",
                "lifecycle_stage": "storage",
            },
            {
                "id": "repo-flow-api-sqs",
                "source_seed_id": "repo-seed-api-layer",
                "target_seed_id": "repo-seed-sqs",
                "label": "publishes async work",
                "rationale": "Repository queue clients indicate asynchronous work.",
                "source_refs": ["Amazon SQS publisher/client"],
                "confidence": 0.66,
                "directionality": "event",
                "transfer_mode": "asynchronous",
                "lifecycle_stage": "notification",
            },
        ],
        "dfd_seed_boundary_suggestions": [
            {
                "id": "repo-boundary-data-tier",
                "name": "Data Tier Boundary",
                "boundary_type": "regulatory",
                "seed_ids": ["repo-seed-postgresql"],
                "rationale": "Repository data-store hints indicate a data boundary.",
                "source_refs": ["PostgreSQL"],
                "confidence": 0.66,
            },
            {
                "id": "repo-boundary-async-messaging",
                "name": "Async Messaging Boundary",
                "boundary_type": "cloud",
                "seed_ids": ["repo-seed-sqs"],
                "rationale": "Repository queue hints indicate asynchronous infrastructure.",
                "source_refs": ["Amazon SQS"],
                "confidence": 0.62,
            },
        ],
        "parsed_at": "2026-05-01T00:00:00Z",
    }


def test_dfd_quick_add_and_view_regeneration_contract(client):
    model_id = _create_threat_model(client, "DFD Quick Add Contract")
    api_node_id = str(uuid.uuid4())
    customer_store_id = str(uuid.uuid4())

    save_response = client.put(
        f"/api/threat-models/{model_id}/dfd",
        json={
            "nodes": [
                {
                    "id": api_node_id,
                    "node_type": "process",
                    "name": "API Gateway",
                    "position_x": 200,
                    "position_y": 100,
                    "properties": {
                        "authentication_type": "oauth2",
                        "network_exposure": "internet",
                    },
                }
            ],
            "edges": [],
            "trust_boundaries": [],
        },
    )
    assert save_response.status_code == 200

    quick_add_response = client.post(
        f"/api/threat-models/{model_id}/dfd/quick-add",
        json={
            "origin_node_id": api_node_id,
            "origin_handle": "source",
            "node": {
                "id": customer_store_id,
                "node_type": "data_store",
                "name": "Customer Store",
                "position_x": 520,
                "position_y": 120,
                "properties": {
                    "data_classification": "Restricted",
                    "encryption_at_rest": "hsm",
                },
            },
            "edge": {
                "label": "customer lookup",
                "properties": {
                    "protocol": "SQL",
                    "directionality": "request",
                    "data_classification": "Restricted",
                },
            },
        },
    )
    assert quick_add_response.status_code == 201
    quick_add = quick_add_response.json()
    assert quick_add["node"]["id"] == customer_store_id
    assert quick_add["edge"]["source_node_id"] == api_node_id
    assert quick_add["edge"]["target_node_id"] == customer_store_id
    assert quick_add["edge"]["properties"]["protocol"] == "SQL"

    views_response = client.post(f"/api/threat-models/{model_id}/dfd/views/regenerate")
    assert views_response.status_code == 200
    views = views_response.json()
    view_types = {view["view_type"] for view in views}
    assert {"context", "container", "data_lifecycle"}.issubset(view_types)
    system_view = next(view for view in views if view["view_type"] == "container")
    assert api_node_id in system_view["node_ids"]
    assert customer_store_id in system_view["node_ids"]

    decomposition_response = client.post(
        f"/api/threat-models/{model_id}/dfd/views/decompositions",
        json={
            "parent_node_id": api_node_id,
            "parent_view_id": system_view["id"],
            "name": "API Gateway Internals",
        },
    )
    assert decomposition_response.status_code == 201
    decomposition = decomposition_response.json()
    assert decomposition["view_type"] == "decomposition"
    assert decomposition["parent_node_id"] == api_node_id
    assert decomposition["graph"]["nodes"]
    assert "API Gateway Internal" in {
        node["name"] for node in decomposition["graph"]["nodes"]
    }

    workspace_response = client.post(
        f"/api/threat-models/{model_id}/dfd/views/workspaces",
        json={"name": "Payments Workspace", "source_view_id": system_view["id"]},
    )
    assert workspace_response.status_code == 201
    workspace = workspace_response.json()
    assert workspace["view_type"] == "workspace"
    assert {node["name"] for node in workspace["graph"]["nodes"]} == {
        "API Gateway",
        "Customer Store",
    }

    workspace_dfd_response = client.get(
        f"/api/threat-models/{model_id}/dfd?view_id={workspace['id']}"
    )
    assert workspace_dfd_response.status_code == 200
    workspace_dfd = workspace_dfd_response.json()
    assert {node["name"] for node in workspace_dfd["nodes"]} == {
        "API Gateway",
        "Customer Store",
    }


def test_repository_suggestion_preview_and_apply_contract(client, db_conn):
    model_id = _create_threat_model(client, "DFD Repository Suggestion Contract")
    api_node_id = str(uuid.uuid4())

    save_response = client.put(
        f"/api/threat-models/{model_id}/dfd",
        json={
            "nodes": [
                {
                    "id": api_node_id,
                    "node_type": "process",
                    "name": "API layer",
                    "position_x": 160,
                    "position_y": 100,
                    "properties": {"runtime_type": "service"},
                }
            ],
            "edges": [],
            "trust_boundaries": [],
        },
    )
    assert save_response.status_code == 200

    cur = db_conn.cursor()
    cur.execute(
        "UPDATE threat_models SET repository_evidence = %s::jsonb WHERE id = %s",
        (json.dumps(_repository_seed_evidence()), model_id),
    )
    cur.close()

    preview_response = client.get(
        f"/api/threat-models/{model_id}/dfd/repository-suggestions"
    )
    assert preview_response.status_code == 200
    preview = preview_response.json()
    assert preview["existing_node_count"] == 1
    assert preview["unmatched_suggestion_count"] == 2
    assert preview["inferred_flow_count"] == 2
    assert preview["inferred_boundary_count"] == 2
    previews_by_id = {
        suggestion["suggestion_id"]: suggestion for suggestion in preview["suggestions"]
    }
    assert previews_by_id["repo-seed-api-layer"]["match_status"] == "matched_existing"
    assert previews_by_id["repo-seed-api-layer"]["matched_node_id"] == api_node_id
    assert previews_by_id["repo-seed-sqs"]["node_type"] == "managed_service"

    apply_response = client.post(
        f"/api/threat-models/{model_id}/dfd/repository-suggestions/apply",
        json={
            "suggestion_ids": [
                "repo-seed-postgresql",
                "repo-seed-sqs",
                "missing-seed",
            ]
        },
    )
    assert apply_response.status_code == 200
    applied = apply_response.json()
    assert applied["summary"]["requested_suggestion_count"] == 3
    assert applied["summary"]["created_nodes"] == 2
    assert applied["summary"]["created_edges"] == 2
    assert applied["summary"]["created_boundaries"] == 2
    assert applied["summary"]["skipped_suggestions"] == ["missing-seed"]

    nodes_by_name = {node["name"]: node for node in applied["dfd"]["nodes"]}
    assert {"API layer", "PostgreSQL", "Amazon SQS"}.issubset(nodes_by_name)
    assert (
        nodes_by_name["PostgreSQL"]["properties"]["repository_seed_id"]
        == "repo-seed-postgresql"
    )
    assert nodes_by_name["Amazon SQS"]["properties"]["component_shape"] == "queue"

    edge_labels = {edge["label"] for edge in applied["dfd"]["edges"]}
    assert edge_labels == {"reads/writes persisted data", "publishes async work"}
    boundary_names = {
        boundary["name"] for boundary in applied["dfd"]["trust_boundaries"]
    }
    assert boundary_names == {"Async Messaging Boundary", "Data Tier Boundary"}

    persisted_response = client.get(f"/api/threat-models/{model_id}/dfd")
    assert persisted_response.status_code == 200
    persisted = persisted_response.json()
    assert {node["name"] for node in persisted["nodes"]} == {
        "API layer",
        "PostgreSQL",
        "Amazon SQS",
    }

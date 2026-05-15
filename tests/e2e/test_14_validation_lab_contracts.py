"""Validation Lab safe evidence-flow contracts."""

from __future__ import annotations

import uuid


def _create_validation_model(client) -> tuple[str, str]:
    response = client.post(
        "/api/threat-models",
        json={
            "system_name": "Validation Lab Contract App",
            "description": "Authentication service with customer login traffic.",
            "data_classification": "Confidential",
            "deployment_model": "cloud",
        },
    )
    assert response.status_code == 201
    model_id = response.json()["id"]
    customer_id = str(uuid.uuid4())
    auth_node_id = str(uuid.uuid4())

    dfd_response = client.put(
        f"/api/threat-models/{model_id}/dfd",
        json={
            "nodes": [
                {
                    "id": customer_id,
                    "node_type": "external_entity",
                    "name": "Banking Customer",
                    "position_x": 0,
                    "position_y": 100,
                    "properties": {
                        "authentication_type": "oauth2",
                        "network_exposure": "internet",
                        "trust_level": "untrusted",
                    },
                },
                {
                    "id": auth_node_id,
                    "node_type": "process",
                    "name": "Authentication Service",
                    "position_x": 300,
                    "position_y": 100,
                    "properties": {
                        "authentication_type": "oauth2",
                        "network_exposure": "internet",
                        "input_validation": "strict",
                        "logging_level": "audit",
                        "handles_sensitive_data": True,
                    },
                },
            ],
            "edges": [
                {
                    "source_node_id": customer_id,
                    "target_node_id": auth_node_id,
                    "label": "login request",
                    "properties": {
                        "protocol": "HTTPS",
                        "directionality": "request",
                        "data_classification": "Confidential",
                    },
                }
            ],
            "trust_boundaries": [],
        },
    )
    assert dfd_response.status_code == 200

    generate_response = client.post(f"/api/threat-models/{model_id}/threats/generate")
    assert generate_response.status_code == 200
    assert generate_response.json()["threats"]
    return model_id, auth_node_id


def test_try_sandbox_persists_synthetic_evidence_and_binding_flow(client):
    model_id, auth_node_id = _create_validation_model(client)

    initial_lab_response = client.get(f"/api/threat-models/{model_id}/validation-lab")
    assert initial_lab_response.status_code == 200
    initial_lab = initial_lab_response.json()
    assert initial_lab["runtime"]["mode"] == "try_sandbox"
    assert initial_lab["runtime"]["try_sandbox_enabled"] is True
    assert initial_lab["runtime"]["run_submission_enabled"] is False

    sandbox_response = client.post(
        f"/api/threat-models/{model_id}/validation-lab/try-sandbox"
    )
    assert sandbox_response.status_code == 201
    sandbox_scan = sandbox_response.json()
    scan_id = sandbox_scan["id"]
    assert sandbox_scan["status"] == "completed"
    assert sandbox_scan["tool_name"] == "semgrep"
    assert sandbox_scan["target_type"] == "repository_path"
    assert sandbox_scan["targets"]["try_sandbox"].startswith("/try-sandbox/")
    assert sandbox_scan["finding_count"] > 0

    detail_response = client.get(f"/api/threat-models/{model_id}/scans/{scan_id}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert len(detail["findings"]) == sandbox_scan["finding_count"]
    finding = detail["findings"][0]
    assert finding["tool_name"] == "semgrep"
    assert finding["deterministic"] is True
    assert finding["evidence_origin"] == "try_sandbox"
    assert finding["synthetic"] is True

    artifacts = detail["execution_artifacts"]
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact["source"] == "ingest"
    assert artifact["sandbox_mode"] == "try_sandbox"
    assert artifact["sandboxed"] is False
    assert artifact["command"] == []
    assert artifact["command_redacted"] is True
    assert artifact["returncode"] == 0
    assert artifact["output_limit_exceeded"] is False
    assert "no scanner executed" in artifact["policy_decision"]
    assert len(artifact["output_sha256"]) == 64

    bind_response = client.post(
        f"/api/threat-models/{model_id}/validation-lab/evidence/{finding['id']}/bind",
        json={"target_node_id": auth_node_id},
    )
    assert bind_response.status_code == 200
    binding = bind_response.json()
    assert binding["target_node_id"] == auth_node_id
    assert binding["target_node_name"] == "Authentication Service"
    assert binding["target_binding"] == "node_bound"
    assert binding["message"].startswith("Evidence bound to Authentication Service")

    rebound_response = client.get(f"/api/threat-models/{model_id}/scans/{scan_id}")
    assert rebound_response.status_code == 200
    rebound = rebound_response.json()
    assert list(rebound["targets"].keys()) == [auth_node_id]
    assert rebound["targets"][auth_node_id].startswith("path:")

    lab_response = client.get(f"/api/threat-models/{model_id}/validation-lab")
    assert lab_response.status_code == 200
    lab = lab_response.json()
    assert any(scan["id"] == scan_id for scan in lab["recent_scans"])
    ledger = next(entry for entry in lab["evidence_ledger"] if entry["scan_id"] == scan_id)
    assert ledger["status"] == "completed"
    assert ledger["tool_name"] == "semgrep"
    assert ledger["artifact_count"] == 1
    assert ledger["deterministic_finding_count"] == sandbox_scan["finding_count"]
    assert ledger["target_binding"] == "node_bound"
    assert len(ledger["output_sha256"]) == 64

"""AI enhancement API contracts using the e2e Bedrock stub."""

from __future__ import annotations

import uuid


def _create_ai_ready_threat_model(client) -> str:
    response = client.post(
        "/api/threat-models",
        json={
            "system_name": "Northstar AI Enhancement Contract",
            "description": "Cloud banking API with transfer and ledger flows.",
            "data_classification": "Confidential",
            "regulatory_scope": ["OSFI B-13"],
            "deployment_model": "cloud",
        },
    )
    assert response.status_code == 201
    model_id = response.json()["id"]

    customer_id = str(uuid.uuid4())
    api_id = str(uuid.uuid4())
    database_id = str(uuid.uuid4())
    dfd_response = client.put(
        f"/api/threat-models/{model_id}/dfd",
        json={
            "nodes": [
                {
                    "id": customer_id,
                    "node_type": "external_entity",
                    "name": "Mobile Banking Customer",
                    "position_x": 0,
                    "position_y": 100,
                    "properties": {
                        "authentication_type": "oauth2",
                        "network_exposure": "internet",
                        "trust_level": "untrusted",
                    },
                },
                {
                    "id": api_id,
                    "node_type": "process",
                    "name": "Authenticated Banking API",
                    "position_x": 260,
                    "position_y": 100,
                    "properties": {
                        "authentication_type": "oauth2",
                        "network_exposure": "internet",
                        "input_validation": "strict",
                        "logging_level": "audit",
                        "handles_financial_data": True,
                    },
                },
                {
                    "id": database_id,
                    "node_type": "data_store",
                    "name": "Account Ledger Database",
                    "position_x": 540,
                    "position_y": 100,
                    "properties": {
                        "data_classification": "Confidential",
                        "encryption_at_rest": "transparent",
                        "backup_strategy": "geo_redundant",
                        "handles_financial_data": True,
                    },
                },
            ],
            "edges": [
                {
                    "source_node_id": customer_id,
                    "target_node_id": api_id,
                    "label": "HTTPS transfer request",
                    "properties": {
                        "protocol": "HTTPS",
                        "directionality": "request",
                        "data_classification": "Confidential",
                    },
                },
                {
                    "source_node_id": api_id,
                    "target_node_id": database_id,
                    "label": "Account ledger write",
                    "properties": {
                        "protocol": "SQL",
                        "directionality": "request",
                        "data_classification": "Confidential",
                    },
                },
            ],
            "trust_boundaries": [],
        },
    )
    assert dfd_response.status_code == 200
    return model_id


def test_analyze_uses_ai_enhancement_and_persists_ai_threat(client):
    model_id = _create_ai_ready_threat_model(client)

    rules_only_response = client.post(
        f"/api/threat-models/{model_id}/analyze",
        params={"rules_only": "true"},
    )
    assert rules_only_response.status_code == 200
    rules_only = rules_only_response.json()
    assert isinstance(rules_only["ai_skipped_reason"], str)
    rules_only_count = len(rules_only["threats"])
    assert rules_only_count > 0

    enhanced_response = client.post(f"/api/threat-models/{model_id}/analyze")
    assert enhanced_response.status_code == 200
    enhanced = enhanced_response.json()
    assert enhanced["ai_skipped_reason"] is None
    assert len(enhanced["threats"]) > rules_only_count

    ai_threats = [
        threat
        for threat in enhanced["threats"]
        if threat["source"] == "AI" and threat["ai_enhanced"] is True
    ]
    assert len(ai_threats) == 1
    ai_threat = ai_threats[0]
    assert ai_threat["rule_id"] == "AI-001"
    assert ai_threat["stride_category"] == "Spoofing"
    assert ai_threat["severity"] == "High"
    assert "Session token replay bypass" in ai_threat["description"]
    assert "OSFI B-13" in ai_threat["relevance_rationale"]
    assert ai_threat["affected_node_ids"]

    persisted_response = client.get(f"/api/threat-models/{model_id}/threats")
    assert persisted_response.status_code == 200
    persisted_ai = [
        threat
        for threat in persisted_response.json()
        if threat["source"] == "AI" and threat["rule_id"] == "AI-001"
    ]
    assert len(persisted_ai) == 1

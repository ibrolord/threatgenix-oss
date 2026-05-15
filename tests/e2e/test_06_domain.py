"""Level 6: STRIDE-NIST + Canadian banking domain sanity."""
import uuid
import pytest


@pytest.mark.order(6)
class TestDomainSanity:

    def test_stride_categories_valid(self, client, factories):
        """All generated threats must have valid STRIDE categories."""
        chain = factories.full_demo_chain()
        threats = chain["threats"]
        valid_stride = {"Spoofing", "Tampering", "Repudiation",
                        "Information Disclosure", "Denial of Service",
                        "Elevation of Privilege"}
        for t in threats:
            assert t["stride_category"] in valid_stride, \
                f"Invalid STRIDE category: {t['stride_category']}"

    def test_compliance_stride_nist_mapping_sanity(self, client):
        """Spoofing should map to IA (Identification/Authentication) family controls."""
        resp = client.get("/api/compliance-mappings/by-stride/Spoofing")
        assert resp.status_code == 200
        mappings = resp.json()
        if mappings:
            nist_ids = [m["nist_control_id"] for m in mappings]
            has_relevant = any(
                nid.startswith("IA-") or nid.startswith("AC-")
                for nid in nist_ids
            )
            assert has_relevant, \
                f"Spoofing maps to {nist_ids} -- expected IA-*/AC-* family controls"

    def test_dfd_node_types_valid(self, client, factories):
        """DFD nodes must be one of: process, data_store, external_entity."""
        model = factories.create_threat_model()
        factories.upload_pdf()
        dfd = client.get(f"/api/threat-models/{model['id']}/dfd")
        for node in dfd.json()["nodes"]:
            assert node["node_type"] in ("process", "data_store", "external_entity"), \
                f"Invalid node type: {node['node_type']}"

    def test_banking_terms_in_dfd(self, client, factories):
        """DFD from banking PDF should contain banking-relevant terms."""
        model = factories.create_threat_model(
            system_name="Northstar Bank Mobile Banking App",
        )
        factories.upload_pdf()
        dfd = client.get(f"/api/threat-models/{model['id']}/dfd")
        nodes = dfd.json()["nodes"]
        all_names = " ".join(n["name"].lower() for n in nodes)
        banking_terms = ["bank", "account", "payment", "transaction", "auth",
                         "user", "customer", "transfer", "api", "database",
                         "mobile", "web", "server", "gateway", "service",
                         "queue", "notification"]
        found = [t for t in banking_terms if t in all_names]
        assert len(found) >= 2, \
            f"Banking PDF DFD nodes contain no banking terms. Names: {all_names}"

    def test_threat_severity_valid(self, client, factories):
        """Threat severity must be one of standard values."""
        chain = factories.full_demo_chain()
        valid_severity = {"Critical", "High", "Medium", "Low"}
        for t in chain["threats"]:
            assert t["severity"] in valid_severity, \
                f"Invalid severity '{t['severity']}' on threat {t['display_id']}"

    def test_error_messages_descriptive(self, client):
        """Error responses must have specific messages, not generic 'Internal Server Error'."""
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/threat-models/{fake_id}")
        assert resp.status_code == 404
        body = resp.json()
        assert "detail" in body
        assert body["detail"] != "Internal server error", \
            "404 should have a specific message, not generic 'Internal server error'"

        resp = client.post("/api/threat-models", json={})
        assert resp.status_code == 422
        body = resp.json()
        assert "detail" in body
        assert any("system_name" in str(e) for e in body["detail"]), \
            f"Validation error should mention 'system_name': {body['detail']}"

"""Level 4: DB state verification."""
import pytest


@pytest.mark.order(4)
class TestDataIntegrity:

    def test_no_orphan_threats(self, db_conn, client, factories):
        """Every threat must belong to an existing threat model."""
        factories.full_demo_chain()
        cur = db_conn.cursor()
        cur.execute("""
            SELECT t.id FROM threats t
            LEFT JOIN threat_models tm ON t.threat_model_id = tm.id
            WHERE tm.id IS NULL
        """)
        orphans = cur.fetchall()
        cur.close()
        assert len(orphans) == 0, f"Found {len(orphans)} orphan threats"

    def test_no_orphan_dfd_nodes(self, db_conn, client, factories):
        factories.full_demo_chain()
        cur = db_conn.cursor()
        cur.execute("""
            SELECT n.id FROM dfd_nodes n
            LEFT JOIN threat_models tm ON n.threat_model_id = tm.id
            WHERE tm.id IS NULL
        """)
        orphans = cur.fetchall()
        cur.close()
        assert len(orphans) == 0, f"Found {len(orphans)} orphan DFD nodes"

    def test_threat_count_api_vs_db(self, db_conn, client, factories):
        """API threat count must match DB count exactly."""
        chain = factories.full_demo_chain()
        mid = chain["model_id"]

        api_resp = client.get(f"/api/threat-models/{mid}/threats")
        api_count = len(api_resp.json())

        cur = db_conn.cursor()
        cur.execute("SELECT COUNT(*) FROM threats WHERE threat_model_id = %s", (mid,))
        db_count = cur.fetchone()[0]
        cur.close()
        assert api_count == db_count, f"API={api_count}, DB={db_count}"

    def test_triage_dismiss_requires_reason(self, client, factories):
        """Dismissing without a reason must return 400, not silently accept."""
        chain = factories.full_demo_chain()
        if not chain["threats"]:
            pytest.skip("No threats")
        threat_id = chain["threats"][0]["id"]
        resp = client.patch(
            f"/api/threat-models/{chain['model_id']}/threats/{threat_id}/triage",
            json={"status": "Dismissed"},  # Missing dismiss_reason
        )
        assert resp.status_code == 400, \
            f"Dismiss without reason should be 400, got {resp.status_code}"

    def test_idempotent_threat_generation(self, db_conn, client, factories):
        """Generating threats twice must not double the count."""
        model = factories.create_threat_model()
        factories.upload_pdf()
        mid = model["id"]

        client.post(f"/api/threat-models/{mid}/threats/generate")
        cur = db_conn.cursor()
        cur.execute("SELECT COUNT(*) FROM threats WHERE threat_model_id = %s", (mid,))
        count1 = cur.fetchone()[0]
        cur.close()

        client.post(f"/api/threat-models/{mid}/threats/generate")
        cur = db_conn.cursor()
        cur.execute("SELECT COUNT(*) FROM threats WHERE threat_model_id = %s", (mid,))
        count2 = cur.fetchone()[0]
        cur.close()

        assert count1 == count2, f"Threat count changed on re-generate: {count1} -> {count2}"

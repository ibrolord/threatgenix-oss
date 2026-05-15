"""Level 3: Race conditions (using threads for concurrency with sync client)."""
import concurrent.futures
from collections import Counter
import pytest
import httpx
from conftest import BACKEND_BASE


@pytest.mark.order(3)
class TestConcurrency:

    def test_concurrent_threat_generation(self, client, factories):
        """Two simultaneous generate calls must not create duplicate threats."""
        model = factories.create_threat_model()
        factories.upload_pdf()
        headers = dict(client.headers)

        def gen():
            with httpx.Client(base_url=BACKEND_BASE, timeout=30, headers=headers) as c:
                return c.post(f"/api/threat-models/{model['id']}/threats/generate")

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            futures = [ex.submit(gen) for _ in range(2)]
            results = [f.result() for f in futures]

        for r in results:
            assert r.status_code == 200

        # Verify no duplicates in final state
        list_resp = client.get(f"/api/threat-models/{model['id']}/threats")
        threats = list_resp.json()
        identities = [
            (
                t["rule_id"],
                tuple(sorted(t.get("affected_node_ids") or [])),
                tuple(sorted(t.get("affected_edge_ids") or [])),
            )
            for t in threats
            if t["rule_id"]
        ]
        counts = Counter(identities)
        duplicates = [identity for identity, count in counts.items() if count > 1]
        assert not duplicates, f"Duplicate threat identities after concurrent generate: {duplicates}"

    def test_concurrent_triage(self, client, factories):
        """Two simultaneous triage calls on the same threat must not corrupt state."""
        chain = factories.full_demo_chain()
        threats = chain["threats"]
        if not threats:
            pytest.skip("No threats generated to triage")
        threat_id = threats[0]["id"]
        model_id = chain["model_id"]
        headers = dict(client.headers)

        def triage_accept():
            with httpx.Client(base_url=BACKEND_BASE, timeout=30, headers=headers) as c:
                return c.patch(
                    f"/api/threat-models/{model_id}/threats/{threat_id}/triage",
                    json={"status": "Accepted"},
                )

        def triage_dismiss():
            with httpx.Client(base_url=BACKEND_BASE, timeout=30, headers=headers) as c:
                return c.patch(
                    f"/api/threat-models/{model_id}/threats/{threat_id}/triage",
                    json={"status": "Dismissed", "dismiss_reason": "Low risk"},
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f1 = ex.submit(triage_accept)
            f2 = ex.submit(triage_dismiss)
            r1 = f1.result()
            r2 = f2.result()

        assert r1.status_code == 200
        assert r2.status_code == 200

        # Final state must be one of the two, not corrupted
        final = client.get(f"/api/threat-models/{model_id}/threats")
        t = next(x for x in final.json() if x["id"] == str(threat_id))
        assert t["status"] in ("Accepted", "Dismissed"), f"Corrupted status: {t['status']}"

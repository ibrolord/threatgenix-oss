"""Level 5: Timing budgets."""
import time
import pytest

# Performance budgets (seconds)
BUDGET_CREATE_MODEL = 2
BUDGET_GENERATE_THREATS = 5
BUDGET_FULL_PIPELINE = 60


@pytest.mark.order(5)
class TestPerformance:

    def test_create_model_under_budget(self, client):
        start = time.monotonic()
        resp = client.post("/api/threat-models", json={
            "system_name": "Perf Test",
            "description": "x",
            "data_classification": "Public",
        })
        elapsed = time.monotonic() - start
        assert resp.status_code == 201
        assert elapsed < BUDGET_CREATE_MODEL, \
            f"create_model took {elapsed:.2f}s, budget is {BUDGET_CREATE_MODEL}s"

    def test_rules_engine_under_budget(self, client, factories):
        model = factories.create_threat_model()
        factories.upload_pdf()
        start = time.monotonic()
        resp = client.post(
            f"/api/threat-models/{model['id']}/threats/generate"
        )
        elapsed = time.monotonic() - start
        assert resp.status_code == 200
        assert elapsed < BUDGET_GENERATE_THREATS, \
            f"rules engine took {elapsed:.2f}s, budget is {BUDGET_GENERATE_THREATS}s"

    def test_full_pipeline_under_budget(self, client, factories):
        """Critical path: create -> upload -> generate threats."""
        start = time.monotonic()
        model = factories.create_threat_model()
        factories.upload_pdf()
        client.post(f"/api/threat-models/{model['id']}/threats/generate")
        elapsed = time.monotonic() - start
        assert elapsed < BUDGET_FULL_PIPELINE, \
            f"Full pipeline took {elapsed:.2f}s, budget is {BUDGET_FULL_PIPELINE}s"

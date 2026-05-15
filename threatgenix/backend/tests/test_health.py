import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_health_check():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert body["api_title"] == "ThreatGenix"
    assert body["runtime_name"] == "threatgenix"
    assert body["deployment_profile"] == "local"


@pytest.mark.asyncio
async def test_health_check_reports_schema_not_ready():
    previous_ready = getattr(app.state, "schema_ready", True)
    previous_error = getattr(app.state, "schema_error", None)
    app.state.schema_ready = False
    app.state.schema_error = "missing required database columns: threat_models.review_state"

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/health")
    finally:
        app.state.schema_ready = previous_ready
        app.state.schema_error = previous_error

    assert response.status_code == 503
    assert response.json() == {
        "status": "degraded",
        "detail": "missing required database columns: threat_models.review_state",
    }

import pytest
from httpx import ASGITransport, AsyncClient, Response

from app.main import app


EXPECTED_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "x-xss-protection": "1; mode=block",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "content-security-policy": "default-src 'self'; script-src 'none'; object-src 'none'",
}


def _assert_security_headers(response: Response) -> None:
    for name, value in EXPECTED_SECURITY_HEADERS.items():
        assert response.headers[name] == value


async def _get(path: str, *, base_url: str = "http://test") -> Response:
    previous_ready = getattr(app.state, "schema_ready", True)
    previous_error = getattr(app.state, "schema_error", None)
    app.state.schema_ready = True
    app.state.schema_error = None

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=base_url) as client:
            return await client.get(path)
    finally:
        app.state.schema_ready = previous_ready
        app.state.schema_error = previous_error


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/health", "/api/threat-catalog"])
async def test_security_headers_are_present_on_public_routes(path: str):
    response = await _get(path)

    assert response.status_code == 200
    _assert_security_headers(response)


@pytest.mark.asyncio
async def test_hsts_is_only_set_for_https_requests():
    http_response = await _get("/api/health", base_url="http://test")
    https_response = await _get("/api/health", base_url="https://test")

    assert "strict-transport-security" not in http_response.headers
    assert (
        https_response.headers["strict-transport-security"]
        == "max-age=63072000; includeSubDomains"
    )

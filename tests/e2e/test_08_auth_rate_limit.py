"""Live HTTP regression for auth login burst throttling."""

from __future__ import annotations

import httpx


def test_auth_login_burst_returns_429_after_limit(client: httpx.Client):
    """Invalid login bursts should authenticate-fail first, then throttle."""
    payload = {
        "email": "qa-rate-limit@example.test",
        "password": "wrong-password",
    }

    responses = [
        client.post("/api/auth/login", json=payload)
        for _ in range(12)
    ]
    statuses = [response.status_code for response in responses]

    assert statuses[:10] == [401] * 10
    assert statuses[10:] == [429, 429]
    assert "rate limit" in responses[10].text.lower()

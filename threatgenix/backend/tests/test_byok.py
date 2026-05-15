"""Tests for BYOK (Bring Your Own Key) endpoints and encryption."""

import uuid
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.user_provider_key import UserProviderKey
from app.services.auth import get_current_user
from app.services.key_encryption import decrypt_key, encrypt_key, mask_key

BASE_URL = "http://test"
API_PREFIX = "/api/llm"
FAKE_USER_A = uuid.uuid4()
FAKE_USER_B = uuid.uuid4()


class FakeUser:
    def __init__(self, user_id: uuid.UUID = FAKE_USER_A):
        self.id = user_id
        self.email = "test@example.com"
        self.full_name = "Test User"
        self.role = "admin"
        self.is_active = True


def _override_user(user_id: uuid.UUID = FAKE_USER_A):
    async def _dep():
        return FakeUser(user_id)
    return _dep


class FakeScalarResult:
    """Simulates scalars().all() and scalar_one_or_none()."""
    def __init__(self, items: list):
        self._items = items

    def scalars(self):
        return self

    def all(self):
        return self._items

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None


class FakeDB:
    """Minimal async DB mock for BYOK tests."""
    def __init__(self):
        self._keys: dict[tuple[uuid.UUID, str], UserProviderKey] = {}
        self._added: list = []

    async def execute(self, stmt):
        # Introspect the compiled statement to figure out what to return
        compiled = str(stmt)
        if "DELETE" in compiled:
            # find and remove matching keys
            keys_to_remove = []
            for k, v in self._keys.items():
                if str(k[0]) in compiled or True:
                    keys_to_remove.append(k)
            for k in keys_to_remove:
                del self._keys[k]
            return FakeScalarResult([])

        # SELECT
        for key_tuple, key_obj in self._keys.items():
            return FakeScalarResult([key_obj])
        return FakeScalarResult([])

    def add(self, obj):
        self._added.append(obj)
        self._keys[(obj.user_id, obj.provider)] = obj

    async def commit(self):
        for obj in self._added:
            if not obj.created_at:
                obj.created_at = datetime.now(timezone.utc)
            self._keys[(obj.user_id, obj.provider)] = obj
        self._added.clear()

    async def refresh(self, obj):
        if not obj.created_at:
            obj.created_at = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def reset_overrides():
    saved = dict(app.dependency_overrides)
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(saved)


# ─── Encryption round-trip tests ──────────────────────────────────


def test_encrypt_decrypt_roundtrip():
    """Encrypted key should decrypt back to the original."""
    original = "sk-test-key-12345678"
    encrypted = encrypt_key(original)
    assert encrypted != original
    assert decrypt_key(encrypted) == original


def test_encrypt_produces_different_ciphertext():
    """Two encryptions of the same key should produce different ciphertext (random nonce)."""
    original = "sk-same-key"
    e1 = encrypt_key(original)
    e2 = encrypt_key(original)
    assert e1 != e2  # different nonces
    assert decrypt_key(e1) == original
    assert decrypt_key(e2) == original


def test_mask_key_format():
    """mask_key should show only the last 4 characters."""
    assert mask_key("sk-ant-1234abcd") == "***********abcd"
    assert mask_key("short") == "*hort"
    assert mask_key("abcd") == "****"
    assert mask_key("ab") == "****"


# ─── API endpoint tests ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_keys_empty():
    """GET /api/llm/keys returns empty list when no keys stored."""
    app.dependency_overrides[get_current_user] = _override_user()

    async def override_db():
        yield FakeDB()

    app.dependency_overrides[get_db] = override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        resp = await client.get(f"{API_PREFIX}/keys")

    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_put_key_invalid_provider():
    """PUT /api/llm/keys/bedrock should return 400 (Bedrock is not BYOK)."""
    app.dependency_overrides[get_current_user] = _override_user()

    async def override_db():
        yield FakeDB()

    app.dependency_overrides[get_db] = override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        resp = await client.put(
            f"{API_PREFIX}/keys/bedrock",
            json={"api_key": "test-key"},
        )

    assert resp.status_code == 400
    assert "does not support BYOK" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_put_key_empty_api_key():
    """PUT with empty api_key should return 400."""
    app.dependency_overrides[get_current_user] = _override_user()

    async def override_db():
        yield FakeDB()

    app.dependency_overrides[get_db] = override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        resp = await client.put(
            f"{API_PREFIX}/keys/openai",
            json={"api_key": "  "},
        )

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_put_and_list_key():
    """PUT a key then GET /keys should return it masked."""
    app.dependency_overrides[get_current_user] = _override_user()

    fake_db = FakeDB()

    async def override_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        # Store key
        resp = await client.put(
            f"{API_PREFIX}/keys/openai",
            json={"api_key": "sk-test1234abcd", "model_override": "gpt-4o"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "openai"
        assert body["masked_key"].endswith("abcd")
        assert "sk-test" not in body["masked_key"]
        assert body["model_override"] == "gpt-4o"

        # List keys
        resp2 = await client.get(f"{API_PREFIX}/keys")
        assert resp2.status_code == 200
        keys = resp2.json()
        assert len(keys) == 1
        assert keys[0]["provider"] == "openai"


@pytest.mark.asyncio
async def test_delete_key():
    """DELETE /api/llm/keys/{provider} should remove the key."""
    app.dependency_overrides[get_current_user] = _override_user()

    fake_db = FakeDB()
    # Pre-populate a key
    key_obj = UserProviderKey(
        user_id=FAKE_USER_A,
        provider="anthropic",
        encrypted_key=encrypt_key("sk-ant-secret"),
        model_override=None,
    )
    key_obj.created_at = datetime.now(timezone.utc)
    fake_db._keys[(FAKE_USER_A, "anthropic")] = key_obj

    async def override_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        resp = await client.delete(f"{API_PREFIX}/keys/anthropic")

    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_test_key_no_key_stored():
    """POST /api/llm/keys/{provider}/test should 404 when no key is stored."""
    app.dependency_overrides[get_current_user] = _override_user()

    async def override_db():
        yield FakeDB()

    app.dependency_overrides[get_db] = override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        resp = await client.post(f"{API_PREFIX}/keys/openai/test")

    assert resp.status_code == 404
    assert "No key stored" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_test_gemini_key_uses_header_not_query_parameter(monkeypatch):
    app.dependency_overrides[get_current_user] = _override_user()
    fake_db = FakeDB()
    fake_db.add(
        UserProviderKey(
            user_id=FAKE_USER_A,
            provider="gemini",
            encrypted_key=encrypt_key("gemini-secret-key"),
        )
    )
    captured: dict[str, object] = {}

    class FakeResponse:
        status_code = 200

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url, *, headers=None):
            captured["url"] = url
            captured["headers"] = headers or {}
            return FakeResponse()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)

    async def override_db():
        yield fake_db

    app.dependency_overrides[get_db] = override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        resp = await client.post(f"{API_PREFIX}/keys/gemini/test")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "provider": "gemini"}
    assert "gemini-secret-key" not in str(captured["url"])
    assert "key=" not in str(captured["url"])
    assert captured["headers"] == {"x-goog-api-key": "gemini-secret-key"}


@pytest.mark.asyncio
async def test_keys_require_auth():
    """BYOK endpoints should return 401 without auth."""
    saved = dict(app.dependency_overrides)
    app.dependency_overrides.clear()

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            resp_get = await client.get(f"{API_PREFIX}/keys")
            resp_put = await client.put(
                f"{API_PREFIX}/keys/openai",
                json={"api_key": "test"},
            )
            resp_del = await client.delete(f"{API_PREFIX}/keys/openai")
            resp_test = await client.post(f"{API_PREFIX}/keys/openai/test")
    finally:
        app.dependency_overrides.update(saved)

    assert resp_get.status_code == 401
    assert resp_put.status_code == 401
    assert resp_del.status_code == 401
    assert resp_test.status_code == 401


@pytest.mark.asyncio
async def test_delete_invalid_provider():
    """DELETE /api/llm/keys/bedrock should return 400."""
    app.dependency_overrides[get_current_user] = _override_user()

    async def override_db():
        yield FakeDB()

    app.dependency_overrides[get_db] = override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
        resp = await client.delete(f"{API_PREFIX}/keys/bedrock")

    assert resp.status_code == 400

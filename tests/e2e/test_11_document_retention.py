"""Live DB regression for document raw-text retention purge."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg

from conftest import TEST_DB_URL_SYNC


def test_document_retention_purges_raw_text_only(client, factories):
    model = factories.create_threat_model(system_name="Document Retention App")
    now = datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc)
    expired_id = uuid.uuid4()
    future_id = uuid.uuid4()
    parsed_components = {
        "parse_result": {
            "components": [{"name": "API Gateway", "component_type": "process"}],
            "flows": [{"source": "API Gateway", "target": "Ledger DB"}],
        }
    }

    async def _seed_documents() -> None:
        conn = await asyncpg.connect(TEST_DB_URL_SYNC)
        try:
            await conn.execute(
                """
                INSERT INTO documents (
                    id, threat_model_id, filename, page_count, raw_text,
                    parsed_components, parsed_at, expires_at, purged
                )
                VALUES
                    ($1, $2, 'expired.pdf', 1, 'expired sensitive raw text',
                     $3::jsonb, $4, $5, false),
                    ($6, $2, 'future.pdf', 1, 'future sensitive raw text',
                     $3::jsonb, $4, $7, false)
                """,
                expired_id,
                uuid.UUID(model["id"]),
                json.dumps(parsed_components),
                now - timedelta(hours=2),
                now - timedelta(seconds=1),
                future_id,
                now + timedelta(hours=1),
            )
        finally:
            await conn.close()

    async def _load_documents() -> dict[uuid.UUID, asyncpg.Record]:
        conn = await asyncpg.connect(TEST_DB_URL_SYNC)
        try:
            records = await conn.fetch(
                """
                SELECT id, raw_text, parsed_components, purged
                FROM documents
                WHERE id = ANY($1::uuid[])
                """,
                [expired_id, future_id],
            )
            return {record["id"]: record for record in records}
        finally:
            await conn.close()

    asyncio.run(_seed_documents())

    from app.services.doc_cleanup import purge_expired_documents

    def parsed_payload(record: asyncpg.Record) -> dict:
        value = record["parsed_components"]
        return json.loads(value) if isinstance(value, str) else value

    assert asyncio.run(purge_expired_documents(now=now)) == 1

    rows = asyncio.run(_load_documents())
    expired = rows[expired_id]
    future = rows[future_id]

    assert expired["raw_text"] is None
    assert expired["purged"] is True
    assert parsed_payload(expired) == parsed_components

    assert future["raw_text"] == "future sensitive raw text"
    assert future["purged"] is False
    assert parsed_payload(future) == parsed_components

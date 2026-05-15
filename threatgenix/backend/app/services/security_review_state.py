from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.schemas.security_review import SecurityReviewStateRecord, SecurityReviewStateUpdate


def _jsonable_review_state_value(value):
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_jsonable_review_state_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _jsonable_review_state_value(item) for key, item in value.items()}
    return value


def normalize_review_state_records(
    raw_records: list[dict] | None,
) -> list[SecurityReviewStateRecord]:
    normalized: list[SecurityReviewStateRecord] = []
    for item in raw_records or []:
        try:
            normalized.append(SecurityReviewStateRecord.model_validate(item))
        except Exception:
            continue
    return sorted(
        normalized,
        key=lambda item: (item.updated_at, item.source_object_type, item.source_object_id),
        reverse=True,
    )


def find_review_state_record(
    raw_records: list[dict] | None,
    *,
    source_object_type: str,
    source_object_id: str,
) -> SecurityReviewStateRecord | None:
    for record in normalize_review_state_records(raw_records):
        if (
            record.source_object_type == source_object_type
            and record.source_object_id == source_object_id
        ):
            return record
    return None


def upsert_review_state_record(
    raw_records: list[dict] | None,
    *,
    source_object_type: str,
    source_object_id: str,
    update: SecurityReviewStateUpdate,
    current_record: SecurityReviewStateRecord | None = None,
) -> list[dict]:
    now = datetime.now(UTC).isoformat()
    existing = current_record or find_review_state_record(
        raw_records,
        source_object_type=source_object_type,
        source_object_id=source_object_id,
    )
    payload = (
        existing.model_dump(mode="json")
        if existing is not None
        else SecurityReviewStateRecord(
            id=str(uuid4()),
            source_object_type=source_object_type,  # type: ignore[arg-type]
            source_object_id=source_object_id,
            created_at=now,
            updated_at=now,
        ).model_dump(mode="json")
    )
    for field in update.model_fields_set:
        payload[field] = _jsonable_review_state_value(getattr(update, field))
    payload["updated_at"] = now

    next_records: list[dict] = []
    replaced = False
    for item in raw_records or []:
        if (
            str(item.get("source_object_type")) == source_object_type
            and str(item.get("source_object_id")) == source_object_id
        ):
            next_records.append(payload)
            replaced = True
        else:
            next_records.append(item)
    if not replaced:
        next_records.append(payload)
    return next_records

from __future__ import annotations

from app.schemas.security_review import (
    SecurityReviewArtifact,
    SecurityReviewStateUpdate,
)
from app.services.security_review_artifacts import replace_artifact_of_kind
from app.services.security_review_state import upsert_review_state_record


def test_upsert_review_state_record_serializes_artifacts_to_jsonable_dicts() -> None:
    records = upsert_review_state_record(
        [],
        source_object_type="threat",
        source_object_id="threat-1",
        update=SecurityReviewStateUpdate(
            artifacts=[
                SecurityReviewArtifact(
                    id="artifact-1",
                    kind="evidence_request",
                    title="Evidence request · Threat 1",
                    summary="Need proof of the control.",
                    body="Requested evidence\n- Upload the cloud scan.",
                    created_at="2026-04-23T12:00:00Z",
                )
            ]
        ),
    )

    assert len(records) == 1
    assert isinstance(records[0]["artifacts"], list)
    assert isinstance(records[0]["artifacts"][0], dict)
    assert records[0]["artifacts"][0]["kind"] == "evidence_request"


def test_replace_artifact_of_kind_keeps_latest_copy_without_duplicate_queue_artifacts() -> None:
    older = SecurityReviewArtifact(
        id="artifact-old",
        kind="evidence_request",
        title="Evidence request · Old",
        summary="Old request",
        body="Requested evidence\n- Old proof.",
        created_at="2026-04-23T12:00:00Z",
    )
    unrelated = SecurityReviewArtifact(
        id="artifact-verify",
        kind="verification_note",
        title="Verification note · Control",
        summary="Verify the control",
        body="Checks to perform\n- Validate the control.",
        created_at="2026-04-23T12:01:00Z",
    )
    replacement = SecurityReviewArtifact(
        id="artifact-new",
        kind="evidence_request",
        title="Evidence request · Current",
        summary="Current request",
        body="Requested evidence\n- Current proof.",
        created_at="2026-04-23T12:05:00Z",
    )

    artifacts = replace_artifact_of_kind([older, unrelated], replacement)

    assert [item.id for item in artifacts] == ["artifact-new", "artifact-verify"]
    assert {item.kind for item in artifacts} == {"evidence_request", "verification_note"}

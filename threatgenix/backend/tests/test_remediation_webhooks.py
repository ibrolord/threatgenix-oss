from __future__ import annotations

import json

import pytest

from app.schemas.security_review import AgentRemediationEvidenceWebhookRequest
from app.services.remediation_webhooks import (
    RemediationWebhookSignatureError,
    normalize_remediation_webhook_event,
    remediation_webhook_required_headers_template,
    remediation_webhook_signature_base_string,
    sign_remediation_webhook_body,
    verify_remediation_webhook_signature,
    verify_remediation_webhook_signature_durable,
)


def _signed_headers(
    raw_body: bytes, *, timestamp: str = "1800000000", nonce: str = "nonce-1"
):
    return {
        "X-SSR-Webhook-Timestamp": timestamp,
        "X-SSR-Webhook-Nonce": nonce,
        "X-SSR-Webhook-Signature": sign_remediation_webhook_body(
            timestamp=timestamp,
            nonce=nonce,
            raw_body=raw_body,
        ),
    }


def test_remediation_webhook_signature_verifies_timestamp_nonce_and_body():
    raw_body = json.dumps(
        {"action_id": "finding:remediation_note", "evidence_summary": "PR merged."},
        separators=(",", ":"),
    ).encode("utf-8")

    verify_remediation_webhook_signature(
        headers=_signed_headers(raw_body, nonce="nonce-verify"),
        raw_body=raw_body,
        scope="tm-1",
        now=1800000001,
    )


def test_remediation_webhook_signature_rejects_replay_nonce():
    raw_body = b'{"evidence_summary":"PR merged."}'
    headers = _signed_headers(raw_body, nonce="nonce-replay")

    verify_remediation_webhook_signature(
        headers=headers,
        raw_body=raw_body,
        scope="tm-1",
        now=1800000001,
    )
    with pytest.raises(RemediationWebhookSignatureError, match="nonce"):
        verify_remediation_webhook_signature(
            headers=headers,
            raw_body=raw_body,
            scope="tm-1",
            now=1800000002,
        )


def test_remediation_webhook_signature_rejects_tampered_body():
    raw_body = b'{"evidence_summary":"PR merged."}'
    headers = _signed_headers(raw_body, nonce="nonce-tamper")

    with pytest.raises(RemediationWebhookSignatureError, match="signature"):
        verify_remediation_webhook_signature(
            headers=headers,
            raw_body=b'{"evidence_summary":"Different proof."}',
            scope="tm-1",
            now=1800000001,
        )


@pytest.mark.asyncio
async def test_remediation_webhook_signature_uses_durable_nonce_store():
    raw_body = b'{"evidence_summary":"PR merged."}'
    headers = _signed_headers(raw_body, nonce="nonce-durable")

    class FakeSession:
        def __init__(self):
            self.added = []
            self.executed = []
            self.flushed = False

        async def execute(self, statement):
            self.executed.append(statement)

        def add(self, item):
            self.added.append(item)

        async def flush(self):
            self.flushed = True

    db = FakeSession()

    await verify_remediation_webhook_signature_durable(
        headers=headers,
        raw_body=raw_body,
        scope="tm-1:github",
        db=db,
        provider="github",
        now=1800000001,
    )

    assert db.flushed is True
    assert len(db.added) == 1
    assert db.added[0].scope == "tm-1:github"
    assert db.added[0].nonce_hash != "nonce-durable"
    assert db.added[0].provider == "github"


def test_remediation_webhook_template_describes_hmac_contract():
    headers = remediation_webhook_required_headers_template()

    assert headers["X-SSR-Webhook-Timestamp"] == "<unix_timestamp_seconds>"
    assert headers["X-SSR-Webhook-Nonce"] == "<unique_random_nonce>"
    assert headers["X-SSR-Webhook-Signature"].startswith("sha256=")
    assert remediation_webhook_signature_base_string() == (
        "timestamp + '.' + nonce + '.' + raw_request_body"
    )


def test_remediation_webhook_event_normalization():
    assert (
        normalize_remediation_webhook_event(
            AgentRemediationEvidenceWebhookRequest(
                provider="github_pr",
                pull_request_url="https://github.com/acme/app/pull/7",
                evidence_summary="PR merged.",
            )
        )
        == "pull_request_evidence"
    )
    assert (
        normalize_remediation_webhook_event(
            AgentRemediationEvidenceWebhookRequest(
                provider="jira",
                external_ticket_id="APP-9",
                evidence_summary="Ticket resolved.",
            )
        )
        == "ticket_evidence"
    )

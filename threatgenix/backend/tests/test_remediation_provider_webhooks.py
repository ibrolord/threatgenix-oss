from __future__ import annotations

import pytest

from app.services.remediation_provider_webhooks import (
    RemediationProviderWebhookError,
    parse_remediation_provider_webhook,
)


def test_parse_github_pull_request_webhook_uses_embedded_action_id():
    request = parse_remediation_provider_webhook(
        provider="github",
        payload={
            "action": "closed",
            "repository": {"full_name": "acme/app"},
            "pull_request": {
                "number": 7,
                "title": "Add trust boundary",
                "html_url": "https://github.com/acme/app/pull/7",
                "body": "action_id: finding:remediation_note",
                "head": {"sha": "abc123"},
            },
        },
    )

    assert request.provider == "github_pr"
    assert request.action_id == "finding:remediation_note"
    assert request.external_ticket_id == "acme/app#7"
    assert request.pull_request_url == "https://github.com/acme/app/pull/7"
    assert request.commit_sha == "abc123"
    assert request.evidence_summary == "GitHub pull request closed: Add trust boundary"


def test_parse_linear_webhook_uses_structured_action_id():
    request = parse_remediation_provider_webhook(
        provider="linear",
        payload={
            "action": "Issue completed",
            "issue": {
                "identifier": "SEC-12",
                "title": "Attach validation proof",
                "url": "https://linear.app/acme/issue/SEC-12",
                "semantic_security_review": {"action_id": "finding:verify"},
            },
        },
    )

    assert request.provider == "linear"
    assert request.action_id == "finding:verify"
    assert request.external_ticket_id == "SEC-12"
    assert request.evidence_url == "https://linear.app/acme/issue/SEC-12"


def test_parse_jira_webhook_extracts_action_id_from_adf_description():
    request = parse_remediation_provider_webhook(
        provider="jira",
        payload={
            "webhookEvent": "jira:issue_updated",
            "issue": {
                "key": "APP-9",
                "self": "https://acme.atlassian.net/rest/api/3/issue/10009",
                "fields": {
                    "summary": "Fix release blocker",
                    "description": {
                        "type": "doc",
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "action_id: finding:fix",
                                    }
                                ],
                            }
                        ],
                    },
                },
            },
        },
    )

    assert request.provider == "jira"
    assert request.action_id == "finding:fix"
    assert request.external_ticket_id == "APP-9"
    assert request.evidence_url == "https://acme.atlassian.net/browse/APP-9"


def test_provider_webhook_requires_action_id():
    with pytest.raises(RemediationProviderWebhookError, match="action_id"):
        parse_remediation_provider_webhook(
            provider="github",
            payload={"issue": {"number": 1, "title": "No callback marker"}},
        )

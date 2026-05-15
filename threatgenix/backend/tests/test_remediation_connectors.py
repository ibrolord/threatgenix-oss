from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.schemas.security_review import (
    AgentRemediationConnectorTicketCreateRequest,
    AgentRemediationTicketDraft,
)
from app.services.remediation_connectors import (
    RemediationConnectorError,
    create_remediation_provider_ticket,
    remediation_webhook_setup,
)


class _Action:
    action_id = "application_review_finding:model:trust-boundary:remediation_note"
    finding_id = "application_review_finding:model:trust-boundary"
    ticket_draft = AgentRemediationTicketDraft(
        provider="github_issue",
        title="[Security] Trust boundary missing",
        body="## Security remediation\nAdd the missing trust boundary.",
        labels=["security-review", "fix-now"],
        priority="p1_now",
    )


def test_remediation_webhook_setup_builds_provider_specific_callback():
    setup = remediation_webhook_setup(
        base_url="https://api.threatgenix.test/",
        threat_model_id="tm-1",
        action=_Action(),  # type: ignore[arg-type]
        provider="jira",
    )

    assert setup.provider == "jira"
    assert setup.provider_label == "Jira"
    assert setup.callback_url == (
        "https://api.threatgenix.test/api/threat-models/tm-1/"
        "agent/remediation-plan/webhooks/providers/jira/evidence"
    )
    assert setup.action_marker == (
        "action_id: application_review_finding:model:trust-boundary:remediation_note"
    )
    assert "jira:issue_updated" in setup.event_filters
    assert setup.required_headers["X-SSR-Webhook-Signature"].startswith("sha256=")
    assert setup.signature_base_string == (
        "timestamp + '.' + nonce + '.' + raw_request_body"
    )


@pytest.mark.asyncio
async def test_provider_connector_requires_confirmation_before_network(monkeypatch):
    post_json = AsyncMock()
    monkeypatch.setattr("app.services.remediation_connectors._post_json", post_json)

    with pytest.raises(RemediationConnectorError, match="confirmation"):
        await create_remediation_provider_ticket(
            body=AgentRemediationConnectorTicketCreateRequest(
                action_id=_Action.action_id,
                provider="github_issue",
                confirmed=False,
                access_token="customer-owned-token",
                github_repository="acme/app",
            ),
            action=_Action(),  # type: ignore[arg-type]
        )

    post_json.assert_not_awaited()


@pytest.mark.asyncio
async def test_github_connector_posts_issue_with_customer_owned_token(monkeypatch):
    post_json = AsyncMock(
        return_value=(
            201,
            {"number": 7, "html_url": "https://github.com/acme/app/issues/7"},
        )
    )
    monkeypatch.setattr("app.services.remediation_connectors._post_json", post_json)

    result = await create_remediation_provider_ticket(
        body=AgentRemediationConnectorTicketCreateRequest(
            action_id=_Action.action_id,
            provider="github_issue",
            confirmed=True,
            access_token="customer-owned-token",
            github_repository="https://github.com/acme/app",
        ),
        action=_Action(),  # type: ignore[arg-type]
    )

    assert result.external_ticket_id == "#7"
    assert result.external_ticket_url == "https://github.com/acme/app/issues/7"
    post_json.assert_awaited_once()
    url = post_json.await_args.args[0]
    payload = post_json.await_args.args[1]
    headers = post_json.await_args.kwargs["headers"]
    assert url == "https://api.github.com/repos/acme/app/issues"
    assert payload["title"] == "[Security] Trust boundary missing"
    assert "customer-owned-token" not in payload["body"]
    assert headers["Authorization"] == "Bearer customer-owned-token"


@pytest.mark.asyncio
async def test_linear_connector_posts_issue_with_customer_owned_token(monkeypatch):
    post_json = AsyncMock(
        return_value=(
            200,
            {
                "data": {
                    "issueCreate": {
                        "success": True,
                        "issue": {
                            "identifier": "SEC-12",
                            "url": "https://linear.app/acme/issue/SEC-12/fix",
                        },
                    }
                }
            },
        )
    )
    monkeypatch.setattr("app.services.remediation_connectors._post_json", post_json)

    result = await create_remediation_provider_ticket(
        body=AgentRemediationConnectorTicketCreateRequest(
            action_id=_Action.action_id,
            provider="linear",
            confirmed=True,
            access_token="linear-token",
            linear_team_id="team-123",
        ),
        action=_Action(),  # type: ignore[arg-type]
    )

    assert result.external_ticket_id == "SEC-12"
    assert result.external_ticket_url == "https://linear.app/acme/issue/SEC-12/fix"
    post_json.assert_awaited_once()
    url = post_json.await_args.args[0]
    payload = post_json.await_args.args[1]
    headers = post_json.await_args.kwargs["headers"]
    assert url == "https://api.linear.app/graphql"
    assert payload["variables"]["input"]["teamId"] == "team-123"
    assert payload["variables"]["input"]["title"] == "[Security] Trust boundary missing"
    assert "linear-token" not in payload["variables"]["input"]["description"]
    assert headers["Authorization"] == "linear-token"


@pytest.mark.asyncio
async def test_jira_connector_posts_issue_with_customer_owned_token(monkeypatch):
    post_json = AsyncMock(return_value=(201, {"key": "APP-9"}))
    monkeypatch.setattr("app.services.remediation_connectors._post_json", post_json)

    result = await create_remediation_provider_ticket(
        body=AgentRemediationConnectorTicketCreateRequest(
            action_id=_Action.action_id,
            provider="jira",
            confirmed=True,
            access_token="jira-token",
            jira_base_url="https://acme.atlassian.net",
            jira_project_key="APP",
            jira_issue_type="Bug",
        ),
        action=_Action(),  # type: ignore[arg-type]
    )

    assert result.external_ticket_id == "APP-9"
    assert result.external_ticket_url == "https://acme.atlassian.net/browse/APP-9"
    post_json.assert_awaited_once()
    url = post_json.await_args.args[0]
    payload = post_json.await_args.args[1]
    headers = post_json.await_args.kwargs["headers"]
    assert url == "https://acme.atlassian.net/rest/api/3/issue"
    assert payload["fields"]["project"]["key"] == "APP"
    assert payload["fields"]["issuetype"]["name"] == "Bug"
    description = payload["fields"]["description"]["content"][0]["content"][0]["text"]
    assert "jira-token" not in description
    assert headers["Authorization"] == "Bearer jira-token"

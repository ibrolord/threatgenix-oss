"""Outbound remediation ticket connectors with explicit reviewer confirmation."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from app.schemas.security_review import (
    AgentRemediationAction,
    AgentRemediationConnectorTicketCreateRequest,
    AgentRemediationPlanResponse,
    AgentRemediationWebhookSetup,
)
from app.services.remediation_webhooks import (
    remediation_webhook_required_headers_template,
    remediation_webhook_signature_base_string,
)


class RemediationConnectorError(ValueError):
    """Raised when a provider ticket cannot be created safely."""


@dataclass(frozen=True)
class RemediationProviderTicketResult:
    provider: str
    external_ticket_id: str
    external_ticket_url: str | None = None


def remediation_evidence_callback_url(base_url: str, threat_model_id: object) -> str:
    return (
        f"{base_url.rstrip('/')}/api/threat-models/{threat_model_id}"
        "/agent/remediation-plan/webhooks/evidence"
    )


def remediation_provider_evidence_callback_url(
    base_url: str, threat_model_id: object, provider: str
) -> str:
    return (
        f"{base_url.rstrip('/')}/api/threat-models/{threat_model_id}"
        f"/agent/remediation-plan/webhooks/providers/{provider}/evidence"
    )


def attach_remediation_webhook_setups(
    plan: AgentRemediationPlanResponse,
    *,
    base_url: str,
    threat_model_id: object,
) -> AgentRemediationPlanResponse:
    for action in plan.actions:
        setups = [
            remediation_webhook_setup(
                base_url=base_url,
                threat_model_id=threat_model_id,
                action=action,
                provider=provider,
            )
            for provider in ("github", "linear", "jira")
        ]
        preferred_provider = _callback_provider_for_ticket(action.ticket_draft.provider)
        action.ticket_draft.callback_setups = setups
        action.ticket_draft.callback_setup = next(
            setup for setup in setups if setup.provider == preferred_provider
        )
    return plan


def remediation_webhook_setup(
    *,
    base_url: str,
    threat_model_id: object,
    action: AgentRemediationAction,
    provider: str,
) -> AgentRemediationWebhookSetup:
    normalized_provider = provider.casefold().strip()
    if normalized_provider not in {"github", "linear", "jira"}:
        raise RemediationConnectorError(f"Unsupported provider: {provider}")
    action_marker = f"action_id: {action.action_id}"
    return AgentRemediationWebhookSetup(
        provider=normalized_provider,  # type: ignore[arg-type]
        provider_label=_provider_label(normalized_provider),
        callback_url=remediation_provider_evidence_callback_url(
            base_url, threat_model_id, normalized_provider
        ),
        action_marker=action_marker,
        action_marker_hint=(
            "Keep this marker in the issue, PR, or ticket description so inbound "
            "provider events can map evidence back to this remediation action."
        ),
        event_filters=_provider_event_filters(normalized_provider),
        registration_steps=_provider_registration_steps(
            normalized_provider, action_marker
        ),
        required_headers=remediation_webhook_required_headers_template(),
        signature_base_string=remediation_webhook_signature_base_string(),
        signing_secret_hint=(
            "Sign the raw provider payload with the ThreatGenix "
            "remediation webhook secret. Do not use a provider API token as the "
            "webhook signing secret."
        ),
    )


def remediation_evidence_callback_payload(
    action: AgentRemediationAction,
    *,
    provider: str,
    result: RemediationProviderTicketResult,
) -> dict[str, str | None]:
    return {
        "action_id": action.action_id,
        "provider": provider,
        "external_ticket_id": result.external_ticket_id,
        "evidence_url": result.external_ticket_url,
        "evidence_summary": (
            "Provider callback evidence for the remediation ticket. Attach PR, "
            "commit, validation output, or reviewer evidence before clearing."
        ),
    }


def _callback_provider_for_ticket(provider: str) -> str:
    if provider == "github_issue":
        return "github"
    return provider


def _provider_label(provider: str) -> str:
    if provider == "github":
        return "GitHub"
    if provider == "linear":
        return "Linear"
    if provider == "jira":
        return "Jira"
    return provider


def _provider_event_filters(provider: str) -> list[str]:
    if provider == "github":
        return [
            "pull_request.closed",
            "pull_request.synchronize",
            "issues.closed",
            "issues.edited",
        ]
    if provider == "linear":
        return [
            "Issue completed",
            "Issue updated",
            "Comment created with evidence link",
        ]
    if provider == "jira":
        return [
            "jira:issue_updated",
            "issue_resolved",
            "comment_created with evidence link",
        ]
    return []


def _provider_registration_steps(provider: str, action_marker: str) -> list[str]:
    if provider == "github":
        return [
            "Create a repository webhook or app callback for pull request and issue events.",
            f"Keep `{action_marker}` in the issue or pull request body.",
            "Forward the raw GitHub JSON body with SSR timestamp, nonce, and HMAC signature headers.",
        ]
    if provider == "linear":
        return [
            "Create a Linear webhook for issue updates in the remediation team workspace.",
            f"Keep `{action_marker}` in the Linear issue description.",
            "Forward the raw Linear JSON body with SSR timestamp, nonce, and HMAC signature headers.",
        ]
    if provider == "jira":
        return [
            "Create a Jira automation or webhook for issue updated and resolved events.",
            f"Keep `{action_marker}` in the Jira issue description or comment.",
            "Forward the raw Jira JSON body with SSR timestamp, nonce, and HMAC signature headers.",
        ]
    return []


async def create_remediation_provider_ticket(
    *,
    body: AgentRemediationConnectorTicketCreateRequest,
    action: AgentRemediationAction,
) -> RemediationProviderTicketResult:
    if not body.confirmed:
        raise RemediationConnectorError(
            "Provider ticket creation requires explicit confirmation."
        )
    if body.access_token is None:
        raise RemediationConnectorError(
            "Provider ticket creation requires a customer-owned access token."
        )

    access_token = body.access_token.get_secret_value()
    if not access_token.strip():
        raise RemediationConnectorError(
            "Provider ticket creation requires a customer-owned access token."
        )

    if body.provider == "github_issue":
        return await _create_github_issue(body, action, access_token)
    if body.provider == "linear":
        return await _create_linear_issue(body, action, access_token)
    if body.provider == "jira":
        return await _create_jira_issue(body, action, access_token)
    raise RemediationConnectorError(f"Unsupported provider: {body.provider}")


async def _create_github_issue(
    body: AgentRemediationConnectorTicketCreateRequest,
    action: AgentRemediationAction,
    access_token: str,
) -> RemediationProviderTicketResult:
    repository = _normalize_github_repository(body.github_repository)
    payload = {
        "title": action.ticket_draft.title,
        "body": _ticket_body_with_callback_hint(action),
        "labels": action.ticket_draft.labels,
    }
    status, response = await _post_json(
        f"https://api.github.com/repos/{repository}/issues",
        payload,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    if status not in {200, 201}:
        raise RemediationConnectorError(f"GitHub Issue creation returned HTTP {status}.")
    number = response.get("number")
    html_url = response.get("html_url")
    ticket_id = f"#{number}" if number is not None else str(response.get("id") or "")
    if not ticket_id:
        raise RemediationConnectorError("GitHub Issue response did not include an issue id.")
    return RemediationProviderTicketResult(
        provider="github_issue",
        external_ticket_id=ticket_id,
        external_ticket_url=str(html_url) if html_url else None,
    )


async def _create_linear_issue(
    body: AgentRemediationConnectorTicketCreateRequest,
    action: AgentRemediationAction,
    access_token: str,
) -> RemediationProviderTicketResult:
    if not body.linear_team_id:
        raise RemediationConnectorError("Linear ticket creation requires linear_team_id.")
    payload = {
        "query": (
            "mutation IssueCreate($input: IssueCreateInput!) { "
            "issueCreate(input: $input) { success issue { identifier url } } }"
        ),
        "variables": {
            "input": {
                "teamId": body.linear_team_id,
                "title": action.ticket_draft.title,
                "description": _ticket_body_with_callback_hint(action),
            }
        },
    }
    status, response = await _post_json(
        "https://api.linear.app/graphql",
        payload,
        headers={"Authorization": access_token},
    )
    if status != 200:
        raise RemediationConnectorError(f"Linear issue creation returned HTTP {status}.")
    issue_create = (
        response.get("data", {}).get("issueCreate", {})
        if isinstance(response.get("data"), dict)
        else {}
    )
    if issue_create.get("success") is not True:
        raise RemediationConnectorError("Linear issue creation was not successful.")
    issue = issue_create.get("issue") if isinstance(issue_create.get("issue"), dict) else {}
    ticket_id = str(issue.get("identifier") or "")
    if not ticket_id:
        raise RemediationConnectorError("Linear response did not include an issue identifier.")
    return RemediationProviderTicketResult(
        provider="linear",
        external_ticket_id=ticket_id,
        external_ticket_url=str(issue.get("url")) if issue.get("url") else None,
    )


async def _create_jira_issue(
    body: AgentRemediationConnectorTicketCreateRequest,
    action: AgentRemediationAction,
    access_token: str,
) -> RemediationProviderTicketResult:
    if not body.jira_base_url or not body.jira_project_key:
        raise RemediationConnectorError(
            "Jira ticket creation requires jira_base_url and jira_project_key."
        )
    base_url = body.jira_base_url.rstrip("/")
    if not base_url.startswith("https://"):
        raise RemediationConnectorError("Jira base URL must use https.")
    payload = {
        "fields": {
            "project": {"key": body.jira_project_key},
            "summary": action.ticket_draft.title,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": _ticket_body_with_callback_hint(action),
                            }
                        ],
                    }
                ],
            },
            "issuetype": {"name": body.jira_issue_type or "Task"},
            "labels": action.ticket_draft.labels[:10],
        }
    }
    status, response = await _post_json(
        f"{base_url}/rest/api/3/issue",
        payload,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if status not in {200, 201}:
        raise RemediationConnectorError(f"Jira issue creation returned HTTP {status}.")
    ticket_id = str(response.get("key") or response.get("id") or "")
    if not ticket_id:
        raise RemediationConnectorError("Jira response did not include an issue key.")
    return RemediationProviderTicketResult(
        provider="jira",
        external_ticket_id=ticket_id,
        external_ticket_url=f"{base_url}/browse/{ticket_id}" if response.get("key") else None,
    )


async def _post_json(
    url: str,
    payload: dict,
    *,
    headers: dict[str, str],
) -> tuple[int, dict]:
    safe_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "threatgenix-remediation-connector/1.0",
        **headers,
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
            response = await client.post(url, json=payload, headers=safe_headers)
    except httpx.HTTPError as exc:
        raise RemediationConnectorError("Provider ticket creation request failed.") from exc
    try:
        parsed = response.json()
    except ValueError:
        parsed = {}
    return response.status_code, parsed if isinstance(parsed, dict) else {}


def _normalize_github_repository(repository: str | None) -> str:
    if not repository:
        raise RemediationConnectorError("GitHub Issue creation requires github_repository.")
    candidate = repository.strip().removesuffix(".git")
    if candidate.startswith("http://") or candidate.startswith("https://"):
        parsed = urlparse(candidate)
        if parsed.netloc.casefold() != "github.com":
            raise RemediationConnectorError("GitHub repository URL must use github.com.")
        candidate = parsed.path.strip("/")
    parts = [part for part in candidate.split("/") if part]
    if len(parts) != 2:
        raise RemediationConnectorError("GitHub repository must be in owner/repo form.")
    return f"{parts[0]}/{parts[1]}"


def _ticket_body_with_callback_hint(action: AgentRemediationAction) -> str:
    return "\n".join(
        [
            action.ticket_draft.body,
            "",
            "## Callback",
            "When remediation evidence is ready, POST provider evidence back to "
            "the ThreatGenix remediation webhook for this action.",
            f"- action_id: {action.action_id}",
            f"- finding_id: {action.finding_id}",
        ]
    )

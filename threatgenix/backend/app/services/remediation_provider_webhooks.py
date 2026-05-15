"""Provider-native remediation callback adapters."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from app.schemas.security_review import AgentRemediationEvidenceWebhookRequest

SUPPORTED_REMEDIATION_WEBHOOK_PROVIDERS = {"github", "linear", "jira"}

_ACTION_ID_RE = re.compile(r"\baction_id\s*:\s*([^\s`]+)", re.IGNORECASE)


class RemediationProviderWebhookError(ValueError):
    """Raised when provider webhook evidence cannot be mapped to an action."""


def parse_remediation_provider_webhook(
    *,
    provider: str,
    payload: Mapping[str, Any],
) -> AgentRemediationEvidenceWebhookRequest:
    normalized_provider = provider.casefold().strip()
    if normalized_provider == "github":
        return _parse_github_webhook(payload)
    if normalized_provider == "linear":
        return _parse_linear_webhook(payload)
    if normalized_provider == "jira":
        return _parse_jira_webhook(payload)
    raise RemediationProviderWebhookError(
        f"Unsupported remediation provider: {provider}."
    )


def _parse_github_webhook(
    payload: Mapping[str, Any],
) -> AgentRemediationEvidenceWebhookRequest:
    pull_request = _mapping(payload.get("pull_request"))
    issue = _mapping(payload.get("issue"))
    repository = _mapping(payload.get("repository"))
    action = _string(payload.get("action")) or "webhook"
    if pull_request:
        action_id = _extract_action_id(payload, pull_request)
        title = _string(pull_request.get("title")) or "GitHub pull request evidence"
        html_url = _string(pull_request.get("html_url"))
        number = pull_request.get("number")
        return AgentRemediationEvidenceWebhookRequest(
            action_id=action_id,
            provider="github_pr",
            external_ticket_id=_github_external_id(repository, number),
            pull_request_url=html_url,
            commit_sha=_string(_mapping(pull_request.get("head")).get("sha")),
            evidence_url=html_url,
            evidence_summary=f"GitHub pull request {action}: {title}",
        )
    if issue:
        action_id = _extract_action_id(payload, issue)
        title = _string(issue.get("title")) or "GitHub issue evidence"
        html_url = _string(issue.get("html_url"))
        number = issue.get("number")
        return AgentRemediationEvidenceWebhookRequest(
            action_id=action_id,
            provider="github_issue",
            external_ticket_id=_github_external_id(repository, number),
            evidence_url=html_url,
            evidence_summary=f"GitHub issue {action}: {title}",
        )
    raise RemediationProviderWebhookError(
        "GitHub remediation webhook must include pull_request or issue payload."
    )


def _parse_linear_webhook(
    payload: Mapping[str, Any],
) -> AgentRemediationEvidenceWebhookRequest:
    issue = _mapping(payload.get("issue") or payload.get("data"))
    if not issue:
        raise RemediationProviderWebhookError(
            "Linear remediation webhook must include issue payload."
        )
    action = _string(payload.get("action") or payload.get("type")) or "webhook"
    action_id = _extract_action_id(payload, issue)
    identifier = _string(issue.get("identifier") or issue.get("id"))
    title = _string(issue.get("title")) or "Linear issue evidence"
    url = _string(issue.get("url"))
    return AgentRemediationEvidenceWebhookRequest(
        action_id=action_id,
        provider="linear",
        external_ticket_id=identifier,
        evidence_url=url,
        evidence_summary=f"Linear issue {action}: {title}",
    )


def _parse_jira_webhook(
    payload: Mapping[str, Any],
) -> AgentRemediationEvidenceWebhookRequest:
    issue = _mapping(payload.get("issue"))
    if not issue:
        raise RemediationProviderWebhookError(
            "Jira remediation webhook must include issue payload."
        )
    event = _string(payload.get("webhookEvent") or payload.get("issue_event_type_name"))
    action = event or "webhook"
    fields = _mapping(issue.get("fields"))
    action_id = _extract_action_id(payload, issue, fields)
    key = _string(issue.get("key") or issue.get("id"))
    title = _string(fields.get("summary")) or "Jira issue evidence"
    url = _jira_issue_url(payload, key)
    return AgentRemediationEvidenceWebhookRequest(
        action_id=action_id,
        provider="jira",
        external_ticket_id=key,
        evidence_url=url,
        evidence_summary=f"Jira issue {action}: {title}",
    )


def _extract_action_id(*sources: Mapping[str, Any]) -> str:
    for source in sources:
        embedded = _mapping(source.get("semantic_security_review"))
        callback = _mapping(source.get("callback"))
        for candidate in (
            source.get("action_id"),
            embedded.get("action_id"),
            callback.get("action_id"),
        ):
            value = _string(candidate)
            if value:
                return value
        text = _deep_text(source)
        match = _ACTION_ID_RE.search(text)
        if match:
            return match.group(1).strip()
    raise RemediationProviderWebhookError(
        "Provider webhook payload did not include a remediation action_id."
    )


def _github_external_id(repository: Mapping[str, Any], number: Any) -> str | None:
    if number is None:
        return None
    full_name = _string(repository.get("full_name"))
    if full_name:
        return f"{full_name}#{number}"
    return f"#{number}"


def _jira_issue_url(payload: Mapping[str, Any], key: str | None) -> str | None:
    if not key:
        return None
    base = _string(payload.get("jira_base_url"))
    if base:
        return f"{base.rstrip('/')}/browse/{key}"
    self_url = _string(_mapping(payload.get("issue")).get("self"))
    if "/rest/api/" in self_url:
        return f"{self_url.split('/rest/api/', 1)[0]}/browse/{key}"
    return None


def _deep_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return "\n".join(_deep_text(item) for item in value.values())
    if isinstance(value, list):
        return "\n".join(_deep_text(item) for item in value)
    return ""


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string(value: Any) -> str | None:
    if value is None:
        return None
    candidate = str(value).strip()
    return candidate or None

"""Model-agnostic adapter boundary for agent orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class AgentModelResult:
    payload: dict[str, Any]
    model_provider: str | None = None
    model_name: str | None = None
    prompt_version: str | None = None
    model_output_hash: str | None = None
    deterministic_fallback_used: bool = True


class AgentModelAdapter(Protocol):
    async def generate_structured(
        self,
        *,
        agent_type: str,
        context_packet: dict[str, Any],
        output_schema: dict[str, Any],
    ) -> AgentModelResult:
        """Generate schema-shaped output for an agent contract."""


class DeterministicFallbackAgentModelAdapter:
    """Rules-only fallback used when no external model is configured."""

    async def generate_structured(
        self,
        *,
        agent_type: str,
        context_packet: dict[str, Any],
        output_schema: dict[str, Any],
    ) -> AgentModelResult:
        threat = context_packet.get("threat") or {}
        evidence_refs = context_packet.get("evidence_refs") or []
        description = str(threat.get("description") or "the selected threat")
        display_id = str(threat.get("display_id") or "selected threat")
        payload = {
            "summary": (
                f"Draft remediation for {display_id}: address the evidence-backed "
                f"risk described as {description[:240]}."
            ),
            "patch_preview": _fallback_patch_preview(agent_type, description),
            "ticket_draft": {
                "title": f"Remediate {display_id}: {description[:80]}",
                "body": _fallback_ticket_body(agent_type, description, evidence_refs),
                "labels": ["threatgenix", agent_type.replace("_", "-")],
            },
            "pr_draft": {
                "title": f"Fix {display_id}: evidence-backed security remediation",
                "body": _fallback_ticket_body(agent_type, description, evidence_refs),
                "target_files": _target_files(evidence_refs),
            },
        }
        output_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return AgentModelResult(payload=payload, model_output_hash=output_hash)


class LLMAgentModelAdapter:
    """Adapter from the existing multi-provider LLM client into the agent contract."""

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        timeout_seconds: float = 20.0,
        prompt_version: str = "agent-orchestration-v1",
    ) -> None:
        self._llm_client = llm_client
        self._timeout_seconds = timeout_seconds
        self._prompt_version = prompt_version
        self._fallback = DeterministicFallbackAgentModelAdapter()

    async def generate_structured(
        self,
        *,
        agent_type: str,
        context_packet: dict[str, Any],
        output_schema: dict[str, Any],
    ) -> AgentModelResult:
        try:
            client = self._llm_client
            if client is None:
                from app.services.llm_client import get_llm_client

                client = get_llm_client()
            redacted_context = _redact_context_packet(context_packet)
            raw_payload = await self._call_model(
                client=client,
                agent_type=agent_type,
                context_packet=redacted_context,
                output_schema=output_schema,
            )
            if not isinstance(raw_payload, dict):
                raise ValueError("model output was not an object")
            try:
                payload = validate_agent_model_payload(raw_payload)
            except ValueError as exc:
                raw_payload = await self._call_model(
                    client=client,
                    agent_type=agent_type,
                    context_packet=redacted_context,
                    output_schema=output_schema,
                    validation_error=str(exc),
                )
                if not isinstance(raw_payload, dict):
                    raise ValueError("model correction output was not an object") from exc
                payload = validate_agent_model_payload(raw_payload)
            output_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            return AgentModelResult(
                payload=payload,
                model_provider=getattr(client, "provider_name", None),
                model_name=getattr(client, "model_name", None),
                prompt_version=self._prompt_version,
                model_output_hash=output_hash,
                deterministic_fallback_used=False,
            )
        except Exception:
            return await self._fallback.generate_structured(
                agent_type=agent_type,
                context_packet=context_packet,
                output_schema=output_schema,
            )

    async def _call_model(
        self,
        *,
        client: Any,
        agent_type: str,
        context_packet: dict[str, Any],
        output_schema: dict[str, Any],
        validation_error: str | None = None,
    ) -> Any:
        return await asyncio.wait_for(
            asyncio.to_thread(
                client.call_with_tools,
                _agent_system_prompt(agent_type),
                _agent_user_message(
                    agent_type,
                    context_packet,
                    validation_error=validation_error,
                ),
                [_agent_output_tool(output_schema)],
                1200,
                self._prompt_version,
            ),
            timeout=self._timeout_seconds,
        )


def validate_agent_model_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Keep model output in the drafting lane and reject unsafe claims."""

    payload = _normalize_agent_model_payload(payload)
    required = {"summary", "patch_preview", "ticket_draft", "pr_draft"}
    missing = sorted(required - set(payload))
    if missing:
        raise ValueError(f"model output missing required fields: {', '.join(missing)}")
    if not isinstance(payload["summary"], str) or not payload["summary"].strip():
        raise ValueError("model output summary must be a non-empty string")
    if not isinstance(payload["patch_preview"], str) or not payload["patch_preview"].strip():
        raise ValueError("model output patch_preview must be a non-empty string")
    for draft_key in ("ticket_draft", "pr_draft"):
        draft = payload[draft_key]
        if not isinstance(draft, dict):
            raise ValueError(f"model output {draft_key} must be an object")
        for text_key in ("title", "body"):
            if not isinstance(draft.get(text_key), str) or not draft[text_key].strip():
                raise ValueError(f"model output {draft_key}.{text_key} must be a non-empty string")
    raw = json.dumps(payload, sort_keys=True).casefold()
    forbidden = (
        "accepted_risk",
        "risk accepted",
        "risk is accepted",
        "validated as fixed",
        "safe to deploy",
        "scanner verified",
        "no risk",
        "compliant",
    )
    forbidden_patterns = (
        r"\bis secure\b",
        r"\bare secure\b",
        r"\bnow secure\b",
        r"\bfully secure\b",
        r"\bsecure (app|application|system|route|endpoint)\b",
        r"\bis fixed\b",
        r"\bhas been fixed\b",
        r"\bresolved\b",
        r"\bremediated\b",
    )
    if any(term in raw for term in forbidden) or any(re.search(pattern, raw) for pattern in forbidden_patterns):
        raise ValueError("model output attempted to make a prohibited truth claim")
    return payload


def _normalize_agent_model_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    for draft_key in ("ticket_draft", "pr_draft"):
        draft = normalized.get(draft_key)
        if isinstance(draft, str):
            try:
                parsed = json.loads(draft)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                draft = parsed
                normalized[draft_key] = draft
        if isinstance(draft, dict):
            for list_key in ("labels", "target_files"):
                value = draft.get(list_key)
                if isinstance(value, str):
                    try:
                        parsed = json.loads(value)
                    except json.JSONDecodeError:
                        parsed = None
                    if isinstance(parsed, list):
                        draft[list_key] = parsed
    return normalized


def _agent_system_prompt(agent_type: str) -> str:
    return (
        "You are drafting remediation support for a ThreatGenix model-agnostic agent contract. "
        f"Agent type: {agent_type}. Use only the supplied evidence context. Draft summaries, patch guidance, "
        "PR wording, and ticket wording. Do not decide validation state, do not claim anything is secure, "
        "fixed, resolved, compliant, or accepted risk, and do not request direct repo/cloud/runtime mutation."
    )


def _agent_user_message(
    agent_type: str,
    context_packet: dict[str, Any],
    *,
    validation_error: str | None = None,
) -> str:
    lines = [
        f"Generate the {agent_type} remediation draft now.",
        "Return one structured object with all required keys:",
        "- summary: non-empty string",
        "- patch_preview: non-empty string",
        "- ticket_draft: object with non-empty title and body, optional labels array",
        "- pr_draft: object with non-empty title and body, optional target_files array",
        "If the handoff should be ticket-first, still include pr_draft as draft wording with target_files as an empty array.",
        "Do not include secure, fixed, resolved, remediated, compliant, accepted risk, or safe-to-deploy claims.",
    ]
    if validation_error:
        lines.extend(
            [
                "Your previous draft failed schema validation.",
                f"Validation error: {validation_error}",
                "Return a corrected draft only.",
            ]
        )
    lines.extend(
        [
            "Evidence context JSON:",
            json.dumps(context_packet, sort_keys=True, default=str),
        ]
    )
    return "\n".join(lines)


def _agent_output_tool(output_schema: dict[str, Any]) -> dict[str, Any]:
    schema = output_schema or {
        "type": "object",
        "required": ["summary", "patch_preview", "ticket_draft", "pr_draft"],
        "properties": {
            "summary": {"type": "string"},
            "patch_preview": {"type": "string"},
            "ticket_draft": {"type": "object"},
            "pr_draft": {"type": "object"},
        },
    }
    return {
        "name": "generate_agent_draft",
        "description": "Return the schema-valid draft output for the selected ThreatGenix agent contract.",
        "inputSchema": {"json": schema},
    }


def _redact_context_packet(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).casefold()
            if any(term in lowered for term in ("secret", "token", "password", "credential", "api_key", "apikey")):
                redacted[key] = "[redacted]"
            else:
                redacted[key] = _redact_context_packet(item)
        return redacted
    if isinstance(value, list):
        return [_redact_context_packet(item) for item in value]
    return value


def _fallback_patch_preview(agent_type: str, description: str) -> str:
    if agent_type == "code_fix":
        return (
            "Code fix guidance:\n"
            "- Locate the affected route, handler, or service named by the evidence refs.\n"
            "- Add or tighten authorization before sensitive data access.\n"
            "- Add a regression test that fails without the authorization check.\n"
            f"- Re-run validation for: {description[:180]}"
        )
    if agent_type == "iac_fix":
        return (
            "IaC fix guidance:\n"
            "- Locate the IaC resource named by Checkov or IaC evidence.\n"
            "- Apply least-privilege network, IAM, encryption, or logging controls.\n"
            "- Avoid broad allow-all changes and document residual risk.\n"
            f"- Re-run validation for: {description[:180]}"
        )
    return (
        "Configuration fix guidance:\n"
        "- Identify whether the setting is code-backed or runtime-owned.\n"
        "- Prefer config-as-code PRs when available; otherwise create an operations ticket.\n"
        "- Attach proof before rerunning validation.\n"
        f"- Re-run validation for: {description[:180]}"
    )


def _fallback_ticket_body(agent_type: str, description: str, evidence_refs: list[dict[str, Any]]) -> str:
    refs = _target_files(evidence_refs)
    refs_text = ", ".join(refs) if refs else "No file path was available; use attached evidence refs."
    return "\n".join(
        [
            "ThreatGenix remediation handoff",
            f"- Agent type: {agent_type}",
            f"- Threat: {description[:300]}",
            f"- Evidence refs: {refs_text}",
            "- Required proof: PR, scanner output, reviewer note, or configuration evidence.",
            "- Do not close until ThreatGenix rerun validation no longer reports this as confirmed.",
        ]
    )


def _target_files(evidence_refs: list[dict[str, Any]]) -> list[str]:
    paths: list[str] = []
    for ref in evidence_refs:
        for source_ref in ref.get("source_refs") or []:
            if isinstance(source_ref, dict):
                path = source_ref.get("path") or source_ref.get("location")
                if isinstance(path, str) and path and path not in paths:
                    paths.append(path)
    return paths[:10]

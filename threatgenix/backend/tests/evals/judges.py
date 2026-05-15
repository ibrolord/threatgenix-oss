from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Protocol, TypeVar

from pydantic import BaseModel

from tests.evals.schema import ClaudeJudgeResult, GeminiJudgeResult, JudgeInput

T = TypeVar("T", bound=BaseModel)


CLAUDE_OUTPUT_EXAMPLE = {
    "supported_top10_count": 8,
    "unsupported_threat_ids": ["T-004"],
    "wrong_stride_ids": [],
    "wrong_severity_ids": [],
    "duplicate_clusters": [["T-008", "T-010"]],
    "missing_critical_themes": ["NSTAR-03"],
    "blocker_findings": [],
    "score_correctness_0_100": 84,
    "verdict": "PARTIAL",
    "low_confidence_ambiguity": False,
}

GEMINI_OUTPUT_EXAMPLE = {
    "generic_threat_ids": ["T-006"],
    "missing_high_value_themes": ["NSTAR-02"],
    "misprioritized_ids": ["T-011"],
    "top10_quality_score_0_100": 78,
    "overall_world_class_score_0_100": 74,
    "world_class_verdict": "PARTIAL",
    "notes": ["The top threat list misses the privileged repair abuse path."],
    "low_confidence_ambiguity": False,
}


class ClaudeJudgeRunner(Protocol):
    def invoke_json_model(
        self,
        prompt: str,
        model_type: type[T],
        *,
        model: str | None = None,
        timeout_seconds: int = 240,
    ) -> T: ...


class ClaudeJudgeCliRunner:
    """Eval-only Claude CLI runner used by the optional audit judge."""

    def __init__(self, *, executable: str = "claude") -> None:
        self.executable = executable

    def invoke_json_model(
        self,
        prompt: str,
        model_type: type[T],
        *,
        model: str | None = None,
        timeout_seconds: int = 240,
    ) -> T:
        if shutil.which(self.executable) is None:
            raise RuntimeError(
                "Claude CLI is not installed or not on PATH. Install Claude Code and ensure "
                "the `claude` command is available before running the eval judge."
            )

        resolved_model = model or os.getenv("THREATGENIX_CLAUDE_MODEL", "opus")
        command = [
            self.executable,
            "--print",
            "--input-format",
            "text",
            "--model",
            resolved_model,
            "--no-session-persistence",
            "--tools",
            "",
            "--output-format",
            "json",
            "--json-schema",
            json.dumps(model_type.model_json_schema(), separators=(",", ":")),
        ]
        result = subprocess.run(
            command,
            input=prompt,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
            env=_sanitized_env(),
        )
        if result.returncode != 0:
            combined = (result.stderr or result.stdout or "").strip()
            if (
                "Not logged in" in combined
                or "claude auth login" in combined
                or "setup-token" in combined
            ):
                raise RuntimeError(
                    "Claude CLI is installed but not authenticated. Run `claude auth login` "
                    "or `claude setup-token` before using the eval judge."
                )
            raise RuntimeError(
                f"Claude CLI command failed ({self.executable}): {combined or 'no output'}"
            )

        payload = _extract_json_object(result.stdout)
        structured_output = payload.get("structured_output")
        if isinstance(structured_output, dict):
            payload = structured_output
        return model_type.model_validate(payload)


def _sanitized_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env.keys()):
        if key.startswith("BASH_FUNC_"):
            env.pop(key, None)
    env.pop("PROMPT_COMMAND", None)
    env.pop("PS1", None)
    return env


def _extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if not text:
        raise ValueError("Model returned empty output")

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"Could not find JSON object in output: {text[:400]}")
    candidate = text[start : end + 1]
    parsed = json.loads(candidate)
    if not isinstance(parsed, dict):
        raise ValueError("Model output was not a JSON object")
    return parsed


def _run_command(command: list[str], prompt: str, timeout_seconds: int) -> str:
    result = subprocess.run(
        [*command, prompt],
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({' '.join(command)}): {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()


def _invoke_json_model(
    command: list[str],
    prompt: str,
    model_type: type[T],
    timeout_seconds: int,
) -> T:
    output = _run_command(command, prompt, timeout_seconds)
    payload = _extract_json_object(output)
    return model_type.model_validate(payload)


def _judge_input_payload(judge_input: JudgeInput) -> str:
    return json.dumps(_compact_judge_payload(judge_input), indent=2, sort_keys=True)


def _compact_threat(threat: dict[str, Any]) -> dict[str, Any]:
    return {
        "display_id": threat.get("display_id"),
        "rule_id": threat.get("rule_id"),
        "severity": threat.get("severity"),
        "stride_category": threat.get("stride_category"),
        "threat_subtype": threat.get("threat_subtype"),
        "description": threat.get("description"),
        "affected_node_ids": threat.get("affected_node_ids", []),
        "source": threat.get("source"),
    }


def _compact_judge_payload(judge_input: JudgeInput) -> dict[str, Any]:
    payload = judge_input.model_dump(mode="json")
    actual_threats = payload.get("actual_threats", [])
    rules_only_threats = payload.get("rules_only_threats", [])
    top_20_threats = payload.get("top_20_threats", [])

    payload["actual_threat_count"] = len(actual_threats)
    payload["rules_only_threat_count"] = len(rules_only_threats)
    payload["top_20_threats"] = [_compact_threat(threat) for threat in top_20_threats]
    payload["actual_threats"] = [_compact_threat(threat) for threat in actual_threats[:40]]
    payload["rules_only_threats"] = [_compact_threat(threat) for threat in rules_only_threats[:25]]

    if len(actual_threats) > 40:
        payload["actual_threats_truncated"] = {
            "included": 40,
            "omitted": len(actual_threats) - 40,
        }
    if len(rules_only_threats) > 25:
        payload["rules_only_threats_truncated"] = {
            "included": 25,
            "omitted": len(rules_only_threats) - 25,
        }
    return payload


def build_claude_prompt(judge_input: JudgeInput) -> str:
    return (
        "You are the correctness judge for ThreatGenix audit runs.\n"
        "Evaluate only the provided evidence package. Do not ask questions.\n"
        "Be strict about unsupported threats, wrong STRIDE categorization, "
        "material severity mistakes, duplicated threats, critical omissions, "
        "and hallucinations.\n"
        "Treat blocker hallucinations in the top 10 as severe.\n"
        "Return exactly one JSON object and no markdown.\n"
        f"JSON schema example:\n{json.dumps(CLAUDE_OUTPUT_EXAMPLE, indent=2)}\n\n"
        "Scoring guidance:\n"
        "- score_correctness_0_100 should heavily penalize unsupported threats, "
        "wrong critical severities, and missed critical themes.\n"
        "- verdict PASS means the output is materially defensible for analyst use.\n"
        "- verdict PARTIAL means usable but with meaningful correctness gaps.\n"
        "- verdict FAIL means the output is not trustworthy.\n\n"
        f"Evidence package:\n{_judge_input_payload(judge_input)}\n"
    )


def build_gemini_prompt(judge_input: JudgeInput) -> str:
    return (
        "You are the world-class quality judge for ThreatGenix audit runs.\n"
        "Evaluate whether the threats are tailored, high-value, well-prioritized, "
        "and credible to a senior threat analyst. Focus on specificity, coverage, "
        "prioritization, analyst utility, and whether the output feels elite or generic.\n"
        "Return exactly one JSON object and no markdown.\n"
        f"JSON schema example:\n{json.dumps(GEMINI_OUTPUT_EXAMPLE, indent=2)}\n\n"
        "Scoring guidance:\n"
        "- top10_quality_score_0_100 scores only the highest-priority 10 threats.\n"
        "- overall_world_class_score_0_100 scores the entire run against an enterprise "
        "world-class standard.\n"
        "- world_class_verdict PASS means world-class or very near it, PARTIAL means "
        "promising but uneven, FAIL means clearly below a world-class bar.\n\n"
        f"Evidence package:\n{_judge_input_payload(judge_input)}\n"
    )


def run_claude_judge(
    judge_input: JudgeInput,
    *,
    timeout_seconds: int = 240,
    wrapper: ClaudeJudgeRunner | None = None,
    model: str | None = None,
) -> ClaudeJudgeResult:
    cli_wrapper = wrapper or ClaudeJudgeCliRunner()
    return cli_wrapper.invoke_json_model(
        build_claude_prompt(judge_input),
        ClaudeJudgeResult,
        model=model,
        timeout_seconds=timeout_seconds,
    )


def run_gemini_judge(
    judge_input: JudgeInput,
    *,
    timeout_seconds: int = 480,
    command: list[str] | None = None,
) -> GeminiJudgeResult:
    if command is None:
        command = [
            "gemini",
            "--approval-mode",
            "plan",
            "--output-format",
            "text",
            "-p",
        ]
    return _invoke_json_model(
        command,
        build_gemini_prompt(judge_input),
        GeminiJudgeResult,
        timeout_seconds,
    )

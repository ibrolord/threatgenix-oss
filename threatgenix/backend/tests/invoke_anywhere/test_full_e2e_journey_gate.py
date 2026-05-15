from __future__ import annotations

import json
from pathlib import Path

from app.services.application_review_journey_gate import (
    FULL_E2E_JOURNEY_STEPS,
    validate_full_e2e_journey,
)


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "full_e2e_journey_trace.json"


def _trace() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_full_e2e_journey_fixture_covers_every_required_step():
    trace = _trace()

    result = validate_full_e2e_journey(trace)

    assert result.passed is True, result.model_dump()
    assert [event["step"] for event in trace["events"]] == list(FULL_E2E_JOURNEY_STEPS)


def test_full_e2e_journey_gate_rejects_missing_mcp_or_pr_report_steps():
    trace = _trace()
    trace["events"] = [
        event
        for event in trace["events"]
        if event["step"] not in {"mcp_ship_decision_requested", "report_exported"}
    ]
    trace["pr_comment_url"] = None
    trace["report_exported"] = False

    result = validate_full_e2e_journey(trace)

    assert result.passed is False
    assert "mcp_ship_decision_requested" in result.missing_steps
    assert "report_exported" in result.missing_steps
    assert "PR comment URL is missing" in result.failures
    assert "report export was not confirmed" in result.failures


def test_full_e2e_journey_gate_rejects_decision_drift_between_cli_web_and_mcp():
    trace = _trace()
    trace["decisions"]["web"] = "verify"

    result = validate_full_e2e_journey(trace)

    assert result.passed is False
    assert "CLI, web, and MCP decisions do not match" in result.failures


def test_full_e2e_journey_gate_rejects_rerun_without_improved_decision():
    trace = _trace()
    trace["decisions"]["after_fix"] = "block"

    result = validate_full_e2e_journey(trace)

    assert result.passed is False
    assert "rerun decision did not improve after fix" in result.failures

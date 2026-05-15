from __future__ import annotations

import json
from pathlib import Path

from app.services.performance_scale_gate import (
    PERFORMANCE_SCALE_SCENARIOS,
    validate_performance_scale_trace,
)


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "performance_scale_trace.json"


def _trace() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_performance_scale_fixture_covers_every_required_scenario_in_order():
    trace = _trace()

    result = validate_performance_scale_trace(trace)

    assert result.passed is True, result.model_dump()
    assert [observation["scenario"] for observation in trace["observations"]] == list(
        PERFORMANCE_SCALE_SCENARIOS
    )


def test_performance_scale_gate_rejects_missing_or_duplicate_scenarios():
    trace = _trace()
    trace["observations"] = [
        observation
        for observation in trace["observations"]
        if observation["scenario"] != "large_diff"
    ]
    trace["observations"].append(dict(trace["observations"][0]))

    result = validate_performance_scale_trace(trace)

    assert result.passed is False
    assert "large_diff" in result.missing_scenarios
    assert "small_diff was reported more than once" in result.failures


def test_performance_scale_gate_rejects_latency_threshold_drift():
    trace = _trace()
    small_diff = trace["observations"][0]
    small_diff["p95_seconds"] = 181
    small_diff["metrics"]["cli_status_p95_seconds"] = 2.1
    small_diff["metrics"]["web_review_page_p95_seconds"] = 3.2

    result = validate_performance_scale_trace(trace)

    assert result.passed is False
    assert "diff-only small PR p95 exceeded 180 seconds" in result.failures
    assert "small_diff CLI status p95 exceeded 2 seconds" in result.failures
    assert "small_diff web review page p95 exceeded 3 seconds" in result.failures


def test_performance_scale_gate_rejects_large_scanner_output_risk():
    trace = _trace()
    scanner_output = trace["observations"][3]
    scanner_output["metrics"]["secret_leak_count"] = 1
    scanner_output["metrics"]["evidence_hash_verified"] = False
    scanner_output["metrics"]["output_chunked_or_truncated"] = False
    scanner_output["metrics"]["parser_completed_seconds"] = 121

    result = validate_performance_scale_trace(trace)

    assert result.passed is False
    assert "large_scanner_output leaked secrets" in result.failures
    assert "large_scanner_output did not verify evidence hash" in result.failures
    assert "large_scanner_output did not confirm bounded output handling" in result.failures
    assert "large_scanner_output parser exceeded 120 seconds" in result.failures


def test_performance_scale_gate_rejects_concurrent_review_isolation_failures():
    trace = _trace()
    concurrent = trace["observations"][4]
    concurrent["metrics"]["tenant_isolation_violations"] = 1
    concurrent["metrics"]["failed_review_count"] = 3
    concurrent["metrics"]["queue_accepted_all_reviews"] = False

    result = validate_performance_scale_trace(trace)

    assert result.passed is False
    assert "concurrent_reviews had tenant isolation violations" in result.failures
    assert "concurrent_reviews exceeded manual failure inspection limit" in result.failures
    assert "concurrent_reviews did not confirm queue acceptance" in result.failures


def test_performance_scale_gate_rejects_repeated_webhook_non_idempotency():
    trace = _trace()
    webhook = trace["observations"][5]
    webhook["metrics"]["duplicate_comment_count"] = 1
    webhook["metrics"]["status_updates_idempotent"] = False
    webhook["metrics"]["signature_replay_rejected"] = False

    result = validate_performance_scale_trace(trace)

    assert result.passed is False
    assert "repeated_webhook_delivery created duplicate comments" in result.failures
    assert "repeated_webhook_delivery did not confirm idempotent status updates" in result.failures
    assert "repeated_webhook_delivery did not reject signature replay" in result.failures


def test_performance_scale_gate_rejects_large_diff_without_async_queueing():
    trace = _trace()
    large_diff = trace["observations"][1]
    large_diff["metrics"]["queued_for_async_review"] = False

    result = validate_performance_scale_trace(trace)

    assert result.passed is False
    assert "large_diff did not confirm async review queueing" in result.failures

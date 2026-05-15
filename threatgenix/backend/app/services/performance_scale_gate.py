"""Performance and scale validator for invoke-anywhere release gates."""

from __future__ import annotations

from pydantic import BaseModel, Field


STATUS_PASS = "pass"

PERFORMANCE_SCALE_SCENARIOS: tuple[str, ...] = (
    "small_diff",
    "large_diff",
    "medium_snapshot",
    "large_scanner_output",
    "concurrent_reviews",
    "repeated_webhook_delivery",
)

DIFF_ONLY_P95_SECONDS = 180
SNAPSHOT_MEDIUM_P95_SECONDS = 600
CLI_STATUS_P95_SECONDS = 2
WEB_REVIEW_PAGE_P95_SECONDS = 3
LARGE_SCANNER_PARSE_SECONDS = 120
MANUALLY_INSPECTABLE_FAILED_REVIEW_LIMIT = 2


class PerformanceScaleObservation(BaseModel):
    scenario: str
    status: str = STATUS_PASS
    p95_seconds: float | None = None
    max_seconds: float | None = None
    detail: str | None = None
    metrics: dict[str, int | float | str | bool | None] = Field(default_factory=dict)


class PerformanceScaleTrace(BaseModel):
    trace_id: str
    source_version: str
    observations: list[PerformanceScaleObservation] = Field(default_factory=list)


class PerformanceScaleResult(BaseModel):
    passed: bool
    missing_scenarios: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)


def validate_performance_scale_trace(
    trace: PerformanceScaleTrace | dict,
) -> PerformanceScaleResult:
    parsed = trace if isinstance(trace, PerformanceScaleTrace) else PerformanceScaleTrace.model_validate(trace)
    observations_by_scenario: dict[str, PerformanceScaleObservation] = {}
    duplicate_scenarios: list[str] = []
    failures: list[str] = []

    for observation in parsed.observations:
        if observation.scenario in observations_by_scenario:
            duplicate_scenarios.append(observation.scenario)
            continue
        observations_by_scenario[observation.scenario] = observation

    missing_scenarios = [
        scenario for scenario in PERFORMANCE_SCALE_SCENARIOS if scenario not in observations_by_scenario
    ]
    for scenario in duplicate_scenarios:
        failures.append(f"{scenario} was reported more than once")
    for observation in parsed.observations:
        failures.extend(_validate_observation(observation))

    return PerformanceScaleResult(
        passed=not missing_scenarios and not failures,
        missing_scenarios=missing_scenarios,
        failures=failures,
    )


def _validate_observation(observation: PerformanceScaleObservation) -> list[str]:
    failures: list[str] = []
    scenario = observation.scenario
    if observation.status != STATUS_PASS:
        failures.append(f"{scenario} status is {observation.status}")

    if scenario == "small_diff":
        failures.extend(
            _require_p95_at_or_below(
                observation,
                DIFF_ONLY_P95_SECONDS,
                "diff-only small PR",
            )
        )
    elif scenario == "large_diff":
        failures.extend(_validate_large_diff(observation))
    elif scenario == "medium_snapshot":
        failures.extend(
            _require_p95_at_or_below(
                observation,
                SNAPSHOT_MEDIUM_P95_SECONDS,
                "medium repo snapshot",
            )
        )
    elif scenario == "large_scanner_output":
        failures.extend(_validate_large_scanner_output(observation))
    elif scenario == "concurrent_reviews":
        failures.extend(_validate_concurrent_reviews(observation))
    elif scenario == "repeated_webhook_delivery":
        failures.extend(_validate_repeated_webhook_delivery(observation))

    failures.extend(_validate_shared_latency_metrics(observation))
    return failures


def _validate_large_diff(observation: PerformanceScaleObservation) -> list[str]:
    failures = _require_p95_at_or_below(
        observation,
        SNAPSHOT_MEDIUM_P95_SECONDS,
        "large diff review",
    )
    if observation.metrics.get("queued_for_async_review") is not True:
        failures.append("large_diff did not confirm async review queueing")
    return failures


def _validate_large_scanner_output(observation: PerformanceScaleObservation) -> list[str]:
    failures: list[str] = []
    if observation.metrics.get("secret_leak_count") != 0:
        failures.append("large_scanner_output leaked secrets")
    if observation.metrics.get("evidence_hash_verified") is not True:
        failures.append("large_scanner_output did not verify evidence hash")
    if observation.metrics.get("output_chunked_or_truncated") is not True:
        failures.append("large_scanner_output did not confirm bounded output handling")
    parser_seconds = _metric_number(observation, "parser_completed_seconds")
    if parser_seconds is None:
        failures.append("large_scanner_output is missing parser_completed_seconds")
    elif parser_seconds > LARGE_SCANNER_PARSE_SECONDS:
        failures.append("large_scanner_output parser exceeded 120 seconds")
    return failures


def _validate_concurrent_reviews(observation: PerformanceScaleObservation) -> list[str]:
    failures: list[str] = []
    if observation.metrics.get("tenant_isolation_violations") != 0:
        failures.append("concurrent_reviews had tenant isolation violations")
    failed_review_count = _metric_number(observation, "failed_review_count")
    if failed_review_count is None:
        failures.append("concurrent_reviews is missing failed_review_count")
    elif failed_review_count > MANUALLY_INSPECTABLE_FAILED_REVIEW_LIMIT:
        failures.append("concurrent_reviews exceeded manual failure inspection limit")
    if observation.metrics.get("queue_accepted_all_reviews") is not True:
        failures.append("concurrent_reviews did not confirm queue acceptance")
    return failures


def _validate_repeated_webhook_delivery(observation: PerformanceScaleObservation) -> list[str]:
    failures: list[str] = []
    if observation.metrics.get("duplicate_comment_count") != 0:
        failures.append("repeated_webhook_delivery created duplicate comments")
    if observation.metrics.get("status_updates_idempotent") is not True:
        failures.append("repeated_webhook_delivery did not confirm idempotent status updates")
    if observation.metrics.get("signature_replay_rejected") is not True:
        failures.append("repeated_webhook_delivery did not reject signature replay")
    return failures


def _validate_shared_latency_metrics(observation: PerformanceScaleObservation) -> list[str]:
    failures: list[str] = []
    cli_status_p95 = _metric_number(observation, "cli_status_p95_seconds")
    if cli_status_p95 is not None and cli_status_p95 > CLI_STATUS_P95_SECONDS:
        failures.append(f"{observation.scenario} CLI status p95 exceeded 2 seconds")
    web_review_page_p95 = _metric_number(observation, "web_review_page_p95_seconds")
    if web_review_page_p95 is not None and web_review_page_p95 > WEB_REVIEW_PAGE_P95_SECONDS:
        failures.append(f"{observation.scenario} web review page p95 exceeded 3 seconds")
    return failures


def _require_p95_at_or_below(
    observation: PerformanceScaleObservation,
    limit_seconds: int,
    label: str,
) -> list[str]:
    if observation.p95_seconds is None:
        return [f"{observation.scenario} is missing p95_seconds"]
    if observation.p95_seconds > limit_seconds:
        return [f"{label} p95 exceeded {limit_seconds} seconds"]
    return []


def _metric_number(
    observation: PerformanceScaleObservation,
    metric_name: str,
) -> float | None:
    value = observation.metrics.get(metric_name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)

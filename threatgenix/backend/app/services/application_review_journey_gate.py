"""Full journey validator for invoke-anywhere release gates."""

from __future__ import annotations

from pydantic import BaseModel, Field


FULL_E2E_JOURNEY_STEPS: tuple[str, ...] = (
    "fresh_repo",
    "cli_review_started",
    "intake_completed",
    "upload_approved",
    "bundle_created",
    "managed_scanners_completed",
    "code_context_extracted",
    "evidence_graph_rebuilt",
    "context_index_updated",
    "cli_decision_returned",
    "web_review_opened",
    "evidence_chain_and_fix_plan_visible",
    "mcp_ship_decision_requested",
    "mcp_matches_web_cli",
    "github_pr_webhook_simulated",
    "pr_comment_and_status_posted",
    "fix_applied",
    "review_rerun",
    "decision_improved",
    "report_exported",
)

DECISION_RISK_RANK = {
    "block": 5,
    "fix": 4,
    "verify": 3,
    "gather_evidence": 2,
    "pass": 1,
}


class JourneyGateEvent(BaseModel):
    step: str
    status: str = "pass"
    detail: str | None = None


class JourneyDecisionParity(BaseModel):
    cli: str
    web: str
    mcp: str
    after_fix: str | None = None


class JourneyGateTrace(BaseModel):
    journey_id: str
    review_id: str
    web_url: str
    pr_comment_url: str | None = None
    report_exported: bool = False
    decisions: JourneyDecisionParity
    events: list[JourneyGateEvent] = Field(default_factory=list)

    @property
    def after_fix_required(self) -> bool:
        steps = {event.step for event in self.events}
        return {"fix_applied", "review_rerun", "decision_improved"}.issubset(steps)


class JourneyGateResult(BaseModel):
    passed: bool
    missing_steps: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)


def validate_full_e2e_journey(trace: JourneyGateTrace | dict) -> JourneyGateResult:
    parsed = trace if isinstance(trace, JourneyGateTrace) else JourneyGateTrace.model_validate(trace)
    events_by_step = {event.step: event for event in parsed.events}
    missing_steps = [step for step in FULL_E2E_JOURNEY_STEPS if step not in events_by_step]
    failures: list[str] = []
    for event in parsed.events:
        if event.status != "pass":
            failures.append(f"{event.step} status is {event.status}")
    if parsed.decisions.cli != parsed.decisions.web or parsed.decisions.cli != parsed.decisions.mcp:
        failures.append("CLI, web, and MCP decisions do not match")
    if parsed.after_fix_required and not _decision_improved(parsed.decisions.cli, parsed.decisions.after_fix):
        failures.append("rerun decision did not improve after fix")
    if parsed.review_id not in parsed.web_url:
        failures.append("web review URL does not include the review id")
    if not parsed.pr_comment_url:
        failures.append("PR comment URL is missing")
    if not parsed.report_exported:
        failures.append("report export was not confirmed")
    return JourneyGateResult(
        passed=not missing_steps and not failures,
        missing_steps=missing_steps,
        failures=failures,
    )


def _decision_improved(before: str, after: str | None) -> bool:
    if after is None:
        return False
    before_rank = DECISION_RISK_RANK.get(before)
    after_rank = DECISION_RISK_RANK.get(after)
    if before_rank is None or after_rank is None:
        return False
    return after_rank < before_rank

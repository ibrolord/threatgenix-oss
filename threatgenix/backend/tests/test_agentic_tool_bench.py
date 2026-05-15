from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.services.agentic_tool_bench import build_agentic_tool_bench


def _tool(name: str = "semgrep", readiness_status: str = "ready") -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        category="static_code_analysis",
        supported_targets=["repository_path"],
        recommended_for=["semantic code flaws"],
        proof_mode="source-code evidence",
        safety_boundary="Local path allowlist.",
        readiness_status=readiness_status,
        blocker_reasons=[] if readiness_status == "ready" else ["Semgrep CLI is missing."],
    )


def _case(
    *,
    case_id: str = "case-1",
    status: str = "needs_evidence",
    priority: str = "P1",
) -> SimpleNamespace:
    return SimpleNamespace(
        case_id=case_id,
        title="JWT verifier accepts untrusted algorithms",
        status=status,
        recommended_checks=[
            SimpleNamespace(
                tool_name="semgrep",
                target_type="repository_path",
                priority=priority,
                reason="Retest authentication source code with a deterministic SAST rule.",
            )
        ],
    )


def _schedule(*, runnable: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        tool_name="semgrep",
        target_type="repository_path",
        runnable=runnable,
        blocked_reason=None if runnable else "Target is outside the allowed runner roots.",
    )


def test_agentic_tool_bench_recommends_ready_policy_gated_tool_run():
    bench = build_agentic_tool_bench(
        inventory=[_tool()],
        product_security_cases=[_case()],
        evidence_ledger=[],
        schedules=[_schedule()],
        run_submission_enabled=True,
    )

    assert bench.status == "ready"
    assert bench.recommendations
    recommendation = bench.recommendations[0]
    assert recommendation.tool_name == "semgrep"
    assert recommendation.priority == "P1"
    assert recommendation.blocked_reason is None
    assert recommendation.saved_target_id is not None
    assert [step.step for step in recommendation.workflow] == [
        "plan",
        "policy_gate",
        "execute",
        "bind",
        "critic",
        "report",
    ]
    assert "source-code security pattern" in bench.capabilities[0].proves


def test_agentic_tool_bench_marks_missing_saved_targets_separately():
    bench = build_agentic_tool_bench(
        inventory=[_tool()],
        product_security_cases=[_case()],
        evidence_ledger=[],
        schedules=[],
        run_submission_enabled=True,
    )

    assert bench.status == "needs_targets"
    assert bench.recommendations[0].blocked_reason
    assert "No saved repository path target" in bench.recommendations[0].blocked_reason


def test_agentic_tool_bench_blocks_when_runner_submission_is_disabled():
    bench = build_agentic_tool_bench(
        inventory=[_tool()],
        product_security_cases=[_case()],
        evidence_ledger=[],
        schedules=[_schedule()],
        run_submission_enabled=False,
    )

    assert bench.status == "blocked"
    assert bench.recommendations[0].blocked_reason
    assert "runner is not enabled" in bench.recommendations[0].blocked_reason


def test_agentic_tool_bench_ignores_already_validated_cases():
    bench = build_agentic_tool_bench(
        inventory=[_tool()],
        product_security_cases=[_case(status="validated")],
        evidence_ledger=[SimpleNamespace()],
        schedules=[_schedule()],
        run_submission_enabled=True,
    )

    assert bench.status == "needs_evidence"
    assert bench.recommendations == []


def test_agentic_tool_bench_uses_next_run_fallback_when_cases_are_closed():
    bench = build_agentic_tool_bench(
        inventory=[_tool()],
        product_security_cases=[_case(status="validated")],
        evidence_ledger=[SimpleNamespace()],
        schedules=[],
        run_submission_enabled=True,
        recommended_next_runs=[
            SimpleNamespace(
                tool_name="semgrep",
                target_type="repository_path",
                priority="P2",
                reason="Retest source assumptions against deterministic evidence.",
                blocked_reason=None,
            )
        ],
    )

    assert bench.status == "needs_targets"
    assert bench.recommendations[0].recommendation_id == "baseline:semgrep:repository_path"
    assert bench.recommendations[0].objective == "Use Semgrep to collect baseline validation evidence."
    assert "No saved repository path target" in bench.recommendations[0].blocked_reason

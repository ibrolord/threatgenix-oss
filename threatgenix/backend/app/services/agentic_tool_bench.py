"""Deterministic planner for agentic validation-tool use."""

from __future__ import annotations

from typing import Any

from app.schemas.validation_lab import (
    AgenticToolBenchResponse,
    AgenticToolCapabilityResponse,
    AgenticToolRecommendationResponse,
    AgenticToolWorkflowStepResponse,
)

_TOOL_PROOF_HINTS: dict[str, list[str]] = {
    "nuclei": ["HTTP exposure", "known vulnerable endpoint behavior", "safe template match"],
    "semgrep": ["source-code security pattern", "auth or data-flow implementation flaw"],
    "osv-scanner": ["dependency advisory match", "lockfile-resolved vulnerable package"],
    "trivy": ["filesystem or IaC misconfiguration", "container or dependency exposure signal"],
    "checkov": ["cloud/IaC policy failure", "network/storage/identity misconfiguration"],
    "trufflehog": ["secret-like token exposure", "credential hygiene issue"],
}

_EVIDENCE_SCHEMA_BY_TOOL: dict[str, list[str]] = {
    "nuclei": ["matched_url", "template_id", "severity", "extracted_results", "output_sha256"],
    "semgrep": ["source_path", "rule_id", "line", "message", "output_sha256"],
    "osv-scanner": ["package", "version", "advisory_id", "cve_ids", "lockfile"],
    "trivy": ["target", "misconfiguration_id", "package_or_resource", "severity"],
    "checkov": ["check_id", "resource", "file_path", "guideline"],
    "trufflehog": ["detector", "source_path", "redacted_secret", "verified_status"],
}

_CRITIC_CHECKS_BY_TOOL: dict[str, list[str]] = {
    "nuclei": [
        "Confirm the matched URL belongs to an authorized target.",
        "Do not validate a semantic threat from an info-only template without product impact.",
    ],
    "semgrep": [
        "Require source path or component metadata before binding to a DFD node.",
        "Demote framework-generic rules when the modeled component is not affected.",
    ],
    "osv-scanner": [
        "Confirm the vulnerable package is reachable in the modeled service.",
        "Do not overstate advisories that are dev-only or outside runtime scope.",
    ],
    "trivy": [
        "Distinguish filesystem dependency findings from cloud/IaC misconfiguration proof.",
        "Require resource or path binding before validating an architecture threat.",
    ],
    "checkov": [
        "Confirm the IaC resource is deployed or belongs to the modeled environment.",
        "Treat policy failures as indicated until environment evidence confirms exposure.",
    ],
    "trufflehog": [
        "Never expose raw secret values in reports or agent context.",
        "Require redaction and owner review before promoting credential exposure.",
    ],
}

_GLOBAL_CRITIC_RULES = [
    "Never claim a vulnerability is validated without tool evidence, imported evidence, or explicit model evidence.",
    "Unbound evidence can indicate risk, but cannot validate a semantic threat until it maps to a DFD node or global target.",
    "Prefer deterministic findings over AI-generated rationale; use agents to explain gaps, not to invent proof.",
    "Block execution when target authorization, sandbox policy, or tenant scope is unclear.",
]


def build_agentic_tool_bench(
    *,
    inventory: list[Any],
    product_security_cases: list[Any],
    evidence_ledger: list[Any],
    schedules: list[Any],
    run_submission_enabled: bool,
    recommended_next_runs: list[Any] | None = None,
) -> AgenticToolBenchResponse:
    """Build an evidence-grounded planning surface for agentic tool use."""

    capabilities = [_capability_for_tool(tool) for tool in inventory]
    recommendations = _build_recommendations(
        product_security_cases=product_security_cases,
        inventory=inventory,
        schedules=schedules,
        run_submission_enabled=run_submission_enabled,
        recommended_next_runs=recommended_next_runs or [],
    )
    planning_inputs = [
        f"{len(product_security_cases)} product security case(s)",
        f"{len(evidence_ledger)} evidence ledger entr{'y' if len(evidence_ledger) == 1 else 'ies'}",
        f"{len(schedules)} saved validation target(s)",
        f"{sum(1 for item in inventory if getattr(item, 'readiness_status', '') == 'ready')} runnable tool(s)",
    ]
    if not recommendations:
        status = "needs_evidence"
        summary = (
            "No agentic tool recommendation is ready yet. Run or import evidence so the planner "
            "can connect tool choice to a concrete threat, target, and evidence gap."
        )
    elif all(item.blocked_reason for item in recommendations):
        if any(item.blocked_reason and "No saved" in item.blocked_reason for item in recommendations):
            status = "needs_targets"
            summary = (
                "The planner found relevant tool actions, but saved validation targets are "
                "needed before execution."
            )
        else:
            status = "blocked"
            summary = (
                "The planner found relevant tool actions, but each one is blocked by runner, "
                "target, or policy requirements."
            )
    elif any(item.blocked_reason for item in recommendations):
        status = "needs_targets"
        summary = (
            "The planner found useful tool actions, but some need saved targets or setup before execution."
        )
    else:
        status = "ready"
        summary = (
            "Agentic planning is ready: recommended tools have a saved target and can flow through "
            "policy gate, execution, binding, critic review, and report output."
        )

    return AgenticToolBenchResponse(
        status=status,
        summary=summary,
        planning_inputs=planning_inputs,
        capabilities=capabilities,
        recommendations=recommendations,
        execution_contract=_workflow_contract(),
        global_critic_rules=_GLOBAL_CRITIC_RULES,
    )


def _capability_for_tool(tool: Any) -> AgenticToolCapabilityResponse:
    name = str(getattr(tool, "name", "unknown"))
    label = _tool_label(name)
    return AgenticToolCapabilityResponse(
        tool_name=name,
        label=label,
        category=str(getattr(tool, "category", "validation")),
        target_types=list(getattr(tool, "supported_targets", []) or []),
        proves=_TOOL_PROOF_HINTS.get(name, [str(getattr(tool, "proof_mode", "validation evidence"))]),
        best_for=list(getattr(tool, "recommended_for", []) or []),
        evidence_schema=_EVIDENCE_SCHEMA_BY_TOOL.get(
            name,
            ["tool_name", "target", "severity", "finding_title", "raw_output"],
        ),
        execution_boundary=str(getattr(tool, "safety_boundary", "authorization and policy gate required")),
        noise_controls=[
            "Normalize raw output into ScanFinding evidence.",
            "Map findings to DFD node metadata before semantic validation.",
            "Keep blocked and unbound states visible instead of dropping evidence.",
        ],
        critic_checks=_CRITIC_CHECKS_BY_TOOL.get(
            name,
            ["Require evidence provenance and binding before promoting confidence."],
        ),
    )


def _build_recommendations(
    *,
    product_security_cases: list[Any],
    inventory: list[Any],
    schedules: list[Any],
    run_submission_enabled: bool,
    recommended_next_runs: list[Any],
) -> list[AgenticToolRecommendationResponse]:
    inventory_by_name = {str(getattr(tool, "name", "")): tool for tool in inventory}
    recs: list[AgenticToolRecommendationResponse] = []
    seen: set[tuple[str, str, str]] = set()
    actionable_cases = [
        case for case in product_security_cases
        if getattr(case, "status", "") != "validated"
    ]
    for case in actionable_cases:
        checks = list(getattr(case, "recommended_checks", []) or [])
        for check in checks:
            tool_name = str(getattr(check, "tool_name", ""))
            target_type = str(getattr(check, "target_type", ""))
            priority = str(getattr(check, "priority", "P2"))
            key = (str(getattr(case, "case_id", "")), tool_name, target_type)
            if key in seen or not tool_name or not target_type:
                continue
            seen.add(key)
            saved_target = _matching_schedule(schedules, tool_name, target_type)
            blocked_reason = _blocked_reason(
                tool=inventory_by_name.get(tool_name),
                saved_target=saved_target,
                target_type=target_type,
                run_submission_enabled=run_submission_enabled,
            )
            recs.append(
                AgenticToolRecommendationResponse(
                    recommendation_id=f"{getattr(case, 'case_id', 'case')}:{tool_name}:{target_type}",
                    priority=priority if priority in {"P1", "P2", "P3"} else "P2",
                    tool_name=tool_name,
                    target_type=target_type,
                    objective=_objective_for_case(case, tool_name),
                    rationale=str(getattr(check, "reason", "")) or _default_rationale(tool_name),
                    evidence_gap=_evidence_gap_for_case(case),
                    expected_evidence=_expected_evidence(tool_name, target_type),
                    blocked_reason=blocked_reason,
                    saved_target_id=getattr(saved_target, "id", None),
                    safety_gates=_safety_gates(tool_name, saved_target, inventory_by_name.get(tool_name)),
                    critic_checks=_CRITIC_CHECKS_BY_TOOL.get(
                        tool_name,
                        ["Require evidence provenance and binding before promoting confidence."],
                    ),
                    workflow=_workflow_contract(tool_name=tool_name),
                )
            )
    if not recs:
        recs.extend(
            _recommendations_from_next_runs(
                recommended_next_runs=recommended_next_runs,
                inventory_by_name=inventory_by_name,
                schedules=schedules,
                run_submission_enabled=run_submission_enabled,
            )
        )
    return sorted(recs, key=lambda item: (item.priority, item.tool_name, item.target_type))[:8]


def _recommendations_from_next_runs(
    *,
    recommended_next_runs: list[Any],
    inventory_by_name: dict[str, Any],
    schedules: list[Any],
    run_submission_enabled: bool,
) -> list[AgenticToolRecommendationResponse]:
    recs: list[AgenticToolRecommendationResponse] = []
    seen: set[tuple[str, str]] = set()
    for run in recommended_next_runs:
        tool_name = str(getattr(run, "tool_name", ""))
        target_type = str(getattr(run, "target_type", ""))
        priority = str(getattr(run, "priority", "P2"))
        if not tool_name or not target_type or (tool_name, target_type) in seen:
            continue
        seen.add((tool_name, target_type))
        saved_target = _matching_schedule(schedules, tool_name, target_type)
        blocked_reason = _blocked_reason(
            tool=inventory_by_name.get(tool_name),
            saved_target=saved_target,
            target_type=target_type,
            run_submission_enabled=run_submission_enabled,
        ) or getattr(run, "blocked_reason", None)
        recs.append(
            AgenticToolRecommendationResponse(
                recommendation_id=f"baseline:{tool_name}:{target_type}",
                priority=priority if priority in {"P1", "P2", "P3"} else "P2",
                tool_name=tool_name,
                target_type=target_type,
                objective=f"Use {_tool_label(tool_name)} to collect baseline validation evidence.",
                rationale=str(getattr(run, "reason", "")) or _default_rationale(tool_name),
                evidence_gap="No active case-specific tool plan is pending; use this to seed fresh evidence.",
                expected_evidence=_expected_evidence(tool_name, target_type),
                blocked_reason=blocked_reason,
                saved_target_id=getattr(saved_target, "id", None),
                safety_gates=_safety_gates(tool_name, saved_target, inventory_by_name.get(tool_name)),
                critic_checks=_CRITIC_CHECKS_BY_TOOL.get(
                    tool_name,
                    ["Require evidence provenance and binding before promoting confidence."],
                ),
                workflow=_workflow_contract(tool_name=tool_name),
            )
        )
    return recs


def _matching_schedule(schedules: list[Any], tool_name: str, target_type: str) -> Any | None:
    return next(
        (
            schedule for schedule in schedules
            if getattr(schedule, "tool_name", None) == tool_name
            and getattr(schedule, "target_type", None) == target_type
        ),
        None,
    )


def _blocked_reason(
    *,
    tool: Any | None,
    saved_target: Any | None,
    target_type: str,
    run_submission_enabled: bool,
) -> str | None:
    if not run_submission_enabled:
        return "Live validation runner is not enabled; import captured evidence or use Try Sandbox."
    if tool is None:
        return "Tool is not registered in this deployment."
    if getattr(tool, "readiness_status", "") != "ready":
        reasons = list(getattr(tool, "blocker_reasons", []) or [])
        return reasons[0] if reasons else f"{_tool_label(getattr(tool, 'name', 'tool'))} is not ready."
    if saved_target is None:
        return f"No saved {target_type.replace('_', ' ')} target exists for this tool."
    if not getattr(saved_target, "runnable", False):
        return getattr(saved_target, "blocked_reason", None) or "Saved target is not runnable."
    return None


def _objective_for_case(case: Any, tool_name: str) -> str:
    title = str(getattr(case, "title", "validation case"))
    return f"Use {_tool_label(tool_name)} to collect evidence for {title}."


def _evidence_gap_for_case(case: Any) -> str:
    status = str(getattr(case, "status", "needs_evidence"))
    if status == "needs_binding":
        return "Evidence exists but is not bound to a modeled component."
    if status == "relevant":
        return "Evidence indicates relevance, but proof is not strong enough for validation."
    return "No concrete validation evidence has been captured for this case."


def _expected_evidence(tool_name: str, target_type: str) -> str:
    proof = ", ".join(_TOOL_PROOF_HINTS.get(tool_name, ["normalized finding"]))
    return f"{proof} on a {target_type.replace('_', ' ')} target with artifact provenance."


def _safety_gates(tool_name: str, saved_target: Any | None, tool: Any | None) -> list[str]:
    gates = [
        "Per-run target authorization must be acknowledged.",
        "Execution must pass tool policy and target-safety checks.",
    ]
    if tool is not None:
        gates.append(str(getattr(tool, "safety_boundary", "Tool boundary must be enforced.")))
    if saved_target is None:
        gates.append(f"Save a {_tool_label(tool_name)} validation target before execution.")
    else:
        gates.append("Use the saved target snapshot for auditability.")
    return gates[:4]


def _workflow_contract(tool_name: str | None = None) -> list[AgenticToolWorkflowStepResponse]:
    tool_label = _tool_label(tool_name) if tool_name else "selected tool"
    return [
        AgenticToolWorkflowStepResponse(
            step="plan",
            owner="Validation Planner",
            detail=f"Choose {tool_label} only when it can close a named evidence gap.",
        ),
        AgenticToolWorkflowStepResponse(
            step="policy_gate",
            owner="Policy Gate",
            detail="Check tenant authorization, target type, allowed roots, sandbox, and runtime policy.",
        ),
        AgenticToolWorkflowStepResponse(
            step="execute",
            owner="Tool Executor",
            detail="Run only the approved adapter through durable task execution; no freeform shell.",
        ),
        AgenticToolWorkflowStepResponse(
            step="bind",
            owner="Evidence Binder",
            detail="Normalize output and bind it to DFD node, resource, package, endpoint, or global target.",
        ),
        AgenticToolWorkflowStepResponse(
            step="critic",
            owner="Evidence Critic",
            detail="Demote noisy, unbound, or non-reachable findings before they affect validation confidence.",
        ),
        AgenticToolWorkflowStepResponse(
            step="report",
            owner="Report Agent",
            detail="Explain only cited evidence, blocked reasons, and remaining gaps.",
        ),
    ]


def _default_rationale(tool_name: str) -> str:
    return f"{_tool_label(tool_name)} can produce evidence for the current validation case."


def _tool_label(tool_name: str) -> str:
    if tool_name == "osv-scanner":
        return "OSV Scanner"
    if tool_name == "external-report":
        return "External Report"
    if tool_name == "pentest-report":
        return "Pentest Report"
    return " ".join(part.capitalize() for part in str(tool_name).split("-"))

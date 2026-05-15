"""Fixture-driven golden and adversarial decision scenarios."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from app.models.application_review_context import ApplicationReviewContextEntry
from app.services.application_review_bundles import canonical_json
from app.services.application_review_decision import evaluate_application_review_decision_entries


ScenarioKind = Literal["golden", "adversarial"]


class DecisionScenarioEntry(BaseModel):
    source_type: str = "manual"
    item_type: str
    title: str
    body: str
    facets: dict = Field(default_factory=dict)
    source_refs: list[dict] = Field(default_factory=list)
    content_hash: str | None = Field(default=None, min_length=64, max_length=64)
    status: str = "active"


class DecisionScenarioExpectation(BaseModel):
    decision: str | None = None
    allowed_decisions: list[str] = Field(default_factory=list)
    scanner_only: bool | None = None
    required_trace: list[str] = Field(default_factory=list)
    required_evidence: list[str] = Field(default_factory=list)
    forbidden_output: list[str] = Field(default_factory=list)

    def decision_set(self) -> set[str]:
        decisions = set(self.allowed_decisions)
        if self.decision:
            decisions.add(self.decision)
        return decisions


class DecisionScenario(BaseModel):
    id: str
    name: str
    kind: ScenarioKind
    safety_critical: bool = False
    policy: dict = Field(default_factory=dict)
    entries: list[DecisionScenarioEntry]
    expected: DecisionScenarioExpectation


class DecisionScenarioResult(BaseModel):
    id: str
    name: str
    kind: ScenarioKind
    expected_decisions: list[str]
    actual_decision: str
    passed: bool
    safety_critical: bool
    false_positive: bool
    false_negative: bool
    required_evidence_present: bool
    forbidden_output_absent: bool
    confidence: str
    explanation_quality: str
    fix_plan_usefulness: str
    decision_trace: list[str]
    reason: str
    failures: list[str] = Field(default_factory=list)


class DecisionScenarioSuiteResult(BaseModel):
    scenario_count: int
    passed_count: int
    failed_count: int
    safety_critical_count: int
    safety_critical_failed_count: int
    false_positive_count: int
    false_negative_count: int
    results: list[DecisionScenarioResult]

    @property
    def passed(self) -> bool:
        return self.failed_count == 0 and self.safety_critical_failed_count == 0


def load_decision_scenarios(path: Path) -> list[DecisionScenario]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    scenarios = payload["scenarios"] if isinstance(payload, dict) else payload
    return [DecisionScenario.model_validate(item) for item in scenarios]


def run_decision_scenario_suite(scenarios: list[DecisionScenario]) -> DecisionScenarioSuiteResult:
    results = [run_decision_scenario(scenario) for scenario in scenarios]
    failed = [result for result in results if not result.passed]
    safety_failed = [result for result in failed if result.safety_critical]
    return DecisionScenarioSuiteResult(
        scenario_count=len(results),
        passed_count=len(results) - len(failed),
        failed_count=len(failed),
        safety_critical_count=sum(1 for result in results if result.safety_critical),
        safety_critical_failed_count=len(safety_failed),
        false_positive_count=sum(1 for result in results if result.false_positive),
        false_negative_count=sum(1 for result in results if result.false_negative),
        results=results,
    )


def run_decision_scenario(scenario: DecisionScenario) -> DecisionScenarioResult:
    review_id = uuid.uuid5(uuid.NAMESPACE_URL, f"threatgenix:scenario:{scenario.id}")
    entries = _scenario_entries(scenario, review_id=review_id)
    decision = evaluate_application_review_decision_entries(
        review_id=review_id,
        entries=entries,
        policy=scenario.policy,
    )
    expected_decisions = scenario.expected.decision_set()
    evidence_corpus = _evidence_corpus(entries)
    output_corpus = canonical_json({"decision": decision.model_dump(mode="json")}).casefold()
    failures: list[str] = []
    if expected_decisions and decision.decision not in expected_decisions:
        failures.append(
            f"decision expected one of {sorted(expected_decisions)}, got {decision.decision}"
        )
    if (
        scenario.expected.scanner_only is not None
        and decision.scanner_only is not scenario.expected.scanner_only
    ):
        failures.append(
            f"scanner_only expected {scenario.expected.scanner_only}, got {decision.scanner_only}"
        )
    for required in scenario.expected.required_trace:
        if not any(required in item for item in decision.decision_trace):
            failures.append(f"missing required trace {required!r}")
    required_evidence_present = all(
        required.casefold() in evidence_corpus for required in scenario.expected.required_evidence
    )
    if not required_evidence_present:
        failures.append("required evidence text was not present")
    forbidden_output_absent = all(
        forbidden.casefold() not in output_corpus
        for forbidden in scenario.expected.forbidden_output
    )
    if not forbidden_output_absent:
        failures.append("forbidden output text was present")
    false_positive = decision.decision == "block" and decision.decision not in expected_decisions
    false_negative = "block" in expected_decisions and decision.decision not in expected_decisions
    if scenario.safety_critical and false_negative:
        failures.append("safety-critical scenario produced a false negative")
    confidence = _confidence_label(
        decision=decision.decision,
        scanner_only=decision.scanner_only,
        evidence_hashes=decision.evidence_hashes,
        decision_trace=decision.decision_trace,
    )
    fix_plan_usefulness = _fix_plan_usefulness(
        decision=decision.decision,
        evidence_hashes=decision.evidence_hashes,
        reason=decision.reason,
        decision_trace=decision.decision_trace,
    )
    if fix_plan_usefulness == "fail":
        failures.append("fix plan usefulness gate failed")
    return DecisionScenarioResult(
        id=scenario.id,
        name=scenario.name,
        kind=scenario.kind,
        expected_decisions=sorted(expected_decisions),
        actual_decision=decision.decision,
        passed=not failures,
        safety_critical=scenario.safety_critical,
        false_positive=false_positive,
        false_negative=false_negative,
        required_evidence_present=required_evidence_present,
        forbidden_output_absent=forbidden_output_absent,
        confidence=confidence,
        explanation_quality="pass" if decision.reason and decision.decision_trace else "fail",
        fix_plan_usefulness=fix_plan_usefulness,
        decision_trace=decision.decision_trace,
        reason=decision.reason,
        failures=failures,
    )


def _scenario_entries(
    scenario: DecisionScenario,
    *,
    review_id: uuid.UUID,
) -> list[ApplicationReviewContextEntry]:
    now = datetime.now(timezone.utc)
    owner_id = uuid.uuid5(uuid.NAMESPACE_URL, f"threatgenix:scenario-owner:{scenario.id}")
    return [
        ApplicationReviewContextEntry(
            id=uuid.uuid5(uuid.NAMESPACE_URL, f"threatgenix:scenario:{scenario.id}:{index}"),
            tenant_key="scenario:golden",
            review_id=review_id,
            owner_id=owner_id,
            organization_id=None,
            source_type=entry.source_type,
            source_object_id=uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"threatgenix:scenario-source:{scenario.id}:{index}",
            ),
            item_type=entry.item_type,
            title=entry.title,
            body=entry.body,
            keywords=entry.body.casefold().split(),
            facets=entry.facets,
            retrieval_text=f"{entry.title} {entry.body}",
            source_refs=entry.source_refs,
            content_hash=entry.content_hash or _entry_hash(scenario.id, index, entry),
            status=entry.status,
            stale_reason=None if entry.status == "active" else "scenario_non_active",
            created_at=now,
            updated_at=now,
        )
        for index, entry in enumerate(scenario.entries)
    ]


def _entry_hash(scenario_id: str, index: int, entry: DecisionScenarioEntry) -> str:
    return hashlib.sha256(
        canonical_json({"scenario_id": scenario_id, "index": index, "entry": entry.model_dump()})
        .encode("utf-8")
    ).hexdigest()


def _evidence_corpus(entries: list[ApplicationReviewContextEntry]) -> str:
    return canonical_json(
        [
            {
                "title": entry.title,
                "body": entry.body,
                "facets": entry.facets,
                "source_refs": entry.source_refs,
                "status": entry.status,
            }
            for entry in entries
        ]
    ).casefold()


def _confidence_label(
    *,
    decision: str,
    scanner_only: bool,
    evidence_hashes: list[str],
    decision_trace: list[str],
) -> str:
    if decision == "gather_evidence":
        return "low"
    if scanner_only or decision == "verify":
        return "medium"
    if evidence_hashes and decision_trace:
        return "high"
    return "medium"


def _fix_plan_usefulness(
    *,
    decision: str,
    evidence_hashes: list[str],
    reason: str,
    decision_trace: list[str],
) -> str:
    if decision in {"pass", "gather_evidence"}:
        return "not_required"
    if evidence_hashes and reason.strip() and decision_trace:
        return "pass"
    return "fail"

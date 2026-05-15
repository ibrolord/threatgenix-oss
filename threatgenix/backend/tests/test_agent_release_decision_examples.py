from __future__ import annotations

import json
from pathlib import Path

from app.schemas.security_review import AgentReleaseDecision, AgentSecurityReviewResponse


EXAMPLES_PATH = (
    Path(__file__).parents[3]
    / "docs"
    / "product"
    / "threatgenix-agent-examples.json"
)


def test_agent_release_decision_examples_cover_and_validate_all_decisions() -> None:
    examples = json.loads(EXAMPLES_PATH.read_text())
    responses = [
        AgentSecurityReviewResponse.model_validate(example["response"])
        for example in examples
    ]

    assert {response.decision for response in responses} == {
        "ship",
        "block",
        "fix_now",
        "verify",
        "gather_evidence",
        "accept_risk",
    }
    assert {example["decision"] for example in examples} == {
        response.decision for response in responses
    }


def test_agent_release_decision_examples_have_deterministic_ci_exit_codes() -> None:
    examples = json.loads(EXAMPLES_PATH.read_text())
    failing_decisions: set[AgentReleaseDecision] = set()
    passing_decisions: set[AgentReleaseDecision] = set()

    for example in examples:
        response = AgentSecurityReviewResponse.model_validate(example["response"])
        if response.ci.should_fail:
            failing_decisions.add(response.decision)
            assert response.ci.exit_code == 1
            assert response.decision in response.ci.blocking_decisions
        else:
            passing_decisions.add(response.decision)
            assert response.ci.exit_code == 0
            assert response.decision not in response.ci.blocking_decisions

    assert failing_decisions == {"block", "fix_now"}
    assert passing_decisions == {"ship", "verify", "gather_evidence", "accept_risk"}


def test_agent_release_decision_examples_include_machine_readable_provenance() -> None:
    examples = json.loads(EXAMPLES_PATH.read_text())
    responses = [
        AgentSecurityReviewResponse.model_validate(example["response"])
        for example in examples
    ]
    evidence_refs = [
        evidence
        for response in responses
        for finding in response.findings
        for evidence in finding.evidence
    ]

    assert evidence_refs
    assert all(evidence.source_object_type for evidence in evidence_refs)
    assert all(evidence.source_object_id for evidence in evidence_refs)
    assert all(evidence.relationship for evidence in evidence_refs)
    assert all(evidence.strength for evidence in evidence_refs)
    assert any(evidence.location == "app/api/share.py:42" for evidence in evidence_refs)
    assert any(evidence.source_object_type == "dfd_node" for evidence in evidence_refs)
    assert any(evidence.source_object_type == "dfd_edge" for evidence in evidence_refs)

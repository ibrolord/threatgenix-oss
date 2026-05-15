from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.schemas.environment_evidence import (
    CodeEvidenceSummary,
    CodeSurface,
    RepositoryEvidence,
)
from app.services.agent_security_review import build_agent_security_review_response
from app.services.security_review_adapter import (
    build_application_security_review,
    build_security_review_findings,
)


FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "semantic_security_review"
    / "release_decision_cases.json"
)


def _load_cases() -> list[dict[str, Any]]:
    return json.loads(FIXTURE_PATH.read_text())


def _repository_evidence(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if payload is None:
        return None

    surfaces = [CodeSurface.model_validate(item) for item in payload["code_surfaces"]]
    summary = CodeEvidenceSummary(
        surface_count=len(surfaces),
        route_count=sum(
            1 for surface in surfaces if surface.kind in {"route", "webhook"}
        ),
        externally_reachable_surface_count=len(surfaces),
        verified_control_count=sum(1 for surface in surfaces if surface.auth_guards),
    )
    evidence = RepositoryEvidence(
        source_type="archive",
        filename=payload["filename"],
        reference=payload["reference"],
        file_count=payload["file_count"],
        languages=payload.get("languages", []),
        frameworks=payload.get("frameworks", []),
        code_surfaces=surfaces,
        code_evidence_summary=summary,
        parsed_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )
    return evidence.model_dump(mode="json")


def _model(case: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        system_name=case["name"],
        description="Fixture-backed ThreatGenix release decision.",
        data_classification="Internal",
        regulatory_scope=[],
        deployment_model="self_hosted",
        repository_evidence=_repository_evidence(case["repository_evidence"]),
        cloud_scan_evidence=None,
        iac_evidence=None,
        environment_context_summary=case["environment_context_summary"],
        owner_id=None,
    )


def _nodes(case: dict[str, Any]) -> list[SimpleNamespace]:
    return [
        SimpleNamespace(
            id=uuid.UUID(item["id"]),
            name=item["name"],
            node_type=item["node_type"],
            trust_boundary_id=None,
            properties=item.get("properties", {}),
        )
        for item in case["nodes"]
    ]


def _edges(case: dict[str, Any]) -> list[SimpleNamespace]:
    return [
        SimpleNamespace(
            id=uuid.UUID(item["id"]),
            source_node_id=uuid.UUID(item["source_node_id"]),
            target_node_id=uuid.UUID(item["target_node_id"]),
            properties={},
        )
        for item in case["edges"]
    ]


def _agent_response(case: dict[str, Any]):
    model = _model(case)
    nodes = _nodes(case)
    edges = _edges(case)
    summary = build_application_security_review(model, [], nodes, edges, [])
    findings = build_security_review_findings(model, [], nodes, edges, [])
    return build_agent_security_review_response(summary, findings)


@pytest.mark.parametrize("case", _load_cases(), ids=lambda case: case["id"])
def test_release_decision_fixture_expected_gap_progression(
    case: dict[str, Any],
) -> None:
    response = _agent_response(case)
    expected = case["expected"]

    assert response.decision == expected["decision"]
    for title in expected["present_gaps"]:
        assert title in response.evidence_gaps
    for title in expected["absent_gaps"]:
        assert title not in response.evidence_gaps


def test_applied_dfd_seed_fixture_has_no_generic_unknowns() -> None:
    case = next(
        item
        for item in _load_cases()
        if item["id"] == "repo_ingested_with_applied_dfd_seeds"
    )
    response = _agent_response(case)

    assert response.decision == "fix_now"
    assert response.evidence_gaps == []
    assert response.findings[0].title == (
        "Externally reachable surfaces lack trust-boundary segmentation"
    )
    assert "does not certify" in response.pass_semantics

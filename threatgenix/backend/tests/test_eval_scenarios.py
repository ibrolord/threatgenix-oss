from __future__ import annotations

from pathlib import Path

import yaml

from app.services.tmac import build_tmac_validation_response
from tests.evals.scenario_builder import SCENARIO_DEFINITIONS, ensure_scenarios_materialized


def test_aurora_scenario_materializes_full_bundle(tmp_path: Path) -> None:
    ensure_scenarios_materialized(tmp_path)

    scenario_dir = tmp_path / "aurora_utility_der"

    assert (scenario_dir / "metadata.yaml").exists()
    assert (scenario_dir / "gold_threat_themes.yaml").exists()
    assert (scenario_dir / "must_not_hallucinate.yaml").exists()
    assert (scenario_dir / "gold_dfd.json").exists()
    assert (scenario_dir / "threat_model.tmac.yaml").exists()
    assert (scenario_dir / "README.md").exists()


def test_aurora_scenario_meets_benchmark_complexity() -> None:
    scenario = SCENARIO_DEFINITIONS["aurora_utility_der"]
    gold_dfd = scenario["gold_dfd"]
    themes = scenario["gold_threat_themes"]

    assert len(gold_dfd["nodes"]) >= 18
    assert len(gold_dfd["edges"]) >= 25
    assert len(gold_dfd["trust_boundaries"]) >= 6
    assert len(themes["critical_themes"]) >= 8
    assert len(themes["important_themes"]) >= 5


def test_aurora_tmac_fixture_validates_and_rounds_up_complexity(tmp_path: Path) -> None:
    ensure_scenarios_materialized(tmp_path)
    content = (tmp_path / "aurora_utility_der" / "threat_model.tmac.yaml").read_text(encoding="utf-8")

    response = build_tmac_validation_response(content)

    assert response.format.value == "yaml"
    assert response.summary.node_count >= 25
    assert response.summary.edge_count >= 25
    assert response.summary.boundary_count >= 6
    assert response.summary.custom_view_count >= 2
    assert response.summary.threat_count >= 10
    assert response.summary.control_count >= 6
    assert response.summary.snapshot_count >= 1
    assert response.summary.review_count >= 1
    assert response.summary.collaborator_count >= 3
    assert response.summary.assignment_count >= 2
    assert response.summary.notification_count >= 1


def test_aurora_tmac_fixture_is_stable_yaml(tmp_path: Path) -> None:
    ensure_scenarios_materialized(tmp_path)
    path = tmp_path / "aurora_utility_der" / "threat_model.tmac.yaml"

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))

    assert payload["metadata"]["system_name"] == "Aurora Utility DER Orchestration and Storm Response Platform"
    assert payload["views"]["custom_views"][0]["view_type"] == "workspace"
    assert payload["component_templates"][0]["group"] == "Utility Control"
    assert payload["property_options"][0]["field"] == "privilege_level"
    assert {item["source"] for item in payload["threats"]} == {"Manual"}

from __future__ import annotations

from datetime import datetime, timezone
import subprocess

import pytest

from tests.evals import judges
from tests.evals.reporting import (
    adjudicate_run,
    compute_coverage_score,
    compute_operational_reliability_score,
    sort_threats,
    summarize_dfd,
)
from tests.evals.run_threat_modeler_audit import (
    apply_delta_patch,
    apply_fixed_repair,
    clone_dfd_with_fresh_ids,
    configure_degradation,
    load_scenario_bundle,
    rebase_delta_patch,
)
from tests.evals.scenario_builder import SCENARIO_DEFINITIONS, ensure_scenarios_materialized
from tests.evals.schema import (
    ClaudeJudgeResult,
    DFDArtifact,
    DegradationEvidence,
    GeminiJudgeResult,
    JudgeInput,
    OperationalChecks,
    ThreatArtifact,
)


def test_scenario_builder_materializes_expected_files(tmp_path):
    created = ensure_scenarios_materialized(tmp_path)
    assert created

    for scenario_id in SCENARIO_DEFINITIONS:
        scenario_dir = tmp_path / scenario_id
        assert (scenario_dir / "metadata.yaml").exists()
        assert (scenario_dir / "gold_threat_themes.yaml").exists()
        assert (scenario_dir / "must_not_hallucinate.yaml").exists()
        assert (scenario_dir / "gold_dfd.json").exists()
        assert (scenario_dir / "narrative.pdf").exists()
        assert (scenario_dir / "structured.pdf").exists()
        assert (scenario_dir / "delta.pdf").exists()
        if "tmac" in SCENARIO_DEFINITIONS[scenario_id]:
            assert (scenario_dir / "threat_model.tmac.yaml").exists()
        if "readme" in SCENARIO_DEFINITIONS[scenario_id]:
            assert (scenario_dir / "README.md").exists()


def test_apply_delta_patch_adds_expected_components(tmp_path):
    ensure_scenarios_materialized(tmp_path)
    bundle = load_scenario_bundle("northstar_bank", tmp_path)
    rebased_gold_dfd, id_map = clone_dfd_with_fresh_ids(bundle.gold_dfd)
    rebased_delta_patch = rebase_delta_patch(bundle.delta_patch, id_map)

    patched = apply_delta_patch(rebased_gold_dfd, rebased_delta_patch)
    node_names = {node.name for node in patched.nodes}
    edge_labels = {edge.label for edge in patched.edges}

    assert "Payroll Aggregator Partner" in node_names
    assert "Treasury Repair Console" in node_names
    assert "repair override and replay" in edge_labels


def test_clone_dfd_with_fresh_ids_preserves_relationships(tmp_path):
    ensure_scenarios_materialized(tmp_path)
    bundle = load_scenario_bundle("gridforge_ot", tmp_path)

    cloned, id_map = clone_dfd_with_fresh_ids(bundle.gold_dfd)

    assert {node.id for node in cloned.nodes}.isdisjoint({node.id for node in bundle.gold_dfd.nodes})
    assert {edge.id for edge in cloned.edges}.isdisjoint({edge.id for edge in bundle.gold_dfd.edges})
    assert {boundary.id for boundary in cloned.trust_boundaries}.isdisjoint(
        {boundary.id for boundary in bundle.gold_dfd.trust_boundaries}
    )
    assert len(id_map) == (
        len(bundle.gold_dfd.nodes)
        + len(bundle.gold_dfd.edges)
        + len(bundle.gold_dfd.trust_boundaries)
    )

    valid_node_ids = {node.id for node in cloned.nodes}
    valid_boundary_ids = {boundary.id for boundary in cloned.trust_boundaries}

    for node in cloned.nodes:
        if node.trust_boundary_id is not None:
            assert node.trust_boundary_id in valid_boundary_ids
    for edge in cloned.edges:
        assert edge.source_node_id in valid_node_ids
        assert edge.target_node_id in valid_node_ids
    for boundary in cloned.trust_boundaries:
        assert set(boundary.node_ids).issubset(valid_node_ids)


def test_apply_fixed_repair_drops_missing_boundary_refs(tmp_path):
    ensure_scenarios_materialized(tmp_path)
    bundle = load_scenario_bundle("northstar_bank", tmp_path)
    rebased_gold_dfd, _ = clone_dfd_with_fresh_ids(bundle.gold_dfd)

    repaired, _ = apply_fixed_repair(DFDArtifact(), rebased_gold_dfd, bundle.metadata)

    valid_boundary_ids = {boundary.id for boundary in repaired.trust_boundaries}
    for node in repaired.nodes:
        assert node.trust_boundary_id is None or node.trust_boundary_id in valid_boundary_ids


def test_coverage_and_adjudication_are_computed_consistently(tmp_path):
    ensure_scenarios_materialized(tmp_path)
    bundle = load_scenario_bundle("gridforge_ot", tmp_path)

    judge_input = JudgeInput(
        generated_at=datetime.now(timezone.utc),
        scenario=bundle.metadata,
        mode="gold_dfd_full",
        gold_dfd_summary=summarize_dfd(bundle.gold_dfd),
        actual_dfd_summary=summarize_dfd(bundle.gold_dfd),
        gold_threat_themes=bundle.gold_themes,
        must_not_hallucinate=bundle.must_not_hallucinate,
        actual_threats=[],
        top_20_threats=[],
        rules_only_threats=[],
        diff_output={"counts": {"added": 0, "removed": 0}},
        triage_persistence_evidence={},
        degradation_evidence=DegradationEvidence(),
        operational_checks=OperationalChecks(
            no_5xx=True,
            export_matches_list_count=True,
        ),
    )

    claude_result = ClaudeJudgeResult(
        supported_top10_count=9,
        unsupported_threat_ids=[],
        wrong_stride_ids=[],
        wrong_severity_ids=[],
        duplicate_clusters=[],
        missing_critical_themes=["GRID-04"],
        blocker_findings=[],
        score_correctness_0_100=88,
        verdict="PASS",
        low_confidence_ambiguity=False,
    )
    gemini_result = GeminiJudgeResult(
        generic_threat_ids=[],
        missing_high_value_themes=["GRID-09"],
        misprioritized_ids=[],
        top10_quality_score_0_100=84,
        overall_world_class_score_0_100=86,
        world_class_verdict="PASS",
        notes=[],
        low_confidence_ambiguity=False,
    )

    coverage_score, missing = compute_coverage_score(
        bundle.gold_themes, claude_result, gemini_result
    )
    operational_score = compute_operational_reliability_score(judge_input)
    scorecard = adjudicate_run(
        judge_input,
        claude_result,
        gemini_result,
        coverage_score,
        operational_score,
        tmp_path / "gridforge_ot" / "gold_dfd_full",
    )

    assert "GRID-04" in missing
    assert "GRID-09" in missing
    assert operational_score == 100.0
    assert scorecard.adjudication == "PASS"
    assert scorecard.weighted_run_score > 80


def test_run_gemini_judge_places_prompt_after_flag(monkeypatch, tmp_path):
    ensure_scenarios_materialized(tmp_path)
    bundle = load_scenario_bundle("northstar_bank", tmp_path)

    judge_input = JudgeInput(
        generated_at=datetime.now(timezone.utc),
        scenario=bundle.metadata,
        mode="gold_dfd_rules_only",
        gold_dfd_summary=summarize_dfd(bundle.gold_dfd),
        actual_dfd_summary=summarize_dfd(bundle.gold_dfd),
        gold_threat_themes=bundle.gold_themes,
        must_not_hallucinate=bundle.must_not_hallucinate,
        actual_threats=[],
        top_20_threats=[],
        rules_only_threats=[],
        diff_output={},
        triage_persistence_evidence={},
        degradation_evidence=DegradationEvidence(),
        operational_checks=OperationalChecks(),
    )

    captured: dict[str, list[str]] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                '{"generic_threat_ids":[],"missing_high_value_themes":[],"misprioritized_ids":[],'
                '"top10_quality_score_0_100":82,"overall_world_class_score_0_100":80,'
                '"world_class_verdict":"PARTIAL","notes":[],"low_confidence_ambiguity":false}'
            ),
            stderr="",
        )

    monkeypatch.setattr(judges.subprocess, "run", fake_run)

    result = judges.run_gemini_judge(judge_input, timeout_seconds=5)

    assert result.world_class_verdict == "PARTIAL"
    assert captured["command"][:6] == [
        "gemini",
        "--approval-mode",
        "plan",
        "--output-format",
        "text",
        "-p",
    ]
    assert captured["command"][-1].startswith("You are the world-class quality judge")


def test_run_claude_judge_uses_structured_cli_output(monkeypatch, tmp_path):
    ensure_scenarios_materialized(tmp_path)
    bundle = load_scenario_bundle("northstar_bank", tmp_path)

    judge_input = JudgeInput(
        generated_at=datetime.now(timezone.utc),
        scenario=bundle.metadata,
        mode="gold_dfd_rules_only",
        gold_dfd_summary=summarize_dfd(bundle.gold_dfd),
        actual_dfd_summary=summarize_dfd(bundle.gold_dfd),
        gold_threat_themes=bundle.gold_themes,
        must_not_hallucinate=bundle.must_not_hallucinate,
        actual_threats=[],
        top_20_threats=[],
        rules_only_threats=[],
        diff_output={},
        triage_persistence_evidence={},
        degradation_evidence=DegradationEvidence(),
        operational_checks=OperationalChecks(),
    )
    captured: dict[str, object] = {}

    monkeypatch.setenv("BASH_FUNC_parse_git_branch%%", "() { :; }")
    monkeypatch.setattr(judges.shutil, "which", lambda executable: f"/usr/local/bin/{executable}")

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs["env"]
        captured["input"] = kwargs["input"]
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=(
                '{"structured_output":{"supported_top10_count":8,"unsupported_threat_ids":[],'
                '"wrong_stride_ids":[],"wrong_severity_ids":[],"duplicate_clusters":[],'
                '"missing_critical_themes":[],"blocker_findings":[],'
                '"score_correctness_0_100":86,"verdict":"PASS",'
                '"low_confidence_ambiguity":false}}'
            ),
            stderr="",
        )

    monkeypatch.setattr(judges.subprocess, "run", fake_run)

    result = judges.run_claude_judge(judge_input, timeout_seconds=5, model="opus")

    assert result.verdict == "PASS"
    args = captured["args"]
    assert isinstance(args, list)
    assert args[:6] == ["claude", "--print", "--input-format", "text", "--model", "opus"]
    assert "--output-format" in args
    assert "--json-schema" in args
    assert captured["input"].startswith("You are the correctness judge")
    env = captured["env"]
    assert isinstance(env, dict)
    assert "BASH_FUNC_parse_git_branch%%" not in env


def test_run_claude_judge_requires_installed_cli(monkeypatch, tmp_path):
    ensure_scenarios_materialized(tmp_path)
    bundle = load_scenario_bundle("northstar_bank", tmp_path)
    judge_input = JudgeInput(
        generated_at=datetime.now(timezone.utc),
        scenario=bundle.metadata,
        mode="gold_dfd_rules_only",
        gold_dfd_summary=summarize_dfd(bundle.gold_dfd),
        actual_dfd_summary=summarize_dfd(bundle.gold_dfd),
        gold_threat_themes=bundle.gold_themes,
        must_not_hallucinate=bundle.must_not_hallucinate,
        actual_threats=[],
        top_20_threats=[],
        rules_only_threats=[],
        diff_output={},
        triage_persistence_evidence={},
        degradation_evidence=DegradationEvidence(),
        operational_checks=OperationalChecks(),
    )

    monkeypatch.setattr(judges.shutil, "which", lambda executable: None)

    with pytest.raises(RuntimeError, match="not installed or not on PATH"):
        judges.run_claude_judge(judge_input, timeout_seconds=5)


def test_sort_threats_preserves_display_rank_over_severity() -> None:
    threats = [
        ThreatArtifact(
            display_id="T-010",
            description="later critical item",
            stride_category="Tampering",
            severity="Critical",
            source="Rules",
        ),
        ThreatArtifact(
            display_id="T-002",
            description="earlier medium item",
            stride_category="Information Disclosure",
            severity="Medium",
            source="Rules",
        ),
        ThreatArtifact(
            display_id="T-001",
            description="first high item",
            stride_category="Spoofing",
            severity="High",
            source="Rules",
        ),
    ]

    assert [threat.display_id for threat in sort_threats(threats)] == [
        "T-001",
        "T-002",
        "T-010",
    ]


def test_compact_judge_payload_truncates_and_slims_threat_lists(tmp_path):
    ensure_scenarios_materialized(tmp_path)
    bundle = load_scenario_bundle("skybridge_airline_ops", tmp_path)

    threats = [
        ThreatArtifact(
            display_id=f"T-{idx:03d}",
            description=f"Threat {idx}",
            stride_category="Tampering",
            severity="High",
            source="Rules",
            rule_id="T-12",
            threat_subtype="Airworthiness and maintenance-state tampering",
            relevance_rationale="verbose rationale that should not appear in the compact payload",
            affected_node_ids=[],
            affected_edge_ids=[],
            compliance_controls=[{"id": "CTRL-1"}],
        )
        for idx in range(1, 51)
    ]

    judge_input = JudgeInput(
        generated_at=datetime.now(timezone.utc),
        scenario=bundle.metadata,
        mode="narrative_full",
        gold_dfd_summary=summarize_dfd(bundle.gold_dfd),
        actual_dfd_summary=summarize_dfd(bundle.gold_dfd),
        gold_threat_themes=bundle.gold_themes,
        must_not_hallucinate=bundle.must_not_hallucinate,
        actual_threats=threats,
        top_20_threats=threats[:20],
        rules_only_threats=threats,
        diff_output={},
        triage_persistence_evidence={},
        degradation_evidence=DegradationEvidence(),
        operational_checks=OperationalChecks(),
    )

    compact = judges._compact_judge_payload(judge_input)

    assert compact["actual_threat_count"] == 50
    assert compact["rules_only_threat_count"] == 50
    assert len(compact["actual_threats"]) == 40
    assert len(compact["rules_only_threats"]) == 25
    assert "relevance_rationale" not in compact["actual_threats"][0]
    assert "compliance_controls" not in compact["actual_threats"][0]


def test_configure_degradation_uses_managed_override_for_invalid_model():
    class DummyClient:
        def __getattr__(self, name):
            raise AssertionError(f"unexpected client call: {name}")

    evidence = configure_degradation(
        DummyClient(),
        "structured_full_invalid_model_config",
        [],
        managed_backend_active=True,
    )

    assert evidence.triggered_by == "managed_backend_env_override"
    assert "AUDIT_FORCE_INVALID_MODEL_CONFIG=true" in evidence.details
    assert evidence.observed is True

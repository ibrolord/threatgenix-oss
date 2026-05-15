from __future__ import annotations

import csv
import html
import json
import random
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import fitz
from weasyprint import HTML

from tests.evals.schema import (
    CampaignSummary,
    ClaudeJudgeResult,
    DFDArtifact,
    DFDArtifactSummary,
    GeminiJudgeResult,
    GoldThreatThemeSet,
    JudgeInput,
    RunScorecard,
    ScenarioMetadata,
    ThreatArtifact,
)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
WORLD_CLASS_THRESHOLD = 85.0
_DISPLAY_ID_RE = re.compile(r"^T-(\d+)$")


def summarize_dfd(dfd: DFDArtifact) -> DFDArtifactSummary:
    boundary_lookup = {str(boundary.id): boundary for boundary in dfd.trust_boundaries}
    node_lookup = {str(node.id): node for node in dfd.nodes}
    boundary_membership: dict[str, list[str]] = {}
    for boundary in dfd.trust_boundaries:
        boundary_membership[boundary.name] = [
            node_lookup.get(str(node_id)).name
            for node_id in boundary.node_ids
            if str(node_id) in node_lookup
        ]
    node_type_counts: dict[str, int] = defaultdict(int)
    for node in dfd.nodes:
        node_type_counts[node.node_type] += 1
        if node.trust_boundary_id and str(node.trust_boundary_id) not in boundary_lookup:
            boundary_membership.setdefault("Unresolved Boundary", []).append(node.name)
    return DFDArtifactSummary(
        node_count=len(dfd.nodes),
        edge_count=len(dfd.edges),
        boundary_count=len(dfd.trust_boundaries),
        node_names=sorted(node.name for node in dfd.nodes),
        boundary_names=sorted(boundary.name for boundary in dfd.trust_boundaries),
        flow_labels=sorted(edge.label for edge in dfd.edges if edge.label),
        node_type_counts=dict(node_type_counts),
        boundary_membership=boundary_membership,
    )


def sort_threats(threats: Iterable[ThreatArtifact]) -> list[ThreatArtifact]:
    def _threat_rank_key(threat: ThreatArtifact) -> tuple[int, int | str, int, str]:
        match = _DISPLAY_ID_RE.match(threat.display_id or "")
        if match:
            return (0, int(match.group(1)), SEVERITY_ORDER.get(threat.severity, 99), threat.display_id)
        return (1, threat.display_id, SEVERITY_ORDER.get(threat.severity, 99), threat.display_id)

    return sorted(
        threats,
        key=_threat_rank_key,
    )


def compute_coverage_score(
    gold_themes: GoldThreatThemeSet,
    claude_result: ClaudeJudgeResult,
    gemini_result: GeminiJudgeResult,
) -> tuple[float, list[str]]:
    critical_ids = {theme.id for theme in gold_themes.critical_themes}
    important_ids = {theme.id for theme in gold_themes.important_themes}
    missing_ids = (
        set(claude_result.missing_critical_themes)
        | set(gemini_result.missing_high_value_themes)
    )
    total_weight = len(critical_ids) * 2 + len(important_ids)
    if total_weight == 0:
        return 100.0, []
    covered_weight = 0
    for theme_id in critical_ids:
        if theme_id not in missing_ids:
            covered_weight += 2
    for theme_id in important_ids:
        if theme_id not in missing_ids:
            covered_weight += 1
    return round((covered_weight / total_weight) * 100.0, 2), sorted(missing_ids)


def compute_operational_reliability_score(judge_input: JudgeInput) -> float:
    checks = [
        judge_input.operational_checks.no_5xx,
        judge_input.operational_checks.export_matches_list_count,
    ]
    if judge_input.mode == "delta_reanalyze":
        checks.append(judge_input.operational_checks.triage_persistence_ok)
    if judge_input.is_degraded_variant:
        checks.append(judge_input.operational_checks.degraded_mode_ok)
    if not checks:
        return 100.0
    return round(sum(100.0 for check in checks if check) / len(checks), 2)


def adjudicate_run(
    judge_input: JudgeInput,
    claude_result: ClaudeJudgeResult,
    gemini_result: GeminiJudgeResult,
    coverage_score: float,
    operational_reliability_score: float,
    run_directory: Path,
) -> RunScorecard:
    correctness_score = round(claude_result.score_correctness_0_100, 2)
    world_class_score = round(gemini_result.overall_world_class_score_0_100, 2)
    weighted_run_score = round(
        correctness_score * 0.4
        + world_class_score * 0.3
        + coverage_score * 0.2
        + operational_reliability_score * 0.1,
        2,
    )

    if claude_result.verdict == "FAIL" or gemini_result.world_class_verdict == "FAIL":
        adjudication = "FAIL"
    elif claude_result.verdict == "PASS" and gemini_result.world_class_verdict == "PASS" and not claude_result.blocker_findings:
        adjudication = "PASS"
    else:
        adjudication = "PARTIAL"

    manual_review_required = any(
        [
            claude_result.verdict != gemini_result.world_class_verdict,
            abs(correctness_score - WORLD_CLASS_THRESHOLD) <= 5,
            abs(world_class_score - WORLD_CLASS_THRESHOLD) <= 5,
            claude_result.low_confidence_ambiguity,
            gemini_result.low_confidence_ambiguity,
        ]
    )
    notes = list(judge_input.operational_checks.notes)
    if judge_input.repair_result and judge_input.repair_result.applied:
        notes.append(
            f"Repair actions applied: {len(judge_input.repair_result.actions)}"
        )

    return RunScorecard(
        scenario_id=judge_input.scenario.scenario_id,
        mode=judge_input.mode,
        run_directory=run_directory,
        correctness_score=correctness_score,
        world_class_score=world_class_score,
        coverage_score=coverage_score,
        operational_reliability_score=operational_reliability_score,
        weighted_run_score=weighted_run_score,
        adjudication=adjudication,
        manual_review_required=manual_review_required,
        blocker_findings=claude_result.blocker_findings,
        missing_themes=sorted(
            set(claude_result.missing_critical_themes)
            | set(gemini_result.missing_high_value_themes)
        ),
        notes=notes,
    )


def overall_campaign_verdict(scorecards: list[RunScorecard]) -> tuple[float, str]:
    if not scorecards:
        return 0.0, "Not ready"

    def _mode_weight(mode: str) -> float:
        if mode.startswith("gold_dfd_"):
            return 0.5
        if mode in {"structured_full", "narrative_full", "narrative_repaired_full"}:
            return 0.3 / 3
        if mode == "delta_reanalyze":
            return 0.1
        return 0.1 / 6

    total_weight = sum(_mode_weight(scorecard.mode) for scorecard in scorecards)
    weighted_score = sum(
        scorecard.weighted_run_score * _mode_weight(scorecard.mode)
        for scorecard in scorecards
    ) / max(total_weight, 1e-9)
    weighted_score = round(weighted_score, 2)

    gold_full_scores = [
        scorecard.weighted_run_score
        for scorecard in scorecards
        if scorecard.mode == "gold_dfd_full"
    ]
    degraded_failures = [
        scorecard
        for scorecard in scorecards
        if "unavailable" in scorecard.mode or "invalid_model_config" in scorecard.mode
        if scorecard.adjudication == "FAIL"
    ]
    delta_runs = [scorecard for scorecard in scorecards if scorecard.mode == "delta_reanalyze"]
    blockers = any(scorecard.blocker_findings for scorecard in scorecards)

    if (
        weighted_score >= WORLD_CLASS_THRESHOLD
        and gold_full_scores
        and all(score >= 90.0 for score in gold_full_scores)
        and not blockers
        and not degraded_failures
        and delta_runs
        and all(scorecard.adjudication != "FAIL" for scorecard in delta_runs)
    ):
        return weighted_score, "world class"
    if weighted_score >= 78.0 and not blockers:
        return weighted_score, "Strong but not world-class"
    if weighted_score >= 60.0:
        return weighted_score, "Promising but unreliable"
    return weighted_score, "Not ready"


def build_manual_review_queue(
    scenario: ScenarioMetadata,
    threats: list[ThreatArtifact],
    scorecard: RunScorecard,
    *,
    random_seed: int = 13,
) -> list[dict]:
    queue: list[dict] = []
    if scorecard.manual_review_required:
        queue.append(
            {
                "type": "run_review",
                "scenario_id": scenario.scenario_id,
                "mode": scorecard.mode,
                "reason": "model_disagreement_or_threshold_band",
                "run_directory": str(scorecard.run_directory),
            }
        )

    sorted_threats = sort_threats(threats)
    top_five = sorted_threats[:5]
    for threat in top_five:
        queue.append(
            {
                "type": "top_severity_threat",
                "scenario_id": scenario.scenario_id,
                "mode": scorecard.mode,
                "threat_display_id": threat.display_id,
                "threat_description": threat.description,
            }
        )

    rng = random.Random(f"{scenario.scenario_id}:{scorecard.mode}:{random_seed}")
    sample_pool = sorted_threats[5:]
    sample = rng.sample(sample_pool, min(5, len(sample_pool)))
    for threat in sample:
        queue.append(
            {
                "type": "random_threat_sample",
                "scenario_id": scenario.scenario_id,
                "mode": scorecard.mode,
                "threat_display_id": threat.display_id,
                "threat_description": threat.description,
            }
        )
    return queue


def build_campaign_summary(
    scorecards: list[RunScorecard],
    manual_review_queue: list[dict],
) -> CampaignSummary:
    weighted_score, verdict = overall_campaign_verdict(scorecards)
    failures: list[dict] = []
    for scorecard in scorecards:
        if scorecard.adjudication != "PASS":
            failures.append(
                {
                    "scenario_id": scorecard.scenario_id,
                    "mode": scorecard.mode,
                    "severity": "blocker" if scorecard.blocker_findings else "major",
                    "notes": scorecard.notes,
                    "blocker_findings": scorecard.blocker_findings,
                    "missing_themes": scorecard.missing_themes,
                }
            )
    return CampaignSummary(
        generated_at=datetime.now(timezone.utc),
        overall_weighted_score=weighted_score,
        final_verdict=verdict,
        run_scorecards=scorecards,
        manual_review_queue=manual_review_queue,
        failures=failures,
    )


def write_scores_csv(scorecards: list[RunScorecard], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "scenario_id",
                "mode",
                "correctness_score",
                "world_class_score",
                "coverage_score",
                "operational_reliability_score",
                "weighted_run_score",
                "adjudication",
                "manual_review_required",
                "run_directory",
            ]
        )
        for scorecard in scorecards:
            writer.writerow(
                [
                    scorecard.scenario_id,
                    scorecard.mode,
                    scorecard.correctness_score,
                    scorecard.world_class_score,
                    scorecard.coverage_score,
                    scorecard.operational_reliability_score,
                    scorecard.weighted_run_score,
                    scorecard.adjudication,
                    scorecard.manual_review_required,
                    str(scorecard.run_directory),
                ]
            )


def _markdown_table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    header = "| " + " | ".join(rows[0]) + " |"
    separator = "| " + " | ".join("---" for _ in rows[0]) + " |"
    body = "\n".join("| " + " | ".join(row) + " |" for row in rows[1:])
    return "\n".join([header, separator, body]) if body else "\n".join([header, separator])


def write_summary_markdown(campaign_summary: CampaignSummary, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    rows = [["Scenario", "Mode", "Run Score", "Verdict", "Manual Review"]]
    for scorecard in sorted(
        campaign_summary.run_scorecards,
        key=lambda item: (item.scenario_id, item.mode),
    ):
        rows.append(
            [
                scorecard.scenario_id,
                scorecard.mode,
                f"{scorecard.weighted_run_score:.2f}",
                scorecard.adjudication,
                "yes" if scorecard.manual_review_required else "no",
            ]
        )
    content = [
        "# ThreatGenix Threat Modeler Audit",
        "",
        f"- Generated: {campaign_summary.generated_at.isoformat()}",
        f"- Overall weighted score: {campaign_summary.overall_weighted_score:.2f}",
        f"- Final verdict: **{campaign_summary.final_verdict}**",
        "",
        "## Run Scorecards",
        "",
        _markdown_table(rows),
        "",
        "## Failure Summary",
        "",
    ]
    if campaign_summary.failures:
        for failure in campaign_summary.failures:
            content.append(
                f"- `{failure['scenario_id']}/{failure['mode']}` "
                f"[{failure['severity']}] blockers={len(failure['blocker_findings'])} "
                f"missing={', '.join(failure['missing_themes']) or 'none'}"
            )
    else:
        content.append("- None")
    content.extend(["", "## Manual Review Queue", ""])
    if campaign_summary.manual_review_queue:
        for item in campaign_summary.manual_review_queue:
            content.append(
                f"- `{item['type']}` {item.get('scenario_id', '')} {item.get('mode', '')} "
                f"{item.get('threat_display_id', '')}".strip()
            )
    else:
        content.append("- None")
    destination.write_text("\n".join(content) + "\n", encoding="utf-8")


def write_failures_markdown(campaign_summary: CampaignSummary, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Ranked Failures", ""]
    if not campaign_summary.failures:
        lines.append("- None")
    else:
        severity_rank = {"blocker": 0, "major": 1, "minor": 2}
        for failure in sorted(
            campaign_summary.failures,
            key=lambda item: severity_rank.get(item["severity"], 99),
        ):
            lines.append(
                f"- `{failure['scenario_id']}/{failure['mode']}` [{failure['severity']}] "
                f"themes={', '.join(failure['missing_themes']) or 'none'}"
            )
            for blocker in failure["blocker_findings"]:
                lines.append(f"  blocker: {blocker}")
            for note in failure["notes"]:
                lines.append(f"  note: {note}")
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_run_snapshot(
    destination: Path,
    judge_input: JudgeInput,
    claude_result: ClaudeJudgeResult,
    gemini_result: GeminiJudgeResult,
    scorecard: RunScorecard,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    top_threats = sort_threats(judge_input.actual_threats)[:10]
    rows = []
    for threat in top_threats:
        rows.append(
            "<tr>"
            f"<td>{html.escape(threat.display_id)}</td>"
            f"<td>{html.escape(threat.severity)}</td>"
            f"<td>{html.escape(threat.stride_category)}</td>"
            f"<td>{html.escape(threat.description[:140])}</td>"
            "</tr>"
        )
    report_html = f"""
    <html>
      <head>
        <style>
          body {{ font-family: Arial, sans-serif; color: #111827; padding: 24px; }}
          h1 {{ font-size: 24px; margin-bottom: 4px; }}
          h2 {{ font-size: 16px; margin-top: 24px; }}
          .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
          .card {{ border: 1px solid #d1d5db; border-radius: 8px; padding: 12px; background: #f9fafb; }}
          table {{ width: 100%; border-collapse: collapse; font-size: 11px; }}
          th, td {{ border: 1px solid #d1d5db; padding: 6px; vertical-align: top; }}
          th {{ background: #f3f4f6; text-align: left; }}
          ul {{ margin: 4px 0 0 18px; }}
        </style>
      </head>
      <body>
        <h1>{html.escape(judge_input.scenario.title)}</h1>
        <div>{html.escape(judge_input.mode)}</div>
        <div class="grid">
          <div class="card"><strong>Run score</strong><br/>{scorecard.weighted_run_score:.2f}</div>
          <div class="card"><strong>Claude correctness</strong><br/>{claude_result.score_correctness_0_100:.2f}</div>
          <div class="card"><strong>Gemini world-class</strong><br/>{gemini_result.overall_world_class_score_0_100:.2f}</div>
          <div class="card"><strong>Operational</strong><br/>{scorecard.operational_reliability_score:.2f}</div>
        </div>
        <h2>DFD Summary</h2>
        <div class="grid">
          <div class="card"><strong>Nodes</strong><br/>{judge_input.actual_dfd_summary.node_count}</div>
          <div class="card"><strong>Edges</strong><br/>{judge_input.actual_dfd_summary.edge_count}</div>
          <div class="card"><strong>Boundaries</strong><br/>{judge_input.actual_dfd_summary.boundary_count}</div>
          <div class="card"><strong>Verdict</strong><br/>{scorecard.adjudication}</div>
        </div>
        <h2>Top Threats</h2>
        <table>
          <thead>
            <tr><th>ID</th><th>Severity</th><th>STRIDE</th><th>Description</th></tr>
          </thead>
          <tbody>
            {''.join(rows) or '<tr><td colspan="4">No threats captured</td></tr>'}
          </tbody>
        </table>
        <h2>Judge Notes</h2>
        <div class="grid">
          <div class="card">
            <strong>Claude blockers</strong>
            <ul>{''.join(f'<li>{html.escape(item)}</li>' for item in claude_result.blocker_findings) or '<li>None</li>'}</ul>
          </div>
          <div class="card">
            <strong>Missing themes</strong>
            <ul>{''.join(f'<li>{html.escape(item)}</li>' for item in scorecard.missing_themes) or '<li>None</li>'}</ul>
          </div>
          <div class="card">
            <strong>Generic threats</strong>
            <ul>{''.join(f'<li>{html.escape(item)}</li>' for item in gemini_result.generic_threat_ids) or '<li>None</li>'}</ul>
          </div>
          <div class="card">
            <strong>Run notes</strong>
            <ul>{''.join(f'<li>{html.escape(item)}</li>' for item in scorecard.notes) or '<li>None</li>'}</ul>
          </div>
        </div>
      </body>
    </html>
    """
    pdf_bytes = HTML(string=report_html).write_pdf()
    pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")
    pixmap = pdf_document.load_page(0).get_pixmap(matrix=fitz.Matrix(2, 2))
    pixmap.save(destination)
    pdf_document.close()


def dump_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def write_campaign_outputs(
    output_root: Path,
    campaign_summary: CampaignSummary,
    claude_outputs: dict[str, dict],
    gemini_outputs: dict[str, dict],
) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    write_summary_markdown(campaign_summary, output_root / "summary.md")
    write_scores_csv(campaign_summary.run_scorecards, output_root / "scores.csv")
    write_failures_markdown(campaign_summary, output_root / "failures.md")
    dump_json(output_root / "manual_review_queue.json", campaign_summary.manual_review_queue)
    judge_output_dir = output_root / "judge_outputs"
    dump_json(judge_output_dir / "claude.json", claude_outputs)
    dump_json(judge_output_dir / "gemini.json", gemini_outputs)

from __future__ import annotations

import argparse
import csv
import copy
import json
import os
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from traceback import format_exc
from typing import Any, Iterator
from uuid import uuid4

import requests
import yaml

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests.evals.judges import run_claude_judge, run_gemini_judge  # noqa: E402
from tests.evals.reporting import (  # noqa: E402
    adjudicate_run,
    build_campaign_summary,
    build_manual_review_queue,
    compute_coverage_score,
    compute_operational_reliability_score,
    dump_json,
    render_run_snapshot,
    sort_threats,
    summarize_dfd,
    write_campaign_outputs,
)
from tests.evals.scenario_builder import SCENARIO_DEFINITIONS, ensure_scenarios_materialized  # noqa: E402
from tests.evals.schema import (  # noqa: E402
    ClaudeJudgeResult,
    DFDArtifact,
    DFDEdgeArtifact,
    DFDNodeArtifact,
    DegradationEvidence,
    GeminiJudgeResult,
    GoldThreatThemeSet,
    JudgeInput,
    OperationalChecks,
    RepairAction,
    RepairScriptResult,
    RunMode,
    RunScorecard,
    ScenarioMetadata,
    ThreatArtifact,
)

RUN_MODES: list[RunMode] = [
    "gold_dfd_full",
    "gold_dfd_rules_only",
    "structured_full",
    "narrative_full",
    "narrative_repaired_full",
    "delta_reanalyze",
    "gold_dfd_full_ai_unavailable",
    "gold_dfd_full_invalid_model_config",
    "gold_dfd_full_threat_intel_unavailable",
    "structured_full_ai_unavailable",
    "structured_full_invalid_model_config",
    "structured_full_threat_intel_unavailable",
]

THREAT_INTEL_UNAVAILABLE_MODES = {
    "gold_dfd_full_threat_intel_unavailable",
    "structured_full_threat_intel_unavailable",
}

AI_UNAVAILABLE_MODES = {
    "gold_dfd_full_ai_unavailable",
    "structured_full_ai_unavailable",
}

INVALID_MODEL_MODES = {
    "gold_dfd_full_invalid_model_config",
    "structured_full_invalid_model_config",
}


@dataclass
class ScenarioBundle:
    metadata: ScenarioMetadata
    gold_themes: GoldThreatThemeSet
    must_not_hallucinate: list[str]
    gold_dfd: DFDArtifact
    narrative_pdf: Path
    structured_pdf: Path
    delta_pdf: Path
    delta_patch: dict[str, Any]


class AuditClient:
    def __init__(self, base_url: str, timeout_seconds: int = 180) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.timeout_seconds = timeout_seconds
        self.token: str | None = None

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        headers = kwargs.pop("headers", {})
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        response = self.session.request(
            method,
            f"{self.base_url}{path}",
            headers=headers,
            timeout=self.timeout_seconds,
            **kwargs,
        )
        return response

    def register_and_login(self, email: str, password: str, full_name: str) -> None:
        register_response = self._request(
            "POST",
            "/auth/register",
            json={"email": email, "password": password, "full_name": full_name},
        )
        if register_response.status_code not in {201, 409}:
            raise RuntimeError(
                f"Register failed: {register_response.status_code} {register_response.text[:300]}"
            )
        login_response = self._request(
            "POST",
            "/auth/login",
            json={"email": email, "password": password},
        )
        if login_response.status_code != 200:
            raise RuntimeError(
                f"Login failed: {login_response.status_code} {login_response.text[:300]}"
            )
        self.token = login_response.json()["access_token"]

    def create_threat_model(self, metadata: ScenarioMetadata) -> dict[str, Any]:
        response = self._request(
            "POST",
            "/threat-models",
            json={
                "system_name": metadata.system_name,
                "description": metadata.description,
                "data_classification": metadata.data_classification,
                "regulatory_scope": metadata.regulatory_scope,
                "deployment_model": metadata.deployment_model,
            },
        )
        if response.status_code != 201:
            raise RuntimeError(
                f"Threat model creation failed: {response.status_code} {response.text[:300]}"
            )
        return response.json()

    def upload_document(self, threat_model_id: str, pdf_path: Path) -> requests.Response:
        with pdf_path.open("rb") as handle:
            return self._request(
                "POST",
                f"/threat-models/{threat_model_id}/documents",
                files={"file": (pdf_path.name, handle, "application/pdf")},
            )

    def get_dfd(self, threat_model_id: str) -> DFDArtifact:
        response = self._request("GET", f"/threat-models/{threat_model_id}/dfd")
        if response.status_code != 200:
            raise RuntimeError(f"DFD fetch failed: {response.status_code} {response.text[:300]}")
        return DFDArtifact.model_validate(response.json())

    def bulk_save_dfd(self, threat_model_id: str, dfd: DFDArtifact) -> DFDArtifact:
        response = self._request(
            "PUT",
            f"/threat-models/{threat_model_id}/dfd",
            json=dfd.model_dump(mode="json"),
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"DFD bulk save failed: {response.status_code} {response.text[:300]}"
            )
        return DFDArtifact.model_validate(response.json())

    def analyze(self, threat_model_id: str, *, rules_only: bool = False) -> requests.Response:
        suffix = "?rules_only=true" if rules_only else ""
        return self._request(
            "POST",
            f"/threat-models/{threat_model_id}/analyze{suffix}",
        )

    def get_threats(self, threat_model_id: str) -> requests.Response:
        return self._request("GET", f"/threat-models/{threat_model_id}/threats")

    def get_threat_summary(self, threat_model_id: str) -> requests.Response:
        return self._request("GET", f"/threat-models/{threat_model_id}/threats/summary")

    def get_threat_diff(self, threat_model_id: str) -> requests.Response:
        return self._request("POST", f"/threat-models/{threat_model_id}/threat-diff")

    def export_threats_csv(self, threat_model_id: str) -> requests.Response:
        return self._request("GET", f"/threat-models/{threat_model_id}/threats/export.csv")

    def triage_threat(
        self,
        threat_model_id: str,
        threat_id: str,
        *,
        status: str,
        dismiss_reason: str | None = None,
    ) -> requests.Response:
        return self._request(
            "PATCH",
            f"/threat-models/{threat_model_id}/threats/{threat_id}/triage",
            json={"status": status, "dismiss_reason": dismiss_reason},
        )

    def get_providers(self) -> dict[str, Any]:
        response = self._request("GET", "/llm/providers")
        if response.status_code != 200:
            raise RuntimeError(
                f"LLM provider fetch failed: {response.status_code} {response.text[:300]}"
            )
        return response.json()

    def switch_provider(self, provider: str, model: str | None = None) -> requests.Response:
        payload = {"provider": provider, "model": model}
        return self._request("POST", "/llm/provider", json=payload)


class ManagedBackend:
    def __init__(
        self,
        backend_dir: Path,
        *,
        port: int,
        env_overrides: dict[str, str] | None = None,
        log_path: Path | None = None,
    ) -> None:
        self.backend_dir = backend_dir
        self.port = port
        self.env_overrides = env_overrides or {}
        self.log_path = log_path
        self.process: subprocess.Popen[str] | None = None
        self._log_handle = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/api"

    def start(self) -> None:
        env = os.environ.copy()
        env.update(self.env_overrides)
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_handle = self.log_path.open("w", encoding="utf-8")
            stdout = self._log_handle
            stderr = subprocess.STDOUT
        else:
            stdout = subprocess.DEVNULL
            stderr = subprocess.STDOUT
        self.process = subprocess.Popen(
            ["uvicorn", "app.main:app", "--port", str(self.port)],
            cwd=self.backend_dir,
            env=env,
            stdout=stdout,
            stderr=stderr,
            text=True,
        )
        self._wait_for_health()

    def _wait_for_health(self, timeout_seconds: int = 90) -> None:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if self.process and self.process.poll() is not None:
                raise RuntimeError("Managed backend exited before becoming healthy")
            try:
                response = requests.get(f"{self.base_url}/health", timeout=5)
                if response.status_code == 200:
                    return
            except requests.RequestException:
                pass
            time.sleep(1)
        raise RuntimeError("Managed backend did not become healthy in time")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None

    def restart(self, env_overrides: dict[str, str]) -> None:
        self.stop()
        self.env_overrides = env_overrides
        self.start()


def load_scenario_bundle(scenario_id: str, scenario_root: Path) -> ScenarioBundle:
    scenario_dir = scenario_root / scenario_id
    metadata = ScenarioMetadata.model_validate(
        yaml.safe_load((scenario_dir / "metadata.yaml").read_text(encoding="utf-8"))
    )
    gold_themes = GoldThreatThemeSet.model_validate(
        yaml.safe_load((scenario_dir / "gold_threat_themes.yaml").read_text(encoding="utf-8"))
    )
    must_not_hallucinate = yaml.safe_load(
        (scenario_dir / "must_not_hallucinate.yaml").read_text(encoding="utf-8")
    )
    gold_dfd = DFDArtifact.model_validate(
        json.loads((scenario_dir / "gold_dfd.json").read_text(encoding="utf-8"))
    )
    return ScenarioBundle(
        metadata=metadata,
        gold_themes=gold_themes,
        must_not_hallucinate=list(must_not_hallucinate),
        gold_dfd=gold_dfd,
        narrative_pdf=scenario_dir / "narrative.pdf",
        structured_pdf=scenario_dir / "structured.pdf",
        delta_pdf=scenario_dir / "delta.pdf",
        delta_patch=SCENARIO_DEFINITIONS[scenario_id].get("delta_patch", {}),
    )


def normalize_name(value: str) -> str:
    return "".join(char.lower() for char in value if char.isalnum())


def clone_dfd_with_fresh_ids(dfd: DFDArtifact) -> tuple[DFDArtifact, dict[str, str]]:
    boundary_id_map = {str(boundary.id): str(uuid4()) for boundary in dfd.trust_boundaries}
    node_id_map = {str(node.id): str(uuid4()) for node in dfd.nodes}
    edge_id_map = {str(edge.id): str(uuid4()) for edge in dfd.edges}
    id_map = {**boundary_id_map, **node_id_map, **edge_id_map}

    payload = dfd.model_dump(mode="json")
    for boundary in payload["trust_boundaries"]:
        boundary["id"] = id_map[boundary["id"]]
        boundary["node_ids"] = [id_map[node_id] for node_id in boundary["node_ids"]]
    for node in payload["nodes"]:
        node["id"] = id_map[node["id"]]
        if node.get("trust_boundary_id") is not None:
            node["trust_boundary_id"] = id_map[node["trust_boundary_id"]]
    for edge in payload["edges"]:
        edge["id"] = id_map[edge["id"]]
        edge["source_node_id"] = id_map[edge["source_node_id"]]
        edge["target_node_id"] = id_map[edge["target_node_id"]]
    return DFDArtifact.model_validate(payload), id_map


def rebase_delta_patch(delta_patch: dict[str, Any], base_id_map: dict[str, str]) -> dict[str, Any]:
    payload = copy.deepcopy(delta_patch)
    id_map = dict(base_id_map)

    for node in payload.get("add_nodes", []):
        original_id = node["id"]
        id_map[original_id] = str(uuid4())
        node["id"] = id_map[original_id]
        if node.get("trust_boundary_id") is not None:
            node["trust_boundary_id"] = id_map.get(
                node["trust_boundary_id"], node["trust_boundary_id"]
            )

    for edge in payload.get("add_edges", []):
        original_id = edge["id"]
        id_map[original_id] = str(uuid4())
        edge["id"] = id_map[original_id]
        edge["source_node_id"] = id_map.get(edge["source_node_id"], edge["source_node_id"])
        edge["target_node_id"] = id_map.get(edge["target_node_id"], edge["target_node_id"])

    payload["add_boundary_membership"] = {
        boundary_name: [id_map.get(node_id, node_id) for node_id in node_ids]
        for boundary_name, node_ids in payload.get("add_boundary_membership", {}).items()
    }
    return payload


def threat_artifacts_from_response(response: requests.Response) -> list[ThreatArtifact]:
    if response.status_code != 200:
        return []
    payload = response.json()
    threats_payload = payload["threats"] if isinstance(payload, dict) and "threats" in payload else payload
    return [ThreatArtifact.model_validate(item) for item in threats_payload]


def dfd_name_maps(dfd: DFDArtifact) -> tuple[dict[str, Any], dict[str, str]]:
    node_by_name = {node.name: node for node in dfd.nodes}
    node_id_to_name = {str(node.id): node.name for node in dfd.nodes}
    return node_by_name, node_id_to_name


def missing_gold_edges(actual: DFDArtifact, gold: DFDArtifact) -> list[dict[str, Any]]:
    _, actual_node_id_to_name = dfd_name_maps(actual)
    gold_node_by_id = {str(node.id): node for node in gold.nodes}
    actual_edges = {
        (
            actual_node_id_to_name.get(str(edge.source_node_id), ""),
            actual_node_id_to_name.get(str(edge.target_node_id), ""),
            edge.label,
        )
        for edge in actual.edges
    }
    missing = []
    for edge in gold.edges:
        descriptor = (
            gold_node_by_id[str(edge.source_node_id)].name,
            gold_node_by_id[str(edge.target_node_id)].name,
            edge.label,
        )
        if descriptor not in actual_edges:
            missing.append(
                {
                    "gold_edge": edge,
                    "source_name": descriptor[0],
                    "target_name": descriptor[1],
                    "label": descriptor[2],
                }
            )
    return missing


def apply_fixed_repair(
    actual: DFDArtifact,
    gold: DFDArtifact,
    metadata: ScenarioMetadata,
) -> tuple[DFDArtifact, RepairScriptResult]:
    working = DFDArtifact.model_validate(actual.model_dump(mode="json"))
    result = RepairScriptResult(applied=False)

    gold_node_by_name = {node.name: node for node in gold.nodes}
    gold_boundary_by_name = {boundary.name: boundary for boundary in gold.trust_boundaries}
    actual_node_by_name = {node.name: node for node in working.nodes}

    critical_components = [name for name in metadata.critical_components if name in gold_node_by_name]
    result.missing_critical_components_before = [
        name for name in critical_components if name not in actual_node_by_name
    ]

    used_actual_ids: set[str] = set()
    remaining_missing = list(result.missing_critical_components_before)

    for missing_name in list(remaining_missing):
        gold_node = gold_node_by_name[missing_name]
        candidates = [
            node
            for node in working.nodes
            if node.node_type == gold_node.node_type
            and str(node.id) not in used_actual_ids
            and node.name not in gold_node_by_name
        ]
        if not candidates:
            continue
        best = max(
            candidates,
            key=lambda node: SequenceMatcher(
                None, normalize_name(node.name), normalize_name(missing_name)
            ).ratio(),
        )
        similarity = SequenceMatcher(
            None, normalize_name(best.name), normalize_name(missing_name)
        ).ratio()
        if similarity < 0.55 or len([a for a in result.actions if a.action == "rename_node"]) >= 2:
            continue
        original_name = best.name
        best.name = missing_name
        result.actions.append(
            RepairAction(
                action="rename_node",
                detail=f"Renamed '{original_name}' to '{missing_name}'",
                target_id=str(best.id),
            )
        )
        used_actual_ids.add(str(best.id))
        result.applied = True
        remaining_missing.remove(missing_name)

    actual_node_by_name = {node.name: node for node in working.nodes}
    for missing_name in remaining_missing[:2]:
        gold_node = gold_node_by_name[missing_name]
        valid_boundary_ids = {boundary.id for boundary in working.trust_boundaries}
        working.nodes.append(
            gold_node.model_copy(
                update={
                    "trust_boundary_id": (
                        gold_node.trust_boundary_id
                        if gold_node.trust_boundary_id in valid_boundary_ids
                        else None
                    )
                }
            )
        )
        result.actions.append(
            RepairAction(
                action="add_node",
                detail=f"Added missing critical component '{missing_name}'",
                target_id=str(gold_node.id),
            )
        )
        result.applied = True

    actual_node_by_name = {node.name: node for node in working.nodes}
    missing_edges = missing_gold_edges(working, gold)
    result.missing_critical_flows_before = [
        f"{edge['source_name']} -> {edge['target_name']} ({edge['label']})"
        for edge in missing_edges
        if edge["source_name"] in metadata.critical_components
        or edge["target_name"] in metadata.critical_components
    ]
    added_edges = 0
    for item in missing_edges:
        if added_edges >= 2:
            break
        if item["source_name"] not in actual_node_by_name or item["target_name"] not in actual_node_by_name:
            continue
        working.edges.append(
            item["gold_edge"].model_copy(
                update={
                    "source_node_id": actual_node_by_name[item["source_name"]].id,
                    "target_node_id": actual_node_by_name[item["target_name"]].id,
                }
            )
        )
        result.actions.append(
            RepairAction(
                action="add_edge",
                detail=(
                    f"Added missing flow {item['source_name']} -> "
                    f"{item['target_name']} ({item['label']})"
                ),
                target_id=str(item["gold_edge"].id),
            )
        )
        added_edges += 1
        result.applied = True

    hallucinated = [
        node
        for node in working.nodes
        if node.name not in gold_node_by_name
        and max(
            (
                SequenceMatcher(None, normalize_name(node.name), normalize_name(gold_name)).ratio()
                for gold_name in gold_node_by_name
            ),
            default=0.0,
        )
        < 0.40
    ]
    result.hallucinated_nodes_before = [node.name for node in hallucinated]
    if hallucinated:
        doomed = hallucinated[0]
        working.nodes = [node for node in working.nodes if node.id != doomed.id]
        working.edges = [
            edge
            for edge in working.edges
            if edge.source_node_id != doomed.id and edge.target_node_id != doomed.id
        ]
        for boundary in working.trust_boundaries:
            boundary.node_ids = [node_id for node_id in boundary.node_ids if node_id != doomed.id]
        result.actions.append(
            RepairAction(
                action="delete_node",
                detail=f"Deleted hallucinated node '{doomed.name}'",
                target_id=str(doomed.id),
            )
        )
        result.applied = True

    actual_node_by_name = {node.name: node for node in working.nodes}
    boundary_fixes = 0
    for boundary_name in metadata.critical_boundaries:
        if boundary_fixes >= 1:
            break
        gold_boundary = gold_boundary_by_name.get(boundary_name)
        if gold_boundary is None:
            continue
        mapped_node_ids = []
        for node_id in gold_boundary.node_ids:
            gold_node = next(node for node in gold.nodes if node.id == node_id)
            if gold_node.name in actual_node_by_name:
                mapped_node_ids.append(actual_node_by_name[gold_node.name].id)
        current_boundary = next(
            (boundary for boundary in working.trust_boundaries if boundary.name == boundary_name),
            None,
        )
        if current_boundary is None:
            working.trust_boundaries.append(
                gold_boundary.model_copy(update={"node_ids": mapped_node_ids})
            )
            result.actions.append(
                RepairAction(
                    action="fix_boundary",
                    detail=f"Added missing trust boundary '{boundary_name}'",
                    target_id=str(gold_boundary.id),
                )
            )
            result.applied = True
            boundary_fixes += 1
            continue
        if set(current_boundary.node_ids) != set(mapped_node_ids):
            current_boundary.node_ids = mapped_node_ids
            result.actions.append(
                RepairAction(
                    action="fix_boundary",
                    detail=f"Aligned trust boundary '{boundary_name}' to gold membership",
                    target_id=str(current_boundary.id),
                )
            )
            result.applied = True
            boundary_fixes += 1

    valid_node_ids = {node.id for node in working.nodes}
    working.edges = [
        edge
        for edge in working.edges
        if edge.source_node_id in valid_node_ids and edge.target_node_id in valid_node_ids
    ]
    for boundary in working.trust_boundaries:
        boundary.node_ids = [node_id for node_id in boundary.node_ids if node_id in valid_node_ids]
    return working, result


def apply_delta_patch(dfd: DFDArtifact, delta_patch: dict[str, Any]) -> DFDArtifact:
    working = DFDArtifact.model_validate(dfd.model_dump(mode="json"))
    existing_node_ids = {node.id for node in working.nodes}
    existing_edge_ids = {edge.id for edge in working.edges}

    for node_payload in delta_patch.get("add_nodes", []):
        node = DFDNodeArtifact.model_validate(node_payload)
        if node.id not in existing_node_ids:
            working.nodes.append(node)
            existing_node_ids.add(node.id)

    for edge_payload in delta_patch.get("add_edges", []):
        edge = DFDEdgeArtifact.model_validate(edge_payload)
        if edge.id not in existing_edge_ids:
            working.edges.append(edge)
            existing_edge_ids.add(edge.id)

    actual_node_by_id = {str(node.id): node for node in working.nodes}
    for boundary_name, node_ids in delta_patch.get("add_boundary_membership", {}).items():
        boundary = next(
            (candidate for candidate in working.trust_boundaries if candidate.name == boundary_name),
            None,
        )
        if boundary is None:
            continue
        for node_id in node_ids:
            if node_id in actual_node_by_id and actual_node_by_id[node_id].id not in boundary.node_ids:
                boundary.node_ids.append(actual_node_by_id[node_id].id)
    return working


def copy_supporting_inputs(run_dir: Path, bundle: ScenarioBundle, mode: str) -> None:
    if mode.startswith("structured"):
        shutil.copy2(bundle.structured_pdf, run_dir / bundle.structured_pdf.name)
    elif mode.startswith("narrative"):
        shutil.copy2(bundle.narrative_pdf, run_dir / bundle.narrative_pdf.name)
    elif mode == "delta_reanalyze":
        shutil.copy2(bundle.delta_pdf, run_dir / bundle.delta_pdf.name)


def parse_csv_count(csv_text: str) -> int:
    reader = csv.reader(csv_text.splitlines())
    rows = list(reader)
    return max(len(rows) - 1, 0) if rows else 0


@contextmanager
def maybe_managed_backend(
    args: argparse.Namespace,
    *,
    env_overrides: dict[str, str] | None = None,
    log_path: Path | None = None,
) -> Iterator[ManagedBackend | None]:
    if not args.manage_backend:
        yield None
        return
    manager = ManagedBackend(
        backend_dir=Path(args.backend_cwd),
        port=args.backend_port,
        env_overrides=env_overrides,
        log_path=log_path,
    )
    manager.start()
    try:
        yield manager
    finally:
        manager.stop()


def configure_degradation(
    client: AuditClient,
    mode: str,
    run_notes: list[str],
    *,
    managed_backend_active: bool,
) -> DegradationEvidence:
    evidence = DegradationEvidence(mode=mode, expected=mode not in RUN_MODES[:6])
    if mode in INVALID_MODEL_MODES and managed_backend_active:
        evidence.triggered_by = "managed_backend_env_override"
        evidence.details.append("AUDIT_FORCE_INVALID_MODEL_CONFIG=true")
        evidence.observed = True
        return evidence

    if mode in AI_UNAVAILABLE_MODES and managed_backend_active:
        evidence.triggered_by = "managed_backend_env_override"
        evidence.details.append("AUDIT_FORCE_AI_UNAVAILABLE=true")
        evidence.observed = True
        return evidence

    if mode in INVALID_MODEL_MODES:
        providers = client.get_providers()
        active = providers.get("active", {})
        provider = active.get("provider", "bedrock")
        response = client.switch_provider(provider, f"audit-invalid-model-{uuid4().hex[:8]}")
        evidence.triggered_by = "provider_switch_invalid_model"
        evidence.details.append(
            f"switch_provider status={response.status_code} provider={provider}"
        )
        evidence.observed = response.status_code in {200, 400, 503}
        return evidence

    if mode in AI_UNAVAILABLE_MODES:
        providers = client.get_providers()
        available = {item["name"] for item in providers.get("available", [])}
        candidate = "ollama" if "ollama" in available else providers.get("active", {}).get("provider", "bedrock")
        response = client.switch_provider(candidate, f"audit-unavailable-model-{uuid4().hex[:8]}")
        evidence.triggered_by = "provider_switch_unavailable_model"
        evidence.details.append(
            f"switch_provider status={response.status_code} provider={candidate}"
        )
        evidence.observed = response.status_code in {200, 400, 503}
        if candidate != "ollama":
            run_notes.append(
                "AI unavailable mode fell back to invalid-model simulation because Ollama was not available."
            )
        return evidence

    if mode in THREAT_INTEL_UNAVAILABLE_MODES and managed_backend_active:
        evidence.triggered_by = "managed_backend_env_override"
        evidence.details.append("AUDIT_DISABLE_THREAT_INTEL=true")
        evidence.observed = True
        return evidence

    if mode in THREAT_INTEL_UNAVAILABLE_MODES:
        evidence.triggered_by = "managed_backend_env_override"
        evidence.details.append(
            "Threat intel unavailable mode requires --manage-backend with AUDIT_DISABLE_THREAT_INTEL=true."
        )
        evidence.observed = False
        return evidence

    return evidence


def evaluate_run(
    args: argparse.Namespace,
    client: AuditClient,
    bundle: ScenarioBundle,
    mode: RunMode,
    run_dir: Path,
    *,
    managed_backend_active: bool,
) -> tuple[JudgeInput, ClaudeJudgeResult, GeminiJudgeResult, RunScorecard]:
    metadata = bundle.metadata
    seeded_gold_dfd, seeded_id_map = clone_dfd_with_fresh_ids(bundle.gold_dfd)
    run_delta_patch = rebase_delta_patch(bundle.delta_patch, seeded_id_map)
    copy_supporting_inputs(run_dir, bundle, mode)
    dump_json(run_dir / "gold_dfd.json", seeded_gold_dfd.model_dump(mode="json"))
    dump_json(run_dir / "gold_threat_themes.json", bundle.gold_themes.model_dump(mode="json"))

    operational = OperationalChecks()
    run_notes: list[str] = []
    degradation = configure_degradation(
        client,
        mode,
        run_notes,
        managed_backend_active=managed_backend_active,
    )

    threat_model = client.create_threat_model(metadata)
    threat_model_id = threat_model["id"]
    dump_json(run_dir / "threat_model.json", threat_model)

    upload_response: requests.Response | None = None
    repair_result: RepairScriptResult | None = None
    if mode.startswith("gold_dfd"):
        client.bulk_save_dfd(threat_model_id, seeded_gold_dfd)
    elif mode.startswith("structured"):
        upload_response = client.upload_document(threat_model_id, bundle.structured_pdf)
        operational.upload_status_code = upload_response.status_code
        try:
            dump_json(run_dir / "upload_response.json", upload_response.json())
        except Exception:
            (run_dir / "upload_response.txt").write_text(upload_response.text, encoding="utf-8")
    elif mode.startswith("narrative"):
        upload_response = client.upload_document(threat_model_id, bundle.narrative_pdf)
        operational.upload_status_code = upload_response.status_code
        try:
            dump_json(run_dir / "upload_response.json", upload_response.json())
        except Exception:
            (run_dir / "upload_response.txt").write_text(upload_response.text, encoding="utf-8")
    elif mode == "delta_reanalyze":
        client.bulk_save_dfd(threat_model_id, seeded_gold_dfd)
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    initial_dfd = client.get_dfd(threat_model_id)
    dump_json(run_dir / "initial_dfd.json", initial_dfd.model_dump(mode="json"))
    operational.notes.extend(run_notes)

    if mode == "narrative_repaired_full":
        repaired_dfd, repair_result = apply_fixed_repair(initial_dfd, seeded_gold_dfd, metadata)
        if repair_result.applied:
            client.bulk_save_dfd(threat_model_id, repaired_dfd)
            dump_json(run_dir / "repair_actions.json", repair_result.model_dump(mode="json"))
            initial_dfd = client.get_dfd(threat_model_id)
            dump_json(run_dir / "repaired_dfd.json", initial_dfd.model_dump(mode="json"))

    triage_evidence: dict[str, Any] = {}
    diff_response: requests.Response | None = None

    if mode == "delta_reanalyze":
        baseline_full = client.analyze(threat_model_id, rules_only=False)
        baseline_rules = client.analyze(threat_model_id, rules_only=True)
        dump_json(run_dir / "baseline_analyze_full.json", baseline_full.json())
        dump_json(run_dir / "baseline_analyze_rules_only.json", baseline_rules.json())
        baseline_threats = threat_artifacts_from_response(baseline_rules)
        delta_added_node_ids = {item["id"] for item in run_delta_patch.get("add_nodes", [])}
        delta_added_edge_ids = {item["id"] for item in run_delta_patch.get("add_edges", [])}
        triage_candidate = next(
            (
                threat
                for threat in baseline_threats
                if not {str(node_id) for node_id in threat.affected_node_ids} & delta_added_node_ids
                and not {str(edge_id) for edge_id in threat.affected_edge_ids} & delta_added_edge_ids
            ),
            baseline_threats[0] if baseline_threats else None,
        )
        if triage_candidate is not None and triage_candidate.id is not None:
            triage_response = client.triage_threat(
                threat_model_id,
                str(triage_candidate.id),
                status="Accepted",
            )
            triage_evidence["baseline_triage_status_code"] = triage_response.status_code
            triage_evidence["baseline_triaged_rule_id"] = triage_candidate.rule_id
            triage_evidence["baseline_triaged_display_id"] = triage_candidate.display_id
        delta_dfd = apply_delta_patch(initial_dfd, run_delta_patch)
        client.bulk_save_dfd(threat_model_id, delta_dfd)
        diff_response = client.get_threat_diff(threat_model_id)
        initial_dfd = client.get_dfd(threat_model_id)
        dump_json(run_dir / "delta_applied_dfd.json", initial_dfd.model_dump(mode="json"))
        if diff_response.status_code == 200:
            dump_json(run_dir / "threat_diff.json", diff_response.json())

    primary_is_rules_only = mode == "gold_dfd_rules_only"
    if primary_is_rules_only:
        analyze_full_response = client.analyze(threat_model_id, rules_only=False)
        analyze_rules_response = client.analyze(threat_model_id, rules_only=True)
    else:
        analyze_rules_response = client.analyze(threat_model_id, rules_only=True)
        analyze_full_response = client.analyze(threat_model_id, rules_only=False)

    operational.rules_only_status_code = analyze_rules_response.status_code
    operational.analyze_status_code = analyze_full_response.status_code
    operational.no_5xx = all(
        status is None or status < 500
        for status in [operational.analyze_status_code, operational.rules_only_status_code, operational.upload_status_code]
    )

    dump_json(
        run_dir / "analyze_rules_only.json",
        analyze_rules_response.json() if analyze_rules_response.headers.get("content-type", "").startswith("application/json") else {"detail": analyze_rules_response.text},
    )
    dump_json(
        run_dir / "analyze_full.json",
        analyze_full_response.json() if analyze_full_response.headers.get("content-type", "").startswith("application/json") else {"detail": analyze_full_response.text},
    )

    if diff_response is None:
        diff_response = client.get_threat_diff(threat_model_id)
        operational.threat_diff_status_code = diff_response.status_code
        if diff_response.status_code == 200:
            dump_json(run_dir / "threat_diff.json", diff_response.json())
    else:
        operational.threat_diff_status_code = diff_response.status_code

    threats_response = client.get_threats(threat_model_id)
    summary_response = client.get_threat_summary(threat_model_id)
    export_response = client.export_threats_csv(threat_model_id)
    operational.export_csv_status_code = export_response.status_code

    actual_threats = threat_artifacts_from_response(threats_response)
    rules_only_threats = threat_artifacts_from_response(analyze_rules_response)
    if primary_is_rules_only:
        actual_threats = rules_only_threats
    elif analyze_full_response.status_code == 200:
        actual_threats = threat_artifacts_from_response(analyze_full_response)

    dump_json(run_dir / "threats.json", [item.model_dump(mode="json") for item in actual_threats])
    if summary_response.status_code == 200:
        dump_json(run_dir / "threats_summary.json", summary_response.json())
    if export_response.status_code == 200:
        (run_dir / "threats_export.csv").write_text(export_response.text, encoding="utf-8")
        operational.export_matches_list_count = parse_csv_count(export_response.text) == len(actual_threats)

    if mode == "delta_reanalyze":
        baseline_rule_id = triage_evidence.get("baseline_triaged_rule_id")
        triage_evidence["post_delta_accepted_rule_ids"] = [
            threat.rule_id for threat in actual_threats if threat.status == "Accepted"
        ]
        operational.triage_persistence_ok = baseline_rule_id in triage_evidence["post_delta_accepted_rule_ids"]

    if mode in INVALID_MODEL_MODES | AI_UNAVAILABLE_MODES | THREAT_INTEL_UNAVAILABLE_MODES:
        full_payload = analyze_full_response.json() if analyze_full_response.headers.get("content-type", "").startswith("application/json") else {}
        operational.ai_skipped_reason = full_payload.get("ai_skipped_reason")
        operational.degraded_mode_ok = (
            analyze_full_response.status_code == 200
            and operational.no_5xx
            and (
                operational.ai_skipped_reason is not None
                or mode in THREAT_INTEL_UNAVAILABLE_MODES
            )
        )
        degradation.observed = operational.degraded_mode_ok or degradation.observed

    final_dfd = client.get_dfd(threat_model_id)
    dump_json(run_dir / "final_dfd.json", final_dfd.model_dump(mode="json"))
    actual_dfd_summary = summarize_dfd(final_dfd)
    gold_dfd_summary = summarize_dfd(seeded_gold_dfd)
    judge_input = JudgeInput(
        generated_at=datetime.now(timezone.utc),
        scenario=metadata,
        mode=mode,
        is_degraded_variant=mode not in RUN_MODES[:6],
        gold_dfd_summary=gold_dfd_summary,
        actual_dfd_summary=actual_dfd_summary,
        gold_threat_themes=bundle.gold_themes,
        must_not_hallucinate=list(
            dict.fromkeys(bundle.must_not_hallucinate + bundle.gold_themes.must_not_hallucinate)
        ),
        actual_threats=sort_threats(actual_threats),
        top_20_threats=sort_threats(actual_threats)[:20],
        rules_only_threats=sort_threats(rules_only_threats),
        diff_output=diff_response.json() if diff_response.status_code == 200 else {"status_code": diff_response.status_code},
        triage_persistence_evidence=triage_evidence,
        degradation_evidence=degradation,
        repair_result=repair_result,
        operational_checks=operational,
    )
    dump_json(run_dir / "judge_input.json", judge_input.model_dump(mode="json"))

    try:
        claude_result = (
            ClaudeJudgeResult(
                supported_top10_count=0,
                unsupported_threat_ids=[],
                wrong_stride_ids=[],
                wrong_severity_ids=[],
                duplicate_clusters=[],
                missing_critical_themes=[],
                blocker_findings=[],
                score_correctness_0_100=0,
                verdict="FAIL",
                low_confidence_ambiguity=True,
            )
            if args.skip_claude
            else run_claude_judge(judge_input)
        )
    except Exception as exc:
        claude_result = ClaudeJudgeResult(
            supported_top10_count=0,
            unsupported_threat_ids=[],
            wrong_stride_ids=[],
            wrong_severity_ids=[],
            duplicate_clusters=[],
            missing_critical_themes=[],
            blocker_findings=[f"Claude judge failed: {exc}"],
            score_correctness_0_100=0,
            verdict="FAIL",
            low_confidence_ambiguity=True,
        )

    try:
        gemini_result = (
            GeminiJudgeResult(
                generic_threat_ids=[],
                missing_high_value_themes=[],
                misprioritized_ids=[],
                top10_quality_score_0_100=0,
                overall_world_class_score_0_100=0,
                world_class_verdict="FAIL",
                notes=["Gemini was skipped."],
                low_confidence_ambiguity=True,
            )
            if args.skip_gemini
            else run_gemini_judge(judge_input)
        )
    except Exception as exc:
        gemini_result = GeminiJudgeResult(
            generic_threat_ids=[],
            missing_high_value_themes=[],
            misprioritized_ids=[],
            top10_quality_score_0_100=0,
            overall_world_class_score_0_100=0,
            world_class_verdict="FAIL",
            notes=[f"Gemini judge failed: {exc}"],
            low_confidence_ambiguity=True,
        )
    dump_json(run_dir / "claude_judge.json", claude_result.model_dump(mode="json"))
    dump_json(run_dir / "gemini_judge.json", gemini_result.model_dump(mode="json"))

    coverage_score, _ = compute_coverage_score(bundle.gold_themes, claude_result, gemini_result)
    operational_score = compute_operational_reliability_score(judge_input)
    scorecard = adjudicate_run(
        judge_input,
        claude_result,
        gemini_result,
        coverage_score,
        operational_score,
        run_dir,
    )
    render_run_snapshot(run_dir / "snapshot.png", judge_input, claude_result, gemini_result, scorecard)
    dump_json(run_dir / "scorecard.json", scorecard.model_dump(mode="json"))

    return judge_input, claude_result, gemini_result, scorecard


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ThreatGenix threat-modeler audit harness")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000/api",
        help="ThreatGenix API base URL",
    )
    parser.add_argument(
        "--output-root",
        default=f"/tmp/threatgenix-evals/{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        help="Directory for audit artifacts",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        dest="scenarios",
        help="Scenario ID to run. Repeat to run multiple.",
    )
    parser.add_argument(
        "--mode",
        action="append",
        dest="modes",
        help="Run mode to execute. Repeat to run multiple.",
    )
    parser.add_argument("--skip-claude", action="store_true", help="Skip Claude judging")
    parser.add_argument("--skip-gemini", action="store_true", help="Skip Gemini judging")
    parser.add_argument("--manage-backend", action="store_true", help="Launch a managed backend subprocess for the audit")
    parser.add_argument("--backend-cwd", default=str(ROOT_DIR), help="Backend working directory for managed backend mode")
    parser.add_argument("--backend-port", type=int, default=18000, help="Port for managed backend mode")
    parser.add_argument("--build-scenarios-only", action="store_true", help="Only materialize the scenario pack and exit")
    parser.add_argument("--server-log-file", help="Copy an existing backend log file into each run directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    scenario_root = Path(__file__).resolve().parent / "scenarios"
    ensure_scenarios_materialized(scenario_root)
    if args.build_scenarios_only:
        print(scenario_root)
        return 0

    scenarios = args.scenarios or sorted(SCENARIO_DEFINITIONS.keys())
    modes = args.modes or RUN_MODES
    output_root = Path(args.output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    backend_env: dict[str, str] = {}
    with maybe_managed_backend(
        args,
        env_overrides=backend_env,
        log_path=output_root / "managed-backend.log" if args.manage_backend else None,
    ) as managed_backend:
        base_url = managed_backend.base_url if managed_backend is not None else args.base_url
        client = AuditClient(base_url)

        scorecards = []
        manual_review_queue: list[dict] = []
        claude_outputs: dict[str, dict] = {}
        gemini_outputs: dict[str, dict] = {}

        for scenario_id in scenarios:
            bundle = load_scenario_bundle(scenario_id, scenario_root)
            for mode in modes:
                if mode in THREAT_INTEL_UNAVAILABLE_MODES and managed_backend is not None:
                    managed_backend.restart(
                        {
                            "AUDIT_DISABLE_THREAT_INTEL": "true",
                        }
                    )
                    base_url = managed_backend.base_url
                    client = AuditClient(base_url)
                elif mode in INVALID_MODEL_MODES and managed_backend is not None:
                    managed_backend.restart(
                        {
                            "AUDIT_FORCE_INVALID_MODEL_CONFIG": "true",
                        }
                    )
                    base_url = managed_backend.base_url
                    client = AuditClient(base_url)
                elif mode in AI_UNAVAILABLE_MODES and managed_backend is not None:
                    managed_backend.restart(
                        {
                            "AUDIT_FORCE_AI_UNAVAILABLE": "true",
                        }
                    )
                    base_url = managed_backend.base_url
                    client = AuditClient(base_url)
                elif managed_backend is not None and managed_backend.env_overrides:
                    managed_backend.restart({})
                    base_url = managed_backend.base_url
                    client = AuditClient(base_url)

                run_dir = output_root / scenario_id / mode
                run_dir.mkdir(parents=True, exist_ok=True)
                email = f"audit-{scenario_id}-{mode}-{uuid4().hex[:8]}@example.com"
                password = f"Audit-{uuid4().hex[:12]}"
                client.register_and_login(email, password, "ThreatGenix Audit Analyst")
                credentials_path = run_dir / "credentials.json"
                dump_json(credentials_path, {"email": email, "password": password})

                if args.server_log_file:
                    source_log = Path(args.server_log_file)
                    if source_log.exists():
                        shutil.copy2(source_log, run_dir / source_log.name)

                run_key = f"{scenario_id}/{mode}"
                try:
                    judge_input, claude_result, gemini_result, typed_scorecard = evaluate_run(
                        args,
                        client,
                        bundle,
                        mode,  # type: ignore[arg-type]
                        run_dir,
                        managed_backend_active=managed_backend is not None,
                    )
                    scorecards.append(typed_scorecard)
                    manual_review_queue.extend(
                        build_manual_review_queue(
                            bundle.metadata,
                            judge_input.actual_threats,
                            typed_scorecard,
                        )
                    )
                    claude_outputs[run_key] = claude_result.model_dump(mode="json")
                    gemini_outputs[run_key] = gemini_result.model_dump(mode="json")
                except Exception as exc:
                    dump_json(
                        run_dir / "error.json",
                        {
                            "error": str(exc),
                            "traceback": format_exc(),
                        },
                    )
                    fail_scorecard = RunScorecard(
                        scenario_id=scenario_id,
                        mode=mode,  # type: ignore[arg-type]
                        run_directory=run_dir,
                        correctness_score=0,
                        world_class_score=0,
                        coverage_score=0,
                        operational_reliability_score=0,
                        weighted_run_score=0,
                        adjudication="FAIL",
                        manual_review_required=True,
                        blocker_findings=[f"Run failed: {exc}"],
                        missing_themes=[],
                        notes=["Run aborted before scoring"],
                    )
                    scorecards.append(fail_scorecard)
                    manual_review_queue.append(
                        {
                            "type": "run_failure",
                            "scenario_id": scenario_id,
                            "mode": mode,
                            "reason": str(exc),
                        }
                    )
                    claude_outputs[run_key] = {"error": "run_failed"}
                    gemini_outputs[run_key] = {"error": "run_failed"}

        campaign_summary = build_campaign_summary(scorecards, manual_review_queue)
        write_campaign_outputs(output_root, campaign_summary, claude_outputs, gemini_outputs)
        print(output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

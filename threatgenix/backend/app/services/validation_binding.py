"""Heuristics for binding validation evidence to modeled DFD components."""
from __future__ import annotations

import json
import re
from collections.abc import Iterable

from app.models.dfd import DFDNode
from app.models.scan import ScanFinding
from app.services.validation_execution_policy import (
    TARGET_AI_SYSTEM,
    TARGET_CONTAINER_IMAGE,
    TARGET_IAC_DIRECTORY,
    TARGET_LOCKFILE,
    TARGET_REPOSITORY_PATH,
    TARGET_URL,
)
from app.services.validation_tools import ValidationEvidence

_SOURCE_PATH_KEYS = (
    "source_path",
    "source_paths",
    "code_path",
    "code_paths",
    "repository_path",
    "repository_paths",
    "repo_path",
    "repo_paths",
)
_PACKAGE_KEYS = ("package", "packages", "dependency", "dependencies")
_RESOURCE_KEYS = (
    "resource",
    "resources",
    "iac_resource",
    "iac_resources",
    "terraform_resource",
    "terraform_resources",
    "cloud_resource",
    "cloud_resources",
)
_IMAGE_KEYS = ("container_image", "container_images", "image", "images")
_AI_SYSTEM_KEYS = (
    "ai_system",
    "ai_systems",
    "agent_name",
    "agent_names",
    "model_name",
    "model_names",
    "rag_source",
    "rag_sources",
)
_DESCRIPTOR_KEYS = (
    "service_name",
    "component_label",
    "component_description",
    *_AI_SYSTEM_KEYS,
)
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_PATH_LINE_SUFFIX_RE = re.compile(r":\d+(?::\d+)?$")
_ALIASES = {
    "authentication": "auth",
    "authorization": "authz",
    "database": "db",
    "gateway": "api",
}


def infer_validation_targets_for_findings(
    nodes: Iterable[DFDNode],
    findings: Iterable[ValidationEvidence],
    *,
    target_type: str,
) -> dict[str, str]:
    """Return node-id to matcher target refs inferred from evidence and node metadata.

    The semantic mapper stores target bindings in ``ScanJob.targets``. For code,
    dependency, IaC, and container evidence, a plain scan target like
    ``/repo`` is too broad, so inferred entries use typed refs such as
    ``path:app/auth.py`` or ``package:pyjwt``.
    """
    if target_type not in {
        TARGET_REPOSITORY_PATH,
        TARGET_LOCKFILE,
        TARGET_IAC_DIRECTORY,
        TARGET_CONTAINER_IMAGE,
        TARGET_URL,
        TARGET_AI_SYSTEM,
    }:
        return {}

    inferred: dict[str, str] = {}
    prepared_nodes = list(nodes)
    prepared_findings = list(findings)
    for node in prepared_nodes:
        if str(node.id) in inferred:
            continue
        for evidence in prepared_findings:
            binding_ref = _binding_ref_for_node_evidence(node, evidence, target_type=target_type)
            if binding_ref:
                inferred[str(node.id)] = binding_ref
                break
    return inferred


def binding_target_for_scan_finding(
    finding: ScanFinding,
    *,
    target_type: str,
    fallback_target: str | None = None,
) -> str:
    """Return a typed semantic target ref for rebinding an existing finding."""
    if target_type == TARGET_REPOSITORY_PATH:
        path = _first_clean_path(_raw_values_for_keys(finding.raw_output, _SOURCE_PATH_KEYS))
        path = path or _clean_path(finding.matched_at)
        if path:
            return f"path:{path}"
    if target_type == TARGET_LOCKFILE:
        package = _first_text(_raw_values_for_keys(finding.raw_output, _PACKAGE_KEYS))
        if package:
            return f"package:{package}"
        path = _first_clean_path(_raw_values_for_keys(finding.raw_output, _SOURCE_PATH_KEYS))
        path = path or _clean_path(finding.matched_at)
        if path:
            return f"path:{path}"
    if target_type == TARGET_IAC_DIRECTORY:
        resource = _first_text(_raw_values_for_keys(finding.raw_output, _RESOURCE_KEYS))
        if resource:
            return f"resource:{resource}"
        path = _first_clean_path(_raw_values_for_keys(finding.raw_output, _SOURCE_PATH_KEYS))
        path = path or _clean_path(finding.matched_at)
        if path:
            return f"path:{path}"
    if target_type == TARGET_CONTAINER_IMAGE:
        image = _first_text(_raw_values_for_keys(finding.raw_output, _IMAGE_KEYS))
        image = image or _first_text([finding.validation_target, fallback_target, finding.matched_at])
        if image:
            return f"image:{image}"
    if target_type == TARGET_AI_SYSTEM:
        ai_target = _first_text(_raw_values_for_keys(finding.raw_output, _AI_SYSTEM_KEYS))
        ai_target = ai_target or _first_text(
            [finding.matched_at, finding.validation_target, fallback_target]
        )
        if ai_target:
            return f"text:{ai_target}"
    return finding.validation_target or fallback_target or finding.matched_at


def _binding_ref_for_node_evidence(
    node: DFDNode,
    evidence: ValidationEvidence,
    *,
    target_type: str,
) -> str | None:
    properties = node.properties if isinstance(node.properties, dict) else {}
    haystack = _evidence_haystack(evidence)

    for value in _values_for_keys(properties, _SOURCE_PATH_KEYS):
        if _text_contains_path(haystack, value):
            return f"path:{value.strip()}"

    for value in _values_for_keys(properties, _PACKAGE_KEYS):
        if _text_contains_token(haystack, value):
            return f"package:{value.strip()}"

    for value in _values_for_keys(properties, _RESOURCE_KEYS):
        if _text_contains_token(haystack, value):
            return f"resource:{value.strip()}"

    for value in _values_for_keys(properties, _IMAGE_KEYS):
        if _text_contains_token(haystack, value):
            return f"image:{value.strip()}"

    if _has_structured_binding_refs(properties, target_type):
        return None

    for value in _values_for_keys(properties, _DESCRIPTOR_KEYS):
        if _descriptor_matches(haystack, value):
            return f"text:{value.strip()}"
    if _descriptor_matches(haystack, node.name):
        return f"text:{node.name.strip()}"

    return None


def _has_structured_binding_refs(properties: dict, target_type: str) -> bool:
    if target_type == TARGET_REPOSITORY_PATH:
        keys = _SOURCE_PATH_KEYS
    elif target_type == TARGET_LOCKFILE:
        keys = _PACKAGE_KEYS + _SOURCE_PATH_KEYS
    elif target_type == TARGET_IAC_DIRECTORY:
        keys = _RESOURCE_KEYS + _SOURCE_PATH_KEYS
    elif target_type == TARGET_CONTAINER_IMAGE:
        keys = _IMAGE_KEYS
    elif target_type == TARGET_AI_SYSTEM:
        keys = _AI_SYSTEM_KEYS
    else:
        return False
    return any(_values_for_keys(properties, keys))


def _values_for_keys(properties: dict, keys: Iterable[str]) -> list[str]:
    values: list[str] = []
    for key in keys:
        raw = properties.get(key)
        if raw is None:
            continue
        if isinstance(raw, str):
            values.extend(part.strip() for part in raw.split(",") if part.strip())
            continue
        if isinstance(raw, list):
            values.extend(str(item).strip() for item in raw if str(item).strip())
            continue
        values.append(str(raw).strip())
    return values


def _raw_values_for_keys(raw: object, keys: Iterable[str]) -> list[str]:
    key_set = set(keys)
    values: list[str] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in key_set:
                    if isinstance(item, list):
                        values.extend(str(part).strip() for part in item if str(part).strip())
                    elif item is not None and str(item).strip():
                        values.append(str(item).strip())
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(raw)
    return values


def _first_text(values: Iterable[str | None]) -> str | None:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return None


def _first_clean_path(values: Iterable[str]) -> str | None:
    for value in values:
        path = _clean_path(value)
        if path:
            return path
    return None


def _clean_path(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith(("path:", "package:", "resource:", "image:", "text:")):
        text = text.split(":", 1)[1].strip()
    text = text.split("#", 1)[0].split("?", 1)[0].strip()
    text = _PATH_LINE_SUFFIX_RE.sub("", text)
    return text or None


def _evidence_haystack(evidence: ValidationEvidence) -> str:
    parts = [
        evidence.target,
        evidence.matched_url,
        evidence.extracted_results or "",
        evidence.template_id or "",
        evidence.finding_title,
        " ".join(evidence.cve_ids or []),
        " ".join(evidence.tags or []),
    ]
    try:
        parts.append(json.dumps(evidence.raw_output, sort_keys=True, default=str))
    except TypeError:
        parts.append(str(evidence.raw_output))
    return "\n".join(parts).casefold()


def _text_contains_path(haystack: str, value: str) -> bool:
    candidate = value.strip().strip("/")
    if not candidate:
        return False
    normalized = candidate.casefold().replace("\\", "/")
    normalized_haystack = haystack.replace("\\", "/")
    pattern = rf"(?<![a-z0-9._-]){re.escape(normalized)}(?![a-z0-9._/-])"
    return re.search(pattern, normalized_haystack) is not None


def _text_contains_token(haystack: str, value: str) -> bool:
    candidate = value.strip().casefold()
    if not candidate:
        return False
    pattern = rf"(?<![a-z0-9._/-]){re.escape(candidate)}(?![a-z0-9._/-])"
    return re.search(pattern, haystack) is not None


def _descriptor_matches(haystack: str, value: str) -> bool:
    tokens = [_ALIASES.get(token, token) for token in _TOKEN_RE.findall(value.casefold())]
    tokens = [token for token in tokens if len(token) >= 3 and token not in {"the", "and", "api", "app"}]
    if not tokens:
        return False
    return any(token in haystack for token in tokens)

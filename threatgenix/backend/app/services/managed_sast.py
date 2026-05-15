"""Review-scoped managed SAST and SARIF normalization."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.models.application_review_bundle import ApplicationReviewBundle
from app.schemas.tool_harness import (
    ToolHarnessFinding,
    ToolHarnessOutput,
    ToolHarnessProvenance,
)
from app.services.application_review_bundles import (
    ReviewBundleValidationError,
    canonical_json,
    safe_manifest_path,
)
from app.services.tool_harness import TRUSTED_HARNESS_ISSUER
from app.services.validation_tools import SemgrepValidationAdapter, ValidationEvidence

MANAGED_SAST_TOOL_NAME = "semgrep"
MANAGED_SAST_OUTPUT_FORMAT = "semgrep-json"
SARIF_OUTPUT_FORMAT = "sarif"


class ManagedSastImportError(ValueError):
    """Raised when managed SAST or SARIF output cannot be normalized."""


def build_managed_sast_harness_output(
    *,
    bundle: ApplicationReviewBundle,
    raw_output: bytes | str | dict[str, Any],
    tool_version: str,
    ruleset_version: str,
    scanner_run_id: str,
    scanner_image: str | None = None,
    scanner_image_digest: str | None = None,
    ruleset_digest: str | None = None,
    raw_artifact_refs: list[str] | None = None,
) -> ToolHarnessOutput:
    """Normalize Semgrep JSON into trusted review harness output.

    This function parses captured scanner output only. It does not execute
    Semgrep or customer code.
    """
    raw_text = _raw_text(raw_output)
    findings = SemgrepValidationAdapter().parse_output(_bundle_target(bundle), raw_text)
    return _tool_output(
        bundle=bundle,
        findings=findings,
        tool_version=tool_version,
        ruleset_version=ruleset_version,
        scanner_run_id=scanner_run_id,
        output_format=MANAGED_SAST_OUTPUT_FORMAT,
        scanner_image=scanner_image,
        scanner_image_digest=scanner_image_digest,
        ruleset_digest=ruleset_digest,
        raw_artifact_refs=raw_artifact_refs or [f"artifact://managed-sast/{scanner_run_id}"],
    )


def build_sarif_harness_output(
    *,
    bundle: ApplicationReviewBundle,
    sarif: bytes | str | dict[str, Any],
    tool_version: str,
    ruleset_version: str,
    scanner_run_id: str,
    scanner_image: str | None = None,
    scanner_image_digest: str | None = None,
    ruleset_digest: str | None = None,
    raw_artifact_refs: list[str] | None = None,
) -> ToolHarnessOutput:
    """Normalize CodeQL/Semgrep-compatible SARIF into trusted harness output."""
    document = _json_document(sarif)
    if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
        raise ManagedSastImportError("SARIF document must include runs.")
    findings: list[ValidationEvidence] = []
    for run in _iter_dicts(document.get("runs")):
        rules = _sarif_rules_by_id(run)
        for result in _iter_dicts(run.get("results")):
            finding = _sarif_result_to_evidence(bundle, run, result, rules)
            if finding is not None:
                findings.append(finding)
    return _tool_output(
        bundle=bundle,
        findings=findings,
        tool_version=tool_version,
        ruleset_version=ruleset_version,
        scanner_run_id=scanner_run_id,
        output_format=SARIF_OUTPUT_FORMAT,
        scanner_image=scanner_image,
        scanner_image_digest=scanner_image_digest,
        ruleset_digest=ruleset_digest,
        raw_artifact_refs=raw_artifact_refs or [f"artifact://sarif/{scanner_run_id}"],
    )


def _tool_output(
    *,
    bundle: ApplicationReviewBundle,
    findings: list[ValidationEvidence],
    tool_version: str,
    ruleset_version: str,
    scanner_run_id: str,
    output_format: str,
    scanner_image: str | None,
    scanner_image_digest: str | None,
    ruleset_digest: str | None,
    raw_artifact_refs: list[str],
) -> ToolHarnessOutput:
    return ToolHarnessOutput(
        tool_name=MANAGED_SAST_TOOL_NAME,
        tool_version=tool_version,
        ruleset_version=ruleset_version,
        scanner_run_id=scanner_run_id,
        bundle_id=bundle.id,
        status="completed",
        findings=[_to_harness_finding(bundle, finding) for finding in findings],
        raw_artifact_refs=list(dict.fromkeys(raw_artifact_refs)),
        provenance=ToolHarnessProvenance(
            issuer=TRUSTED_HARNESS_ISSUER,
            tool_name=MANAGED_SAST_TOOL_NAME,
            scanner_run_id=scanner_run_id,
            bundle_id=bundle.id,
            output_format=output_format,
            scanner_image=scanner_image,
            scanner_image_digest=scanner_image_digest,
            ruleset_digest=ruleset_digest,
        ),
    )


def _to_harness_finding(
    bundle: ApplicationReviewBundle,
    finding: ValidationEvidence,
) -> ToolHarnessFinding:
    path, start_line, end_line = _split_matched_location(finding.matched_url)
    _require_bundle_path(bundle, path)
    return ToolHarnessFinding(
        rule_id=finding.template_id or finding.finding_title,
        title=finding.finding_title,
        severity=_harness_severity(finding.severity),
        path=path,
        start_line=start_line,
        end_line=end_line,
        evidence_snippet_sha256=_evidence_hash(finding.raw_output),
        confidence="high" if finding.severity in {"critical", "high"} else "medium",
        source_type="sast",
    )


def _sarif_result_to_evidence(
    bundle: ApplicationReviewBundle,
    run: dict[str, Any],
    result: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> ValidationEvidence | None:
    rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "").strip()
    if not rule_id:
        return None
    location = _primary_sarif_location(result)
    if location is None:
        return None
    path = _sarif_location_path(location)
    if not path:
        return None
    _require_bundle_path(bundle, path)
    region = _dict(location.get("physicalLocation", {}).get("region"))
    start_line = int(region.get("startLine") or 1)
    end_line = region.get("endLine")
    matched = f"{path}:{start_line}"
    message = _sarif_message_text(result) or _sarif_rule_name(rules.get(rule_id)) or rule_id
    rule = rules.get(rule_id) or {}
    severity = _sarif_severity(result, rule)
    raw = {
        "sarif_result": result,
        "sarif_rule": rule,
        "sarif_tool": _sarif_tool_name(run),
    }
    if end_line:
        raw["endLine"] = end_line
    return ValidationEvidence(
        tool_name=MANAGED_SAST_TOOL_NAME,
        target=_bundle_target(bundle),
        severity=severity,
        finding_title=message,
        cve_ids=[],
        tags=["sarif", "sast", "code", _sarif_tool_name(run).casefold()],
        matched_url=matched,
        raw_output=raw,
        deterministic=True,
        template_id=rule_id,
        extracted_results=matched,
    )


def _sarif_rules_by_id(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = _dict(_dict(run.get("tool")).get("driver"))
    return {
        str(rule.get("id")): rule
        for rule in _iter_dicts(driver.get("rules"))
        if rule.get("id")
    }


def _primary_sarif_location(result: dict[str, Any]) -> dict[str, Any] | None:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return None
    return locations[0] if isinstance(locations[0], dict) else None


def _sarif_location_path(location: dict[str, Any]) -> str:
    physical = _dict(location.get("physicalLocation"))
    artifact = _dict(physical.get("artifactLocation"))
    return str(artifact.get("uri") or "").strip()


def _sarif_message_text(result: dict[str, Any]) -> str:
    message = _dict(result.get("message"))
    return str(message.get("text") or message.get("markdown") or "").strip()


def _sarif_rule_name(rule: dict[str, Any] | None) -> str:
    if not isinstance(rule, dict):
        return ""
    return str(rule.get("name") or rule.get("shortDescription", {}).get("text") or "").strip()


def _sarif_tool_name(run: dict[str, Any]) -> str:
    driver = _dict(_dict(run.get("tool")).get("driver"))
    return str(driver.get("name") or "sarif").strip()


def _sarif_severity(result: dict[str, Any], rule: dict[str, Any]) -> str:
    properties = _dict(rule.get("properties"))
    security_severity = properties.get("security-severity")
    if security_severity is not None:
        try:
            value = float(security_severity)
        except (TypeError, ValueError):
            value = 0.0
        if value >= 9.0:
            return "critical"
        if value >= 7.0:
            return "high"
        if value >= 4.0:
            return "medium"
        return "low"
    return {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "low",
    }.get(str(result.get("level") or "").casefold(), "medium")


def _split_matched_location(value: str) -> tuple[str, int, int | None]:
    if ":" not in value:
        return value, 1, None
    path, line = value.rsplit(":", 1)
    try:
        parsed = int(line)
    except ValueError:
        return value, 1, None
    return path, max(1, parsed), None


def _require_bundle_path(bundle: ApplicationReviewBundle, path: str) -> None:
    try:
        safe_path = safe_manifest_path(path)
        manifest_paths = {
            safe_manifest_path(str(item.get("path", "")))
            for item in (bundle.manifest or [])
        }
    except ReviewBundleValidationError as exc:
        raise ManagedSastImportError(str(exc)) from exc
    if safe_path not in manifest_paths:
        raise ManagedSastImportError(f"Finding path is not present in bundle manifest: {safe_path}")


def _harness_severity(value: str) -> str:
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Low",
        "unknown": "Low",
    }.get(value.casefold(), "Medium")


def _evidence_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _json_document(value: bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        document = json.loads(_raw_text(value))
    except json.JSONDecodeError as exc:
        raise ManagedSastImportError("Scanner output must be valid JSON.") from exc
    if not isinstance(document, dict):
        raise ManagedSastImportError("Scanner output must be a JSON object.")
    return document


def _raw_text(value: bytes | str | dict[str, Any]) -> str:
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _bundle_target(bundle: ApplicationReviewBundle) -> str:
    return f"tgx-review-bundle://{bundle.id}"


def _iter_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}

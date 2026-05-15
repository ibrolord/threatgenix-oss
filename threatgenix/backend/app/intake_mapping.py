"""Pure intake answer mapping shared by the API service and packaged CLI."""

from __future__ import annotations


REVIEW_FIELD_MAPPINGS = {
    "app_name": "system_name",
    "app_description": "description",
    "business_purpose": "description",
    "data_classification": "data_classification",
    "regulatory_scope": "regulatory_scope",
    "deployment_model": "deployment_model",
    "out_of_scope": "out_of_scope_statement",
}


def threat_model_fields_from_intake(
    answers: dict[str, object],
    *,
    fallback_app_name: str | None = None,
) -> dict[str, object]:
    system_name = _first_text(answers.get("app_name"), fallback_app_name)
    description = _first_text(
        answers.get("app_description"),
        answers.get("business_purpose"),
        "Created by ThreatGenix review intake.",
    )
    fields: dict[str, object] = {
        "system_name": system_name,
        "description": description,
        "data_classification": _classification(answers.get("data_classification")),
        "regulatory_scope": answers.get("regulatory_scope") or [],
    }
    deployment = _deployment_model(answers.get("deployment_model"))
    if deployment:
        fields["deployment_model"] = deployment
    out_of_scope = answers.get("out_of_scope")
    if isinstance(out_of_scope, list) and out_of_scope:
        fields["out_of_scope_statement"] = "; ".join(str(item) for item in out_of_scope)
    return fields


def _first_text(*values: object) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "ThreatGenix Application"


def _classification(value: object) -> str:
    classification = str(value or "internal").replace("_", " ").title()
    if classification in {"Public", "Internal", "Confidential", "Restricted"}:
        return classification
    return "Internal"


def _deployment_model(value: object) -> str | None:
    if value in {"aws", "azure", "gcp", "vercel"}:
        return "cloud"
    if value == "on_prem":
        return "on-prem"
    if value == "hybrid":
        return "hybrid"
    return None

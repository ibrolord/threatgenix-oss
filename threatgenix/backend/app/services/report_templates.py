from __future__ import annotations

import re
from typing import Any

from app.schemas.report import (
    BUILT_IN_TEMPLATE_IDS,
    DEFAULT_SECTIONS,
    VALID_SECTION_IDS,
    ReportTemplateDefinition,
    ReportTemplateSection,
)


BUILT_IN_SECTION_LABELS: dict[str, str] = {
    "executive_summary": "Executive Summary",
    "scope": "Scope",
    "system_context": "System Context and Dependencies",
    "dfd": "Data Flow Diagram",
    "arch_diagrams": "Architectural Diagrams",
    "threats": "Threat Scenarios and Findings",
    "controls": "Controls and Risk Treatment",
    "assumptions": "Assumptions and Dependencies",
    "compliance": "Control and Compliance Mapping",
    "scan_validation": "Validation and Testing Evidence",
    "responsibility_matrix": "Shared Responsibility and Outsourced Services",
    "threat_intel_refs": "Threat Intelligence References",
    "methodology": "Methodology",
    "attestation": "Analyst Attestation",
}

BUILT_IN_SECTION_DESCRIPTIONS: dict[str, str] = {
    "executive_summary": "Board and leadership summary of key risk posture, top threats, and residual risk.",
    "scope": "Model scope, data classification, and in-scope system overview.",
    "system_context": "Critical integrations, data stores, exposures, and operational dependencies.",
    "dfd": "Threat-model DFD with trust boundaries and protected assets.",
    "arch_diagrams": "Supplemental architecture views and supporting diagrams.",
    "threats": "Threat scenarios, severity, ownership, and mitigation status.",
    "controls": "Existing controls, mapped mitigations, and treatment posture.",
    "assumptions": "Assumptions, constraints, and third-party or process dependencies.",
    "compliance": "Mappings to control frameworks and regulatory obligations.",
    "scan_validation": "Validation evidence from scans and testing activities.",
    "responsibility_matrix": "Customer/provider or internal/external ownership boundaries.",
    "threat_intel_refs": "ATT&CK, CAPEC, and CWE references mapped to identified threats.",
    "methodology": "Threat-modeling method, evidence inputs, and review caveats.",
    "attestation": "Analyst sign-off, signature lines, and scheduled review date.",
}


def _builtin_section(
    source_section_id: str,
    *,
    title: str | None = None,
    intro_text: str | None = None,
) -> ReportTemplateSection:
    return ReportTemplateSection(
        id=source_section_id,
        kind="built_in",
        source_section_id=source_section_id,
        title=title or BUILT_IN_SECTION_LABELS[source_section_id],
        intro_text=intro_text,
    )


BUILT_IN_REPORT_TEMPLATES: list[ReportTemplateDefinition] = [
    ReportTemplateDefinition(
        id="default",
        name="Default",
        description="Balanced detailed report for engineering and security review.",
        audience="engineering",
        cover_title="Threat Model Report",
        cover_subtitle="Detailed engineering view",
        built_in=True,
        sections=[_builtin_section(section_id) for section_id in DEFAULT_SECTIONS],
    ),
    ReportTemplateDefinition(
        id="minimal",
        name="Minimal",
        description="Compact document focused on essentials and decisions.",
        audience="engineering",
        cover_title="Threat Model Summary",
        cover_subtitle="Compact architecture and threat snapshot",
        built_in=True,
        sections=[
            _builtin_section("executive_summary"),
            _builtin_section("scope"),
            _builtin_section("dfd"),
            _builtin_section("threats"),
            _builtin_section("methodology"),
        ],
    ),
    ReportTemplateDefinition(
        id="executive",
        name="Executive",
        description="Leadership-friendly summary of business context, risk posture, and top actions.",
        audience="executive",
        cover_title="Executive Threat Summary",
        cover_subtitle="Leadership risk posture and action view",
        built_in=True,
        sections=[
            _builtin_section("executive_summary"),
            _builtin_section("system_context"),
            _builtin_section("dfd"),
            _builtin_section("threats"),
            _builtin_section("compliance"),
            _builtin_section("methodology"),
        ],
    ),
    ReportTemplateDefinition(
        id="financial_services",
        name="Financial Services Detailed",
        description=(
            "Structured for regulated financial institutions with emphasis on critical functions, "
            "dependencies, scenario evidence, residual risk, and control mapping."
        ),
        audience="financial_services",
        cover_title="Financial Services Threat Assessment",
        cover_subtitle="Banking and regulated-service review packet",
        built_in=True,
        sections=[
            _builtin_section(
                "executive_summary",
                intro_text="Summarize material risk posture, top scenarios, and residual exposure for leadership review.",
            ),
            _builtin_section(
                "scope",
                title="Scope, Criticality, and Review Context",
                intro_text="Document system purpose, business criticality, data classification, and regulatory scope.",
            ),
            _builtin_section(
                "system_context",
                title="Critical Functions, Dependencies, and Exposure",
                intro_text="Capture key systems, services, third parties, data stores, and externally exposed paths supporting the modeled service.",
            ),
            _builtin_section(
                "dfd",
                title="Threat Modeling Diagrams",
                intro_text="Show trust boundaries, core flows, and protected assets clearly enough for control validation and review.",
            ),
            _builtin_section("arch_diagrams"),
            _builtin_section(
                "threats",
                title="Threat Scenarios and Findings",
                intro_text="List prioritized scenarios with severity, status, and accountable owners.",
            ),
            _builtin_section(
                "controls",
                title="Controls, Gaps, and Risk Treatment",
                intro_text="Describe current mitigations, treatment status, and evidence gaps that remain open.",
            ),
            _builtin_section(
                "assumptions",
                title="Assumptions, Constraints, and Third-Party Dependencies",
                intro_text="Record assumptions and external dependencies that materially affect residual risk.",
            ),
            _builtin_section(
                "compliance",
                title="Regulatory and Control Mapping",
                intro_text="Map findings to frameworks and obligations that matter to regulated review workflows.",
            ),
            _builtin_section(
                "scan_validation",
                title="Validation and Testing Evidence",
                intro_text="Summarize testing, scan correlation, and validation coverage for findings in scope.",
            ),
            _builtin_section(
                "responsibility_matrix",
                title="Shared Responsibility and Outsourced Service Coverage",
                intro_text="Clarify provider-managed versus institution-managed exposures and supporting services.",
            ),
            _builtin_section("methodology"),
            ReportTemplateSection(
                id="board-prompts",
                kind="custom_text",
                title="Review Prompts",
                body=(
                    "Management review should confirm whether the remaining residual risks are within risk appetite, "
                    "whether critical dependencies and outsourced services are adequately covered by controls and testing, "
                    "and whether open actions have named owners and target completion dates."
                ),
            ),
            _builtin_section("attestation"),
        ],
    ),
]

BUILT_IN_REPORT_TEMPLATE_BY_ID = {
    template.id: template for template in BUILT_IN_REPORT_TEMPLATES
}


def make_report_template_id(label: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", label.strip().lower()).strip("-")
    return slug or "custom-report-template"


def normalize_report_template(
    candidate: ReportTemplateDefinition | dict[str, Any],
    *,
    built_in: bool = False,
) -> ReportTemplateDefinition:
    template = (
        candidate
        if isinstance(candidate, ReportTemplateDefinition)
        else ReportTemplateDefinition.model_validate(candidate)
    )
    template_id = template.id.strip()
    if not template_id:
        raise ValueError("Report template id is required.")
    if not built_in and template_id in BUILT_IN_TEMPLATE_IDS:
        raise ValueError(f"`{template_id}` is reserved for a built-in report template.")

    normalized_sections: list[ReportTemplateSection] = []
    seen_section_ids: set[str] = set()
    for index, section in enumerate(template.sections):
        source_section_id = (
            section.source_section_id
            if section.kind == "built_in"
            else None
        )
        normalized_id = section.id.strip() or (
            source_section_id if section.kind == "built_in" else f"custom-{index + 1}"
        )
        if normalized_id in seen_section_ids:
            raise ValueError(f"Duplicate report template section id `{normalized_id}`.")
        seen_section_ids.add(normalized_id)

        if section.kind == "built_in":
            source = (source_section_id or normalized_id).strip()
            if source not in VALID_SECTION_IDS:
                raise ValueError(f"Unknown built-in report section `{source}`.")
            normalized_sections.append(
                section.model_copy(
                    update={
                        "id": normalized_id,
                        "source_section_id": source,
                        "title": section.title.strip() or BUILT_IN_SECTION_LABELS[source],
                        "intro_text": (section.intro_text or "").strip() or None,
                        "body": None,
                    }
                )
            )
            continue

        body = (section.body or "").strip()
        if not body:
            raise ValueError("Custom text report sections require a body.")
        normalized_sections.append(
            section.model_copy(
                update={
                    "id": normalized_id,
                    "source_section_id": None,
                    "title": section.title.strip(),
                    "intro_text": (section.intro_text or "").strip() or None,
                    "body": body,
                }
            )
        )

    return template.model_copy(
        update={
            "id": template_id,
            "name": template.name.strip(),
            "description": template.description.strip(),
            "audience": template.audience.strip() or "engineering",
            "cover_title": template.cover_title.strip(),
            "cover_subtitle": (template.cover_subtitle or "").strip() or None,
            "built_in": built_in,
            "sections": normalized_sections,
        }
    )


def load_custom_report_templates(
    raw_templates: list[dict[str, Any]] | None,
) -> list[ReportTemplateDefinition]:
    templates: list[ReportTemplateDefinition] = []
    seen_ids: set[str] = set()
    for item in raw_templates or []:
        try:
            normalized = normalize_report_template(item, built_in=False)
        except Exception:
            continue
        if normalized.id in seen_ids:
            continue
        seen_ids.add(normalized.id)
        templates.append(normalized)
    return templates


def list_report_templates(
    raw_templates: list[dict[str, Any]] | None,
) -> list[ReportTemplateDefinition]:
    custom_templates = sorted(
        load_custom_report_templates(raw_templates),
        key=lambda template: template.name.casefold(),
    )
    return [*BUILT_IN_REPORT_TEMPLATES, *custom_templates]


def get_report_template(
    raw_templates: list[dict[str, Any]] | None,
    template_id: str | None,
) -> ReportTemplateDefinition:
    if template_id:
        for template in list_report_templates(raw_templates):
            if template.id == template_id:
                return template
    return BUILT_IN_REPORT_TEMPLATE_BY_ID["default"]


def serialize_custom_report_templates(
    templates: list[ReportTemplateDefinition] | list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    normalized_custom_templates: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for item in templates or []:
        normalized = normalize_report_template(item, built_in=False)
        if normalized.id in seen_ids:
            raise ValueError(f"Duplicate report template id `{normalized.id}`.")
        seen_ids.add(normalized.id)
        normalized_custom_templates.append(
            normalized.model_dump(mode="json", exclude={"built_in"})
        )
    return normalized_custom_templates

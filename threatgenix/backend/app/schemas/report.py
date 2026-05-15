from datetime import date, datetime
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.schemas.threat import ComplianceControlRef, ThreatResponse


VALID_SECTION_IDS = frozenset(
    [
        "executive_summary",
        "scope",
        "system_context",
        "dfd",
        "arch_diagrams",
        "threats",
        "controls",
        "assumptions",
        "compliance",
        "scan_validation",
        "responsibility_matrix",
        "threat_intel_refs",
        "methodology",
        "attestation",
    ]
)

DEFAULT_SECTIONS = [
    "executive_summary",
    "scope",
    "system_context",
    "dfd",
    "arch_diagrams",
    "threats",
    "controls",
    "assumptions",
    "compliance",
    "scan_validation",
    "responsibility_matrix",
    "threat_intel_refs",
    "methodology",
    "attestation",
]

BUILT_IN_TEMPLATE_IDS = frozenset(["default", "minimal", "executive", "financial_services"])


class ArchDiagram(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    image_base64: str


class ReportTemplateSection(BaseModel):
    id: str = Field(..., min_length=1, max_length=80)
    kind: Literal["built_in", "custom_text"] = "built_in"
    source_section_id: str | None = Field(default=None, max_length=80)
    title: str = Field(..., min_length=1, max_length=200)
    intro_text: str | None = Field(default=None, max_length=2000)
    body: str | None = Field(default=None, max_length=6000)

    @model_validator(mode="after")
    def validate_shape(self) -> "ReportTemplateSection":
        if self.kind == "built_in":
            source = (self.source_section_id or self.id).strip()
            if source not in VALID_SECTION_IDS:
                raise ValueError(f"Unknown built-in report section `{source}`.")
            self.source_section_id = source
            self.body = None
            return self

        self.source_section_id = None
        if not (self.body or "").strip():
            raise ValueError("Custom text report sections require a body.")
        return self


class ReportTemplateDefinition(BaseModel):
    id: str = Field(..., min_length=1, max_length=80)
    name: str = Field(..., min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    audience: str = Field(default="engineering", max_length=80)
    cover_title: str = Field(default="Threat Model Report", min_length=1, max_length=120)
    cover_subtitle: str | None = Field(default=None, max_length=200)
    built_in: bool = False
    sections: list[ReportTemplateSection] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_sections(self) -> "ReportTemplateDefinition":
        seen_ids: set[str] = set()
        if not self.sections:
            raise ValueError("Report templates must include at least one section.")
        for section in self.sections:
            if section.id in seen_ids:
                raise ValueError(f"Duplicate report template section id `{section.id}`.")
            seen_ids.add(section.id)
        return self


class ReportRequest(BaseModel):
    threat_model_id: Optional[UUID] = None  # Accepted but ignored — use URL path parameter
    # ~1.5 MB decoded max — prevents OOM on WeasyPrint PDF generation
    dfd_image_base64: str = Field("", max_length=2_000_000)
    # Ordered list of section IDs to include. None = all sections in default order.
    sections: Optional[list[str]] = None


class ReportConfigUpdate(BaseModel):
    report_template: Optional[str] = Field(None, max_length=80)
    report_watermark_text: Optional[str] = Field(None, max_length=200)
    report_logo_base64: Optional[str] = Field(None, max_length=500_000)  # ~375 KB decoded max
    arch_diagrams: Optional[list[ArchDiagram]] = None
    report_templates: Optional[list[ReportTemplateDefinition]] = None
    analyst_name: Optional[str] = Field(None, max_length=255)
    analyst_attestation: Optional[str] = None
    next_review_date: Optional[date] = None
    out_of_scope_statement: Optional[str] = None


class ReportTemplateLibraryUpdate(BaseModel):
    report_template_library: list[ReportTemplateDefinition] = Field(default_factory=list)


class ReportData(BaseModel):
    system_name: str
    description: str
    data_classification: str
    created_at: datetime
    generated_at: datetime
    dfd_image_base64: str
    threats: list[ThreatResponse]
    compliance_summary: list[ComplianceControlRef]
    methodology_text: str

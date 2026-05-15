from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class ParsedComponent(BaseModel):
    name: str
    component_type: Literal["process", "data_store", "external_entity", "human_actor"]
    confidence: float = Field(ge=0.0, le=1.0)
    description: str = ""
    extraction_source: str = "heuristic"
    evidence_page: int | None = None
    evidence_snippet: str = ""


class ParsedFlow(BaseModel):
    source: str
    target: str
    label: str = ""
    confidence: float = Field(ge=0.0, le=1.0)
    data_types: list[str] = Field(
        default_factory=list,
        description="Types of data in this flow (e.g., 'PAN', 'PII', 'credentials', 'session_token', 'transaction_data')",
    )
    extraction_source: str = "heuristic"
    evidence_page: int | None = None
    evidence_snippet: str = ""


class ParsedBoundary(BaseModel):
    name: str
    contains: list[str]
    extraction_source: str = "heuristic"
    evidence_page: int | None = None
    evidence_snippet: str = ""


class DocumentParseResult(BaseModel):
    components: list[ParsedComponent]
    flows: list[ParsedFlow]
    boundaries: list[ParsedBoundary]
    raw_text_excerpt: str = ""


class DocumentExtractionEvidence(BaseModel):
    component_count: int = 0
    flow_count: int = 0
    boundary_count: int = 0
    diagram_pages: list[int] = Field(default_factory=list)
    diagram_artifacts: list[str] = Field(default_factory=list)
    extraction_sources: list[str] = Field(default_factory=list)
    low_confidence_areas: list[str] = Field(default_factory=list)
    raw_text_excerpt: str = ""
    detected_doc_type: str | None = None


class ExtractionOutcome(BaseModel):
    parse_result: DocumentParseResult
    extraction_status: Literal["complete", "partial"] = "complete"
    warnings: list[str] = Field(default_factory=list)
    evidence: DocumentExtractionEvidence = Field(default_factory=DocumentExtractionEvidence)


class DocumentUploadResponse(BaseModel):
    document_id: UUID
    filename: str
    page_count: int
    parse_result: DocumentParseResult
    extraction_status: Literal["complete", "partial"] = "complete"
    warnings: list[str] = Field(default_factory=list)
    evidence: DocumentExtractionEvidence = Field(default_factory=DocumentExtractionEvidence)

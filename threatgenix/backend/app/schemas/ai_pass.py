from typing import Optional

from pydantic import BaseModel

from app.schemas.dfd import DFDResponse
from app.schemas.threat import ThreatResponse


class AIPassInput(BaseModel):
    dfd: DFDResponse
    rules_threats: list[ThreatResponse]
    doc_excerpt: str
    document_context_summary: str = ""
    system_name: str
    description: str = ""
    data_classification: str
    regulatory_scope: list[str] = []
    deployment_model: Optional[str] = None
    environment_context_summary: str = ""


class RegulatoryCitation(BaseModel):
    framework: str
    section: str
    description: str = ""


class AIThreatRaw(BaseModel):
    description: str
    stride_category: str
    severity: str
    enhances_rule_threat_id: Optional[str] = None
    reasoning: str
    relevance_rationale: str = ""
    affected_node_names: list[str] = []
    regulatory_citations: list[RegulatoryCitation] = []


class AIPassOutput(BaseModel):
    threats: list[AIThreatRaw]
    model_id: str
    input_tokens: int
    output_tokens: int
    latency_ms: float

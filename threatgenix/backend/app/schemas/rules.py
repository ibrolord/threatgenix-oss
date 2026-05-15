from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class RuleDefinition(BaseModel):
    rule_id: str
    stride_category: str
    threat_subtype: str
    description_template: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    requires_boundary_crossing: bool = True


class GeneratedThreat(BaseModel):
    rule_id: str
    display_id: str
    stride_category: str
    threat_subtype: str
    severity: str
    description: str
    affected_node_ids: list[str]
    affected_edge_ids: list[str]
    relevance_rationale: str = ""
    source: str = "Rules"
    provider_managed: bool = False
    crosses_trust_boundary: bool = False


class RuleEngineOutput(BaseModel):
    threats: list[GeneratedThreat]
    execution_time_ms: float
    rules_evaluated: int
    rules_fired: int
    warnings: list[str] = Field(default_factory=list)

from __future__ import annotations

from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.schemas.rules import GeneratedThreat
from app.services.rules.engine import evaluate_rules


NODE_CUSTOMER = "10000000-0000-0000-0000-000000000001"
NODE_PAYMENTS_API = "10000000-0000-0000-0000-000000000002"
EDGE_CHECKOUT = "20000000-0000-0000-0000-000000000001"
BOUNDARY_PCI = "30000000-0000-0000-0000-000000000001"


EXPECTED_GOLDEN_THREATS = [
    {
        "display_id": "T-001",
        "rule_id": "T-08",
        "stride_category": "Tampering",
        "threat_subtype": "High-risk control message tampering",
        "severity": "Critical",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-002",
        "rule_id": "E-02",
        "stride_category": "Elevation of Privilege",
        "threat_subtype": "Privileged workflow abuse across boundary",
        "severity": "Critical",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-003",
        "rule_id": "S-01",
        "stride_category": "Spoofing",
        "threat_subtype": "Identity spoofing across trust boundary",
        "severity": "High",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-004",
        "rule_id": "S-03",
        "stride_category": "Spoofing",
        "threat_subtype": "High-value external actor spoofing",
        "severity": "High",
        "affected_node_ids": [NODE_CUSTOMER],
        "affected_edge_ids": [],
        "crosses_trust_boundary": False,
    },
    {
        "display_id": "T-005",
        "rule_id": "S-04",
        "stride_category": "Spoofing",
        "threat_subtype": "Unauthenticated process receives cross-boundary flow",
        "severity": "High",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-006",
        "rule_id": "T-01",
        "stride_category": "Tampering",
        "threat_subtype": "Data tampering in transit across boundary",
        "severity": "High",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-007",
        "rule_id": "T-05",
        "stride_category": "Tampering",
        "threat_subtype": "Missing input validation on external input",
        "severity": "High",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-008",
        "rule_id": "R-02",
        "stride_category": "Repudiation",
        "threat_subtype": "Weak auditability on critical workflow",
        "severity": "High",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-009",
        "rule_id": "I-01",
        "stride_category": "Information Disclosure",
        "threat_subtype": "Data exposure in transit across boundary",
        "severity": "High",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-010",
        "rule_id": "E-01",
        "stride_category": "Elevation of Privilege",
        "threat_subtype": "Privilege escalation via external access across boundary",
        "severity": "High",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-011",
        "rule_id": "E-06",
        "stride_category": "Elevation of Privilege",
        "threat_subtype": "Missing input validation on cross-boundary process",
        "severity": "High",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-012",
        "rule_id": "S-02",
        "stride_category": "Spoofing",
        "threat_subtype": "Spoofed data flow across boundary",
        "severity": "Medium",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-013",
        "rule_id": "R-01",
        "stride_category": "Repudiation",
        "threat_subtype": "Unaudited external entity interaction",
        "severity": "Medium",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
    {
        "display_id": "T-014",
        "rule_id": "D-01",
        "stride_category": "Denial of Service",
        "threat_subtype": "External entity flood attack on process",
        "severity": "Medium",
        "affected_node_ids": [NODE_CUSTOMER, NODE_PAYMENTS_API],
        "affected_edge_ids": [EDGE_CHECKOUT],
        "crosses_trust_boundary": True,
    },
]


def _build_golden_dfd() -> DFDResponse:
    return DFDResponse(
        nodes=[
            DFDNodeResponse(
                id=NODE_CUSTOMER,
                node_type="external_entity",
                name="Customer Browser",
                position_x=0,
                position_y=0,
                trust_boundary_id=None,
                properties={},
            ),
            DFDNodeResponse(
                id=NODE_PAYMENTS_API,
                node_type="process",
                name="Payments API",
                position_x=220,
                position_y=0,
                trust_boundary_id=BOUNDARY_PCI,
                properties={},
            ),
        ],
        edges=[
            DFDEdgeResponse(
                id=EDGE_CHECKOUT,
                source_node_id=NODE_CUSTOMER,
                target_node_id=NODE_PAYMENTS_API,
                label="checkout payment request with cardholder data",
                properties={},
            )
        ],
        trust_boundaries=[
            TrustBoundaryResponse(
                id=BOUNDARY_PCI,
                name="PCI Zone",
                node_ids=[NODE_PAYMENTS_API],
            )
        ],
    )


def _project_threat(threat: GeneratedThreat) -> dict[str, object]:
    return {
        "display_id": threat.display_id,
        "rule_id": threat.rule_id,
        "stride_category": threat.stride_category,
        "threat_subtype": threat.threat_subtype,
        "severity": threat.severity,
        "affected_node_ids": threat.affected_node_ids,
        "affected_edge_ids": threat.affected_edge_ids,
        "crosses_trust_boundary": threat.crosses_trust_boundary,
    }


def test_golden_pci_checkout_dfd_produces_stable_threat_set() -> None:
    result = evaluate_rules(_build_golden_dfd())

    assert result.warnings == []
    assert result.rules_evaluated == 68
    assert result.rules_fired == 14
    assert [_project_threat(threat) for threat in result.threats] == EXPECTED_GOLDEN_THREATS

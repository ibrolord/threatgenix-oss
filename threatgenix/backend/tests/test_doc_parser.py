
import pytest
from fastapi import HTTPException

from app.services.doc_parser import heuristic_parse_architecture
from app.services.document_ingestion import parse_uploaded_document


def test_heuristic_parse_architecture_infers_operational_flows_from_structured_sections() -> None:
    raw_text = """
System Name: SkyBridge Airways
Trust Boundary: Cloud Operations Platform Boundary
Contains:
- Operations Workflow Service [Process]
- Dispatch Release Service [Process]
- Crew Recovery Engine [Process]
- Maintenance Control Service [Process]
- Operational Messaging Service [Process]
- EFB Sync Service [Process]
- Turnaround Coordination Service [Process]

Trust Boundary: Aircraft and Crew Edge Boundary
Contains:
- Electronic Flight Bag Client [External Entity]
- ACARS / Satcom Messaging Provider [External Entity]
- Aircraft Health Feed [External Entity]

Trust Boundary: External Aviation Services Boundary
Contains:
- Weather Intelligence Provider [External Entity]
- MRO Vendor System [External Entity]
- Airport CDM Feed [External Entity]

Trust Boundary: Vendor Support and Security Boundary
Contains:
- Vendor Support Enclave [External Entity]

Privileged Workflows:
- Crew recovery manager reassigns pairings during disruptions under legality constraints.
- Vendor support operator receives time-boxed diagnostic access after airline approval.

Security Properties:
- EFB Sync Service: signed package manifest required before client synchronization
- Operational Messaging Service: message integrity checks for provider handoff acknowledgements

Abuse Cases To Consider:
- Tampered health-feed or MRO updates causing incorrect maintenance decisions
- False turnaround readiness causing unsafe departure pressure
"""

    result = heuristic_parse_architecture(raw_text)
    flow_triplets = {(flow.source, flow.target, flow.label) for flow in result.flows}

    assert (
        "Operations Workflow Service",
        "Crew Recovery Engine",
        "disruption recovery action",
    ) in flow_triplets
    assert (
        "Operational Messaging Service",
        "ACARS / Satcom Messaging Provider",
        "provider handoff acknowledgement",
    ) in flow_triplets
    assert (
        "EFB Sync Service",
        "Electronic Flight Bag Client",
        "signed package manifest",
    ) in flow_triplets
    assert (
        "Vendor Support Enclave",
        "Maintenance Control Service",
        "diagnostic access request",
    ) in flow_triplets
    assert (
        "Weather Intelligence Provider",
        "Dispatch Release Service",
        "weather and NOTAM package",
    ) in flow_triplets
    assert (
        "Aircraft Health Feed",
        "Maintenance Control Service",
        "aircraft health alert",
    ) in flow_triplets
    assert (
        "MRO Vendor System",
        "Maintenance Control Service",
        "maintenance recommendation upload",
    ) in flow_triplets


def test_heuristic_parse_architecture_normalizes_flow_label_artifacts() -> None:
    raw_text = """
System: NorthStar
Trust Boundary: Customer and Partner Edge
Contains:
- Open Banking Partner [External Entity]
- Payments Orchestrator [Process]

Data Flows:
- Payments Orchestrator -> Open Banking Partner: > : payment status callback
"""

    result = heuristic_parse_architecture(raw_text)

    assert len(result.flows) == 1
    assert result.flows[0].label == "payment status callback"


def test_heuristic_parse_architecture_recovers_records_retention_anchor_from_narrative() -> None:
    raw_text = """
SkyBridge Airways keeps core identity, privileged access management, records retention,
and several system-of-record databases on premises while workflow applications run in a
primary public cloud tenant. Auditors have repeatedly flagged that immutable operational
records are not consistently threat-modeled during exception handling.
"""

    result = heuristic_parse_architecture(raw_text)
    component_names = {component.name for component in result.components}

    assert "Records Retention Vault" in component_names


def test_heuristic_parse_architecture_recovers_analytics_workloads_anchor_from_narrative() -> None:
    raw_text = """
SkyBridge Airways keeps several system-of-record databases on premises while workflow
applications, API mediation, rules processing, and analytics workloads run in a primary
    public cloud tenant. Dispatch planning and maintenance control depend on operational truth
    and status updates staying separate during exception handling.
"""

    result = heuristic_parse_architecture(raw_text)
    components = {component.name: component for component in result.components}

    assert "Analytics Workloads" in components
    assert components["Analytics Workloads"].component_type == "process"


def test_heuristic_parse_architecture_recovers_vendor_support_anchor_from_narrative() -> None:
    raw_text = """
SkyBridge Airways routes maintenance and dispatch decisions through the Maintenance
Control Platform and a flight operations control platform while vendor support providers
can join time-boxed diagnostic sessions after airline approval for urgent issues.
Maintenance Control Platform remains responsible for authorizing the diagnostic access
request.
"""

    result = heuristic_parse_architecture(raw_text)
    component_names = {component.name for component in result.components}
    flow_triplets = {(flow.source, flow.target, flow.label) for flow in result.flows}

    assert "Vendor Support Enclave" in component_names
    assert (
        "Vendor Support Enclave",
        "Maintenance Control Platform",
        "diagnostic access request",
    ) in flow_triplets


# ---- S-20: file upload size limit ----

class _FakeUploadFile:
    """Minimal UploadFile stand-in for testing parse_uploaded_document."""

    def __init__(self, filename: str, content_type: str, data: bytes) -> None:
        self.filename = filename
        self.content_type = content_type
        self._data = data

    async def read(self) -> bytes:
        return self._data


@pytest.mark.asyncio
async def test_parse_uploaded_document_rejects_oversized_file() -> None:
    """S-20: files exceeding max_upload_mb must return 413 before parsing."""
    from app.config import settings

    oversized = b"x" * (settings.max_upload_mb * 1024 * 1024 + 1)
    fake_file = _FakeUploadFile("big.pdf", "application/pdf", oversized)

    with pytest.raises(HTTPException) as exc_info:
        await parse_uploaded_document(fake_file)  # type: ignore[arg-type]

    assert exc_info.value.status_code == 413
    assert str(settings.max_upload_mb) in exc_info.value.detail


@pytest.mark.asyncio
async def test_parse_uploaded_document_accepts_file_within_limit() -> None:
    """S-20: files below max_upload_mb must not be rejected for size reasons."""

    # Build a tiny "file" — let it fail on PDF validation (400), not size (413)
    tiny = b"not a real pdf"
    fake_file = _FakeUploadFile("small.pdf", "application/pdf", tiny)

    with pytest.raises(HTTPException) as exc_info:
        await parse_uploaded_document(fake_file)  # type: ignore[arg-type]

    # Must fail for content reasons, NOT for size
    assert exc_info.value.status_code != 413

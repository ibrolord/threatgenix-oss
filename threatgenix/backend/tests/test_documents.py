"""Tests for document upload endpoint (F-02)."""

import io
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.services.auth import get_current_user
from app.services.document_ingestion import ParsedUploadedDocument
from app.schemas.document import (
    ExtractionOutcome,
    DocumentParseResult,
    ParsedBoundary,
    ParsedComponent,
    ParsedFlow,
)

BASE_URL = "http://test"


async def override_get_db():
    yield AsyncMock()


FAKE_USER_ID = uuid.uuid4()


class FakeUser:
    id = FAKE_USER_ID
    email = "test@example.com"
    full_name = "Test User"
    role = "admin"
    is_active = True


async def override_get_current_user():
    return FakeUser()


app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user


def _api_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/documents"


class FakeThreatModel:
    def __init__(self, id=None, system_name="Test System"):
        self.id = id or uuid.uuid4()
        self.system_name = system_name
        self.description = ""
        self.data_classification = "Internal"
        self.owner_id = FAKE_USER_ID
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _apply_overrides():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user


def _make_fake_parse_result() -> DocumentParseResult:
    return DocumentParseResult(
        components=[
            ParsedComponent(name="API Gateway", component_type="process", confidence=0.9, description="Gateway"),
            ParsedComponent(name="User DB", component_type="data_store", confidence=0.85, description="Database"),
        ],
        flows=[
            ParsedFlow(source="API Gateway", target="User DB", label="query", confidence=0.8),
        ],
        boundaries=[
            ParsedBoundary(name="DMZ", contains=["API Gateway"]),
        ],
        raw_text_excerpt="Sample text...",
    )


def _make_fake_extraction_outcome(
    *,
    parse_result: DocumentParseResult | None = None,
    extraction_status: str = "complete",
    warnings: list[str] | None = None,
) -> ExtractionOutcome:
    return ExtractionOutcome(
        parse_result=parse_result or _make_fake_parse_result(),
        extraction_status=extraction_status,
        warnings=warnings or [],
    )


def _make_simple_pdf_bytes() -> bytes:
    """Create a minimal valid PDF using PyMuPDF."""
    import fitz

    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Test document content for threat modeling.")
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


def _make_vector_diagram_pdf_bytes() -> bytes:
    """Create a small vector-based architecture diagram for deterministic extraction tests."""
    import fitz

    doc = fitz.open()
    page = doc.new_page()
    left = fitz.Rect(60, 60, 220, 120)
    right = fitz.Rect(300, 60, 460, 120)
    shape = page.new_shape()
    shape.draw_rect(left)
    shape.draw_rect(right)
    shape.draw_line((220, 90), (300, 90))
    shape.finish(color=(0, 0, 0), fill=None, width=1)
    shape.commit()
    page.insert_textbox(left, "API Gateway", fontsize=12, align=1)
    page.insert_textbox(right, "User DB", fontsize=12, align=1)
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


def _make_raster_diagram_pdf_bytes() -> bytes:
    """Create a small rasterized architecture diagram for OCR-backed extraction tests."""
    import fitz
    image_bytes = io.BytesIO(_make_raster_diagram_png_bytes())

    doc = fitz.open()
    page = doc.new_page(width=600, height=220)
    page.insert_image(fitz.Rect(0, 0, 600, 200), stream=image_bytes.getvalue())
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


def _make_png_bytes() -> bytes:
    from PIL import Image

    image = Image.new("RGB", (120, 80), "white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _make_raster_diagram_png_bytes() -> bytes:
    from PIL import Image, ImageDraw

    image = Image.new("RGB", (600, 200), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((40, 40, 220, 120), outline="black", width=3)
    draw.rectangle((360, 40, 540, 120), outline="black", width=3)
    draw.line((220, 80, 360, 80), fill="black", width=3)
    draw.text((85, 65), "API Gateway", fill="black")
    draw.text((430, 65), "User DB", fill="black")

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _make_docx_bytes(*, text: str, embedded_images: list[bytes] | None = None) -> bytes:
    import zipfile

    buffer = io.BytesIO()
    document_xml = f"""<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
    <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">
      <w:body>
        <w:p><w:r><w:t>{text}</w:t></w:r></w:p>
      </w:body>
    </w:document>
    """.encode("utf-8")

    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"></Types>")
        archive.writestr("_rels/.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"></Relationships>")
        archive.writestr("word/document.xml", document_xml)
        archive.writestr("word/_rels/document.xml.rels", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"></Relationships>")
        for index, image_bytes in enumerate(embedded_images or [], start=1):
            archive.writestr(f"word/media/image{index}.png", image_bytes)

    return buffer.getvalue()


@pytest.mark.asyncio
async def test_upload_valid_pdf_returns_201():
    """Upload a valid PDF -> 201 with parse result."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_parse = _make_fake_extraction_outcome()
    pdf_bytes = _make_simple_pdf_bytes()

    fake_doc_id = uuid.uuid4()

    # Build a mock DB that assigns an id when add() is called
    mock_db = AsyncMock()
    mock_db.add = MagicMock(side_effect=lambda obj: setattr(obj, "id", fake_doc_id))

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch("app.api.documents.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
        patch(
            "app.api.documents.parse_uploaded_document",
            new_callable=AsyncMock,
            return_value=ParsedUploadedDocument(
                file_bytes=pdf_bytes,
                filename="test.pdf",
                file_kind="pdf",
                page_count=1,
                raw_text="Test document content",
                diagram_pages=[],
                diagram_artifacts=[],
                diagram_parse_result=DocumentParseResult(components=[], flows=[], boundaries=[], raw_text_excerpt=""),
            ),
        ),
        patch("app.api.documents.extract_components_from_text", new_callable=AsyncMock, return_value=fake_parse),
        patch("app.api.documents.generate_dfd_from_parse_result", new_callable=AsyncMock),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                _api_url(tm_id),
                files={"file": ("test.pdf", io.BytesIO(pdf_bytes), "application/pdf")},
            )

    # Reset override
    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 201
    body = response.json()
    assert body["filename"] == "test.pdf"
    assert body["page_count"] == 1
    assert len(body["parse_result"]["components"]) == 2
    assert len(body["parse_result"]["flows"]) == 1
    assert len(body["parse_result"]["boundaries"]) == 1
    assert body["extraction_status"] == "complete"
    assert body["warnings"] == []
    assert body["evidence"]["component_count"] == 2
    assert body["evidence"]["flow_count"] == 1
    assert body["evidence"]["boundary_count"] == 1
    assert body["evidence"]["diagram_pages"] == []
    assert body["evidence"]["diagram_artifacts"] == []
    assert body["evidence"]["raw_text_excerpt"] == "Sample text..."


@pytest.mark.asyncio
async def test_upload_threat_model_not_found_returns_404():
    """Upload to non-existent threat model -> 404."""
    tm_id = uuid.uuid4()

    with patch("app.api.documents.get_threat_model", new_callable=AsyncMock, return_value=None):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                _api_url(tm_id),
                files={"file": ("test.pdf", io.BytesIO(b"fake"), "application/pdf")},
            )

    assert response.status_code == 404
    assert response.json()["detail"] == "Threat model not found"


@pytest.mark.asyncio
async def test_upload_unsupported_file_returns_400():
    """Upload an unsupported file -> 400 from the ingestion layer."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)

    from fastapi import HTTPException

    async def mock_parse_uploaded_document(file):
        raise HTTPException(status_code=400, detail="Unsupported file type.")

    with (
        patch("app.api.documents.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
        patch("app.api.documents.parse_uploaded_document", side_effect=mock_parse_uploaded_document),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                _api_url(tm_id),
                files={"file": ("readme.txt", io.BytesIO(b"not a pdf"), "text/plain")},
            )

    assert response.status_code == 400
    assert "Unsupported file type" in response.json()["detail"]


@pytest.mark.asyncio
async def test_validate_pdf_rejects_non_pdf():
    """Unit test: validate_pdf raises 400 for non-PDF bytes."""
    from unittest.mock import AsyncMock as AM

    from app.services.doc_parser import validate_pdf

    fake_file = AM()
    fake_file.read = AsyncMock(return_value=b"this is not a PDF file at all")
    fake_file.filename = "bad.txt"

    with pytest.raises(Exception) as exc_info:
        await validate_pdf(fake_file)
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_validate_pdf_accepts_valid_pdf():
    """Unit test: validate_pdf accepts a real PDF and returns bytes + page count."""
    from app.services.doc_parser import validate_pdf

    pdf_bytes = _make_simple_pdf_bytes()

    fake_file = AsyncMock()
    fake_file.read = AsyncMock(return_value=pdf_bytes)
    fake_file.filename = "test.pdf"

    result_bytes, page_count = await validate_pdf(fake_file)
    assert result_bytes == pdf_bytes
    assert page_count == 1


@pytest.mark.asyncio
async def test_parse_uploaded_document_accepts_docx_with_embedded_diagram():
    from fastapi import UploadFile

    from app.services.document_ingestion import parse_uploaded_document

    docx_bytes = _make_docx_bytes(
        text="System design technical specification for payments and identity.",
        embedded_images=[_make_raster_diagram_png_bytes()],
    )
    file = UploadFile(filename="design.docx", file=io.BytesIO(docx_bytes))

    result = await parse_uploaded_document(file)

    assert result.file_kind == "docx"
    assert result.page_count == 1
    assert "technical specification" in result.raw_text.lower()
    assert result.diagram_artifacts == ["embedded image 1"]
    assert {"API Gateway", "User DB"} <= {component.name for component in result.diagram_parse_result.components}


@pytest.mark.asyncio
async def test_parse_uploaded_document_accepts_image_diagram():
    from fastapi import UploadFile

    from app.services.document_ingestion import parse_uploaded_document

    image = _make_raster_diagram_png_bytes()
    file = UploadFile(filename="diagram.png", file=io.BytesIO(image))

    result = await parse_uploaded_document(file)

    assert result.file_kind == "image"
    assert result.page_count == 1
    assert result.diagram_artifacts == ["uploaded image"]
    assert {"API Gateway", "User DB"} <= {component.name for component in result.diagram_parse_result.components}


@pytest.mark.asyncio
async def test_parse_uploaded_document_accepts_image_by_content_type_without_extension():
    from fastapi import UploadFile

    from app.services.document_ingestion import parse_uploaded_document

    image = _make_raster_diagram_png_bytes()
    file = UploadFile(
        filename="architecture-diagram",
        file=io.BytesIO(image),
        headers={"content-type": "image/png"},
    )

    result = await parse_uploaded_document(file)

    assert result.file_kind == "image"
    assert result.diagram_artifacts == ["uploaded image"]
    assert {"API Gateway", "User DB"} <= {component.name for component in result.diagram_parse_result.components}


@pytest.mark.asyncio
async def test_upload_empty_parse_result_preserves_existing_dfd():
    """Empty extraction results should fail the upload instead of wiping the DFD."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    pdf_bytes = _make_simple_pdf_bytes()
    empty_parse = DocumentParseResult(
        components=[],
        flows=[],
        boundaries=[],
        raw_text_excerpt="",
    )

    mock_db = AsyncMock()
    mock_db.add = MagicMock()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch("app.api.documents.get_threat_model", new_callable=AsyncMock, return_value=fake_tm),
        patch("app.api.documents.get_llm_client_for_user_async", new_callable=AsyncMock, return_value=object()),
        patch(
            "app.api.documents.parse_uploaded_document",
            new_callable=AsyncMock,
            return_value=ParsedUploadedDocument(
                file_bytes=pdf_bytes,
                filename="test.pdf",
                file_kind="pdf",
                page_count=1,
                raw_text="Test document content",
                diagram_pages=[],
                diagram_artifacts=[],
                diagram_parse_result=DocumentParseResult(components=[], flows=[], boundaries=[], raw_text_excerpt=""),
            ),
        ),
        patch(
            "app.api.documents.extract_components_from_text",
            new_callable=AsyncMock,
            return_value=ExtractionOutcome(
                parse_result=empty_parse,
                extraction_status="partial",
                warnings=["No data flows were extracted."],
            ),
        ),
        patch("app.api.documents.generate_dfd_from_parse_result", new_callable=AsyncMock) as mock_generate_dfd,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                _api_url(tm_id),
                files={"file": ("test.pdf", io.BytesIO(pdf_bytes), "application/pdf")},
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 422
    assert "Existing DFD was left unchanged" in response.json()["detail"]
    mock_db.add.assert_called_once()
    mock_db.commit.assert_awaited()
    mock_generate_dfd.assert_not_awaited()


def test_extract_text_from_pdf():
    """Unit test: extract_text_from_pdf returns text from PDF."""
    from app.services.doc_parser import extract_text_from_pdf

    pdf_bytes = _make_simple_pdf_bytes()
    text = extract_text_from_pdf(pdf_bytes)
    assert "Test document content" in text


def test_extract_diagram_parse_result_detects_vector_components():
    from app.services.diagram_extraction import extract_diagram_parse_result

    pdf_bytes = _make_vector_diagram_pdf_bytes()
    diagram_pages, parse_result = extract_diagram_parse_result(pdf_bytes)

    component_names = {component.name for component in parse_result.components}
    flow_pairs = {(flow.source, flow.target) for flow in parse_result.flows}

    assert diagram_pages == [1]
    assert {"API Gateway", "User DB"} <= component_names
    assert ("API Gateway", "User DB") in flow_pairs
    assert all(component.extraction_source == "diagram" for component in parse_result.components)


def test_extract_diagram_parse_result_detects_raster_components_and_connector():
    from app.services.diagram_extraction import (
        extract_diagram_parse_result,
        raster_ocr_available,
    )

    if not raster_ocr_available():
        pytest.skip("RapidOCR not available")

    pdf_bytes = _make_raster_diagram_pdf_bytes()
    diagram_pages, parse_result = extract_diagram_parse_result(pdf_bytes)

    component_names = {component.name for component in parse_result.components}
    flow_pairs = {(flow.source, flow.target) for flow in parse_result.flows}

    assert diagram_pages == [1]
    assert {"API Gateway", "User DB"} <= component_names
    assert ("API Gateway", "User DB") in flow_pairs
    assert any(component.extraction_source == "diagram_ocr" for component in parse_result.components)


@pytest.mark.asyncio
async def test_extract_components_from_text_uses_structured_heuristics_when_ai_fails():
    """Structured architecture text should parse without a working LLM call."""
    from app.services.ai_extraction import extract_components_from_text

    class FakeClient:
        def call_with_tools(self, **kwargs):
            return None

    raw_text = """
    System: NorthStar Omnichannel Payments Platform
    Trust Boundary: Customer and Partner Edge
    Contains:
    - Consumer Mobile App [external_entity]
    - Open Banking Partner [external_entity]
    - API Gateway [process]
    Trust Boundary: Restricted Data Zone
    Contains:
    - Core Banking Ledger [data_store]
    Data Flows:
    - Consumer Mobile App -> API Gateway: OAuth2 + payment initiation
    - API Gateway -> Core Banking Ledger: posting and balance update
    """

    outcome = await extract_components_from_text(
        raw_text=raw_text,
        system_name="NorthStar",
        client=FakeClient(),
    )
    result = outcome.parse_result

    component_names = {component.name for component in result.components}
    assert {"Consumer Mobile App", "Open Banking Partner", "API Gateway", "Core Banking Ledger"} <= component_names
    assert len(result.flows) == 2
    assert len(result.boundaries) == 2
    assert outcome.extraction_status == "complete"


@pytest.mark.asyncio
async def test_extract_components_from_text_uses_narrative_heuristics_when_ai_fails():
    """Narrative text should still yield a repairable component set."""
    from app.services.ai_extraction import extract_components_from_text

    class FakeClient:
        def call_with_tools(self, **kwargs):
            return None

    raw_text = """
    NorthStar Bank routes requests through the API Gateway into the Payments Orchestrator.
    The orchestrator invokes the Fraud Scoring Engine and AML Screening Service before
    sending items to the SWIFT Connector and Core Banking Ledger. Treasury Portal User
    approvals and Open Banking Partner requests also reach the API Gateway.
    """

    outcome = await extract_components_from_text(
        raw_text=raw_text,
        system_name="NorthStar",
        client=FakeClient(),
    )
    result = outcome.parse_result

    component_names = {component.name for component in result.components}
    assert "API Gateway" in component_names
    assert "Payments Orchestrator" in component_names
    assert "Fraud Scoring Engine" in component_names
    assert "SWIFT Connector" in component_names
    assert "Open Banking Partner" in component_names
    assert "Treasury Portal User" in component_names
    assert len(result.flows) > 0


@pytest.mark.asyncio
async def test_extract_components_from_text_accepts_mixed_case_structured_types():
    """Structured component bullets with display-case types should still parse."""
    from app.services.ai_extraction import extract_components_from_text

    class FakeClient:
        def call_with_tools(self, **kwargs):
            return None

    raw_text = """
    Trust Boundary: Cloud Operations Platform Boundary
    Contains:
    - API Gateway [Process]
    - Audit and Decision Log [Data Store]
    - Electronic Flight Bag Client [External Entity]
    """

    outcome = await extract_components_from_text(
        raw_text=raw_text,
        system_name="SkyBridge",
        client=FakeClient(),
    )

    component_types = {component.name: component.component_type for component in outcome.parse_result.components}
    assert component_types["API Gateway"] == "process"
    assert component_types["Audit and Decision Log"] == "data_store"
    assert component_types["Electronic Flight Bag Client"] == "external_entity"
    assert len(outcome.parse_result.boundaries) == 1


@pytest.mark.asyncio
async def test_extract_components_from_text_marks_partial_when_flows_missing():
    """A component-only extraction should be marked partial with warnings."""
    from app.services.ai_extraction import extract_components_from_text

    class FakeClient:
        def call_with_tools(self, **kwargs):
            return None

    raw_text = """
    Trust Boundary: Vendor Support and Security Boundary
    Contains:
    - Vendor Support Enclave [External Entity]
    - Privileged Access Broker [Process]
    """

    outcome = await extract_components_from_text(
        raw_text=raw_text,
        system_name="SkyBridge",
        client=FakeClient(),
    )

    assert outcome.extraction_status == "partial"
    assert any("No data flows" in warning for warning in outcome.warnings)


@pytest.mark.asyncio
async def test_extract_components_from_text_runs_focused_flow_pass_when_coverage_is_sparse():
    """Large structured systems with sparse external flows should trigger the flow-only pass."""
    from app.services.ai_extraction import extract_components_from_text

    class FakeClient:
        def __init__(self) -> None:
            self.calls = 0

        def call_with_tools(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return {
                    "components": [
                        {"name": "Federated Identity Service", "component_type": "process", "confidence": 0.9, "description": "Identity broker"},
                        {"name": "API Gateway", "component_type": "process", "confidence": 0.9, "description": "Ingress"},
                        {"name": "Operations Workflow Service", "component_type": "process", "confidence": 0.9, "description": "Workflow"},
                        {"name": "Dispatch Release Service", "component_type": "process", "confidence": 0.9, "description": "Dispatch decisions"},
                        {"name": "Maintenance Control Service", "component_type": "process", "confidence": 0.9, "description": "Maintenance decisions"},
                        {"name": "Turnaround Coordination Service", "component_type": "process", "confidence": 0.9, "description": "Turnaround state"},
                        {"name": "EFB Sync Service", "component_type": "process", "confidence": 0.9, "description": "Crew sync"},
                        {"name": "Aircraft Health Feed", "component_type": "external_entity", "confidence": 0.9, "description": "Aircraft telemetry"},
                        {"name": "Weather Intelligence Provider", "component_type": "external_entity", "confidence": 0.9, "description": "Weather"},
                        {"name": "Electronic Flight Bag Client", "component_type": "external_entity", "confidence": 0.9, "description": "Crew client"},
                    ],
                    "flows": [
                        {
                            "source": "Federated Identity Service",
                            "target": "API Gateway",
                            "label": "authentication request",
                            "confidence": 0.8,
                            "data_types": ["credentials"],
                        }
                    ],
                    "boundaries": [],
                }
            return {
                "flows": [
                    {
                        "source": "Weather Intelligence Provider",
                        "target": "Dispatch Release Service",
                        "label": "weather and NOTAM package",
                        "confidence": 0.8,
                        "data_types": ["public"],
                    },
                    {
                        "source": "Aircraft Health Feed",
                        "target": "Maintenance Control Service",
                        "label": "aircraft health alert",
                        "confidence": 0.8,
                        "data_types": ["config"],
                    },
                    {
                        "source": "EFB Sync Service",
                        "target": "Electronic Flight Bag Client",
                        "label": "dispatch release package",
                        "confidence": 0.8,
                        "data_types": ["config"],
                    },
                ]
            }

    raw_text = """
    Trust Boundary: Cloud Operations Platform Boundary
    Contains:
    - Federated Identity Service [Process]
    - API Gateway [Process]
    - Operations Workflow Service [Process]
    - Dispatch Release Service [Process]
    - Maintenance Control Service [Process]
    - Turnaround Coordination Service [Process]
    - EFB Sync Service [Process]
    Trust Boundary: External Aviation Services Boundary
    Contains:
    - Aircraft Health Feed [External Entity]
    - Weather Intelligence Provider [External Entity]
    - Electronic Flight Bag Client [External Entity]
    Privileged Workflows:
    - Dispatchers review weather, maintenance, and turnaround state before release.
    - EFB Sync Service publishes release packages to pilot devices.
    - Maintenance Control Service consumes aircraft health alerts.
    """

    client = FakeClient()
    outcome = await extract_components_from_text(
        raw_text=raw_text,
        system_name="SkyBridge",
        client=client,
    )

    flow_pairs = {
        (flow.source, flow.target)
        for flow in outcome.parse_result.flows
    }
    assert ("Weather Intelligence Provider", "Dispatch Release Service") in flow_pairs
    assert ("Aircraft Health Feed", "Maintenance Control Service") in flow_pairs
    assert ("EFB Sync Service", "Electronic Flight Bag Client") in flow_pairs
    assert client.calls == 2


@pytest.mark.asyncio
async def test_extract_components_from_text_sanitizes_narrative_pseudo_components():
    """Narrative extraction should drop location and flow-label pseudo-components."""
    from app.services.ai_extraction import extract_components_from_text

    class FakeClient:
        def call_with_tools(self, **kwargs):
            return {
                "components": [
                    {
                        "name": "on-premises data centers",
                        "component_type": "process",
                        "confidence": 0.8,
                        "description": "Location where core identity, privileged access management, records retention, and several system-of-record databases are hosted.",
                    },
                    {
                        "name": "public cloud tenant",
                        "component_type": "process",
                        "confidence": 0.8,
                        "description": "Primary location where workflow applications, API mediation, rules processing, and analytics workloads run.",
                    },
                    {
                        "name": "weather data",
                        "component_type": "data_store",
                        "confidence": 0.7,
                        "description": "Data related to weather conditions.",
                    },
                    {
                        "name": "crew operational messaging",
                        "component_type": "external_entity",
                        "confidence": 0.7,
                        "description": "External entities providing crew operational messaging.",
                    },
                    {
                        "name": "EFB synchronization service",
                        "component_type": "process",
                        "confidence": 0.82,
                        "description": "Short-form alias from the narrative.",
                    },
                    {
                        "name": "Electronic Flight Bag (EFB) synchronization service",
                        "component_type": "process",
                        "confidence": 0.9,
                        "description": "Canonical crew-package delivery service.",
                    },
                    {
                        "name": "flight crews",
                        "component_type": "external_entity",
                        "confidence": 0.88,
                        "description": "Airline flight crews.",
                    },
                    {
                        "name": "Records Retention Vault",
                        "component_type": "data_store",
                        "confidence": 0.85,
                        "description": "Recovered retained operational evidence store.",
                    },
                    {
                        "name": "Safety Investigation Workspace",
                        "component_type": "process",
                        "confidence": 0.83,
                        "description": "Recovered investigation workflow.",
                    },
                ],
                "flows": [
                    {
                        "source": "on-premises data centers",
                        "target": "public cloud tenant",
                        "label": "core identity and privileged access management data",
                        "confidence": 0.8,
                        "data_types": [],
                    },
                    {
                        "source": "EFB synchronization service",
                        "target": "flight crews",
                        "label": "dispatch releases, notices, and aircraft-specific status packages",
                        "confidence": 0.85,
                        "data_types": [],
                    },
                    {
                        "source": "Safety Investigation Workspace",
                        "target": "Records Retention Vault",
                        "label": "safety investigation data",
                        "confidence": 0.77,
                        "data_types": ["audit_log"],
                    },
                ],
                "boundaries": [
                    {
                        "name": "Internal Network",
                        "contains": [
                            "on-premises data centers",
                            "public cloud tenant",
                            "Records Retention Vault",
                            "Safety Investigation Workspace",
                        ],
                    },
                    {
                        "name": "Aircraft and Crew Edge Boundary",
                        "contains": [
                            "EFB synchronization service",
                            "flight crews",
                            "crew operational messaging",
                        ],
                    },
                ],
            }

    raw_text = """
    SkyBridge Airways keeps core identity, privileged access management, records retention,
    and several system-of-record databases on premises in airline data centers. Workflow
    applications, API mediation, rules processing, and analytics workloads run in a primary
    public cloud tenant with a warm standby region. Flight crews receive dispatch releases,
    notices, and aircraft-specific status packages through the Electronic Flight Bag (EFB)
    synchronization service. Safety investigators retrieve immutable decision records from
    the records retention vault.
    """

    outcome = await extract_components_from_text(
        raw_text=raw_text,
        system_name="SkyBridge",
        client=FakeClient(),
    )

    result = outcome.parse_result
    component_names = {component.name for component in result.components}
    flow_pairs = {(flow.source, flow.target, flow.label) for flow in result.flows}
    boundary_membership = {
        boundary.name: set(boundary.contains)
        for boundary in result.boundaries
    }

    assert "on-premises data centers" not in component_names
    assert "public cloud tenant" not in component_names
    assert "weather data" not in component_names
    assert "crew operational messaging" not in component_names
    assert "EFB synchronization service" not in component_names
    assert "Electronic Flight Bag (EFB) synchronization service" in component_names
    assert "Records Retention Vault" in component_names
    assert "Safety Investigation Workspace" in component_names
    assert (
        "Electronic Flight Bag (EFB) synchronization service",
        "flight crews",
        "dispatch releases, notices, and aircraft-specific status packages",
    ) in flow_pairs
    assert (
        "Safety Investigation Workspace",
        "Records Retention Vault",
        "safety investigation data",
    ) in flow_pairs
    assert not any(
        source == "on-premises data centers" or target == "public cloud tenant"
        for source, target, _ in flow_pairs
    )
    assert "Internal Network" in boundary_membership
    assert "on-premises data centers" not in boundary_membership["Internal Network"]
    assert "public cloud tenant" not in boundary_membership["Internal Network"]


def test_supplement_sparse_boundaries_adds_inferred_narrative_zones():
    """Sparse narrative zoning should be supplemented instead of left at one boundary."""
    from app.services.doc_parser import supplement_sparse_boundaries

    raw_text = """
    SkyBridge Airways relies on airport station teams and contracted ground handlers to
    publish turnaround updates through partner APIs while dispatchers coordinate with
    maintenance control. Weather providers and flight-plan optimization providers feed
    external operational data, and vendor support providers can join diagnostic sessions
    for urgent issues.
    """
    parse_result = DocumentParseResult(
        components=[
            ParsedComponent(name="Electronic Flight Bag (EFB) synchronization service", component_type="process", confidence=0.9, description=""),
            ParsedComponent(name="Maintenance Control Platform", component_type="process", confidence=0.9, description=""),
            ParsedComponent(name="Flight Operations and Maintenance Control Platform", component_type="process", confidence=0.9, description=""),
            ParsedComponent(name="Airport station teams", component_type="external_entity", confidence=0.8, description=""),
            ParsedComponent(name="Contracted ground handlers", component_type="external_entity", confidence=0.8, description=""),
            ParsedComponent(name="Partner APIs", component_type="process", confidence=0.8, description=""),
            ParsedComponent(name="Weather providers", component_type="external_entity", confidence=0.8, description=""),
            ParsedComponent(name="Flight-plan optimization providers", component_type="external_entity", confidence=0.8, description=""),
            ParsedComponent(name="Vendor-support personnel", component_type="external_entity", confidence=0.8, description=""),
            ParsedComponent(name="Vendor support providers", component_type="external_entity", confidence=0.8, description=""),
        ],
        flows=[],
        boundaries=[
            ParsedBoundary(
                name="Application Control Plane",
                contains=[
                    "Electronic Flight Bag (EFB) synchronization service",
                    "Maintenance Control Platform",
                    "Flight Operations and Maintenance Control Platform",
                ],
            )
        ],
        raw_text_excerpt=raw_text[:500],
    )

    supplemented = supplement_sparse_boundaries(raw_text, parse_result)
    boundary_names = {boundary.name for boundary in supplemented.boundaries}
    assert "Application Control Plane" in boundary_names
    assert "Airport and Station Operations Boundary" in boundary_names
    assert "External Aviation Services Boundary" in boundary_names
    assert "Vendor Support and Security Boundary" in boundary_names


@pytest.mark.asyncio
async def test_extract_components_from_text_supplements_sparse_boundaries_after_merge():
    """AI-added components should trigger supplemental boundary coverage after merge."""
    from app.services.ai_extraction import extract_components_from_text

    class FakeClient:
        def __init__(self) -> None:
            self.calls = 0

        def call_with_tools(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return {
                    "components": [
                        {"name": "Airport station teams", "component_type": "external_entity", "confidence": 0.9, "description": "Airport staff"},
                        {"name": "Contracted ground handlers", "component_type": "external_entity", "confidence": 0.9, "description": "Ground operations"},
                        {"name": "Weather providers", "component_type": "external_entity", "confidence": 0.9, "description": "Weather data"},
                        {"name": "Vendor support providers", "component_type": "external_entity", "confidence": 0.9, "description": "Vendor support"},
                    ],
                    "flows": [],
                    "boundaries": [
                        {
                            "name": "Application Control Plane",
                            "contains": ["Maintenance Control Platform"],
                        }
                    ],
                }
            return {"flows": []}

    raw_text = """
    SkyBridge Airways routes release decisions through the Maintenance Control Platform,
    Flight Operations and Maintenance Control Platform, and Electronic Flight Bag (EFB)
    synchronization service while dispatch teams manage airport turnaround pressure.
    """

    outcome = await extract_components_from_text(
        raw_text=raw_text,
        system_name="SkyBridge",
        client=FakeClient(),
    )

    boundary_names = {boundary.name for boundary in outcome.parse_result.boundaries}
    assert "Application Control Plane" in boundary_names
    assert len(boundary_names) >= 2
    assert not any(
        "trust boundaries were extracted" in warning.lower()
        for warning in outcome.warnings
    )

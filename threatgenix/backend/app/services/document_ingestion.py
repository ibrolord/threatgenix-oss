"""Normalize supported uploaded documents into a common extraction input."""

from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import Path
import re
import zipfile
import xml.etree.ElementTree as ET

from fastapi import HTTPException, UploadFile
import fitz
from PIL import Image, UnidentifiedImageError

from app.config import settings
from app.schemas.document import DocumentParseResult, ParsedBoundary, ParsedComponent, ParsedFlow
from app.services.diagram_extraction import extract_diagram_parse_result
from app.services.doc_parser import extract_text_from_pdf, normalize_extracted_text

SUPPORTED_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp"}
SUPPORTED_DOCUMENT_SUFFIXES = {".pdf", ".docx", *SUPPORTED_IMAGE_SUFFIXES}
PDF_MIME_TYPES = {"application/pdf"}
DOCX_MIME_TYPES = {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
IMAGE_MIME_TYPES = {"image/png", "image/jpeg", "image/webp"}


@dataclass(slots=True)
class ParsedUploadedDocument:
    file_bytes: bytes
    filename: str
    file_kind: str
    page_count: int
    raw_text: str
    diagram_pages: list[int]
    diagram_artifacts: list[str]
    diagram_parse_result: DocumentParseResult


async def parse_uploaded_document(file: UploadFile) -> ParsedUploadedDocument:
    """Validate and normalize a supported upload into text and diagram evidence."""
    filename = file.filename or "untitled"
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    max_bytes = settings.max_upload_mb * 1024 * 1024
    if len(file_bytes) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is {settings.max_upload_mb} MB.",
        )

    file_kind = _detect_file_kind(filename, file.content_type)

    if file_kind == "pdf":
        page_count = _validate_pdf_bytes(file_bytes)
        diagram_pages, diagram_parse_result = extract_diagram_parse_result(file_bytes)
        diagram_artifacts = [f"page {page}" for page in diagram_pages]
        raw_text = _combine_text_with_diagram_evidence(
            extract_text_from_pdf(file_bytes),
            diagram_parse_result,
        )
        return ParsedUploadedDocument(
            file_bytes=file_bytes,
            filename=filename,
            file_kind="pdf",
            page_count=page_count,
            raw_text=raw_text,
            diagram_pages=diagram_pages,
            diagram_artifacts=diagram_artifacts,
            diagram_parse_result=diagram_parse_result,
        )

    if file_kind == "docx":
        _validate_docx_bytes(file_bytes)
        raw_text = extract_text_from_docx(file_bytes)
        page_count = count_docx_logical_pages(file_bytes)
        if page_count > settings.pdf_max_pages:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Document exceeds maximum of {settings.pdf_max_pages} logical pages "
                    f"(got {page_count})."
                ),
            )
        diagram_parse_result, diagram_artifacts = extract_docx_diagram_parse_result(file_bytes)
        raw_text = _combine_text_with_diagram_evidence(raw_text, diagram_parse_result)
        return ParsedUploadedDocument(
            file_bytes=file_bytes,
            filename=filename,
            file_kind="docx",
            page_count=page_count,
            raw_text=raw_text,
            diagram_pages=[],
            diagram_artifacts=diagram_artifacts,
            diagram_parse_result=diagram_parse_result,
        )

    if file_kind == "image":
        _validate_image_bytes(file_bytes)
        diagram_parse_result = extract_image_diagram_parse_result(file_bytes)
        has_diagram_evidence = bool(diagram_parse_result.components or diagram_parse_result.flows)
        raw_text = _combine_text_with_diagram_evidence("", diagram_parse_result)
        return ParsedUploadedDocument(
            file_bytes=file_bytes,
            filename=filename,
            file_kind="image",
            page_count=1,
            raw_text=raw_text,
            diagram_pages=[1] if has_diagram_evidence else [],
            diagram_artifacts=["uploaded image"] if has_diagram_evidence else [],
            diagram_parse_result=diagram_parse_result,
        )

    supported = ", ".join(sorted(SUPPORTED_DOCUMENT_SUFFIXES))
    raise HTTPException(
        status_code=400,
        detail=f"Unsupported file type. Upload one of: {supported}.",
    )


def _detect_file_kind(filename: str, content_type: str | None) -> str:
    suffix = Path(filename).suffix.lower()
    if suffix == ".pdf":
        return "pdf"
    if suffix == ".docx":
        return "docx"
    if suffix in SUPPORTED_IMAGE_SUFFIXES:
        return "image"

    normalized_content_type = (content_type or "").lower()
    if normalized_content_type in PDF_MIME_TYPES:
        return "pdf"
    if normalized_content_type in DOCX_MIME_TYPES:
        return "docx"
    if normalized_content_type in IMAGE_MIME_TYPES:
        return "image"
    return "unsupported"


def _validate_pdf_bytes(pdf_bytes: bytes) -> int:
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception:
        raise HTTPException(status_code=400, detail="File is not a valid PDF.")

    try:
        page_count = doc.page_count
    finally:
        doc.close()

    if page_count == 0:
        raise HTTPException(status_code=400, detail="PDF has no pages.")
    if page_count > settings.pdf_max_pages:
        raise HTTPException(
            status_code=400,
            detail=f"PDF exceeds maximum of {settings.pdf_max_pages} pages (got {page_count}).",
        )
    return page_count


def _validate_docx_bytes(docx_bytes: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(docx_bytes)) as archive:
            if "word/document.xml" not in archive.namelist():
                raise HTTPException(status_code=400, detail="DOCX is missing word/document.xml.")
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="File is not a valid DOCX document.")


def _validate_image_bytes(image_bytes: bytes) -> None:
    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            image.verify()
    except (UnidentifiedImageError, OSError):
        raise HTTPException(status_code=400, detail="File is not a valid image.")


def extract_text_from_docx(docx_bytes: bytes) -> str:
    """Extract plain text from a DOCX document."""
    with zipfile.ZipFile(io.BytesIO(docx_bytes)) as archive:
        document_xml = archive.read("word/document.xml")

    root = ET.fromstring(document_xml)
    paragraphs: list[str] = []

    for paragraph in root.iter():
        if _local_name(paragraph.tag) != "p":
            continue
        fragments: list[str] = []
        for element in paragraph.iter():
            local_name = _local_name(element.tag)
            if local_name == "t" and element.text:
                fragments.append(element.text)
            elif local_name == "tab":
                fragments.append("\t")
            elif local_name == "br":
                fragments.append("\n")
        text = normalize_extracted_text("".join(fragments)).strip()
        if text:
            paragraphs.append(text)

    return "\n".join(paragraphs)


def count_docx_logical_pages(docx_bytes: bytes) -> int:
    """Estimate DOCX page count from page breaks; falls back to 1."""
    with zipfile.ZipFile(io.BytesIO(docx_bytes)) as archive:
        document_xml = archive.read("word/document.xml")

    root = ET.fromstring(document_xml)
    page_breaks = 0
    for element in root.iter():
        if _local_name(element.tag) != "br":
            continue
        for attribute_name, value in element.attrib.items():
            if _local_name(attribute_name) == "type" and value == "page":
                page_breaks += 1
    return max(1, page_breaks + 1)


def extract_docx_diagram_parse_result(docx_bytes: bytes) -> tuple[DocumentParseResult, list[str]]:
    """Extract diagram evidence from images embedded in DOCX files."""
    aggregated = _empty_parse_result()
    artifacts: list[str] = []

    with zipfile.ZipFile(io.BytesIO(docx_bytes)) as archive:
        media_files = sorted(
            name
            for name in archive.namelist()
            if name.startswith("word/media/")
            and Path(name).suffix.lower() in SUPPORTED_IMAGE_SUFFIXES
        )

        for index, media_name in enumerate(media_files, start=1):
            image_bytes = archive.read(media_name)
            image_result = extract_image_diagram_parse_result(image_bytes)
            if not image_result.components and not image_result.flows:
                continue
            artifacts.append(f"embedded image {index}")
            aggregated = _merge_parse_results(aggregated, image_result)

    return aggregated, artifacts


def extract_image_diagram_parse_result(image_bytes: bytes) -> DocumentParseResult:
    """Extract diagram evidence from a standalone image by wrapping it in a temporary PDF."""
    with Image.open(io.BytesIO(image_bytes)) as image:
        width, height = image.size

    document = fitz.open()
    try:
        page = document.new_page(width=max(1, width), height=max(1, height))
        page.insert_image(fitz.Rect(0, 0, max(1, width), max(1, height)), stream=image_bytes)
        pdf_bytes = document.tobytes()
    finally:
        document.close()

    _, parse_result = extract_diagram_parse_result(pdf_bytes)
    return parse_result


def _combine_text_with_diagram_evidence(raw_text: str, parse_result: DocumentParseResult) -> str:
    supplement = _parse_result_to_context_text(parse_result)
    normalized_text = raw_text.strip()
    if normalized_text and supplement:
        return f"{normalized_text}\n\nDiagram Evidence\n{supplement}".strip()
    if supplement:
        return supplement
    return normalized_text


def _parse_result_to_context_text(parse_result: DocumentParseResult) -> str:
    lines: list[str] = []

    if parse_result.components:
        lines.append("Components:")
        for component in parse_result.components:
            bits = [component.name]
            if component.component_type:
                bits.append(f"[{component.component_type}]")
            if component.evidence_page is not None:
                bits.append(f"(page {component.evidence_page})")
            lines.append("- " + " ".join(bits))

    if parse_result.flows:
        lines.append("Flows:")
        for flow in parse_result.flows:
            lines.append(f"- {flow.source} -> {flow.target}: {flow.label}")

    if parse_result.boundaries:
        lines.append("Trust Boundaries:")
        for boundary in parse_result.boundaries:
            lines.append(f"- {boundary.name}: {', '.join(boundary.contains)}")

    return "\n".join(lines).strip()


def _merge_parse_results(primary: DocumentParseResult, secondary: DocumentParseResult) -> DocumentParseResult:
    components: dict[str, ParsedComponent] = {
        _normalize_component_name(component.name): component
        for component in primary.components
    }
    for component in secondary.components:
        components.setdefault(_normalize_component_name(component.name), component)

    flows: list[ParsedFlow] = list(primary.flows)
    seen_flows = {
        (
            _normalize_component_name(flow.source),
            _normalize_component_name(flow.target),
            flow.label.strip().lower(),
        )
        for flow in flows
    }
    for flow in secondary.flows:
        key = (
            _normalize_component_name(flow.source),
            _normalize_component_name(flow.target),
            flow.label.strip().lower(),
        )
        if key not in seen_flows:
            flows.append(flow)
            seen_flows.add(key)

    boundaries: dict[str, ParsedBoundary] = {
        _normalize_component_name(boundary.name): boundary
        for boundary in primary.boundaries
    }
    for boundary in secondary.boundaries:
        normalized_name = _normalize_component_name(boundary.name)
        if normalized_name not in boundaries:
            boundaries[normalized_name] = boundary
            continue
        merged_contains = {
            _normalize_component_name(name): name
            for name in boundaries[normalized_name].contains
        }
        for component_name in boundary.contains:
            merged_contains.setdefault(_normalize_component_name(component_name), component_name)
        boundaries[normalized_name] = boundaries[normalized_name].model_copy(
            update={"contains": list(merged_contains.values())}
        )

    return DocumentParseResult(
        components=list(components.values()),
        flows=flows,
        boundaries=list(boundaries.values()),
        raw_text_excerpt=primary.raw_text_excerpt or secondary.raw_text_excerpt,
    )


def _empty_parse_result() -> DocumentParseResult:
    return DocumentParseResult(
        components=[],
        flows=[],
        boundaries=[],
        raw_text_excerpt="",
    )


def _normalize_component_name(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip().lower().replace("-", " ").replace("_", " "))


def _local_name(value: str) -> str:
    return value.rsplit("}", 1)[-1]

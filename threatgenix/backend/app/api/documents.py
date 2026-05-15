"""Document upload endpoint (Block 6)."""

import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.document import Document
from app.models.user import User
from app.schemas.document import DocumentUploadResponse, ExtractionOutcome
from app.services.ai_extraction import (
    build_extraction_evidence,
    classify_document_type,
    extract_components_from_text,
    merge_parse_results,
)
from app.services.auth import get_current_user
from app.services.dfd_generator import generate_dfd_from_parse_result
from app.services.llm_client import get_llm_client_for_user_async
from app.services.model_collaboration import require_model_permission
from app.services.document_ingestion import parse_uploaded_document
from app.services.doc_parser import assess_parse_result
from app.services.threat_model import get_threat_model

logger = logging.getLogger(__name__)
MIN_VIABLE_COMPONENTS = 2

router = APIRouter(
    prefix="/api/threat-models/{threat_model_id}/documents",
    tags=["documents"],
)


@router.post("", response_model=DocumentUploadResponse, status_code=201)
async def upload_document(
    threat_model_id: UUID,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DocumentUploadResponse:
    """Upload a supported design document, extract components, and auto-generate DFD."""
    threat_model = require_model_permission(
        await get_threat_model(db, threat_model_id),
        current_user,
        "write",
    )

    parsed_document = await parse_uploaded_document(file)
    page_count = parsed_document.page_count
    raw_text = parsed_document.raw_text
    diagram_pages = parsed_document.diagram_pages
    diagram_artifacts = parsed_document.diagram_artifacts
    diagram_parse_result = parsed_document.diagram_parse_result
    detected_doc_type = classify_document_type(raw_text) or (
        "architecture_diagram" if parsed_document.file_kind == "image" else None
    )

    # Extract components using AI — BYOK-aware: checks user's stored key first
    try:
        llm_client = await get_llm_client_for_user_async(current_user.id, db)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Document analysis is currently unavailable: {exc}",
        )

    extraction_outcome: ExtractionOutcome = await extract_components_from_text(
        raw_text=raw_text,
        system_name=threat_model.system_name,
        client=llm_client,
    )
    parse_result = merge_parse_results(
        diagram_parse_result,
        extraction_outcome.parse_result,
    )
    extraction_status, warnings = assess_parse_result(raw_text, parse_result)
    evidence = build_extraction_evidence(
        raw_text,
        parse_result,
        warnings=warnings,
        diagram_pages=diagram_pages,
        diagram_artifacts=diagram_artifacts,
        detected_doc_type=detected_doc_type,
    )
    extraction_outcome = ExtractionOutcome(
        parse_result=parse_result,
        extraction_status=extraction_status,
        warnings=warnings,
        evidence=evidence,
    )

    # Store Document record
    document = Document(
        threat_model_id=threat_model_id,
        filename=file.filename or "untitled.pdf",
        page_count=page_count,
        raw_text=raw_text,
        parsed_components=extraction_outcome.model_dump(),
        parsed_at=datetime.now(timezone.utc),
    )
    db.add(document)

    if len(parse_result.components) < MIN_VIABLE_COMPONENTS:
        await db.commit()
        raise HTTPException(
            status_code=422,
            detail=(
                "Could not extract enough architecture components from the document. "
                "Existing DFD was left unchanged."
            ),
        )

    # Auto-generate DFD from parse result
    await generate_dfd_from_parse_result(db, threat_model_id, parse_result)

    await db.commit()
    await db.refresh(document)

    return DocumentUploadResponse(
        document_id=document.id,
        filename=document.filename,
        page_count=document.page_count,
        parse_result=parse_result,
        extraction_status=extraction_outcome.extraction_status,
        warnings=extraction_outcome.warnings,
        evidence=extraction_outcome.evidence,
    )

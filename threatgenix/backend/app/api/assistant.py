from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
from app.models.threat import Threat
from app.models.user import User
from app.schemas.assistant import AssistantRequest, AssistantResponse
from app.schemas.dfd import (
    DFDEdgeResponse,
    DFDNodeResponse,
    DFDResponse,
    TrustBoundaryResponse,
)
from app.schemas.threat import ThreatResponse
from app.services.assistant import respond_to_assistant_request
from app.services.auth import get_current_user
from app.services.compliance_service import lookup_controls_batch
from app.services.model_collaboration import require_model_permission
from app.services.security_review_adapter import (
    build_application_security_review,
    build_security_review_findings,
)
from app.services.security_review_state import normalize_review_state_records
from app.services.tmac import (
    build_tmac_scaffold,
    build_tmac_validation_response,
    diff_tmac_against_model,
)
from app.services.threat_model import get_threat_model

router = APIRouter(
    prefix="/api/threat-models/{threat_model_id}/assistant",
    tags=["assistant"],
)


async def _handle_tmac_command(
    threat_model,
    request: AssistantRequest,
    *,
    db: AsyncSession,
) -> AssistantResponse | None:
    message = request.message.strip()
    lowered = message.casefold()
    if not lowered.startswith("/tmac"):
        return None

    remainder = message[len("/tmac"):].strip()
    if not remainder or remainder.casefold() == "help":
        return AssistantResponse(
            mode="ask",
            answer=(
                "TMAC commands are deterministic. Use `/tmac scaffold` for a starter file, "
                "`/tmac validate <yaml/json>` to validate pasted model code, and "
                "`/tmac diff <yaml/json>` to compare pasted TMAC against the current model. "
                "Use the TMAC button on the threat model page to export or import full files."
            ),
            references=[],
        )

    command, content = (remainder.split(None, 1) + [""])[:2] if remainder else ["", ""]
    command = command.casefold()
    content = content.strip()

    if command == "scaffold":
        scaffold = build_tmac_scaffold(threat_model)
        return AssistantResponse(
            mode="ask",
            answer=f"```yaml\n{scaffold.strip()}\n```",
            references=[],
        )

    if command == "validate":
        if not content:
            return AssistantResponse(
                mode="ask",
                answer="Paste TMAC after `/tmac validate` so I can validate it deterministically.",
                references=[],
            )
        try:
            validation = build_tmac_validation_response(content)
        except HTTPException as exc:
            return AssistantResponse(
                mode="ask",
                answer=f"Validation error: {_format_tmac_exception(exc)}",
                references=[],
            )
        warning_text = (
            "\nWarnings:\n- " + "\n- ".join(validation.warnings)
            if validation.warnings
            else ""
        )
        return AssistantResponse(
            mode="ask",
            answer=(
                f"TMAC is valid `{validation.format.value}`.\n"
                f"Nodes: {validation.summary.node_count}, "
                f"flows: {validation.summary.edge_count}, "
                f"boundaries: {validation.summary.boundary_count}, "
                f"custom views: {validation.summary.custom_view_count}, "
                f"threats: {validation.summary.threat_count}.{warning_text}"
            ),
            references=[],
        )

    if command == "diff":
        if not content:
            return AssistantResponse(
                mode="ask",
                answer="Paste TMAC after `/tmac diff` so I can compare it against the current live model.",
                references=[],
            )
        try:
            diff = await diff_tmac_against_model(db, threat_model=threat_model, content=content)
        except HTTPException as exc:
            return AssistantResponse(
                mode="ask",
                answer=f"Validation error: {_format_tmac_exception(exc)}",
                references=[],
            )
        warning_text = (
            "\nWarnings:\n- " + "\n- ".join(diff.warnings)
            if diff.warnings
            else ""
        )
        changed = ", ".join(diff.changed_sections) if diff.changed_sections else "none"
        return AssistantResponse(
            mode="ask",
            answer=(
                f"Changed sections: {changed}.\n"
                f"Current model nodes/flows/threats: "
                f"{diff.current_summary.node_count}/{diff.current_summary.edge_count}/{diff.current_summary.threat_count}.\n"
                f"Incoming TMAC nodes/flows/threats: "
                f"{diff.incoming_summary.node_count}/{diff.incoming_summary.edge_count}/{diff.incoming_summary.threat_count}."
                f"{warning_text}"
            ),
            references=[],
        )

    return AssistantResponse(
        mode="ask",
        answer="Unknown TMAC command. Use `/tmac help` for the deterministic command set.",
        references=[],
    )


def _format_tmac_exception(exc: HTTPException) -> str:
    detail = exc.detail
    if isinstance(detail, str):
        return detail
    if isinstance(detail, dict):
        message = detail.get("message")
        errors = detail.get("errors")
        if isinstance(errors, list) and errors:
            return f"{message or 'TMAC validation failed.'} Errors: {errors}"
        if isinstance(message, str) and message:
            return message
    return "TMAC validation failed."


async def _require_owner(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> User:
    threat_model = await get_threat_model(db, threat_model_id)
    require_model_permission(threat_model, current_user, "read")  # type: ignore[arg-type]
    return current_user


@router.post("/respond", response_model=AssistantResponse)
async def respond(
    threat_model_id: UUID,
    request: AssistantRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(_require_owner),
) -> AssistantResponse:
    threat_model = await get_threat_model(db, threat_model_id)
    if threat_model is None:
        raise HTTPException(status_code=404, detail="Threat model not found")

    tmac_response = await _handle_tmac_command(threat_model, request, db=db)
    if tmac_response is not None:
        return tmac_response

    nodes_result = await db.execute(
        select(DFDNode).where(DFDNode.threat_model_id == threat_model_id)
    )
    edges_result = await db.execute(
        select(DFDEdge).where(DFDEdge.threat_model_id == threat_model_id)
    )
    boundaries_result = await db.execute(
        select(TrustBoundary).where(TrustBoundary.threat_model_id == threat_model_id)
    )
    threats_result = await db.execute(
        select(Threat)
        .where(Threat.threat_model_id == threat_model_id)
        .order_by(Threat.display_id)
    )

    nodes = nodes_result.scalars().all()
    edges = edges_result.scalars().all()
    boundaries = boundaries_result.scalars().all()
    threat_rows = threats_result.scalars().all()

    dfd = DFDResponse(
        nodes=[DFDNodeResponse.model_validate(node) for node in nodes],
        edges=[DFDEdgeResponse.model_validate(edge) for edge in edges],
        trust_boundaries=[TrustBoundaryResponse.model_validate(boundary) for boundary in boundaries],
    )

    controls_map = await lookup_controls_batch(db, threat_rows)
    threats: list[ThreatResponse] = []
    for threat in threat_rows:
        response = ThreatResponse.model_validate(threat)
        response.compliance_controls = controls_map.get(threat.id, [])
        threats.append(response)

    review_state = normalize_review_state_records(
        getattr(threat_model, "review_state", None)
    )
    review_summary = build_application_security_review(
        threat_model,
        threat_rows,
        nodes,
        edges,
        boundaries,
    )
    review_findings = build_security_review_findings(
        threat_model,
        threat_rows,
        nodes,
        edges,
        boundaries,
        review_state=review_state,
    )

    return respond_to_assistant_request(
        request=request,
        user_id=current_user.id,
        threat_model_name=threat_model.system_name,
        description=threat_model.description or "",
        data_classification=threat_model.data_classification,
        regulatory_scope=threat_model.regulatory_scope or [],
        deployment_model=threat_model.deployment_model,
        dfd=dfd,
        threats=threats,
        environment_context_summary=threat_model.environment_context_summary,
        assumption_count=len(threat_model.assumptions or []),
        review_summary=review_summary,
        review_findings=review_findings,
    )

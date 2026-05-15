from app.schemas.environment_evidence import FindingCodeLink
from app.schemas.security_review import (
    SecurityReviewApplicationSummary,
    SecurityReviewArtifact,
    SecurityReviewCoverageSummary,
    SecurityReviewEvidenceAnchor,
    SecurityReviewFinding,
    SecurityReviewFindingListResponse,
    SecurityReviewRiskAcceptance,
)
from app.services.agent_security_review import (
    build_agent_ci_contract,
    build_agent_remediation_plan_response,
    build_agent_security_review_response,
    build_customer_packet_source_fingerprints,
    build_customer_security_packet_response,
)


def _summary(*, missing_evidence_sources: int = 0) -> SecurityReviewApplicationSummary:
    return SecurityReviewApplicationSummary(
        generated_at="2026-04-30T20:00:00Z",
        system_name="Payments",
        overall_priority="p1_now",
        overall_action_bucket="engineer_now",
        focus_statement="Review the release decision.",
        coverage=SecurityReviewCoverageSummary(
            total_findings=1,
            attached_evidence_sources=1,
            missing_evidence_sources=missing_evidence_sources,
        ),
    )


def _finding(**overrides) -> SecurityReviewFinding:
    data = {
        "id": "threat:finding-1",
        "source_object_type": "threat",
        "source_object_id": "finding-1",
        "threat_id": "finding-1",
        "display_id": "T-001",
        "wire_kind": "threat",
        "display_kind": "threat",
        "source_provenance": "rules_engine",
        "source_system": "threatgenix",
        "title": "Public route writes tenant data",
        "priority": "p0_blocker",
        "numeric_score": 92,
        "wire_action_bucket": "bright_red_line",
        "queue_bucket": "fix_now",
        "computed_queue_bucket": "fix_now",
        "truth_status": "validated",
        "exploitability": "high",
        "urgency": "immediate",
        "business_impact": "severe",
        "regulatory_pressure": "red_line",
        "confidence": "high",
        "is_real": True,
        "is_urgent": True,
        "is_exploitable_in_context": True,
        "is_regulatory_or_control_relevant": True,
        "needs_engineering_change": True,
        "needs_evidence": False,
        "why_now": "Public route reaches tenant data.",
        "impacted_assets": ["Tenant data"],
        "entry_point": "POST /api/share",
        "evidence_refs": ["repository", "dfd"],
        "linked_threat_ids": ["finding-1"],
        "linked_change_ids": [],
        "linked_control_ids": [],
        "code_links": [],
        "owner": None,
        "due_at": None,
        "note": None,
        "artifacts": [],
        "review_status": "open",
        "last_non_terminal_bucket": None,
        "primary_mode": "findings",
        "noise_disposition": "focus",
        "computed_recommendation_changed": False,
        "systemic": False,
        "next_best_action": "Require authentication and tenant ownership checks.",
        "next_step": "Add regression coverage for cross-tenant access.",
        "rationale_excerpt": "Validated public route reaches tenant data.",
    }
    data.update(overrides)
    return SecurityReviewFinding(**data)


def _findings_response(
    *findings: SecurityReviewFinding,
) -> SecurityReviewFindingListResponse:
    return SecurityReviewFindingListResponse(
        generated_at="2026-04-30T20:00:00Z",
        system_name="Payments",
        findings=list(findings),
    )


def test_agent_release_decision_blocks_only_when_grounded() -> None:
    response = build_agent_security_review_response(
        _summary(),
        _findings_response(_finding()),
    )

    assert response.decision == "block"
    assert response.ci.fail_policy == "block_only"
    assert response.ci.should_fail is True
    assert response.ci.exit_code == 1
    assert response.findings[0].decision == "block"
    assert response.findings[0].risk_path == [
        "POST /api/share",
        "Tenant data",
        "Public route writes tenant data",
    ]
    assert {item.type for item in response.findings[0].evidence} == {
        "repository",
        "dfd",
    }
    repository_ref = next(
        item for item in response.findings[0].evidence if item.type == "repository"
    )
    assert repository_ref.source_object_type == "repository_evidence"
    assert repository_ref.source_object_id == "repository_evidence"
    assert repository_ref.relationship == "supports_review_finding"
    assert repository_ref.strength == "strong"
    assert "does not certify" in response.pass_semantics


def test_agent_release_decision_preserves_object_level_dfd_anchors() -> None:
    response = build_agent_security_review_response(
        _summary(),
        _findings_response(
            _finding(
                evidence_anchors=[
                    SecurityReviewEvidenceAnchor(
                        type="dfd",
                        reference="dfd_node:node-api",
                        claim="DFD node Public API is affected by this finding.",
                        validated=True,
                        source_object_type="dfd_node",
                        source_object_id="node-api",
                        location="dfd_node:node-api",
                        relationship="affected_component",
                        strength="strong",
                    ),
                    SecurityReviewEvidenceAnchor(
                        type="dfd",
                        reference="dfd_edge:edge-api-db",
                        claim="DFD flow API to database is affected by this finding.",
                        validated=True,
                        source_object_type="dfd_edge",
                        source_object_id="edge-api-db",
                        location="dfd_edge:edge-api-db",
                        relationship="affected_flow",
                        strength="strong",
                    ),
                ],
            )
        ),
    )

    dfd_refs = [item for item in response.findings[0].evidence if item.type == "dfd"]
    assert any(item.source_object_type == "dfd_node" for item in dfd_refs)
    assert any(item.source_object_type == "dfd_edge" for item in dfd_refs)
    assert any(item.source_object_id == "node-api" for item in dfd_refs)
    assert any(item.relationship == "affected_flow" for item in dfd_refs)


def test_agent_release_decision_includes_risk_acceptance_attestation_state() -> None:
    response = build_agent_security_review_response(
        _summary(),
        _findings_response(
            _finding(
                review_status="accepted",
                risk_acceptance=SecurityReviewRiskAcceptance(
                    finding_title="Public route writes tenant data",
                    status="active",
                    accepted_by="Priya Reviewer",
                    accepted_at="2026-04-30T20:00:00Z",
                    expires_at="2026-06-01T00:00:00Z",
                    acceptance_rationale="Temporary acceptance for migration.",
                    compensating_control="Manual log review.",
                    reopen_triggers=[],
                ),
            )
        ),
    )

    manual_ref = next(
        item
        for item in response.findings[0].evidence
        if item.source_object_type == "human_attestation"
    )
    assert response.findings[0].decision == "accept_risk"
    assert manual_ref.location == "risk_acceptance:active"
    assert manual_ref.relationship == "accepted_by_reviewer"
    assert "Priya Reviewer" in manual_ref.claim


def test_agent_release_decision_downgrades_ungrounded_blockers_to_evidence_gap() -> (
    None
):
    response = build_agent_security_review_response(
        _summary(),
        _findings_response(
            _finding(
                truth_status="theoretical",
                evidence_refs=[],
                code_links=[],
                confidence="low",
            )
        ),
    )

    assert response.decision == "gather_evidence"
    assert response.findings[0].decision == "gather_evidence"
    assert response.evidence_gaps == ["Public route writes tenant data"]
    assert response.findings[0].verification.required is True
    assert (
        "at least one non-AI evidence reference"
        in response.findings[0].verification.evidence_needed
    )


def test_agent_remediation_plan_preserves_decision_guardrails() -> None:
    summary = _summary(missing_evidence_sources=1)
    findings_response = _findings_response(
        _finding(
            artifacts=[
                SecurityReviewArtifact(
                    id="artifact-1",
                    kind="remediation_note",
                    title="Remediation note for Missing caller authentication",
                    summary="Authentication remediation is ready to verify.",
                    body="Require authenticated caller identity.",
                    created_at="2026-04-30T21:00:00Z",
                )
            ]
        ),
        _finding(
            id="application_review_finding:model:scanner-evidence",
            source_object_type="application_review_finding",
            source_object_id="model:scanner-evidence",
            threat_id=None,
            title="Scanner validation is missing",
            priority="p2_sprint",
            wire_action_bucket="fill_evidence_gap",
            queue_bucket="gather_evidence",
            computed_queue_bucket="gather_evidence",
            truth_status="contextual",
            confidence="medium",
            needs_engineering_change=False,
            needs_evidence=True,
            is_real=False,
            is_urgent=False,
            is_exploitable_in_context=False,
            is_regulatory_or_control_relevant=False,
            impacted_assets=[],
            entry_point=None,
            evidence_refs=[],
            linked_threat_ids=[],
            primary_mode="model_health",
            noise_disposition="queue",
            next_step="Attach a scanner run or explain why runtime validation is out of scope.",
        ),
    )
    agent_response = build_agent_security_review_response(
        summary,
        findings_response,
    )

    plan = build_agent_remediation_plan_response(
        summary, agent_response, findings_response
    )

    assert plan.loop_status == "ready"
    assert plan.current_decision == "block"
    assert len(plan.actions) == 2
    remediation = plan.actions[0]
    evidence_request = plan.actions[1]
    assert remediation.action_kind == "patch_guidance"
    assert remediation.artifact_kind == "remediation_note"
    assert remediation.expected_next_decision == "verify"
    assert remediation.ticket_draft.external_creation_status == "draft_only"
    assert remediation.transition.status == "ready_for_verify"
    assert remediation.transition.artifact_count == 1
    assert evidence_request.action_kind == "evidence_request"
    assert evidence_request.artifact_kind == "evidence_request"
    assert "grounded evidence chain" in evidence_request.evidence_needed
    assert plan.action_history[0].artifact_kind == "remediation_note"
    assert "does not clear a finding" in plan.summary
    assert "## Action history" in plan.plan_markdown
    assert "## Rerun instructions" in plan.plan_markdown


def test_agent_remediation_plan_keeps_ticket_handoff_separate_from_evidence() -> None:
    summary = _summary(missing_evidence_sources=1)
    findings_response = _findings_response(
        _finding(
            id="application_review_finding:model:scanner-evidence",
            source_object_type="application_review_finding",
            source_object_id="model:scanner-evidence",
            threat_id=None,
            title="Scanner validation is missing",
            priority="p2_sprint",
            wire_action_bucket="fill_evidence_gap",
            queue_bucket="gather_evidence",
            computed_queue_bucket="gather_evidence",
            truth_status="contextual",
            confidence="medium",
            needs_engineering_change=False,
            needs_evidence=True,
            is_real=False,
            is_urgent=False,
            is_exploitable_in_context=False,
            is_regulatory_or_control_relevant=False,
            impacted_assets=[],
            entry_point=None,
            evidence_refs=[],
            linked_threat_ids=[],
            primary_mode="model_health",
            noise_disposition="queue",
            next_step="Attach a scanner run or explain why runtime validation is out of scope.",
            artifacts=[
                SecurityReviewArtifact(
                    id="artifact-ticket-1",
                    kind="evidence_request",
                    title="External ticket handoff · Scanner validation is missing",
                    summary="Confirmed external ticket handoff.",
                    body="\n".join(
                        [
                            "External ticket handoff",
                            "- Provider: linear",
                            "- Ticket id: LIN-42",
                            "- Ticket URL: https://linear.app/acme/issue/LIN-42",
                        ]
                    ),
                    created_at="2026-04-30T21:00:00Z",
                )
            ],
        )
    )
    agent_response = build_agent_security_review_response(summary, findings_response)

    plan = build_agent_remediation_plan_response(
        summary, agent_response, findings_response
    )

    action = plan.actions[0]
    assert action.ticket_draft.provider == "linear"
    assert action.ticket_draft.external_creation_status == "created"
    assert action.ticket_draft.external_ticket_id == "LIN-42"
    assert action.transition.status == "evidence_still_missing"


def test_agent_remediation_plan_advances_after_inbound_evidence_webhook() -> None:
    summary = _summary(missing_evidence_sources=1)
    findings_response = _findings_response(
        _finding(
            id="application_review_finding:model:scanner-evidence",
            source_object_type="application_review_finding",
            source_object_id="model:scanner-evidence",
            threat_id=None,
            title="Scanner validation is missing",
            priority="p2_sprint",
            wire_action_bucket="fill_evidence_gap",
            queue_bucket="gather_evidence",
            computed_queue_bucket="gather_evidence",
            truth_status="contextual",
            confidence="medium",
            needs_engineering_change=False,
            needs_evidence=True,
            is_real=False,
            is_urgent=False,
            is_exploitable_in_context=False,
            is_regulatory_or_control_relevant=False,
            impacted_assets=[],
            entry_point=None,
            evidence_refs=[],
            linked_threat_ids=[],
            primary_mode="model_health",
            noise_disposition="queue",
            next_step="Attach a scanner run or explain why runtime validation is out of scope.",
            artifacts=[
                SecurityReviewArtifact(
                    id="artifact-evidence-1",
                    kind="verification_note",
                    title="Inbound remediation evidence · Scanner validation is missing",
                    summary="External remediation evidence was ingested.",
                    body="\n".join(
                        [
                            "Inbound evidence webhook",
                            "- Pull request: https://github.com/acme/app/pull/7",
                            "Evidence summary",
                            "- Scanner output was attached.",
                        ]
                    ),
                    created_at="2026-04-30T21:00:00Z",
                )
            ],
        )
    )
    agent_response = build_agent_security_review_response(summary, findings_response)

    plan = build_agent_remediation_plan_response(
        summary, agent_response, findings_response
    )

    assert plan.actions[0].transition.status == "ready_for_rerun"


def test_agent_release_decision_preserves_code_provenance() -> None:
    response = build_agent_security_review_response(
        _summary(),
        _findings_response(
            _finding(
                code_links=[
                    FindingCodeLink(
                        finding_key="model:code-unprotected-sensitive-surface",
                        surface_id="surface-payments-post",
                        surface_name="POST /payments",
                        source_file="app/api/payments.py",
                        line_number=42,
                        relationship="confirms_missing_control",
                        summary="Route writes payment data without detected authorization.",
                        risk_signal_ids=["risk-missing-authz"],
                    )
                ],
            )
        ),
    )

    code_ref = response.findings[0].evidence[0]
    assert code_ref.type == "code"
    assert code_ref.reference == "app/api/payments.py:42"
    assert code_ref.source_object_type == "code_surface"
    assert code_ref.source_object_id == "surface-payments-post"
    assert code_ref.location == "app/api/payments.py:42"
    assert code_ref.relationship == "confirms_missing_control"
    assert code_ref.strength == "strong"
    assert code_ref.validated is True


def test_agent_release_decision_uses_precise_ship_semantics() -> None:
    response = build_agent_security_review_response(
        _summary(),
        _findings_response(
            _finding(
                priority="p4_monitor",
                wire_action_bucket="monitor",
                queue_bucket=None,
                computed_queue_bucket="backlog",
                review_status="mitigated",
                needs_engineering_change=False,
                truth_status="validated",
            )
        ),
    )

    assert response.decision == "ship"
    assert response.ci.should_fail is False
    assert response.ci.exit_code == 0
    assert response.findings == []
    assert response.decision_reason == response.pass_semantics


def test_agent_ci_contract_respects_configured_fail_policy() -> None:
    assert build_agent_ci_contract("fix_now").exit_code == 0
    configured = build_agent_ci_contract("fix_now", "block_or_fix_now")
    assert configured.should_fail is True
    assert configured.exit_code == 1
    assert configured.blocking_decisions == ["block", "fix_now"]

    verify_policy = build_agent_ci_contract("verify", "block_fix_now_or_verify")
    assert verify_policy.should_fail is True
    assert verify_policy.exit_code == 1

    disabled = build_agent_ci_contract("block", "never")
    assert disabled.should_fail is False
    assert disabled.exit_code == 0


def test_customer_security_packet_separates_proven_assumed_and_unknown() -> None:
    summary = _summary(missing_evidence_sources=2)
    findings = _findings_response(
        _finding(
            code_links=[
                FindingCodeLink(
                    finding_key="model:code-unprotected-sensitive-surface",
                    surface_id="surface-share-post",
                    surface_name="POST /share",
                    source_file="app/api/share.py",
                    line_number=12,
                    relationship="confirms_missing_control",
                    summary="Route writes tenant data without an ownership check.",
                    risk_signal_ids=["risk-missing-authz"],
                )
            ],
        ),
        _finding(
            id="application_review_finding:model:evidence-gap",
            source_object_type="application_review_finding",
            source_object_id="model:evidence-gap",
            threat_id=None,
            display_id=None,
            wire_kind="evidence_gap",
            display_kind="evidence_gap",
            source_provenance="app_review_projection",
            title="Scanner validation is missing",
            priority="p2_sprint",
            wire_action_bucket="fill_evidence_gap",
            queue_bucket="gather_evidence",
            computed_queue_bucket="gather_evidence",
            truth_status="contextual",
            confidence="medium",
            needs_engineering_change=False,
            needs_evidence=True,
            is_real=False,
            is_urgent=False,
            is_exploitable_in_context=False,
            is_regulatory_or_control_relevant=False,
            impacted_assets=[],
            entry_point=None,
            evidence_refs=[],
            linked_threat_ids=[],
            primary_mode="model_health",
            noise_disposition="queue",
            next_step="Attach a scanner run or explain why runtime validation is out of scope.",
        ),
    )
    agent_response = build_agent_security_review_response(summary, findings)

    packet = build_customer_security_packet_response(
        summary,
        findings,
        agent_response,
        scope=["System: Payments.", "Repository evidence is attached."],
        source_fingerprints=build_customer_packet_source_fingerprints(
            summary=summary,
            findings_response=findings,
            agent_response=agent_response,
            repository_evidence={
                "source_type": "github",
                "filename": "threatgenix.zip",
                "parsed_at": "2026-04-30T20:00:00Z",
                "pull_request": {
                    "repository": "example-org/threatgenix",
                    "number": 12,
                    "head_sha": "abc123",
                    "fetched_at": "2026-04-30T20:01:00Z",
                },
            },
        ),
    )

    assert packet.audience == "customer_security_review"
    assert packet.packet_version == "customer_packet_v1"
    assert packet.packet_hash.startswith("sha256:")
    assert packet.redaction_profile == "customer_safe_v1"
    assert packet.release_decision == "block"
    assert len(packet.source_fingerprints) == 5
    assert {source.source_type for source in packet.source_fingerprints} == {
        "review_summary",
        "review_findings",
        "agent_decision",
        "repository",
        "pull_request",
    }
    assert all(
        source.fingerprint.startswith("sha256:")
        for source in packet.source_fingerprints
    )
    assert any("raw repository contents" in item for item in packet.redaction_notes)
    assert any("connected to this review" in item for item in packet.proven)
    assert any("does not certify" in item for item in packet.assumptions)
    assert any("expected evidence" in item for item in packet.unknowns)
    assert any("Runtime or scanner" in item for item in packet.unknowns)
    assert packet.validated_risks[0].title == "Public route writes tenant data"
    assert packet.evidence_gaps[0].title == "Scanner validation is missing"
    assert "Packet hash: sha256:" in packet.customer_safe_markdown
    assert "## Source fingerprints" in packet.customer_safe_markdown
    assert "## External sharing controls" in packet.customer_safe_markdown
    assert "## What is proven" in packet.customer_safe_markdown
    assert "## What remains unknown" in packet.customer_safe_markdown


def test_customer_security_packet_counts_imported_scan_evidence_without_overclaiming() -> (
    None
):
    summary = _summary()
    findings = _findings_response(_finding(evidence_refs=["repository", "dfd"]))
    agent_response = build_agent_security_review_response(summary, findings)

    packet = build_customer_security_packet_response(
        summary,
        findings,
        agent_response,
        source_fingerprints=build_customer_packet_source_fingerprints(
            summary=summary,
            findings_response=findings,
            agent_response=agent_response,
            repository_evidence={
                "source_type": "github",
                "filename": "example-app.zip",
                "parsed_at": "2026-05-01T20:00:00Z",
            },
            validation_scan_evidence=[
                {
                    "id": "scan-semgrep-1",
                    "tool_name": "semgrep",
                    "target_type": "repository_path",
                    "status": "completed",
                    "finding_count": 2,
                    "completed_at": "2026-05-01T20:02:00Z",
                }
            ],
        ),
    )

    assert {source.source_type for source in packet.source_fingerprints} == {
        "review_summary",
        "review_findings",
        "agent_decision",
        "repository",
        "scan",
    }
    assert any(
        source.label == "Semgrep validation scan (2 findings)"
        for source in packet.source_fingerprints
    )
    assert any(
        "Connected evidence types:" in item and "scan" in item for item in packet.proven
    )
    assert not any(
        "Runtime or scanner validation evidence is not connected." in item
        for item in packet.unknowns
    )
    assert any(
        "not yet mapped to a customer-visible reviewed risk" in item
        for item in packet.unknowns
    )


def test_customer_security_packet_keeps_verify_findings_customer_visible() -> None:
    summary = _summary()
    findings = _findings_response(
        _finding(
            priority="p4_monitor",
            wire_action_bucket="verify_control",
            queue_bucket="verify",
            computed_queue_bucket="verify",
            needs_engineering_change=False,
            needs_evidence=True,
            evidence_refs=["scan", "dfd", "repository"],
            evidence_anchors=[
                SecurityReviewEvidenceAnchor(
                    type="scan",
                    reference="semgrep:src/api/campaigns.js:13",
                    claim="Semgrep confirmed the tenant ownership gap.",
                    validated=True,
                    source_object_type="scan_finding",
                    source_object_id="finding-1",
                    location="src/api/campaigns.js:13",
                    relationship="confirms_review_finding",
                    strength="strong",
                )
            ],
        )
    )
    agent_response = build_agent_security_review_response(summary, findings)
    packet = build_customer_security_packet_response(summary, findings, agent_response)

    assert packet.validated_risks[0].title == "Public route writes tenant data"
    assert packet.validated_risks[0].customer_status == "needs_verification"
    assert packet.evidence_gaps == []


def test_customer_security_packet_does_not_count_missing_evidence_as_proven() -> None:
    summary = _summary(missing_evidence_sources=3)
    findings = _findings_response(
        _finding(
            id="application_review_finding:model:missing-cloud-iac-dfd",
            source_object_type="application_review_finding",
            source_object_id="model:missing-cloud-iac-dfd",
            threat_id=None,
            display_id=None,
            wire_kind="evidence_gap",
            display_kind="evidence_gap",
            source_provenance="app_review_projection",
            title="Cloud, IaC, and DFD evidence are missing",
            priority="p2_sprint",
            wire_action_bucket="fill_evidence_gap",
            queue_bucket="gather_evidence",
            computed_queue_bucket="gather_evidence",
            truth_status="contextual",
            confidence="medium",
            needs_engineering_change=False,
            needs_evidence=True,
            is_real=False,
            is_urgent=False,
            is_exploitable_in_context=False,
            is_regulatory_or_control_relevant=False,
            impacted_assets=[],
            entry_point=None,
            evidence_refs=["cloud", "iac", "dfd"],
            linked_threat_ids=[],
            primary_mode="model_health",
            noise_disposition="queue",
            next_best_action="Attach cloud, IaC, and DFD evidence before sharing.",
        ),
    )
    agent_response = build_agent_security_review_response(summary, findings)

    packet = build_customer_security_packet_response(
        summary,
        findings,
        agent_response,
        source_fingerprints=build_customer_packet_source_fingerprints(
            summary=summary,
            findings_response=findings,
            agent_response=agent_response,
            repository_evidence={
                "source_type": "github",
                "filename": "threatgenix.zip",
                "parsed_at": "2026-04-30T20:00:00Z",
                "pull_request": {
                    "repository": "example-org/threatgenix",
                    "number": 12,
                    "head_sha": "abc123",
                    "fetched_at": "2026-04-30T20:01:00Z",
                },
            },
        ),
    )

    proven_text = " ".join(packet.proven).lower()
    assert "repository" in proven_text
    assert "cloud" not in proven_text
    assert "iac" not in proven_text
    assert "dfd" not in proven_text
    assert any("expected evidence" in item for item in packet.unknowns)
    assert any(
        "Cloud, IaC, and DFD evidence are missing" in item for item in packet.unknowns
    )
    assert any("Runtime or scanner" in item for item in packet.unknowns)
    assert not any(
        "Exact repository or code-surface" in item for item in packet.unknowns
    )
    assert (
        packet.evidence_gaps[0].evidence_summary
        == "No customer-safe validation evidence is connected yet."
        " Expected evidence types: cloud, dfd, iac."
    )


def test_customer_security_packet_hash_ignores_regeneration_timestamps() -> None:
    summary = _summary()
    findings = _findings_response(_finding())
    agent_response = build_agent_security_review_response(summary, findings)
    packet = build_customer_security_packet_response(
        summary,
        findings,
        agent_response,
        source_fingerprints=build_customer_packet_source_fingerprints(
            summary=summary,
            findings_response=findings,
            agent_response=agent_response,
        ),
    )

    regenerated_summary = summary.model_copy(
        update={"generated_at": "2026-05-01T22:30:00Z"}
    )
    regenerated_findings = findings.model_copy(
        update={"generated_at": "2026-05-01T22:30:01Z"}
    )
    regenerated_agent_response = agent_response.model_copy(
        update={"generated_at": "2026-05-01T22:30:02Z"}
    )
    regenerated_packet = build_customer_security_packet_response(
        regenerated_summary,
        regenerated_findings,
        regenerated_agent_response,
        source_fingerprints=build_customer_packet_source_fingerprints(
            summary=regenerated_summary,
            findings_response=regenerated_findings,
            agent_response=regenerated_agent_response,
        ),
    )

    assert regenerated_packet.generated_at != packet.generated_at
    assert regenerated_packet.packet_hash == packet.packet_hash
    assert [
        source.fingerprint for source in regenerated_packet.source_fingerprints
    ] == [source.fingerprint for source in packet.source_fingerprints]

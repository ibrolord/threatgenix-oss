from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from types import SimpleNamespace

from app.schemas.environment_evidence import (
    CloudFinding,
    CloudScanEvidence,
    CodeControlSignal,
    CodeEvidenceSummary,
    CodeRiskSignal,
    CodeSurface,
    IacEvidence,
    RepositoryEvidence,
)
from app.schemas.threat import (
    ThreatIntelKevRef,
    ThreatIntelResponse,
    ThreatIntelTechniqueRef,
)
from app.services.security_review_adapter import (
    build_application_security_review,
    build_security_review_context,
    build_security_review_findings,
    evaluate_threat_security_reviews,
)
from app.schemas.security_review import (
    SecurityReviewArtifact,
    SecurityReviewStateRecord,
)


def _make_model() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        system_name="Payments API",
        description="Handles regulated payment traffic.",
        data_classification="Restricted",
        regulatory_scope=["PCI DSS"],
        deployment_model="cloud",
        repository_evidence=None,
        cloud_scan_evidence=None,
        iac_evidence=None,
        environment_context_summary=None,
        owner_id=None,
        documents=[],
    )


def _make_repository_evidence(
    *,
    surfaces: list[CodeSurface],
    controls: list[CodeControlSignal] | None = None,
    risks: list[CodeRiskSignal] | None = None,
) -> dict:
    controls = controls or []
    risks = risks or []
    summary = CodeEvidenceSummary(
        surface_count=len(surfaces),
        route_count=sum(
            1 for surface in surfaces if surface.kind in {"route", "webhook"}
        ),
        control_signal_count=len(controls),
        risk_signal_count=len(risks),
        externally_reachable_surface_count=len(surfaces),
        unprotected_sensitive_surface_count=len(
            {
                signal.surface_id
                for signal in risks
                if signal.risk_type in {"missing_authentication", "missing_validation"}
            }
        ),
        verified_control_count=len(controls),
        missing_control_count=sum(
            1
            for signal in risks
            if signal.risk_type in {"missing_authentication", "missing_validation"}
        ),
    )
    return RepositoryEvidence(
        source_type="archive",
        filename="repo.zip",
        reference="main",
        file_count=1,
        code_surfaces=surfaces,
        code_control_signals=controls,
        code_risk_signals=risks,
        code_evidence_summary=summary,
        parsed_at=datetime(2026, 4, 10, tzinfo=timezone.utc),
    ).model_dump(mode="json")


def _make_node(
    node_id: uuid.UUID,
    name: str,
    node_type: str,
    properties: dict,
    *,
    trust_boundary_id: uuid.UUID | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=node_id,
        name=name,
        node_type=node_type,
        trust_boundary_id=trust_boundary_id,
        properties=properties,
    )


def _make_edge(
    edge_id: uuid.UUID,
    source_node_id: uuid.UUID,
    target_node_id: uuid.UUID,
    properties: dict | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=edge_id,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        properties=properties or {},
    )


def _make_threat(
    threat_id: uuid.UUID,
    *,
    display_id: str,
    description: str,
    affected_node_ids: list[uuid.UUID],
    affected_edge_ids: list[uuid.UUID],
    status: str = "Open",
    severity: str = "High",
    control_effectiveness: str = "none",
    residual_risk_level: str | None = None,
    qualification_label: str | None = None,
) -> SimpleNamespace:
    now = datetime(2026, 4, 10, tzinfo=timezone.utc)
    return SimpleNamespace(
        id=threat_id,
        threat_model_id=uuid.uuid4(),
        display_id=display_id,
        description=description,
        stride_category="Elevation of Privilege",
        threat_subtype=None,
        severity=severity,
        source="AI+Rules",
        status=status,
        dismiss_reason="Accepted pending rollout" if status == "Accepted" else None,
        rule_id="RULE-1",
        ai_enhanced=True,
        provider_managed=False,
        original_rule_threat_id=None,
        affected_node_ids=affected_node_ids,
        affected_edge_ids=affected_edge_ids,
        relevance_rationale="The gateway is internet-facing and currently over-privileged.",
        mitigation_plan="Restrict role scope",
        mitigation_owner="priya" if status != "Open" else None,
        due_date=None,
        mitigation_notes="Compensating controls exist"
        if status == "Accepted"
        else None,
        control_effectiveness=control_effectiveness,
        residual_risk_level=residual_risk_level,
        closed_at=now if status == "Accepted" else None,
        qualification_score=None,
        qualification_label=qualification_label,
        qualification_note=None,
        auto_score=None,
        analyst_score=None,
        analyst_score_rationale=None,
        ai_likelihood_score=None,
        ai_likelihood_assessment=None,
        ai_likelihood_generated_at=None,
        cluster_id=None,
        false_positive_reason="accepted_risk" if status == "Accepted" else None,
        qualification_completed_at=now,
        created_at=now,
    )


def test_build_security_review_context_infers_assets_and_risk_acceptance() -> None:
    model = _make_model()
    node_api_id = uuid.uuid4()
    node_vault_id = uuid.uuid4()
    edge_id = uuid.uuid4()
    nodes = [
        _make_node(
            node_api_id,
            "Public API",
            "process",
            {
                "internet_facing": True,
                "network_exposure": "internet",
                "data_classification": "Internal",
            },
        ),
        _make_node(
            node_vault_id,
            "Token Vault",
            "data_store",
            {
                "data_classification": "Restricted",
                "privilege_level": "admin",
            },
        ),
    ]
    edges = [_make_edge(edge_id, node_api_id, node_vault_id)]
    threat = _make_threat(
        uuid.uuid4(),
        display_id="T-001",
        description="Compromised API credentials can reach the token vault.",
        affected_node_ids=[node_api_id, node_vault_id],
        affected_edge_ids=[edge_id],
        status="Accepted",
        control_effectiveness="full",
        residual_risk_level="High",
        qualification_label="Review",
    )
    threat.due_date = date(2026, 6, 30)
    intel = ThreatIntelResponse(
        local_severity="High",
        highest_external_severity="Critical",
        semantic_matches_inferred=False,
        scan_cve_ids=["CVE-2026-0001"],
        attack_techniques=[
            ThreatIntelTechniqueRef(
                technique_id="T1078",
                name="Valid Accounts",
                tactic="credential-access",
                match_type="exact",
            )
        ],
        kev_entries=[
            ThreatIntelKevRef(
                cve_id="CVE-2026-0001",
                vendor_project="Example",
                product="Gateway",
                vulnerability_name="Known issue",
                match_type="scan_cve",
            )
        ],
    )

    context = build_security_review_context(
        model,
        threat,
        nodes,
        edges,
        intel=intel,
        scan_status="confirmed",
    )

    assert context.entry_point == "Public API"
    assert context.target_asset == "Token Vault"
    assert context.data_classification == "Restricted"
    assert context.has_exact_threat_intel is True
    assert context.has_known_exploited_vulnerability is True
    assert context.existing_risk_acceptance is not None
    assert context.existing_risk_acceptance.status == "active"
    assert context.existing_risk_acceptance.accepted_by == "priya"
    assert context.existing_risk_acceptance.expires_at == "2026-06-30"
    assert context.previous_priority == "p3_backlog"


def test_build_security_review_findings_projects_threat_risk_acceptance() -> None:
    model = _make_model()
    node_api_id = uuid.uuid4()
    node_vault_id = uuid.uuid4()
    edge_id = uuid.uuid4()
    nodes = [
        _make_node(
            node_api_id,
            "Public API",
            "process",
            {"internet_facing": True, "network_exposure": "internet"},
        ),
        _make_node(
            node_vault_id,
            "Token Vault",
            "data_store",
            {"data_classification": "Restricted"},
        ),
    ]
    edges = [_make_edge(edge_id, node_api_id, node_vault_id)]
    threat = _make_threat(
        uuid.uuid4(),
        display_id="T-001",
        description="Compromised API credentials can reach the token vault.",
        affected_node_ids=[node_api_id, node_vault_id],
        affected_edge_ids=[edge_id],
        status="Accepted",
        control_effectiveness="full",
        residual_risk_level="Low",
        qualification_label="Review",
    )
    threat.due_date = date(2026, 6, 30)

    response = build_security_review_findings(
        model,
        [threat],
        nodes,
        edges,
        [],
    )

    finding = next(item for item in response.findings if item.id == f"threat:{threat.id}")
    assert finding.review_status == "accepted"
    assert finding.risk_acceptance is not None
    assert finding.risk_acceptance.status == "active"
    assert finding.risk_acceptance.accepted_by == "priya"
    assert finding.risk_acceptance.expires_at == "2026-06-30"
    assert finding.risk_acceptance.acceptance_rationale == "Accepted pending rollout"
    assert finding.risk_acceptance.compensating_control == "Restrict role scope"
    anchors = {
        (anchor.source_object_type, anchor.source_object_id)
        for anchor in finding.evidence_anchors
    }
    assert ("dfd_node", str(node_api_id)) in anchors
    assert ("dfd_node", str(node_vault_id)) in anchors
    assert ("dfd_edge", str(edge_id)) in anchors


def test_evaluate_threat_security_reviews_attaches_related_attack_paths() -> None:
    model = _make_model()
    node_api_id = uuid.uuid4()
    node_vault_id = uuid.uuid4()
    edge_id = uuid.uuid4()
    nodes = [
        _make_node(
            node_api_id,
            "Public API",
            "process",
            {"internet_facing": True, "network_exposure": "internet"},
        ),
        _make_node(
            node_vault_id,
            "Token Vault",
            "data_store",
            {"data_classification": "Restricted"},
        ),
    ]
    edges = [_make_edge(edge_id, node_api_id, node_vault_id)]
    threat_api = _make_threat(
        uuid.uuid4(),
        display_id="T-001",
        description="Auth bypass at the public API.",
        affected_node_ids=[node_api_id],
        affected_edge_ids=[],
        severity="Critical",
    )
    threat_vault = _make_threat(
        uuid.uuid4(),
        display_id="T-002",
        description="The token vault can be reached from the compromised API path.",
        affected_node_ids=[node_api_id, node_vault_id],
        affected_edge_ids=[edge_id],
    )

    decisions = evaluate_threat_security_reviews(
        model,
        [threat_api, threat_vault],
        nodes,
        edges,
        scan_status_by_threat_id={str(threat_api.id): "confirmed"},
    )

    first_decision = decisions[str(threat_api.id)]
    assert first_decision.related_attack_paths
    assert first_decision.related_attack_paths[0].entry_point == "Public API"
    assert first_decision.related_attack_paths[0].target_asset == "Token Vault"
    assert str(threat_api.id) in first_decision.related_attack_paths[0].finding_keys


def test_build_application_security_review_includes_systemic_blind_spots() -> None:
    model = _make_model()
    node_api_id = uuid.uuid4()
    node_vault_id = uuid.uuid4()
    edge_id = uuid.uuid4()
    nodes = [
        _make_node(
            node_api_id,
            "Public API",
            "process",
            {"internet_facing": True, "network_exposure": "internet"},
        ),
        _make_node(
            node_vault_id,
            "Token Vault",
            "data_store",
            {"data_classification": "Restricted", "privilege_level": "admin"},
        ),
    ]
    edges = [_make_edge(edge_id, node_api_id, node_vault_id)]
    threat = _make_threat(
        uuid.uuid4(),
        display_id="T-001",
        description="Auth bypass at the public API.",
        affected_node_ids=[node_api_id],
        affected_edge_ids=[],
        severity="Critical",
    )

    summary = build_application_security_review(
        model,
        [threat],
        nodes,
        edges,
        [],
        scan_status_by_threat_id={str(threat.id): "confirmed"},
    )

    assert summary.system_name == "Payments API"
    assert summary.coverage.systemic_findings >= 3
    assert summary.coverage.public_entry_points == 1
    assert summary.coverage.restricted_assets == 1
    assert summary.blind_spots
    assert any(
        item.title
        == "Cloud configuration evidence is missing for an in-scope deployment"
        for item in summary.blind_spots
    )
    assert any(item.systemic for item in summary.top_findings)


def test_build_security_review_context_keeps_scan_backed_findings_as_threats() -> None:
    model = _make_model()
    node_api_id = uuid.uuid4()
    node_store_id = uuid.uuid4()
    edge_id = uuid.uuid4()
    nodes = [
        _make_node(
            node_api_id,
            "Public API",
            "api_gateway",
            {"internet_facing": True, "network_exposure": "internet"},
        ),
        _make_node(
            node_store_id,
            "Customer Store",
            "data_store",
            {"data_classification": "Restricted"},
        ),
    ]
    edges = [_make_edge(edge_id, node_api_id, node_store_id)]
    threat = _make_threat(
        uuid.uuid4(),
        display_id="T-100",
        description="Known issue on the public API path.",
        affected_node_ids=[node_api_id, node_store_id],
        affected_edge_ids=[edge_id],
        severity="Critical",
    )
    intel = ThreatIntelResponse(
        local_severity="Critical",
        highest_external_severity="Critical",
        semantic_matches_inferred=False,
        scan_cve_ids=["CVE-2026-0100"],
        attack_techniques=[],
        kev_entries=[],
    )

    context = build_security_review_context(
        model,
        threat,
        nodes,
        edges,
        intel=intel,
        scan_status="confirmed",
    )
    findings = build_security_review_findings(
        model,
        [threat],
        nodes,
        edges,
        [],
        intel_by_threat_id={str(threat.id): intel},
        scan_status_by_threat_id={str(threat.id): "confirmed"},
    )

    assert context.finding_kind == "threat"
    assert findings.findings[0].wire_kind == "threat"
    assert all(
        finding.wire_kind
        not in {"vulnerability", "drift", "pr_risk", "incident_signal"}
        for finding in findings.findings
    )


def test_boundary_crossing_control_plane_path_ranks_above_low_signal_backlog() -> None:
    model = _make_model()
    boundary_external = uuid.uuid4()
    boundary_internal = uuid.uuid4()
    node_partner_id = uuid.uuid4()
    node_gateway_id = uuid.uuid4()
    node_role_id = uuid.uuid4()
    node_worker_id = uuid.uuid4()
    edge_ingress_id = uuid.uuid4()
    edge_role_id = uuid.uuid4()
    nodes = [
        _make_node(
            node_partner_id,
            "Market Operator",
            "external_entity",
            {"authenticated": True},
            trust_boundary_id=boundary_external,
        ),
        _make_node(
            node_gateway_id,
            "DER Control API",
            "api_gateway",
            {
                "internet_facing": True,
                "network_exposure": "internet",
                "service_name": "control-api",
                "crown_jewel": True,
            },
            trust_boundary_id=boundary_internal,
        ),
        _make_node(
            node_role_id,
            "Dispatch IAM Role",
            "iam_role",
            {"privilege_level": "admin", "stores_credentials": True},
            trust_boundary_id=boundary_internal,
        ),
        _make_node(
            node_worker_id,
            "Batch Worker",
            "process",
            {},
            trust_boundary_id=boundary_internal,
        ),
    ]
    edges = [
        _make_edge(edge_ingress_id, node_partner_id, node_gateway_id),
        _make_edge(edge_role_id, node_gateway_id, node_role_id),
    ]
    critical_threat = _make_threat(
        uuid.uuid4(),
        display_id="T-200",
        description="Privilege escalation through the control plane path.",
        affected_node_ids=[node_gateway_id, node_role_id],
        affected_edge_ids=[edge_ingress_id, edge_role_id],
        severity="Critical",
    )
    backlog_threat = _make_threat(
        uuid.uuid4(),
        display_id="T-201",
        description="Low-signal batch worker hardening.",
        affected_node_ids=[node_worker_id],
        affected_edge_ids=[],
        severity="Low",
        qualification_label="Low Signal",
    )

    findings = build_security_review_findings(
        model,
        [critical_threat, backlog_threat],
        nodes,
        edges,
        [],
        scan_status_by_threat_id={str(critical_threat.id): "confirmed"},
    )

    threat_findings = [
        finding for finding in findings.findings if finding.display_id is not None
    ]

    assert threat_findings[0].display_id == "T-200"
    assert threat_findings[0].queue_bucket == "fix_now"
    assert threat_findings[0].numeric_score > threat_findings[1].numeric_score


def test_empty_model_review_routes_missing_inputs_into_gather_evidence() -> None:
    model = _make_model()

    findings = build_security_review_findings(
        model,
        [],
        [],
        [],
        [],
    )

    by_key = {finding.source_object_id: finding for finding in findings.findings}

    assert by_key["model:dfd-coverage"].display_kind == "evidence_gap"
    assert by_key["model:dfd-coverage"].queue_bucket == "gather_evidence"
    assert by_key["model:repository-evidence"].queue_bucket == "gather_evidence"
    assert by_key["model:cloud-evidence"].queue_bucket == "gather_evidence"
    assert by_key["model:iac-evidence"].queue_bucket == "gather_evidence"
    assert findings.default_finding_id in {
        "application_review_finding:model:dfd-coverage",
        "application_review_finding:model:cloud-evidence",
    }


def test_compliance_heavy_evidence_gaps_land_in_gather_evidence() -> None:
    model = _make_model()
    model.regulatory_scope = ["PCI DSS", "SOC 2"]
    node_api_id = uuid.uuid4()
    node_store_id = uuid.uuid4()
    nodes = [
        _make_node(
            node_api_id,
            "Public API",
            "api_gateway",
            {"internet_facing": True, "network_exposure": "internet"},
        ),
        _make_node(
            node_store_id,
            "Cardholder Store",
            "data_store",
            {"data_classification": "Restricted"},
        ),
    ]

    findings = build_security_review_findings(
        model,
        [],
        nodes,
        [],
        [],
    )

    compliance_gap_keys = {
        "model:cloud-evidence",
        "model:iac-evidence",
        "model:environment-context",
        "model:repository-evidence",
    }
    matching = [
        finding
        for finding in findings.findings
        if finding.source_object_id in compliance_gap_keys
    ]

    assert matching
    assert all(finding.display_kind == "evidence_gap" for finding in matching)
    assert all(finding.queue_bucket == "gather_evidence" for finding in matching)


def test_out_of_scope_cloud_iac_sources_do_not_create_missing_evidence_gaps() -> None:
    model = _make_model()
    model.out_of_scope_statement = (
        "Cloud and IaC evidence are out of scope for this repo-only pilot."
    )
    model.repository_evidence = _make_repository_evidence(surfaces=[])
    model.environment_context_summary = "Repository evidence is connected."
    node_id = uuid.uuid4()
    nodes = [
        _make_node(
            node_id,
            "API layer",
            "process",
            {"internet_facing": True, "network_exposure": "internet"},
        )
    ]

    findings = build_security_review_findings(
        model,
        [],
        nodes,
        [],
        [],
    )
    by_key = {finding.source_object_id: finding for finding in findings.findings}

    assert "model:cloud-evidence" not in by_key
    assert "model:iac-evidence" not in by_key

    summary = build_application_security_review(model, [], nodes, [], [])

    assert summary.coverage.missing_evidence_sources == 0


def test_persisted_review_artifacts_are_merged_into_findings() -> None:
    model = _make_model()
    node_api_id = uuid.uuid4()
    node_vault_id = uuid.uuid4()
    edge_id = uuid.uuid4()
    nodes = [
        _make_node(
            node_api_id,
            "Public API",
            "process",
            {"internet_facing": True, "network_exposure": "internet"},
        ),
        _make_node(
            node_vault_id,
            "Token Vault",
            "data_store",
            {"data_classification": "Restricted"},
        ),
    ]
    edges = [_make_edge(edge_id, node_api_id, node_vault_id)]
    threat = _make_threat(
        uuid.uuid4(),
        display_id="T-003",
        description="The public API can reach the restricted vault without sufficient trust partitioning.",
        affected_node_ids=[node_api_id, node_vault_id],
        affected_edge_ids=[edge_id],
        severity="Critical",
    )

    findings = build_security_review_findings(
        model,
        [threat],
        nodes,
        edges,
        [],
        review_state=[
            SecurityReviewStateRecord(
                id="review-state-1",
                source_object_type="threat",
                source_object_id=str(threat.id),
                queue_bucket="fix_now",
                review_status="open",
                artifacts=[
                    SecurityReviewArtifact(
                        id="artifact-1",
                        kind="remediation_note",
                        title="Remediation note · Public API path",
                        summary="Concrete engineering follow-up.",
                        body="Objective\n- Reduce the risk.",
                        created_at="2026-04-23T12:00:00Z",
                    )
                ],
                created_at="2026-04-23T12:00:00Z",
                updated_at="2026-04-23T12:05:00Z",
            )
        ],
    )

    finding = next(
        item for item in findings.findings if item.threat_id == str(threat.id)
    )
    assert len(finding.artifacts) == 1
    assert finding.artifacts[0].kind == "remediation_note"
    assert "Reduce the risk" in finding.artifacts[0].body


def test_code_risk_evidence_routes_matching_threat_to_gather_evidence() -> None:
    model = _make_model()
    surface = CodeSurface(
        id="surface-vendor-callback",
        kind="webhook",
        name="POST /callbacks/vendor",
        method="POST",
        path="/callbacks/vendor",
        source_file="src/routes/vendor.js",
        line_number=12,
        sensitive_data_signals=["Tokens and session secrets"],
        validation_signals=["Raw JSON/body access"],
        risk_flags=["No auth guard on sensitive-data route"],
    )
    model.repository_evidence = _make_repository_evidence(
        surfaces=[surface],
        risks=[
            CodeRiskSignal(
                id="risk-vendor-missing-auth",
                surface_id=surface.id,
                risk_type="missing_authentication",
                severity="High",
                evidence="No auth guard was detected on a route that handles tokens.",
            )
        ],
    )
    node_id = uuid.uuid4()
    threat = _make_threat(
        uuid.uuid4(),
        display_id="T-300",
        description="Vendor callback token replay can bypass authentication.",
        affected_node_ids=[node_id],
        affected_edge_ids=[],
        severity="High",
    )
    findings = build_security_review_findings(
        model,
        [threat],
        [
            _make_node(
                node_id, "Vendor Callback", "api_gateway", {"internet_facing": True}
            )
        ],
        [],
        [],
    )

    finding = next(
        item for item in findings.findings if item.threat_id == str(threat.id)
    )
    assert finding.queue_bucket == "gather_evidence"
    assert finding.priority == "p3_backlog"
    assert finding.truth_status == "contextual"
    assert finding.confidence == "medium"
    assert finding.is_real is False
    assert finding.exploitability == "low"
    assert finding.is_exploitable_in_context is False
    assert finding.needs_evidence is True
    assert finding.needs_engineering_change is False
    assert finding.code_links[0].relationship == "confirms_missing_control"
    assert finding.code_links[0].source_file == "src/routes/vendor.js"
    assert "contextual" in finding.why_now


def test_code_scan_and_semantic_intel_combine_into_exploitable_fix_now() -> None:
    model = _make_model()
    surface = CodeSurface(
        id="surface-vendor-callback",
        kind="webhook",
        name="POST /callbacks/vendor",
        method="POST",
        path="/callbacks/vendor",
        source_file="src/routes/vendor.js",
        line_number=12,
        sensitive_data_signals=["Tokens and session secrets"],
        validation_signals=["Raw JSON/body access"],
        risk_flags=["No auth guard on sensitive-data route"],
    )
    model.repository_evidence = _make_repository_evidence(
        surfaces=[surface],
        risks=[
            CodeRiskSignal(
                id="risk-vendor-missing-auth",
                surface_id=surface.id,
                risk_type="missing_authentication",
                severity="High",
                evidence="No auth guard was detected on a route that handles tokens.",
            )
        ],
    )
    node_id = uuid.uuid4()
    threat = _make_threat(
        uuid.uuid4(),
        display_id="T-302",
        description="Vendor callback token replay can bypass authentication.",
        affected_node_ids=[node_id],
        affected_edge_ids=[],
        severity="Critical",
    )
    intel = ThreatIntelResponse(
        local_severity="Critical",
        highest_external_severity="High",
        semantic_matches_inferred=True,
        scan_cve_ids=["CVE-2026-3020"],
        attack_techniques=[
            ThreatIntelTechniqueRef(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                tactic="initial-access",
                match_type="semantic",
            )
        ],
        kev_entries=[],
    )

    context = build_security_review_context(
        model,
        threat,
        [
            _make_node(
                node_id, "Vendor Callback", "api_gateway", {"internet_facing": True}
            )
        ],
        [],
        intel=intel,
        scan_status="confirmed",
    )
    findings = build_security_review_findings(
        model,
        [threat],
        [
            _make_node(
                node_id, "Vendor Callback", "api_gateway", {"internet_facing": True}
            )
        ],
        [],
        [],
        intel_by_threat_id={str(threat.id): intel},
        scan_status_by_threat_id={str(threat.id): "confirmed"},
    )

    finding = next(
        item for item in findings.findings if item.threat_id == str(threat.id)
    )
    assert context.scan_status == "confirmed"
    assert context.has_semantic_threat_intel is True
    assert context.evidence_strength == "strong"
    assert context.change_surface == "code"
    assert context.code_links[0].relationship == "confirms_missing_control"
    assert context.finding_sources == ["scan", "threat_intel", "dfd", "repository"]
    assert finding.queue_bucket == "fix_now"
    assert finding.wire_kind == "threat"
    assert finding.is_exploitable_in_context is True
    assert finding.needs_engineering_change is True
    assert "validation scan confirmed" in finding.why_now


def test_code_control_evidence_moves_matching_threat_to_verify() -> None:
    model = _make_model()
    surface = CodeSurface(
        id="surface-payments-charge",
        kind="route",
        name="POST /payments/charge",
        method="POST",
        path="/payments/charge",
        source_file="app/api/payments.py",
        line_number=8,
        auth_guards=["get_current_user"],
        sensitive_data_signals=["Payment card data"],
        validation_signals=["Typed request parameters"],
    )
    model.repository_evidence = _make_repository_evidence(
        surfaces=[surface],
        controls=[
            CodeControlSignal(
                id="control-payments-auth",
                surface_id=surface.id,
                control_type="authentication",
                strength="strong",
                evidence="get_current_user",
            ),
            CodeControlSignal(
                id="control-payments-validation",
                surface_id=surface.id,
                control_type="validation",
                strength="strong",
                evidence="Typed request parameters",
            ),
        ],
    )
    node_id = uuid.uuid4()
    threat = _make_threat(
        uuid.uuid4(),
        display_id="T-301",
        description="Payments charge endpoint may miss authorization and request validation.",
        affected_node_ids=[node_id],
        affected_edge_ids=[],
        severity="Medium",
    )
    findings = build_security_review_findings(
        model,
        [threat],
        [_make_node(node_id, "Payments Charge", "process", {})],
        [],
        [],
    )

    finding = next(
        item for item in findings.findings if item.threat_id == str(threat.id)
    )
    assert finding.queue_bucket == "verify"
    assert finding.needs_evidence is True
    assert finding.code_links[0].relationship == "shows_compensating_control"


def test_unmapped_code_surface_creates_gather_evidence_finding() -> None:
    model = _make_model()
    surface = CodeSurface(
        id="surface-admin-users",
        kind="route",
        name="GET /admin/users",
        method="GET",
        path="/admin/users",
        source_file="src/routes/admin.ts",
        line_number=21,
        auth_guards=["require_admin"],
    )
    model.repository_evidence = _make_repository_evidence(
        surfaces=[surface],
        controls=[
            CodeControlSignal(
                id="control-admin-authz",
                surface_id=surface.id,
                control_type="authorization",
                strength="strong",
                evidence="require_admin",
            )
        ],
    )
    node_id = uuid.uuid4()

    findings = build_security_review_findings(
        model,
        [],
        [_make_node(node_id, "Customer API", "process", {"internet_facing": True})],
        [],
        [],
    )
    finding = next(
        item
        for item in findings.findings
        if item.source_object_id == "model:code-evidence-mapping"
    )

    assert finding.queue_bucket == "gather_evidence"
    assert finding.display_kind == "evidence_gap"
    assert finding.code_links[0].relationship == "unmodeled_surface"


def test_dfd_code_surface_mapping_evidence_clears_mapping_gap() -> None:
    model = _make_model()
    surface = CodeSurface(
        id="surface-campaign-stats",
        kind="route",
        name="GET /campaigns/:id/stats",
        method="GET",
        path="/campaigns/:id/stats",
        source_file="src/api/routes.js",
        line_number=8,
        auth_guards=["authenticate"],
    )
    model.repository_evidence = _make_repository_evidence(
        surfaces=[surface],
        controls=[
            CodeControlSignal(
                id="control-campaign-auth",
                surface_id=surface.id,
                control_type="authentication",
                strength="strong",
                evidence="authenticate",
            )
        ],
    )
    node_id = uuid.uuid4()

    findings = build_security_review_findings(
        model,
        [],
        [
            _make_node(
                node_id,
                "API layer",
                "process",
                {
                    "mapped_code_surface_ids": [surface.id],
                    "code_mapping_review_status": "approved",
                },
            )
        ],
        [],
        [],
    )

    assert all(
        item.source_object_id != "model:code-evidence-mapping"
        for item in findings.findings
    )


def test_repository_seed_source_refs_clear_matching_code_mapping_gap() -> None:
    model = _make_model()
    surface = CodeSurface(
        id="surface-campaign-stats",
        kind="route",
        name="GET /campaigns/:id/stats",
        method="GET",
        path="/campaigns/:id/stats",
        source_file="src/api/routes.js",
        line_number=8,
        auth_guards=["authenticate"],
    )
    model.repository_evidence = _make_repository_evidence(surfaces=[surface])
    source_id = uuid.uuid4()
    target_id = uuid.uuid4()

    findings = build_security_review_findings(
        model,
        [],
        [
            _make_node(source_id, "API layer", "process", {}),
            _make_node(target_id, "Application service", "process", {}),
        ],
        [
            _make_edge(
                uuid.uuid4(),
                source_id,
                target_id,
                {
                    "repository_seed_source_refs": [
                        "GET /campaigns/:id/stats (src/api/routes.js:8)"
                    ]
                },
            )
        ],
        [],
    )

    assert all(
        item.source_object_id != "model:code-evidence-mapping"
        for item in findings.findings
    )


def test_connected_cloud_iac_and_document_evidence_create_object_anchors() -> None:
    model = _make_model()
    model.repository_evidence = _make_repository_evidence(surfaces=[])
    model.environment_context_summary = "Environment evidence is connected."
    model.documents = [
        SimpleNamespace(
            id=uuid.UUID("11111111-1111-4111-8111-111111111111"),
            filename="architecture.pdf",
            raw_text="Public API sends payment data to the tenant database.",
            parsed_components=None,
        )
    ]
    model.cloud_scan_evidence = CloudScanEvidence(
        provider="prowler",
        filename="prowler.json",
        finding_count=1,
        high_signal_findings=[
            CloudFinding(
                category="internet_exposure",
                severity="High",
                service="ec2",
                resource="sg-123",
                detail="Security group allows public ingress to the API.",
                source_finding_id="prowler-ec2-sg-public-api",
            )
        ],
        exposed_services=["ec2 / sg-123"],
        parsed_at=datetime(2026, 4, 10, tzinfo=timezone.utc),
    ).model_dump(mode="json")
    model.iac_evidence = IacEvidence(
        source_type="single_file",
        filename="main.tf",
        reference="prod/network",
        resource_count=1,
        resource_types=["aws_security_group"],
        resource_names=["aws_security_group.public_api"],
        public_exposure=["main.tf allows 0.0.0.0/0 ingress"],
        parsed_at=datetime(2026, 4, 10, tzinfo=timezone.utc),
    ).model_dump(mode="json")

    findings = build_security_review_findings(
        model,
        [],
        [],
        [],
        [],
    )

    cloud_finding = next(
        item
        for item in findings.findings
        if item.source_object_id == "model:cloud-scan-high-signal"
    )
    iac_finding = next(
        item
        for item in findings.findings
        if item.source_object_id == "model:iac-object-risk"
    )

    assert any(
        anchor.source_object_type == "cloud_finding"
        and anchor.location == "cloud_finding:prowler-ec2-sg-public-api"
        for anchor in cloud_finding.evidence_anchors
    )
    assert any(
        anchor.source_object_type == "iac_resource"
        and anchor.location.startswith("iac_resource:prod/network")
        for anchor in iac_finding.evidence_anchors
    )
    assert any(
        anchor.source_object_type == "document_excerpt"
        and anchor.source_object_id == "11111111-1111-4111-8111-111111111111"
        for anchor in cloud_finding.evidence_anchors
    )

import sys
import types
import uuid
from datetime import date, datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import fitz
import pytest

from app.services import pdf_report


class _FakeThreatModel:
    def __init__(self, threat_model_id: uuid.UUID) -> None:
        self.id = threat_model_id
        self.system_name = "Payments Platform"
        self.description = "Threat model description"
        self.data_classification = "Restricted"
        self.report_template = "default"
        self.report_logo_base64 = None
        self.report_watermark_text = None
        self.owner_id = uuid.uuid4()
        self.organization_id = None
        self.created_at = datetime(2026, 4, 1, tzinfo=timezone.utc)


class _FakeThreat:
    def __init__(
        self,
        *,
        threat_model_id: uuid.UUID,
        display_id: str,
        status: str,
        mitigation_plan: str | None = None,
        mitigation_owner: str | None = None,
        due_date: date | None = None,
        mitigation_notes: str | None = None,
    ) -> None:
        self.id = uuid.uuid4()
        self.threat_model_id = threat_model_id
        self.display_id = display_id
        self.description = f"{display_id} description"
        self.stride_category = "Tampering"
        self.threat_subtype = None
        self.severity = "High"
        self.source = "Rules"
        self.status = status
        self.dismiss_reason = None
        self.rule_id = "T-TEST"
        self.ai_enhanced = False
        self.original_rule_threat_id = None
        self.affected_node_ids = []
        self.affected_edge_ids = []
        self.relevance_rationale = None
        self.mitigation_plan = mitigation_plan
        self.mitigation_owner = mitigation_owner
        self.due_date = due_date
        self.mitigation_notes = mitigation_notes
        self.control_effectiveness = "none"
        self.residual_risk_level = None
        self.provider_managed = False
        self.closed_at = None
        self.created_at = datetime(2026, 4, 1, tzinfo=timezone.utc)


class _FakeScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeScalars:
    def __init__(self, values):
        self._values = values

    def all(self):
        return list(self._values)


class _FakeListResult:
    def __init__(self, values):
        self._values = values

    def scalars(self):
        return _FakeScalars(self._values)


class _FakeValidationRun:
    def __init__(self, threat: _FakeThreat, threat_model: _FakeThreatModel) -> None:
        self.threat_id = threat.id
        self.threat_model_id = threat_model.id
        self.owner_id = threat_model.owner_id
        self.organization_id = threat_model.organization_id
        self.conclusion = "confirmed"
        self.exploitability = {
            "status": "exploitable",
            "attacker_profile": "authenticated low-privilege tenant user",
            "confidence": "high",
        }
        self.domain_agent_plan = [
            {"label": "SAST Agent", "domain_agent": "sast", "tools": ["semgrep"]}
        ]
        self.evidence_refs = [{"id": str(uuid.uuid4())}]
        self.created_at = datetime(2026, 4, 2, tzinfo=timezone.utc)


class _FakeRemediationRun:
    def __init__(self, threat: _FakeThreat, threat_model: _FakeThreatModel) -> None:
        self.threat_id = threat.id
        self.threat_model_id = threat_model.id
        self.owner_id = threat_model.owner_id
        self.organization_id = threat_model.organization_id
        self.status = "handoff_created"
        self.handoff_delivery_status = "delivered"
        self.external_ticket_url = "https://github.com/northstar/export-api/issues/42"
        self.created_at = datetime(2026, 4, 3, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_generate_report_preserves_mitigation_tracking(monkeypatch):
    threat_model_id = uuid.uuid4()
    fake_threat_model = _FakeThreatModel(threat_model_id)
    in_progress_threat = _FakeThreat(
        threat_model_id=threat_model_id,
        display_id="T-001",
        status="In Progress",
        mitigation_plan="Rotate signing keys and enforce mTLS.",
        mitigation_owner="Platform Security",
        due_date=date(2026, 5, 1),
        mitigation_notes="Tracked in TG-42.",
    )
    planned_threat = _FakeThreat(
        threat_model_id=threat_model_id,
        display_id="T-002",
        status="Open",
        mitigation_plan="Add request validation.",
    )

    execute_calls = []

    async def fake_execute(statement):
        execute_calls.append(statement)
        if len(execute_calls) == 1:
            # First call: load ThreatModel
            return _FakeScalarResult(fake_threat_model)
        if len(execute_calls) == 2:
            # Second call: load Threat rows
            return _FakeListResult([in_progress_threat, planned_threat])
        # Third+ calls: scan job / scan threat results — return no scan
        return _FakeScalarResult(None)

    fake_db = MagicMock()
    fake_db.execute = AsyncMock(side_effect=fake_execute)
    monkeypatch.setattr(
        pdf_report,
        "lookup_controls_batch",
        AsyncMock(return_value={in_progress_threat.id: [], planned_threat.id: []}),
    )

    captured_context = {}

    class _FakeTemplate:
        def render(self, **context):
            captured_context.update(context)
            return "<html><body>report</body></html>"

    class _FakeEnvironment:
        def __init__(self, *args, **kwargs):
            pass

        def get_template(self, template_name):
            captured_context["template_name"] = template_name
            return _FakeTemplate()

    class _FakeHtml:
        def __init__(self, *, string):
            self.string = string

        def write_pdf(self):
            return b"%PDF-test%"

    monkeypatch.setattr(pdf_report, "Environment", _FakeEnvironment)
    monkeypatch.setitem(sys.modules, "weasyprint", types.SimpleNamespace(HTML=_FakeHtml))

    pdf_bytes = await pdf_report.generate_report(fake_db, threat_model_id)

    assert pdf_bytes == b"%PDF-test%"
    assert captured_context["template_name"] == "report_structured.html"
    dfd_section = next(
        section for section in captured_context["render_sections"] if section["kind"] == "dfd"
    )
    assert "dfd_integrity_sha256" in dfd_section
    threats_section = next(
        section for section in captured_context["render_sections"] if section["kind"] == "threats"
    )
    assert threats_section["threats"] == [
        {
            "display_id": "T-001",
            "stride_category": "Tampering",
            "severity": "High",
            "description": "T-001 description",
            "source": "Rules",
            "status": "In Progress",
            "relevance_rationale": "",
            "rule_id": "T-TEST",
            "threat_subtype": "",
            "ai_enhanced": False,
            "mitigation_plan": "Rotate signing keys and enforce mTLS.",
            "mitigation_owner": "Platform Security",
            "mitigation_due_date": "2026-05-01",
            "mitigation_status": "In Progress",
            "control_effectiveness": "none",
            "residual_risk_level": "High",
            "provider_managed": False,
            "citations": [],
            "agent_validation": None,
        },
        {
            "display_id": "T-002",
            "stride_category": "Tampering",
            "severity": "High",
            "description": "T-002 description",
            "source": "Rules",
            "status": "Open",
            "relevance_rationale": "",
            "rule_id": "T-TEST",
            "threat_subtype": "",
            "ai_enhanced": False,
            "mitigation_plan": "Add request validation.",
            "mitigation_owner": "",
            "mitigation_due_date": "",
            "mitigation_status": "Planned",
            "control_effectiveness": "none",
            "residual_risk_level": "High",
            "provider_managed": False,
            "citations": [],
            "agent_validation": None,
        },
    ]
    assert pdf_report.REPORTABLE_STATUSES == ("Open", "In Progress", "Mitigated", "Accepted")
    executive_summary = next(
        section
        for section in captured_context["render_sections"]
        if section["kind"] == "executive_summary"
    )
    assert executive_summary["residual_risk_summary"] == {
        "Critical": 0,
        "High": 2,
        "Medium": 0,
        "Low": 0,
        "Negligible": 0,
    }


@pytest.mark.asyncio
async def test_generate_report_includes_agent_validation_outcomes(monkeypatch):
    threat_model_id = uuid.uuid4()
    fake_threat_model = _FakeThreatModel(threat_model_id)
    threat = _FakeThreat(
        threat_model_id=threat_model_id,
        display_id="T-AGENT-001",
        status="Open",
    )
    validation = _FakeValidationRun(threat, fake_threat_model)
    remediation = _FakeRemediationRun(threat, fake_threat_model)
    execute_calls = []

    async def fake_execute(statement):
        execute_calls.append(statement)
        if len(execute_calls) == 1:
            return _FakeScalarResult(fake_threat_model)
        if len(execute_calls) == 2:
            return _FakeListResult([threat])
        if len(execute_calls) == 3:
            return _FakeListResult([validation])
        if len(execute_calls) == 4:
            return _FakeListResult([remediation])
        return _FakeScalarResult(None)

    fake_db = MagicMock()
    fake_db.execute = AsyncMock(side_effect=fake_execute)
    monkeypatch.setattr(
        pdf_report,
        "lookup_controls_batch",
        AsyncMock(return_value={threat.id: []}),
    )

    captured_context = {}

    class _FakeTemplate:
        def render(self, **context):
            captured_context.update(context)
            return "<html><body>report</body></html>"

    class _FakeEnvironment:
        def __init__(self, *args, **kwargs):
            pass

        def get_template(self, template_name):
            return _FakeTemplate()

    class _FakeHtml:
        def __init__(self, *, string):
            self.string = string

        def write_pdf(self):
            return b"%PDF-test%"

    monkeypatch.setattr(pdf_report, "Environment", _FakeEnvironment)
    monkeypatch.setitem(sys.modules, "weasyprint", types.SimpleNamespace(HTML=_FakeHtml))

    await pdf_report.generate_report(fake_db, threat_model_id)

    scan_section = next(
        section
        for section in captured_context["render_sections"]
        if section["kind"] == "scan_validation"
    )
    assert scan_section["agent_validation_results"] == [
        {
            "display_id": "T-AGENT-001",
            "conclusion": "confirmed",
            "exploitability_status": "exploitable",
            "attacker_profile": "authenticated low-privilege tenant user",
            "confidence": "high",
            "evidence_count": 1,
            "domain_agents": [{"label": "SAST Agent", "tools": "semgrep"}],
            "handoff_status": "handoff_created",
            "handoff_delivery_status": "delivered",
            "external_ticket_url": "https://github.com/northstar/export-api/issues/42",
        }
    ]


@pytest.mark.asyncio
async def test_generate_report_writes_parseable_pdf_with_required_sections(monkeypatch):
    threat_model_id = uuid.uuid4()
    fake_threat_model = _FakeThreatModel(threat_model_id)
    fake_threat_model.report_template = "minimal"
    threat = _FakeThreat(
        threat_model_id=threat_model_id,
        display_id="T-001",
        status="Open",
        mitigation_plan="Add integrity checks before writing payment state.",
    )

    execute_calls = []

    async def fake_execute(statement):
        execute_calls.append(statement)
        if len(execute_calls) == 1:
            return _FakeScalarResult(fake_threat_model)
        if len(execute_calls) == 2:
            return _FakeListResult([threat])
        return _FakeScalarResult(None)

    fake_db = MagicMock()
    fake_db.execute = AsyncMock(side_effect=fake_execute)
    monkeypatch.setattr(
        pdf_report,
        "lookup_controls_batch",
        AsyncMock(return_value={threat.id: []}),
    )

    pdf_bytes = await pdf_report.generate_report(
        fake_db,
        threat_model_id,
        dfd_image_base64=(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
        ),
        dfd_integrity_sha256="dfd-sha256-test",
        sections=["executive_summary", "scope", "dfd", "threats", "methodology"],
    )

    assert pdf_bytes.startswith(b"%PDF")
    with fitz.open(stream=pdf_bytes, filetype="pdf") as document:
        assert document.page_count >= 1
        image_count = sum(len(page.get_images(full=True)) for page in document)
        parsed_text = "\n".join(page.get_text("text") for page in document)

    assert image_count >= 1
    for required_text in (
        "Payments Platform",
        "Executive Summary",
        "Scope",
        "Data Flow Diagram",
        "dfd-sha256-test",
        "Threat Scenarios and Findings",
        "T-001",
        "T-001 description",
        "Methodology",
        "STRIDE",
    ):
        assert required_text in parsed_text

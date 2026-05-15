import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ThreatModelPage from "./ThreatModelPage";
import { api } from "../api/client";
import type { ThreatResponse } from "../types/api";

const apiMocks = vi.hoisted(() => ({
  analyze: vi.fn(),
  getDFD: vi.fn(),
  getDFDQualityGates: vi.fn(),
  getEvidenceStatus: vi.fn(),
  getThreatModel: vi.fn(),
  getThreats: vi.fn(),
}));

const diffMocks = vi.hoisted(() => ({
  clearDiff: vi.fn(),
  triggerDiff: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: apiMocks,
}));

vi.mock("../auth/useAuth", () => ({
  useAuth: () => ({
    updateReportTemplateLibrary: vi.fn(),
    user: {
      email: "analyst@example.test",
      email_verified: true,
      organization_name: "ThreatGenix OSS",
      report_template_library: [],
      role: "security_engineer",
    },
  }),
}));

vi.mock("../hooks/useThreatDiff", () => ({
  useThreatDiff: () => ({
    clearDiff: diffMocks.clearDiff,
    diff: null,
    isLoading: false,
    triggerDiff: diffMocks.triggerDiff,
  }),
}));

vi.mock("../components/dfd/DFDCanvas", () => ({
  DFDCanvas: () => <div data-testid="dfd-canvas" />,
}));

vi.mock("../components/DocumentUpload", () => ({
  DocumentUpload: () => <div>Document Upload</div>,
}));

vi.mock("../components/EnvironmentEvidencePanel", () => ({
  EnvironmentEvidencePanel: () => <div>Environment Evidence</div>,
}));

vi.mock("../components/threats/ThreatFilterBar", () => ({
  ThreatFilterBar: ({ visibleCount }: { visibleCount: number }) => (
    <div>Visible threats: {visibleCount}</div>
  ),
}));

vi.mock("../components/threats/ThreatTable", () => ({
  ThreatTable: ({ threats }: { threats: Array<{ display_id: string }> }) => (
    <div data-testid="threat-table">
      {threats.map((threat) => threat.display_id).join(", ")}
    </div>
  ),
}));

vi.mock("../components/threats/ThreatTriageModal", () => ({
  ThreatTriageModal: () => null,
}));

vi.mock("../components/threats/ThreatDashboard", () => ({
  ThreatDashboard: () => <div>Threat Dashboard</div>,
}));

vi.mock("../components/threats/ThreatDiffBanner", () => ({
  ThreatDiffBanner: () => <div>Threat Diff Banner</div>,
}));

vi.mock("../components/threats/ThreatSearchPanel", () => ({
  ThreatSearchPanel: () => <div>Threat Search</div>,
}));

vi.mock("../components/threats/ThreatPriorityStrip", () => ({
  ThreatPriorityStrip: () => <div>Threat Priority Strip</div>,
}));

vi.mock("../components/scan/ScanPanel", () => ({
  ScanPanel: () => <div>Scan Panel</div>,
}));

vi.mock("../components/ThreatModelInspectorRail", () => ({
  ThreatModelInspectorRail: () => <aside>Inspector</aside>,
}));

vi.mock("../components/ThreatModelCodeModal", () => ({
  ThreatModelCodeModal: () => null,
}));

vi.mock("../components/ReportExportModal", () => ({
  ReportExportModal: () => null,
}));

vi.mock("../components/threats/QualificationQueuePanel", () => ({
  QualificationQueuePanel: () => null,
}));

const deterministicRuleThreat: ThreatResponse = {
  id: "threat-1",
  display_id: "T-001",
  description: "Rules-only threat survives provider outage.",
  stride_category: "Tampering",
  threat_subtype: "Data tampering in transit",
  severity: "High",
  source: "Rules",
  status: "Open",
  rule_id: "T-01",
  ai_enhanced: false,
  original_rule_threat_id: null,
  affected_node_ids: ["node-1"],
  affected_edge_ids: ["edge-1"],
  relevance_rationale: "Cross-boundary payment request.",
  mitigation_plan: null,
  mitigation_owner: null,
  mitigation_notes: null,
  dismiss_reason: null,
  due_date: null,
  control_effectiveness: "none",
  residual_risk_level: "High",
  provider_managed: false,
  closed_at: null,
  compliance_controls: [],
  qualification_score: null,
  qualification_label: null,
  qualification_note: null,
  auto_score: null,
  analyst_score: null,
  analyst_score_rationale: null,
  ai_likelihood_score: null,
  ai_likelihood_assessment: null,
  ai_likelihood_generated_at: null,
  cluster_id: null,
  false_positive_reason: null,
  qualification_completed_at: null,
  created_at: "2026-05-15T00:00:00Z",
};

function renderThreatModelPage() {
  return render(
    <MemoryRouter initialEntries={["/threat-models/tm-1"]}>
      <Routes>
        <Route path="/threat-models/:id" element={<ThreatModelPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ThreatModelPage AI degradation", () => {
  beforeEach(() => {
    const storage = new Map<string, string>();
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: {
        clear: vi.fn(() => storage.clear()),
        getItem: vi.fn((key: string) => storage.get(key) ?? null),
        removeItem: vi.fn((key: string) => storage.delete(key)),
        setItem: vi.fn((key: string, value: string) => storage.set(key, value)),
      },
    });
    vi.clearAllMocks();
    vi.mocked(api.getThreatModel).mockResolvedValue({
      id: "tm-1",
      system_name: "Payments API",
      description: "Payment processing model.",
      data_classification: "Restricted",
      regulatory_scope: [],
      deployment_model: "cloud",
      repository_evidence: null,
      cloud_scan_evidence: null,
      iac_evidence: null,
      environment_context_summary: null,
      report_template: "default",
      report_templates: [],
      arch_diagrams: [],
      created_at: "2026-05-15T00:00:00Z",
      updated_at: "2026-05-15T00:00:00Z",
    });
    vi.mocked(api.getDFDQualityGates).mockResolvedValue({
      blocking_count: 0,
      warning_count: 0,
      results: [],
    });
    vi.mocked(api.getEvidenceStatus).mockResolvedValue({
      threat_model_id: "tm-1",
      projection_status: "current",
      generated_at: "2026-05-15T00:00:00Z",
      source_count: 0,
      item_count: 0,
      entity_count: 0,
      relationship_count: 0,
      observation_count: 0,
      finding_count: 0,
      sources_by_type: [],
      items_by_type: [],
      entities_by_type: [],
      findings_by_kind: [],
      freshness: [],
      coverage_gaps: [],
    });
    vi.mocked(api.getDFD).mockResolvedValue({
      nodes: [{
        id: "node-1",
        node_type: "process",
        name: "Payments API",
        position_x: 100,
        position_y: 120,
        trust_boundary_id: null,
        properties: {},
      }],
      edges: [],
      trust_boundaries: [],
    });
    vi.mocked(api.getThreats).mockResolvedValue([]);
    vi.mocked(api.analyze).mockResolvedValue({
      threats: [deterministicRuleThreat],
      ai_skipped_reason: "AI enhancement is currently unavailable",
    });
  });

  it("keeps deterministic rule threats visible and shows the AI outage banner", async () => {
    const user = userEvent.setup();
    renderThreatModelPage();

    const generateButton = await screen.findByRole("button", { name: "Generate Threats" });
    await waitFor(() => expect(generateButton).toBeEnabled());

    await user.click(generateButton);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "AI enhancement is currently unavailable",
    );
    expect(screen.getByTestId("threat-table")).toHaveTextContent("T-001");
    expect(screen.getByText("Visible threats: 1")).toBeInTheDocument();
    expect(api.analyze).toHaveBeenCalledWith("tm-1");
  });
});

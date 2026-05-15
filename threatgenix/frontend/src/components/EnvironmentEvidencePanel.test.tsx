import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EnvironmentEvidencePanel } from "./EnvironmentEvidencePanel";
import type { ThreatModelResponse } from "../types/api";

const { previewRepositoryDfdSeeds, applyRepositoryDfdSeeds } = vi.hoisted(() => ({
  previewRepositoryDfdSeeds: vi.fn(),
  applyRepositoryDfdSeeds: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: {
    previewRepositoryDfdSeeds,
    applyRepositoryDfdSeeds,
    clearRepositoryEvidence: vi.fn(),
    uploadRepositoryEvidence: vi.fn(),
    importRepositoryEvidenceFromGitHub: vi.fn(),
    refreshRepositoryEvidenceFromGitHub: vi.fn(),
    uploadCloudScanEvidence: vi.fn(),
    clearCloudScanEvidence: vi.fn(),
    uploadIacEvidence: vi.fn(),
    clearIacEvidence: vi.fn(),
    importIacIntoDfd: vi.fn(),
  },
}));

function makeModel(): ThreatModelResponse {
  return {
    id: "tm-1",
    system_name: "Repo Seed Review",
    description: "Pull Request Review",
    data_classification: "Confidential",
    regulatory_scope: [],
    deployment_model: null,
    report_templates: [],
    created_at: "2026-05-01T00:00:00Z",
    updated_at: "2026-05-01T00:00:00Z",
    repository_evidence: {
      source_type: "archive",
      filename: "repo.zip",
      connection: null,
      reference: "repo/main",
      file_count: 4,
      languages: ["TypeScript"],
      frameworks: ["React"],
      entrypoints: ["src/main.tsx"],
      api_routes: ["GET /api/reviews"],
      webhook_endpoints: [],
      route_auth_map: [],
      unprotected_routes: [],
      sensitive_routes: [],
      routes_with_raw_input: [],
      risky_routes: [],
      auth_surfaces: [],
      auth_mechanisms: [],
      data_stores: ["PostgreSQL"],
      queues: ["Amazon SQS"],
      external_integrations: [],
      outbound_calls: [],
      deployment_clues: [],
      infrastructure_resources: [],
      security_sensitive_paths: [],
      code_surfaces: [],
      code_control_signals: [],
      code_risk_signals: [],
      finding_code_links: [],
      code_evidence_summary: {
        surface_count: 0,
        route_count: 0,
        control_signal_count: 0,
        risk_signal_count: 0,
        linked_finding_count: 0,
        externally_reachable_surface_count: 0,
        unprotected_sensitive_surface_count: 0,
        verified_control_count: 0,
        missing_control_count: 0,
      },
      dfd_seed_suggestions: [
        {
          id: "repo-seed-api-layer",
          node_type: "process",
          label: "API layer",
          rationale: "Repository route definitions indicate an API surface.",
          source_refs: ["GET /api/reviews"],
          confidence: 0.82,
        },
        {
          id: "repo-seed-postgresql",
          node_type: "data_store",
          label: "PostgreSQL",
          rationale: "Repository dependency hints indicate a data store.",
          source_refs: ["PostgreSQL"],
          confidence: 0.72,
        },
      ],
      warnings: [],
      parsed_at: "2026-05-01T00:00:00Z",
    },
    cloud_scan_evidence: null,
    iac_evidence: null,
    environment_context_summary: null,
  };
}

describe("EnvironmentEvidencePanel", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: {
        getItem: vi.fn(() => null),
        setItem: vi.fn(),
        removeItem: vi.fn(),
        clear: vi.fn(),
      },
    });
  });

  it("previews and applies selected repository DFD seeds", async () => {
    const user = userEvent.setup();
    const onImportedToDfd = vi.fn();
    previewRepositoryDfdSeeds.mockResolvedValue({
      suggestions: [
        {
          suggestion_id: "repo-seed-api-layer",
          label: "API layer",
          node_type: "process",
          rationale: "Repository route definitions indicate an API surface.",
          source_refs: ["GET /api/reviews"],
          confidence: 0.82,
          match_status: "matched_existing",
          matched_node_id: "node-1",
          matched_node_name: "API layer",
          proposed_node: {
            node_type: "process",
            name: "API layer",
          },
        },
        {
          suggestion_id: "repo-seed-postgresql",
          label: "PostgreSQL",
          node_type: "data_store",
          rationale: "Repository dependency hints indicate a data store.",
          source_refs: ["PostgreSQL"],
          confidence: 0.72,
          match_status: "new",
          matched_node_id: null,
          matched_node_name: null,
          proposed_node: {
            node_type: "data_store",
            name: "PostgreSQL",
          },
        },
      ],
      existing_node_count: 1,
      unmatched_suggestion_count: 1,
      inferred_flow_count: 1,
      inferred_boundary_count: 1,
    });
    applyRepositoryDfdSeeds.mockResolvedValue({
      dfd: { nodes: [], edges: [], trust_boundaries: [] },
      summary: {
        requested_suggestion_count: 1,
        matched_existing_nodes: 0,
        created_nodes: 1,
        created_edges: 1,
        created_boundaries: 1,
        skipped_suggestions: [],
        warnings: [],
      },
    });

    render(
      <EnvironmentEvidencePanel
        threatModelId="tm-1"
        model={makeModel()}
        onUpdated={vi.fn()}
        onImportedToDfd={onImportedToDfd}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Preview DFD seeds" }));

    expect(
      await screen.findByText(
        /1 new suggestion from 2 repo-derived seeds with 1 inferred flow and 1 boundary candidate/i,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/Already matched to API layer/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/PostgreSQL/i)).toBeChecked();

    await user.click(screen.getByRole("button", { name: "Apply selected" }));

    await waitFor(() => {
      expect(applyRepositoryDfdSeeds).toHaveBeenCalledWith("tm-1", {
        suggestion_ids: ["repo-seed-postgresql"],
      });
    });
    expect(onImportedToDfd).toHaveBeenCalledWith(
      expect.objectContaining({
        summary: expect.objectContaining({
          created_nodes: 1,
          created_edges: 1,
          created_boundaries: 1,
        }),
      }),
    );
  });
});

import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import IntakeForm from "./IntakeForm";

const { createThreatModel, importRepositoryEvidenceFromGitHub } = vi.hoisted(() => ({
  createThreatModel: vi.fn(),
  importRepositoryEvidenceFromGitHub: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: {
    createThreatModel,
    importRepositoryEvidenceFromGitHub,
  },
}));

describe("IntakeForm", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("blocks overlong architecture summaries before they hit the backend", async () => {
    const user = userEvent.setup();

    render(<IntakeForm onSuccess={vi.fn()} />);

    await user.type(screen.getByLabelText("Application or PR Name"), "Northstar Banking Mesh");
    fireEvent.change(screen.getByLabelText("Review Summary"), {
      target: { value: "x".repeat(501) },
    });
    await user.click(screen.getByRole("button", { name: "Start Security Review" }));

    expect(
      await screen.findByText(/Review summary must be 500 characters or fewer/i),
    ).toBeInTheDocument();
    expect(createThreatModel).not.toHaveBeenCalled();
  });

  it("imports GitHub PR evidence before opening the review", async () => {
    const user = userEvent.setup();
    const onSuccess = vi.fn();
    createThreatModel.mockResolvedValue({
      id: "review-1",
      system_name: "Payments PR",
      description: "Pull Request Review",
      data_classification: "Confidential",
      regulatory_scope: [],
      deployment_model: null,
      repository_evidence: null,
      cloud_scan_evidence: null,
      iac_evidence: null,
      environment_context_summary: null,
      report_templates: [],
      created_at: "2026-05-01T00:00:00Z",
      updated_at: "2026-05-01T00:00:00Z",
    });
    importRepositoryEvidenceFromGitHub.mockResolvedValue({
      repository_evidence: {
        source_type: "archive",
        filename: "example-org-threatgenix.zip",
        reference: "example-org/threatgenix@refs/pull/22/head :: Pull request #22",
        file_count: 5,
        languages: ["TypeScript"],
        frameworks: ["React"],
        entrypoints: [],
        api_routes: [],
        webhook_endpoints: [],
        route_auth_map: [],
        unprotected_routes: [],
        sensitive_routes: [],
        routes_with_raw_input: [],
        risky_routes: [],
        auth_surfaces: [],
        auth_mechanisms: [],
        data_stores: [],
        queues: [],
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
        warnings: [],
        parsed_at: "2026-05-01T00:00:00Z",
      },
      cloud_scan_evidence: null,
      iac_evidence: null,
      environment_context_summary: "Repository Evidence",
    });

    render(<IntakeForm onSuccess={onSuccess} />);

    await user.type(screen.getByLabelText("Application or PR Name"), "Payments PR");
    await user.selectOptions(screen.getByLabelText("Review Goal"), "Pull Request Review");
    await user.type(
      screen.getByLabelText("GitHub Repo or PR"),
      "https://github.com/example-org/threatgenix/pull/22",
    );
    await user.click(screen.getByRole("button", { name: "Start Security Review" }));

    expect(importRepositoryEvidenceFromGitHub).toHaveBeenCalledWith("review-1", {
      repository: "example-org/threatgenix",
      ref: "refs/pull/22/head",
      reference: "Pull request #22",
      pull_request_number: 22,
      pull_request_url: "https://github.com/example-org/threatgenix/pull/22",
    }, undefined);
    expect(onSuccess).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "review-1",
        repository_evidence: expect.objectContaining({
          reference: "example-org/threatgenix@refs/pull/22/head :: Pull request #22",
        }),
      }),
    );
  });

  it("passes a one-time GitHub token for private repo intake and clears it", async () => {
    const user = userEvent.setup();
    createThreatModel.mockResolvedValue({
      id: "review-private-1",
      system_name: "Private Repo Review",
      description: "Repo/Application Review",
      data_classification: "Confidential",
      regulatory_scope: [],
      deployment_model: null,
      repository_evidence: null,
      cloud_scan_evidence: null,
      iac_evidence: null,
      environment_context_summary: null,
      report_templates: [],
      created_at: "2026-05-01T00:00:00Z",
      updated_at: "2026-05-01T00:00:00Z",
    });
    importRepositoryEvidenceFromGitHub.mockRejectedValue(
      new Error("GitHub repository could not be accessed"),
    );

    render(<IntakeForm onSuccess={vi.fn()} />);

    await user.type(screen.getByLabelText("Application or PR Name"), "Private Repo Review");
    await user.type(screen.getByLabelText("GitHub Repo or PR"), "example-org/private-app");
    await user.type(screen.getByLabelText("GitHub Access Token"), "github_pat_private");
    await user.click(screen.getByRole("button", { name: "Start Security Review" }));

    expect(importRepositoryEvidenceFromGitHub).toHaveBeenCalledWith(
      "review-private-1",
      {
        repository: "example-org/private-app",
        ref: undefined,
        reference: "Repo/Application Review",
        pull_request_number: undefined,
        pull_request_url: undefined,
      },
      "github_pat_private",
    );
    expect(await screen.findByLabelText("GitHub Access Token")).toHaveValue("");
    expect(
      screen.getByText(/Re-enter the token in Environment Setup/i),
    ).toBeInTheDocument();
  });
});

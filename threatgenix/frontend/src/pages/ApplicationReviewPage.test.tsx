import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import type {
  ApplicationReview,
  ApplicationReviewAIExplanation,
  ApplicationReviewArtifact,
  ApplicationReviewContextPacket,
  ApplicationReviewContextSearchResponse,
  ApplicationReviewDecision,
} from "../types/api";
import ApplicationReviewPage from "./ApplicationReviewPage";

vi.mock("../api/client", () => ({
  api: {
    getApplicationReview: vi.fn(),
    getApplicationReviewArtifact: vi.fn(),
    getAgentReviewStatus: vi.fn(),
    searchApplicationReviewContext: vi.fn(),
    getApplicationReviewContextPacket: vi.fn(),
    getApplicationReviewAIExplanation: vi.fn(),
    rebuildApplicationReviewContextIndex: vi.fn(),
    evaluateApplicationReviewDecision: vi.fn(),
  },
}));

const review: ApplicationReview = {
  id: "review-1",
  tenant_key: "user:1",
  owner_id: "owner-1",
  organization_id: null,
  threat_model_id: "tm-1",
  parent_review_id: null,
  review_lineage_id: "lineage-1",
  app_name: "ExampleApp",
  invocation_surface: "cli",
  input_kind: "diff",
  status: "completed",
  decision: "verify",
  commit_sha: "abc123",
  bundle_hash: null,
  scope_fingerprint: "a".repeat(64),
  idempotency_key: "review-key",
  requested_tools: ["semgrep"],
  scope: {},
  context: {},
  policy: {},
  result_summary: "High-severity scanner evidence needs supporting context.",
  error_message: null,
  created_at: "2026-05-01T00:00:00Z",
  updated_at: "2026-05-01T00:00:00Z",
};

const context: ApplicationReviewContextSearchResponse = {
  review_id: "review-1",
  query: "",
  results: [
    {
      id: "entry-1",
      review_id: "review-1",
      source_type: "scan_finding",
      source_object_id: "finding-1",
      item_type: "scanner_finding",
      title: "Sensitive export route is missing authorization",
      body: "severity=high missing authorization sensitive customer export",
      keywords: ["severity=high", "authorization"],
      facets: { severity: "high" },
      retrieval_text: "severity=high missing authorization sensitive customer export",
      source_refs: [{ type: "path", path: "apps/api/users.py:42" }],
      content_hash: "d".repeat(64),
      status: "active",
      stale_reason: null,
      created_at: "2026-05-01T00:00:00Z",
      updated_at: "2026-05-01T00:00:00Z",
    },
  ],
};

const artifact: ApplicationReviewArtifact = {
  review,
  web_url: "https://threatgenix.example/reviews/review-1",
  decision_record: {
    decision: "verify",
    reason: "High-severity scanner evidence needs supporting context.",
    evidence_snapshot_hash: "e".repeat(64),
    decision_engine_version: "appsec-decision-v1.0.0",
    decision_trace: ["engine:appsec-decision-v1.0.0", "scanner_only_high_requires_verification"],
  },
  raw_evidence: context.results,
  raw_evidence_count: 1,
  has_stale_evidence: false,
  missing_evidence: [],
  source_ref_count: 1,
  evidence_chains: [
    {
      chain_id: "chain:dddddddddddddddd",
      title: "Sensitive export route is missing authorization",
      item_type: "scanner_finding",
      status: "active",
      stale_reason: null,
      content_hash: "d".repeat(64),
      source_refs: [{ type: "path", path: "apps/api/users.py:42" }],
      steps: [
        {
          step_type: "context_entry",
          label: "scanner_finding: Sensitive export route is missing authorization",
          source_ref: null,
          content_hash: "d".repeat(64),
        },
        {
          step_type: "source_ref",
          label: "path: apps/api/users.py:42",
          source_ref: { type: "path", path: "apps/api/users.py:42" },
          content_hash: "d".repeat(64),
        },
      ],
    },
  ],
  graph_slice: {
    nodes: [
      {
        id: "review:review-1",
        label: "ExampleApp",
        node_type: "review",
        evidence_hashes: [],
        status: "completed",
      },
      {
        id: "evidence:dddddddddddddddd",
        label: "Sensitive export route is missing authorization",
        node_type: "scanner_finding",
        evidence_hashes: ["d".repeat(64)],
        status: "active",
      },
      {
        id: "source:path-apps-api-users.py:42",
        label: "path: apps/api/users.py:42",
        node_type: "source_ref",
        evidence_hashes: ["d".repeat(64)],
        status: null,
      },
    ],
    edges: [
      {
        source: "review:review-1",
        target: "evidence:dddddddddddddddd",
        relationship: "contains_evidence",
        evidence_hashes: ["d".repeat(64)],
      },
      {
        source: "evidence:dddddddddddddddd",
        target: "source:path-apps-api-users.py:42",
        relationship: "supported_by_source_ref",
        evidence_hashes: ["d".repeat(64)],
      },
    ],
    missing_context: [],
  },
  fix_plan: [
    {
      title: "Resolve cited scanner finding",
      action: "Patch the affected code or attach proof that the scanner signal is not exploitable.",
      verification: "Rerun the review and confirm the decision changes.",
      cited_content_hashes: ["d".repeat(64)],
      source_refs: [{ type: "path", path: "apps/api/users.py:42" }],
    },
  ],
  accepted_risks: [],
  rerun_history: [
    {
      review_id: "review-1",
      parent_review_id: null,
      status: "completed",
      decision: "verify",
      commit_sha: "abc123",
      evidence_snapshot_hash: "e".repeat(64),
      updated_at: "2026-05-01T00:00:00Z",
    },
  ],
  redacted: true,
};

const packet: ApplicationReviewContextPacket = {
  version: "threatgenix_context_packet_v1",
  review_id: "review-1",
  app_name: "ExampleApp",
  commit_sha: "abc123",
  deterministic_decision: "verify",
  policy: {},
  evidence_snapshot_hash: "f".repeat(64),
  entries: [
    {
      entry_id: "entry-1",
      item_type: "scanner_finding",
      title: "Sensitive export route is missing authorization",
      untrusted_text: "[UNTRUSTED_REVIEW_CONTEXT_BEGIN]\nseverity=high\n[UNTRUSTED_REVIEW_CONTEXT_END]",
      source_refs: [{ type: "path", path: "apps/api/users.py:42" }],
      content_hash: "d".repeat(64),
    },
  ],
  missing_evidence: ["No cloud exposure evidence was indexed."],
};

const aiExplanation: ApplicationReviewAIExplanation = {
  review_id: "review-1",
  packet,
  output: {
    summary: "Deterministic decision is verify. Grounded evidence includes export route evidence.",
    proposed_decision: "verify",
    cited_content_hashes: ["d".repeat(64)],
    fix_plan: [
      {
        title: "Verify missing evidence",
        remediation: "Add cloud exposure evidence before changing the deterministic decision.",
        cited_content_hashes: ["d".repeat(64)],
      },
    ],
  },
  validation: { valid: true, errors: [] },
  explanation_status: "ready",
  prompt_contract: ["Do not change deterministic decision."],
};

const agentStatus = {
  review,
  web_url: "https://threatgenix.example/reviews/review-1",
  api_status_url: "https://threatgenix.example/api/agent/reviews/review-1/status",
  terminal_commands: [
    {
      label: "Check review status",
      command:
        'curl -sS -H "Authorization: Bearer $THREATGENIX_TOKEN" "https://threatgenix.example/api/agent/reviews/review-1/status"',
      description: "Reads the tenant-scoped review, decision, web URL, and agent command contract.",
    },
  ],
  agent_tools: [
    {
      name: "threatgenix.review.status",
      method: "GET",
      endpoint: "https://threatgenix.example/api/agent/reviews/review-1/status",
      description: "Return review status, decision, web URL, and terminal command hints.",
    },
  ],
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/reviews/review-1"]}>
      <Routes>
        <Route path="/reviews/:reviewId" element={<ApplicationReviewPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ApplicationReviewPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getApplicationReview).mockResolvedValue(review);
    vi.mocked(api.getApplicationReviewArtifact).mockResolvedValue(artifact);
    vi.mocked(api.getAgentReviewStatus).mockResolvedValue(agentStatus);
    vi.mocked(api.searchApplicationReviewContext).mockResolvedValue(context);
    vi.mocked(api.getApplicationReviewContextPacket).mockResolvedValue(packet);
    vi.mocked(api.getApplicationReviewAIExplanation).mockResolvedValue(aiExplanation);
    vi.mocked(api.rebuildApplicationReviewContextIndex).mockResolvedValue({
      review_id: "review-1",
      entry_count: 1,
    });
    vi.mocked(api.evaluateApplicationReviewDecision).mockResolvedValue({
      review_id: "review-1",
      decision: "block",
      reason: "High-severity scanner evidence is supported by indexed application context.",
      evidence_hashes: ["d".repeat(64)],
      scanner_only: false,
      evidence_snapshot_hash: "e".repeat(64),
      decision_engine_version: "appsec-decision-v1.0.0",
      replayed: false,
      decision_trace: ["engine:appsec-decision-v1.0.0"],
    } satisfies ApplicationReviewDecision);
  });

  it("renders the direct application review artifact with findings and source refs", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { name: "ExampleApp" })).toBeInTheDocument();
    expect(screen.getAllByText("Verify").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole("heading", { name: "Invoke Anywhere" })).toBeInTheDocument();
    expect(screen.getByText("Check review status")).toBeInTheDocument();
    expect(screen.getByText(/THREATGENIX_TOKEN/)).toBeInTheDocument();
    expect(screen.getByText("GET threatgenix.review.status")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Review Artifact" })).toBeInTheDocument();
    expect(screen.getByText("https://threatgenix.example/reviews/review-1")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Raw Evidence" })).toBeInTheDocument();
    expect(screen.getByText("appsec-decision-v1.0.0")).toBeInTheDocument();
    expect(screen.getByText("scanner_only_high_requires_verification")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Evidence Chains" })).toBeInTheDocument();
    expect(screen.getByText("1 chains")).toBeInTheDocument();
    expect(screen.getByText("context_entry")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Graph Slice" })).toBeInTheDocument();
    expect(screen.getByText("3 nodes / 2 edges")).toBeInTheDocument();
    expect(screen.getByText(/contains_evidence/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Artifact Fix Plan" })).toBeInTheDocument();
    expect(screen.getByText("Resolve cited scanner finding")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Rerun History" })).toBeInTheDocument();
    expect(screen.getByText("abc123")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Accepted Risks" })).toBeInTheDocument();
    expect(screen.getByText("No accepted risks are indexed for this review.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Grounded AI Explanation" })).toBeInTheDocument();
    expect(screen.getAllByText(/Grounded evidence includes export route evidence/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("Verify missing evidence")).toBeInTheDocument();
    expect(screen.getAllByText(/Add cloud exposure evidence/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole("heading", { name: "Customer-Ready Report" })).toBeInTheDocument();
    expect(screen.getByText(/Security Review Report: ExampleApp/)).toBeInTheDocument();
    expect(screen.getAllByText("Sensitive export route is missing authorization").length).toBeGreaterThanOrEqual(3);
    expect(screen.getAllByText("path: apps/api/users.py:42").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText("No cloud exposure evidence was indexed.")).toBeInTheDocument();
    expect(screen.getByText(new RegExp(`Evidence snapshot: ${"f".repeat(16)}`))).toBeInTheDocument();
  });

  it("evaluates the deterministic decision and reloads the review", async () => {
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "Evaluate Decision" }));

    await waitFor(() => {
      expect(api.evaluateApplicationReviewDecision).toHaveBeenCalledWith("review-1");
    });
    expect(api.getApplicationReview).toHaveBeenCalledTimes(2);
  });

  it("copies the customer-ready report markdown when the browser exposes clipboard", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "Copy Report" }));

    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(expect.stringContaining("# Security Review Report: ExampleApp"));
    });
    expect(screen.getByText("Copied report.")).toBeInTheDocument();
  });

  it("normalizes load failures into a branded not-found state", async () => {
    vi.mocked(api.getApplicationReview).mockRejectedValue(new Error("404: Review not found"));

    renderPage();

    expect(
      await screen.findByRole("heading", { name: "Application review not found" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("404: Review not found")).not.toBeInTheDocument();
  });
});

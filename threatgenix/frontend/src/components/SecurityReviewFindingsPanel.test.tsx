import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type {
  SecurityReviewFindingListResponse,
  ThreatModelResponse,
} from "../types/api";
import { SecurityReviewFindingsPanel } from "./SecurityReviewFindingsPanel";

const emptyFindingsResponse = {
  threat_model_id: "tm-1",
  generated_at: "2026-05-01T00:00:00Z",
  counts: {
    total: 0,
    by_priority: {},
    by_status: {},
    by_queue_bucket: {},
    by_primary_mode: {},
  },
  findings: [],
} as unknown as SecurityReviewFindingListResponse;

const model = {
  id: "tm-1",
  system_name: "SSR hosted QA smoke",
  description: "Hosted reviewer journey QA smoke model.",
  data_classification: "Internal",
} as unknown as ThreatModelResponse;

describe("SecurityReviewFindingsPanel", () => {
  it("shows an evidence-limited empty state instead of asking for a missing finding", () => {
    render(
      <SecurityReviewFindingsPanel
        threatModelId="tm-1"
        model={model}
        threats={[]}
        findingsResponse={emptyFindingsResponse}
        selectedFindingId={null}
        onSelectFinding={vi.fn()}
        onQueueBucketChange={vi.fn()}
        onStatusChange={vi.fn()}
        onRiskAcceptanceSubmit={vi.fn()}
        onCreateArtifact={vi.fn()}
      />,
    );

    expect(screen.getByText("No application findings yet.")).toBeInTheDocument();
    expect(screen.getByText(/This does not mean the application is secure/i)).toBeInTheDocument();
    expect(screen.getByText("Evidence-limited review state.")).toBeInTheDocument();
    expect(screen.queryByText("Select a review finding.")).not.toBeInTheDocument();
  });
});

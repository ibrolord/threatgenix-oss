import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PortfolioSummary, PortfolioTrendResponse } from "../types/api";
import DashboardPage from "./DashboardPage";
import { api } from "../api/client";

vi.mock("../api/client", () => ({
  api: {
    getPortfolioSummary: vi.fn(),
    getPortfolioTrends: vi.fn(),
  },
}));

vi.mock("../auth/useAuth", () => ({
  useAuth: () => ({
    user: {
      email: "analyst@example.com",
      full_name: "Security Analyst",
      role: "security_engineer",
      organization_id: "org-1",
      organization_name: "Acme Security",
      organization_subscription_tier: "enterprise",
      organization_is_active: true,
      is_active: true,
      email_verified: true,
      report_template_library: [],
    },
  }),
}));

const mockSummary: PortfolioSummary = {
  total_models: 2,
  total_threats: 15,
  threats_by_severity: {
    Critical: 2,
    High: 3,
    Medium: 6,
    Low: 4,
  },
  threats_by_status: {
    Open: 2,
    Accepted: 5,
    Dismissed: 8,
  },
  threats_by_stride: {
    Spoofing: 1,
  },
  residual_risk_by_level: {
    High: 1,
  },
  models_by_classification: {
    Restricted: 1,
    Internal: 1,
  },
  controls_by_status: {
    implemented: 2,
  },
  open_reviews: 0,
  models_pending_review: 0,
  models_with_drift: 0,
  shared_models: 0,
  open_assignments: 0,
  overdue_assignments: 0,
  unread_notifications: 0,
  recent_models: [
    {
      id: "tm-1",
      system_name: "Northstar Bank — Open Banking API Platform",
      data_classification: "Restricted",
      created_at: "2026-04-16T00:00:00Z",
      updated_at: "2026-04-17T00:00:00Z",
      threat_count: 12,
    },
    {
      id: "tm-2",
      system_name: "Treasury Ledger",
      data_classification: "Internal",
      created_at: "2026-04-15T00:00:00Z",
      updated_at: "2026-04-16T00:00:00Z",
      threat_count: 3,
    },
  ],
};

const mockTrends: PortfolioTrendResponse = {
  latest_summary: "Threat activity is flattening.",
  points: [
    {
      date: "2026-04-15",
      snapshot_count: 1,
      threat_count: 10,
      high_risk_threat_count: 4,
      review_events: 1,
      control_events: 0,
    },
  ],
};

describe("DashboardPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getPortfolioSummary).mockResolvedValue(mockSummary);
    vi.mocked(api.getPortfolioTrends).mockResolvedValue(mockTrends);
  });

  it("surfaces the focused pilot metrics and removes deferred dashboard cards", async () => {
    render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    );

    expect(await screen.findByText("Critical + High")).toBeInTheDocument();
    expect(screen.getByText("Acme Security")).toBeInTheDocument();
    expect(screen.getByText("Enterprise SaaS")).toBeInTheDocument();
    expect(screen.getByText("AI boundary: review Settings")).toBeInTheDocument();
    expect(screen.getByText("Triage Progress")).toBeInTheDocument();
    expect(screen.queryByText("Shared Models")).not.toBeInTheDocument();
    expect(screen.queryByText("Open Assignments")).not.toBeInTheDocument();
    expect(screen.queryByText("Unread Notifications")).not.toBeInTheDocument();
    expect(screen.queryByText("Governance & Validation")).not.toBeInTheDocument();
    expect(screen.queryByText("Residual Risk Profile")).not.toBeInTheDocument();

    expect(screen.getByText("Critical + High").parentElement).toHaveClass("dashboard-summary-card-critical");
    expect(screen.getByText("Triage Progress").parentElement).toHaveClass("dashboard-summary-card-success");
    expect(screen.getByText("Restricted")).toHaveStyle("background: #7c3aed;");
  });

  it("preserves the empty state when there are no models", async () => {
    vi.mocked(api.getPortfolioSummary).mockResolvedValue({
      ...mockSummary,
      total_models: 0,
      total_threats: 0,
      threats_by_severity: {},
      threats_by_status: {},
      recent_models: [],
    });
    vi.mocked(api.getPortfolioTrends).mockResolvedValue({
      latest_summary: "",
      points: [],
    });

    render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    );

    expect(await screen.findByText("Start Your First Security Review")).toBeInTheDocument();
    expect(screen.queryByText("Critical + High")).not.toBeInTheDocument();
    expect(screen.queryByText("Trend Activity")).not.toBeInTheDocument();
  });
});

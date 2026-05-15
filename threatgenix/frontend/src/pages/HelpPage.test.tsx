import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import HelpPage from "./HelpPage";

function renderHelpPage() {
  return render(
    <MemoryRouter>
      <HelpPage />
    </MemoryRouter>,
  );
}

describe("HelpPage", () => {
  it("documents the current product security journey", () => {
    renderHelpPage();

    expect(screen.getByRole("heading", { name: "Help & Documentation" })).toBeInTheDocument();
    expect(screen.getByText("6. Review Evidence and Validation")).toBeInTheDocument();
    expect(screen.getByText("7. Export Stakeholder Output")).toBeInTheDocument();
    expect(screen.getByText(/Open Security Review for the dedicated queue/i)).toBeInTheDocument();
    expect(screen.getByText(/Bind global evidence to DFD nodes/i)).toBeInTheDocument();

    expect(screen.queryByText(/Click Submit/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Analyze with AI/i)).not.toBeInTheDocument();
  });
});

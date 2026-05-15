import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { GenerateThreatsButton } from "./GenerateThreatsButton";

const { analyze } = vi.hoisted(() => ({
  analyze: vi.fn(),
}));

vi.mock("../../api/client", () => ({
  api: {
    analyze,
  },
}));

describe("GenerateThreatsButton", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("explains DFD readiness and does not call analysis while disabled by a reason", async () => {
    const user = userEvent.setup();
    const disabledReason =
      "Build or upload a DFD before generating threats. ThreatGenix needs components, data flows, or trust boundaries to run STRIDE analysis.";

    render(
      <GenerateThreatsButton
        threatModelId="tm-1"
        onGenerated={vi.fn()}
        disabledReason={disabledReason}
      />,
    );

    const button = screen.getByRole("button", { name: "Generate Threats" });
    expect(button).toBeDisabled();
    expect(screen.getByText(disabledReason)).toBeInTheDocument();

    await user.click(button);

    expect(analyze).not.toHaveBeenCalled();
  });
});

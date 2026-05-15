import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { DFDComponentTemplateResponse } from "../../types/api";
import { DFDStencilPalette } from "./DFDStencilPalette";

const customTemplate: DFDComponentTemplateResponse = {
  id: "custom-kafka-broker",
  built_in: false,
  label: "Kafka Broker",
  description: "Reusable internal event broker.",
  semantic_node_type: "data_store",
  shape: "queue",
  group: "Messaging",
  default_name: "Kafka Broker",
  default_properties: { store_type: "queue" },
  ai_generated: false,
  rationale: null,
};

describe("DFDStencilPalette", () => {
  it("surfaces custom component creation and placement", async () => {
    const user = userEvent.setup();
    const onCreateNode = vi.fn();
    const onCreateTemplate = vi.fn();
    const onCreateCustom = vi.fn();

    render(
      <DFDStencilPalette
        customTemplates={[customTemplate]}
        onHide={vi.fn()}
        onCreateNode={onCreateNode}
        onCreateTemplate={onCreateTemplate}
        onCreateBoundary={vi.fn()}
        onCreateCustom={onCreateCustom}
      />
    );

    expect(screen.getByText("Your Components")).toBeInTheDocument();
    expect(screen.getByText("Messaging")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Create custom" }));
    expect(onCreateCustom).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: /Kafka Broker/i }));
    expect(onCreateTemplate).toHaveBeenCalledWith(customTemplate);

    await user.click(screen.getByRole("button", { name: /Process/i }));
    expect(onCreateNode).toHaveBeenCalledWith("process");
  });
});

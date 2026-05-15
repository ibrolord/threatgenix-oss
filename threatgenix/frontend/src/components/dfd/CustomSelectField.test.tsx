import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { CustomSelectField } from "./CustomSelectField";

describe("CustomSelectField", () => {
  it("lets users switch a dropdown into custom mode and type a value", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(
      <CustomSelectField
        id="auth-type"
        label="Authentication"
        value="oauth2"
        options={[
          { value: "none", label: "None" },
          { value: "oauth2", label: "OAuth 2" },
        ]}
        onChange={onChange}
        customPlaceholder="Enter a custom authentication type"
      />
    );

    await user.selectOptions(screen.getByLabelText("Authentication"), "__custom__");
    const customInput = screen.getByPlaceholderText("Enter a custom authentication type");
    await user.type(customInput, "FIDO2");

    expect(onChange).toHaveBeenLastCalledWith("FIDO2");
  });

  it("hydrates unknown saved values back into the custom input", () => {
    render(
      <CustomSelectField
        id="boundary-type"
        label="Boundary Type"
        value="Partner Zone"
        options={[
          { value: "network", label: "Network" },
          { value: "cloud", label: "Cloud" },
        ]}
        onChange={vi.fn()}
        customPlaceholder="Enter a custom boundary type"
      />
    );

    expect(screen.getByLabelText("Boundary Type")).toHaveValue("__custom__");
    expect(screen.getByDisplayValue("Partner Zone")).toBeInTheDocument();
  });

  it("does not reset custom mode when the callback identity changes", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const { rerender } = render(
      <CustomSelectField
        id="semantic-type"
        label="Semantic Type"
        value="process"
        options={[
          { value: "process", label: "Process" },
          { value: "data_store", label: "Data Store" },
        ]}
        onChange={onChange}
        onCustomModeChange={vi.fn()}
        customPlaceholder="Enter a custom semantic type"
      />
    );

    await user.selectOptions(screen.getByLabelText("Semantic Type"), "__custom__");
    const customInput = screen.getByPlaceholderText("Enter a custom semantic type");
    await user.type(customInput, "Event Broker");

    rerender(
      <CustomSelectField
        id="semantic-type"
        label="Semantic Type"
        value="process"
        options={[
          { value: "process", label: "Process" },
          { value: "data_store", label: "Data Store" },
        ]}
        onChange={onChange}
        onCustomModeChange={vi.fn()}
        customPlaceholder="Enter a custom semantic type"
      />
    );

    expect(screen.getByPlaceholderText("Enter a custom semantic type")).toHaveValue("Event Broker");
  });
});

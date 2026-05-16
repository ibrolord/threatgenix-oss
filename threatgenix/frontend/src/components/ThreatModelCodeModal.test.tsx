import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import { ThreatModelCodeModal } from "./ThreatModelCodeModal";

vi.mock("../api/client", () => ({
  api: {
    exportTMAC: vi.fn(),
    getTMACScaffold: vi.fn(),
    validateTMAC: vi.fn(),
    diffTMAC: vi.fn(),
    importTMAC: vi.fn(),
    assistantRespond: vi.fn(),
  },
}));

const defaultValidation = {
  format: "yaml" as const,
  summary: {
    node_count: 2,
    edge_count: 1,
    boundary_count: 1,
    built_in_view_count: 4,
    custom_view_count: 1,
    threat_count: 3,
    assumption_count: 1,
    control_count: 1,
    component_template_count: 1,
    property_option_count: 1,
    snapshot_count: 0,
    review_count: 0,
    collaborator_count: 0,
    assignment_count: 0,
    notification_count: 0,
  },
  warnings: [],
};

const defaultDiff = {
  current_summary: {
    node_count: 1,
    edge_count: 0,
    boundary_count: 0,
    built_in_view_count: 4,
    custom_view_count: 0,
    threat_count: 0,
    assumption_count: 0,
    control_count: 0,
    component_template_count: 0,
    property_option_count: 0,
    snapshot_count: 0,
    review_count: 0,
    collaborator_count: 0,
    assignment_count: 0,
    notification_count: 0,
  },
  incoming_summary: defaultValidation.summary,
  changed_sections: ["dfd", "threats"],
  warnings: [],
};

describe("ThreatModelCodeModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.exportTMAC).mockResolvedValue(
      new Blob(["tmac_version: '1.0'\nmetadata:\n  system_name: Live Model\n"], {
        type: "application/x-yaml",
      }),
    );
    vi.mocked(api.getTMACScaffold).mockResolvedValue(
      new Blob(["tmac_version: '1.0'\nmetadata:\n  system_name: Scaffold\n"], {
        type: "application/x-yaml",
      }),
    );
    vi.mocked(api.validateTMAC).mockResolvedValue(defaultValidation);
    vi.mocked(api.diffTMAC).mockResolvedValue(defaultDiff);
    vi.mocked(api.importTMAC).mockResolvedValue({
      mode: "replace",
      threat_model_id: "tm-123",
      system_name: "Scoped Model",
      created_new: false,
      applied_operational_state: true,
      applied_binary_assets: true,
      summary: defaultValidation.summary,
      warnings: [],
    });
    vi.mocked(api.assistantRespond).mockResolvedValue({
      mode: "build",
      answer:
        "```yaml\ntmac_version: '1.0'\nmetadata:\n  system_name: AI Draft\n```",
      references: [],
      findings: [],
      action_artifacts: [],
      guided_steps: [],
      proposal: null,
      degraded_reason: null,
    });
  });

  it("loads the live TMAC document into the editor on open", async () => {
    render(
      <ThreatModelCodeModal
        threatModelId="tm-123"
        onClose={vi.fn()}
        onImported={vi.fn()}
      />,
    );

    await waitFor(() => {
      expect(api.exportTMAC).toHaveBeenCalledWith("tm-123", "yaml", {
        include_operational_state: false,
        include_binary_assets: false,
      });
    });

    expect(await screen.findByDisplayValue(/system_name: Live Model/)).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Open TMAC Guide" })[0]).toHaveAttribute(
      "href",
      "/docs/tmac",
    );
  });

  it("validates editor content and renders the summary and live diff", async () => {
    const user = userEvent.setup();

    render(
      <ThreatModelCodeModal
        threatModelId="tm-123"
        onClose={vi.fn()}
        onImported={vi.fn()}
      />,
    );

    const editor = await screen.findByPlaceholderText(
      "The live TMAC document loads here. You can also paste YAML or JSON.",
    );

    fireEvent.change(editor, { target: { value: "tmac_version: '1.0'" } });
    await user.click(screen.getByRole("button", { name: "Validate Now" }));

    await waitFor(() => {
      expect(api.validateTMAC).toHaveBeenCalledWith("tmac_version: '1.0'");
      expect(api.diffTMAC).toHaveBeenCalledWith("tm-123", "tmac_version: '1.0'");
    });

    expect(screen.getByText("Detected as YAML and structurally valid.")).toBeInTheDocument();
    expect(screen.getByText("Changed sections: dfd, threats.")).toBeInTheDocument();
    expect(screen.getAllByText("Nodes")[0]).toBeInTheDocument();
    expect(screen.getAllByText("2")[0]).toBeInTheDocument();
  });

  it("can request an AI draft and load it into the editor", async () => {
    const user = userEvent.setup();

    render(
      <ThreatModelCodeModal
        threatModelId="tm-123"
        onClose={vi.fn()}
        onImported={vi.fn()}
      />,
    );

    const editor = await screen.findByPlaceholderText(
      "The live TMAC document loads here. You can also paste YAML or JSON.",
    );

    fireEvent.change(editor, {
      target: { value: "tmac_version: '1.0'\nmetadata:\n  system_name: Before AI" },
    });
    await user.type(
      screen.getByPlaceholderText(
        "Tell AI what to review, explain, or change. For example: Add a secrets vault and update the related threats.",
      ),
      "Rename the system and keep the TMAC valid.",
    );
    await user.click(screen.getByRole("button", { name: "Generate Draft" }));

    await waitFor(() => {
      expect(api.assistantRespond).toHaveBeenCalledWith(
        "tm-123",
        expect.objectContaining({
          mode_hint: "build",
          message: expect.stringContaining("Rename the system and keep the TMAC valid."),
        }),
      );
    });

    await user.click(screen.getByRole("button", { name: "Load AI Draft into Editor" }));

    expect(await screen.findByDisplayValue(/system_name: AI Draft/)).toBeInTheDocument();
  });

  it("blocks whole-document AI passes for oversized drafts", async () => {
    const user = userEvent.setup();

    render(
      <ThreatModelCodeModal
        threatModelId="tm-123"
        onClose={vi.fn()}
        onImported={vi.fn()}
      />,
    );

    const editor = await screen.findByPlaceholderText(
      "The live TMAC document loads here. You can also paste YAML or JSON.",
    );
    fireEvent.change(editor, { target: { value: "a".repeat(12_001) } });

    await user.click(screen.getByRole("button", { name: "Generate Draft" }));

    expect(await screen.findByText(/This TMAC draft is large for a whole-document AI pass\./)).toBeInTheDocument();
    expect(api.assistantRespond).not.toHaveBeenCalled();
  });

  it("passes scope options through export and import actions", async () => {
    const user = userEvent.setup();
    const onImported = vi.fn();
    const createObjectURL = vi.fn(() => "blob:mock");
    const revokeObjectURL = vi.fn();
    const originalCreateObjectURL = URL.createObjectURL;
    const originalRevokeObjectURL = URL.revokeObjectURL;
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    Object.defineProperty(URL, "createObjectURL", {
      value: createObjectURL,
      configurable: true,
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      value: revokeObjectURL,
      configurable: true,
    });

    render(
      <ThreatModelCodeModal
        threatModelId="tm-123"
        onClose={vi.fn()}
        onImported={onImported}
      />,
    );

    const editor = await screen.findByPlaceholderText(
      "The live TMAC document loads here. You can also paste YAML or JSON.",
    );
    fireEvent.change(editor, { target: { value: "tmac_version: '1.0'" } });

    await user.click(screen.getByLabelText("Include governance and collaboration state"));
    await user.click(screen.getByLabelText("Include embedded reporting assets"));
    await user.click(screen.getByRole("button", { name: "Download TMAC" }));

    await waitFor(() => {
      expect(api.exportTMAC).toHaveBeenLastCalledWith("tm-123", "yaml", {
        include_operational_state: true,
        include_binary_assets: true,
      });
    });

    await user.click(screen.getByRole("button", { name: "Apply to Live Model" }));

    await waitFor(() => {
      expect(api.importTMAC).toHaveBeenCalledWith({
        content: "tmac_version: '1.0'",
        mode: "replace",
        target_threat_model_id: "tm-123",
        apply_operational_state: true,
        apply_binary_assets: true,
      });
    });

    expect(onImported).toHaveBeenCalled();

    clickSpy.mockRestore();
    Object.defineProperty(URL, "createObjectURL", {
      value: originalCreateObjectURL,
      configurable: true,
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      value: originalRevokeObjectURL,
      configurable: true,
    });
  });
});

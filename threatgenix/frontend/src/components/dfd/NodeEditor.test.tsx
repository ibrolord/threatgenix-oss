import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { NodeEditor } from "./NodeEditor";

const {
  getDFDComponentTemplates,
  getDFDPropertyOptions,
  updateNode,
} = vi.hoisted(() => ({
  getDFDComponentTemplates: vi.fn(),
  getDFDPropertyOptions: vi.fn(),
  updateNode: vi.fn(),
}));

vi.mock("../../api/client", () => ({
  api: {
    getDFDComponentTemplates,
    getDFDPropertyOptions,
    updateNode,
    createDFDPropertyOption: vi.fn(),
    suggestDFDPropertyOption: vi.fn(),
    deleteDFDPropertyOption: vi.fn(),
  },
}));

describe("NodeEditor", () => {
  beforeEach(() => {
    getDFDComponentTemplates.mockReset();
    getDFDPropertyOptions.mockReset();
    updateNode.mockReset();
    getDFDComponentTemplates.mockResolvedValue([]);
    getDFDPropertyOptions.mockResolvedValue([]);
    updateNode.mockResolvedValue({
      id: "node-1",
      node_type: "api_gateway",
      name: "Public API",
      position_x: 0,
      position_y: 0,
      trust_boundary_id: null,
      scan_target_url: "https://api.example.com",
      scan_target_ports: "443,8443",
      properties: {},
    });
  });

  it("saves scan target metadata as node fields", async () => {
    const user = userEvent.setup();
    const onSaved = vi.fn();

    render(
      <NodeEditor
        threatModelId="tm-1"
        nodeId="node-1"
        initialName="Public API"
        initialType="api_gateway"
        initialProperties={{}}
        initialScanTargetUrl={null}
        initialScanTargetPorts={null}
        onSaved={onSaved}
        onClose={vi.fn()}
      />,
    );

    await user.type(await screen.findByLabelText("Target URL"), "https://api.example.com");
    await user.type(screen.getByLabelText("Ports"), "443,8443");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(updateNode).toHaveBeenCalledWith(
      "tm-1",
      "node-1",
      expect.objectContaining({
        scan_target_url: "https://api.example.com",
        scan_target_ports: "443,8443",
      }),
      null,
    );
    expect(onSaved).toHaveBeenCalledWith(expect.objectContaining({
      scan_target_url: "https://api.example.com",
    }));
  });
});

import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  DFDComponentTemplateResponse,
  DFDResponse,
} from "../../types/api";
import { DFDCanvas } from "./DFDCanvas";

const {
  getDFD,
  getDFDComponentTemplates,
  getDFDViews,
} = vi.hoisted(() => ({
  getDFD: vi.fn(),
  getDFDComponentTemplates: vi.fn(),
  getDFDViews: vi.fn(),
}));

vi.mock("../../api/client", () => ({
  api: {
    getDFD,
    getDFDComponentTemplates,
    getDFDViews,
  },
}));

vi.mock("@xyflow/react", async () => {
  const React = await vi.importActual<typeof import("react")>("react");

  return {
    MarkerType: { ArrowClosed: "arrowclosed" },
    SelectionMode: { Partial: "partial" },
    Position: { Left: "left", Right: "right" },
    getBezierPath: () => ["M0,0 C0,0 1,1 1,1", 0, 0],
    BaseEdge: () => null,
    EdgeLabelRenderer: ({ children }: { children: React.ReactNode }) =>
      React.createElement(React.Fragment, null, children),
    Handle: (props: Record<string, unknown>) =>
      React.createElement("span", { ...props, "data-testid": "mock-handle" }),
    useNodesState: (initialNodes: unknown[]) => {
      const [nodes, setNodes] = React.useState(initialNodes);
      return [nodes, setNodes, vi.fn()];
    },
    useEdgesState: (initialEdges: unknown[]) => {
      const [edges, setEdges] = React.useState(initialEdges);
      return [edges, setEdges, vi.fn()];
    },
    ReactFlow: ({
      nodes,
      onInit,
    }: {
      nodes: Array<{
        id: string;
        data?: {
          label?: string;
          onHandleClick?: (
            event: React.MouseEvent<HTMLButtonElement>,
            nodeId: string,
            side: "source" | "target"
          ) => void;
        };
      }>;
      onInit?: (instance: {
        screenToFlowPosition: (point: { x: number; y: number }) => { x: number; y: number };
        fitView: () => void;
        setViewport: () => void;
        zoomIn: () => void;
        zoomOut: () => void;
      }) => void;
    }) => {
      React.useEffect(() => {
        onInit?.({
          screenToFlowPosition: (point) => point,
          fitView: vi.fn(),
          setViewport: vi.fn(),
          zoomIn: vi.fn(),
          zoomOut: vi.fn(),
        });
      }, [onInit]);

      return React.createElement(
        "div",
        { "data-testid": "mock-react-flow" },
        nodes.map((node) =>
          React.createElement(
            "div",
            {
              key: node.id,
              className: "react-flow__node",
              "data-id": node.id,
            },
            React.createElement("span", null, node.data?.label),
            React.createElement(
              "button",
              {
                type: "button",
                "aria-label": "Add or connect a downstream node",
                onClick: (event: React.MouseEvent<HTMLButtonElement>) =>
                  node.data?.onHandleClick?.(event, node.id, "source"),
              },
              "+"
            )
          )
        )
      );
    },
  };
});

const baseDfd: DFDResponse = {
  nodes: [
    {
      id: "node-1",
      node_type: "process",
      name: "Payment Processor",
      position_x: 200,
      position_y: 160,
      trust_boundary_id: null,
      properties: {},
    },
  ],
  edges: [],
  trust_boundaries: [],
};

const quickAddTemplate: DFDComponentTemplateResponse = {
  id: "api-gateway",
  built_in: true,
  label: "API Gateway",
  description: "External ingress layer",
  semantic_node_type: "api_gateway",
  shape: "gateway",
  group: "Network",
  default_name: "API Gateway",
  default_properties: {},
  ai_generated: false,
  rationale: null,
};

describe("DFDCanvas", () => {
  beforeEach(() => {
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: {
        getItem: vi.fn(() => null),
        setItem: vi.fn(),
        removeItem: vi.fn(),
        clear: vi.fn(),
      },
    });
    getDFD.mockResolvedValue(baseDfd);
    getDFDViews.mockResolvedValue([]);
    getDFDComponentTemplates.mockResolvedValue([quickAddTemplate]);
  });

  it("positions the quick-add menu relative to the flow surface when the stencil palette is open", async () => {
    const originalGetBoundingClientRect = HTMLElement.prototype.getBoundingClientRect;
    vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (
      this: HTMLElement
    ) {
      if (this.classList.contains("dfd-flow-surface")) {
        return {
          x: 260,
          y: 100,
          left: 260,
          top: 100,
          right: 1000,
          bottom: 560,
          width: 740,
          height: 460,
          toJSON: () => ({}),
        };
      }
      if (this.classList.contains("dfd-canvas-stage")) {
        return {
          x: 0,
          y: 100,
          left: 0,
          top: 100,
          right: 1000,
          bottom: 560,
          width: 1000,
          height: 460,
          toJSON: () => ({}),
        };
      }
      return originalGetBoundingClientRect.call(this);
    });

    render(<DFDCanvas threatModelId="tm-1" />);

    const quickAddButton = await screen.findByRole("button", {
      name: "Add or connect a downstream node",
    });
    fireEvent.click(quickAddButton, { clientX: 600, clientY: 220 });

    const menu = await screen.findByRole("menu", { name: "Quick add DFD node" });
    expect(menu).toHaveStyle({ left: "354px", top: "120px" });
    await waitFor(() => expect(getDFD).toHaveBeenCalledWith("tm-1", null));
  });
});

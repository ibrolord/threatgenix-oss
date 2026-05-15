import type { Node } from "@xyflow/react";
import type { TrustBoundaryResponse } from "../../types/api";

const BOUNDARY_PADDING = 20;
export const DEFAULT_BOUNDARY_WIDTH = 280;
export const DEFAULT_BOUNDARY_HEIGHT = 180;
export const MIN_BOUNDARY_WIDTH = 220;
export const MIN_BOUNDARY_HEIGHT = 140;
const NODE_WIDTH = 180;
const NODE_HEIGHT = 64;

function mergeBoundaryGeometry(
  storedGeometry: { x: number; y: number; width: number; height: number },
  derivedGeometry: { x: number; y: number; width: number; height: number } | null
): { x: number; y: number; width: number; height: number } {
  if (!derivedGeometry) {
    return storedGeometry;
  }

  const left = Math.min(storedGeometry.x, derivedGeometry.x);
  const top = Math.min(storedGeometry.y, derivedGeometry.y);
  const right = Math.max(
    storedGeometry.x + storedGeometry.width,
    derivedGeometry.x + derivedGeometry.width
  );
  const bottom = Math.max(
    storedGeometry.y + storedGeometry.height,
    derivedGeometry.y + derivedGeometry.height
  );

  return {
    x: left,
    y: top,
    width: right - left,
    height: bottom - top,
  };
}

export function buildBoundaryNodes(
  boundaries: TrustBoundaryResponse[],
  nodePositions: Map<string, { x: number; y: number }>,
  mode: "stored" | "derive" = "stored"
): Node[] {
  return boundaries.map((boundary) => {
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;

    for (const nodeId of boundary.node_ids) {
      const pos = nodePositions.get(nodeId);
      if (!pos) continue;
      minX = Math.min(minX, pos.x);
      minY = Math.min(minY, pos.y);
      maxX = Math.max(maxX, pos.x + NODE_WIDTH);
      maxY = Math.max(maxY, pos.y + NODE_HEIGHT);
    }

    const derivedGeometry = Number.isFinite(minX)
      ? {
          x: minX - BOUNDARY_PADDING,
          y: minY - BOUNDARY_PADDING,
          width: maxX - minX + BOUNDARY_PADDING * 2,
          height: maxY - minY + BOUNDARY_PADDING * 2,
        }
      : null;
    const geometry =
      mode === "derive"
        ? derivedGeometry ?? {
            x: boundary.position_x ?? 0,
            y: boundary.position_y ?? 0,
            width: boundary.width ?? DEFAULT_BOUNDARY_WIDTH,
            height: boundary.height ?? DEFAULT_BOUNDARY_HEIGHT,
          }
        : mergeBoundaryGeometry(
            {
              x: boundary.position_x ?? derivedGeometry?.x ?? 0,
              y: boundary.position_y ?? derivedGeometry?.y ?? 0,
              width: boundary.width ?? derivedGeometry?.width ?? DEFAULT_BOUNDARY_WIDTH,
              height: boundary.height ?? derivedGeometry?.height ?? DEFAULT_BOUNDARY_HEIGHT,
            },
            derivedGeometry
          );

    return {
      id: boundary.id,
      type: "trustBoundary",
      draggable: false,
      selectable: true,
      focusable: false,
      zIndex: 10,
      position: {
        x: geometry.x,
        y: geometry.y,
      },
      data: {
        label: boundary.name,
        boundary_type: boundary.boundary_type,
        parent_boundary_id: boundary.parent_boundary_id ?? null,
      },
      style: {
        width: geometry.width,
        height: geometry.height,
      },
    };
  });
}

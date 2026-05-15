import type {
  MouseEvent as ReactMouseEvent,
  PointerEvent as ReactPointerEvent,
} from "react";
import type { Node, NodeProps, ResizeParams } from "@xyflow/react";
import type { BoundaryType, KnownBoundaryType } from "../../types/api";
import {
  MIN_BOUNDARY_HEIGHT,
  MIN_BOUNDARY_WIDTH,
} from "./trustBoundaryGeometry";

export type TrustBoundaryData = {
  label: string;
  boundary_type?: BoundaryType;
  parent_boundary_id?: string | null;
  onEdit?: (boundaryId: string) => void;
  onMoveStart?: (boundaryId: string) => void;
  onMoveEnd?: (boundaryId: string, position: { x: number; y: number }) => void;
  onResizeEnd?: (boundaryId: string, params: ResizeParams) => void;
};
export type TrustBoundaryNodeType = Node<TrustBoundaryData, "trustBoundary">;

const BOUNDARY_STYLES: Record<
  KnownBoundaryType,
  { borderColor: string; background: string; label: string; accent: string }
> = {
  network: {
    borderColor: "#38bdf8",
    background: "rgba(14, 165, 233, 0.08)",
    label: "Network",
    accent: "#0f172a",
  },
  organizational: {
    borderColor: "#a78bfa",
    background: "rgba(139, 92, 246, 0.08)",
    label: "Third-Party / Org",
    accent: "#2e1065",
  },
  regulatory: {
    borderColor: "#f87171",
    background: "rgba(239, 68, 68, 0.08)",
    label: "Regulatory Scope",
    accent: "#7f1d1d",
  },
  privilege: {
    borderColor: "#fbbf24",
    background: "rgba(245, 158, 11, 0.08)",
    label: "Privileged Zone",
    accent: "#78350f",
  },
  cloud: {
    borderColor: "#34d399",
    background: "rgba(16, 185, 129, 0.08)",
    label: "Cloud Scope",
    accent: "#064e3b",
  },
};

function isKnownBoundaryType(value: BoundaryType | undefined): value is KnownBoundaryType {
  if (!value) {
    return false;
  }
  return value in BOUNDARY_STYLES;
}
function getViewportZoom(nodeElement: HTMLElement): number {
  const viewport = nodeElement.closest<HTMLElement>(".react-flow__viewport");
  if (!viewport) {
    return 1;
  }

  const transform = window.getComputedStyle(viewport).transform;
  if (!transform || transform === "none") {
    return 1;
  }

  try {
    const matrix = new DOMMatrixReadOnly(transform);
    return matrix.a || 1;
  } catch {
    return 1;
  }
}

function beginBoundaryResizeDrag(
  boundaryElement: HTMLElement,
  startClientX: number,
  startClientY: number,
  edges: {
    resizeLeft: boolean;
    resizeRight: boolean;
    resizeTop: boolean;
    resizeBottom: boolean;
  },
  inputMode: "mouse" | "pointer",
  onResizeEnd: (params: ResizeParams) => void
) {
  const zoom = getViewportZoom(boundaryElement);
  const startWidth = boundaryElement.offsetWidth;
  const startHeight = boundaryElement.offsetHeight;
  const initialTransform = window.getComputedStyle(boundaryElement).transform;
  const initialMatrix =
    initialTransform && initialTransform !== "none"
      ? new DOMMatrixReadOnly(initialTransform)
      : new DOMMatrixReadOnly();
  const startX = initialMatrix.e;
  const startY = initialMatrix.f;

  boundaryElement.classList.add("dfd-trust-boundary-resizing");

  const applyPreviewSize = (clientX: number, clientY: number) => {
    const deltaX = (clientX - startClientX) / zoom;
    const deltaY = (clientY - startClientY) / zoom;
    let nextX = startX;
    let nextY = startY;
    let nextWidth = startWidth;
    let nextHeight = startHeight;

    if (edges.resizeLeft) {
      nextWidth = Math.max(MIN_BOUNDARY_WIDTH, startWidth - deltaX);
      nextX = startX + (startWidth - nextWidth);
    } else if (edges.resizeRight) {
      nextWidth = Math.max(MIN_BOUNDARY_WIDTH, startWidth + deltaX);
    }

    if (edges.resizeTop) {
      nextHeight = Math.max(MIN_BOUNDARY_HEIGHT, startHeight - deltaY);
      nextY = startY + (startHeight - nextHeight);
    } else if (edges.resizeBottom) {
      nextHeight = Math.max(MIN_BOUNDARY_HEIGHT, startHeight + deltaY);
    }

    boundaryElement.style.width = `${nextWidth}px`;
    boundaryElement.style.height = `${nextHeight}px`;
    boundaryElement.style.transform = `translate(${nextX}px, ${nextY}px)`;
    return { nextX, nextY, nextWidth, nextHeight };
  };

  const handlePointerMove = (moveEvent: PointerEvent) => {
    applyPreviewSize(moveEvent.clientX, moveEvent.clientY);
  };

  const handleMouseMove = (moveEvent: MouseEvent) => {
    applyPreviewSize(moveEvent.clientX, moveEvent.clientY);
  };

  const finish = (clientX: number, clientY: number) => {
    const { nextX, nextY, nextWidth, nextHeight } = applyPreviewSize(clientX, clientY);
    boundaryElement.classList.remove("dfd-trust-boundary-resizing");
    window.removeEventListener("pointermove", handlePointerMove);
    window.removeEventListener("pointerup", cleanupPointer);
    window.removeEventListener("mousemove", handleMouseMove);
    window.removeEventListener("mouseup", cleanupMouse);
    onResizeEnd({
      x: nextX,
      y: nextY,
      width: nextWidth,
      height: nextHeight,
    });
  };

  const cleanupPointer = (endEvent: PointerEvent) => {
    finish(endEvent.clientX, endEvent.clientY);
  };

  const cleanupMouse = (endEvent: MouseEvent) => {
    finish(endEvent.clientX, endEvent.clientY);
  };

  if (inputMode === "pointer") {
    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", cleanupPointer);
    return;
  }

  window.addEventListener("mousemove", handleMouseMove);
  window.addEventListener("mouseup", cleanupMouse);
}

function beginBoundaryMoveDrag(
  boundaryElement: HTMLElement,
  startClientX: number,
  startClientY: number,
  inputMode: "mouse" | "pointer",
  onMoveEnd: (position: { x: number; y: number }) => void
) {
  const zoom = getViewportZoom(boundaryElement);
  const initialTransform = window.getComputedStyle(boundaryElement).transform;
  const initialMatrix =
    initialTransform && initialTransform !== "none"
      ? new DOMMatrixReadOnly(initialTransform)
      : new DOMMatrixReadOnly();
  const startX = initialMatrix.e;
  const startY = initialMatrix.f;

  boundaryElement.classList.add("dfd-trust-boundary-dragging");

  const applyPreviewMove = (clientX: number, clientY: number) => {
    const deltaX = (clientX - startClientX) / zoom;
    const deltaY = (clientY - startClientY) / zoom;
    const nextX = startX + deltaX;
    const nextY = startY + deltaY;
    boundaryElement.style.transform = `translate(${nextX}px, ${nextY}px)`;
    return { nextX, nextY };
  };

  const handlePointerMove = (moveEvent: PointerEvent) => {
    applyPreviewMove(moveEvent.clientX, moveEvent.clientY);
  };

  const handleMouseMove = (moveEvent: MouseEvent) => {
    applyPreviewMove(moveEvent.clientX, moveEvent.clientY);
  };

  const finish = (clientX: number, clientY: number) => {
    const { nextX, nextY } = applyPreviewMove(clientX, clientY);
    boundaryElement.classList.remove("dfd-trust-boundary-dragging");
    boundaryElement.style.transform = `translate(${nextX}px, ${nextY}px)`;
    window.removeEventListener("pointermove", handlePointerMove);
    window.removeEventListener("pointerup", cleanupPointer);
    window.removeEventListener("mousemove", handleMouseMove);
    window.removeEventListener("mouseup", cleanupMouse);
    onMoveEnd({ x: nextX, y: nextY });
  };

  const cleanupPointer = (endEvent: PointerEvent) => {
    finish(endEvent.clientX, endEvent.clientY);
  };

  const cleanupMouse = (endEvent: MouseEvent) => {
    finish(endEvent.clientX, endEvent.clientY);
  };

  if (inputMode === "pointer") {
    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", cleanupPointer);
    return;
  }

  window.addEventListener("mousemove", handleMouseMove);
  window.addEventListener("mouseup", cleanupMouse);
}

export function TrustBoundaryNode({
  id,
  data,
  selected,
}: NodeProps<TrustBoundaryNodeType>) {
  const label = data.label || "Trust Boundary";
  const boundaryStyle = isKnownBoundaryType(data.boundary_type)
    ? BOUNDARY_STYLES[data.boundary_type]
    : null;
  const isEditable = Boolean(data.onEdit);
  const isMovable = Boolean(data.onMoveEnd);
  const isResizable = Boolean(data.onResizeEnd);
  const prefersPointerEvents =
    typeof window !== "undefined" && "PointerEvent" in window;

  const handleBoundaryMovePointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    const dragHandle = event.currentTarget;
    const pointerId = event.pointerId;
    const boundaryElement = event.currentTarget.closest<HTMLElement>(".react-flow__node");
    if (!boundaryElement || !isMovable) {
      return;
    }
    data.onMoveStart?.(id);
    dragHandle.setPointerCapture?.(pointerId);
    beginBoundaryMoveDrag(
      boundaryElement,
      event.clientX,
      event.clientY,
      "pointer",
      (position) => {
        try {
          if (dragHandle.hasPointerCapture?.(pointerId)) {
            dragHandle.releasePointerCapture(pointerId);
          }
        } catch {
          // Ignore stale pointer-capture cleanup and keep the state update flowing.
        }
        data.onMoveEnd?.(id, position);
      }
    );
  };

  const handleBoundaryMoveMouseDown = (event: ReactMouseEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    const boundaryElement = event.currentTarget.closest<HTMLElement>(".react-flow__node");
    if (!boundaryElement || !isMovable) {
      return;
    }
    data.onMoveStart?.(id);
    beginBoundaryMoveDrag(boundaryElement, event.clientX, event.clientY, "mouse", (position) => {
      data.onMoveEnd?.(id, position);
    });
  };

  const maybeStartBoundaryResize = (
    shellElement: HTMLDivElement,
    target: HTMLElement | null,
    clientX: number,
    clientY: number,
    preventDefault: () => void,
    stopPropagation: () => void,
    inputMode: "mouse" | "pointer",
    capture?: () => void,
    release?: () => void
  ) => {
    if (!isResizable) {
      return;
    }
    if (target?.closest(".dfd-boundary-edit-button")) {
      return;
    }
    if (target?.closest(".dfd-boundary-drag-handle")) {
      return;
    }

    const shellRect = shellElement.getBoundingClientRect();
    const nearLeftEdge = clientX - shellRect.left <= 18;
    const nearRightEdge = shellRect.right - clientX <= 28;
    const nearTopEdge = clientY - shellRect.top <= 18;
    const nearBottomEdge = shellRect.bottom - clientY <= 28;
    if (!nearLeftEdge && !nearRightEdge && !nearTopEdge && !nearBottomEdge) {
      return;
    }

    preventDefault();
    stopPropagation();

    const boundaryElement = shellElement.closest<HTMLElement>(".react-flow__node");
    if (!boundaryElement) {
      return;
    }
    capture?.();
    beginBoundaryResizeDrag(
      boundaryElement,
      clientX,
      clientY,
      {
        resizeLeft: nearLeftEdge,
        resizeRight: !nearLeftEdge && nearRightEdge,
        resizeTop: nearTopEdge,
        resizeBottom: !nearTopEdge && nearBottomEdge,
      },
      inputMode,
      (params) => {
        release?.();
        data.onResizeEnd?.(id, params);
      }
    );
  };

  const handleBoundaryPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    const shellElement = event.currentTarget;
    const pointerId = event.pointerId;
    maybeStartBoundaryResize(
      shellElement,
      event.target as HTMLElement | null,
      event.clientX,
      event.clientY,
      () => event.preventDefault(),
      () => event.stopPropagation(),
      "pointer",
      () => shellElement.setPointerCapture?.(pointerId),
      () => {
        try {
          if (shellElement.hasPointerCapture?.(pointerId)) {
            shellElement.releasePointerCapture(pointerId);
          }
        } catch {
          // Ignore stale pointer-capture cleanup and keep the resize commit flowing.
        }
      }
    );
  };

  const handleBoundaryMouseDown = (event: ReactMouseEvent<HTMLDivElement>) => {
    maybeStartBoundaryResize(
      event.currentTarget,
      event.target as HTMLElement | null,
      event.clientX,
      event.clientY,
      () => event.preventDefault(),
      () => event.stopPropagation(),
      "mouse"
    );
  };

  return (
    <div
      className={`dfd-trust-boundary-shell${selected ? " dfd-trust-boundary-shell-selected" : ""}`}
      data-testid="dfd-trust-boundary"
      data-boundary-id={id}
      data-boundary-name={label}
      data-selected={selected ? "true" : "false"}
      style={{
        width: "100%",
        height: "100%",
        border: `2px ${boundaryStyle ? "solid" : "dashed"} ${boundaryStyle?.borderColor ?? "#999"}`,
        borderRadius: 8,
        background: boundaryStyle?.background ?? "transparent",
        position: "relative",
        pointerEvents: "none",
        transition: "box-shadow 140ms ease, background 140ms ease",
      }}
    >
      <div
        className={`dfd-boundary-drag-surface${isMovable ? " dfd-boundary-drag-handle nodrag nopan" : ""}`}
        title={isMovable ? "Drag to move trust boundary" : label}
        aria-label={isMovable ? "Drag to move trust boundary" : label}
        onPointerDown={isMovable ? handleBoundaryMovePointerDown : undefined}
        onMouseDown={
          isMovable && !prefersPointerEvents ? handleBoundaryMoveMouseDown : undefined
        }
      >
        <span
          className="dfd-boundary-label"
          style={{
            fontSize: 12,
            fontWeight: 600,
            color: boundaryStyle?.accent ?? "#666",
            background: "rgba(255,255,255,0.85)",
            padding: "1px 6px",
            borderRadius: 2,
          }}
        >
          {label}
        </span>
      </div>
      {isMovable ? (
        <>
          <span
            aria-hidden="true"
            className="dfd-boundary-frame-handle dfd-boundary-frame-handle-top nodrag nopan"
            onPointerDown={handleBoundaryMovePointerDown}
            onMouseDown={!prefersPointerEvents ? handleBoundaryMoveMouseDown : undefined}
          />
          <span
            aria-hidden="true"
            className="dfd-boundary-frame-handle dfd-boundary-frame-handle-right nodrag nopan"
            onPointerDown={handleBoundaryMovePointerDown}
            onMouseDown={!prefersPointerEvents ? handleBoundaryMoveMouseDown : undefined}
          />
          <span
            aria-hidden="true"
            className="dfd-boundary-frame-handle dfd-boundary-frame-handle-bottom nodrag nopan"
            onPointerDown={handleBoundaryMovePointerDown}
            onMouseDown={!prefersPointerEvents ? handleBoundaryMoveMouseDown : undefined}
          />
          <span
            aria-hidden="true"
            className="dfd-boundary-frame-handle dfd-boundary-frame-handle-left nodrag nopan"
            onPointerDown={handleBoundaryMovePointerDown}
            onMouseDown={!prefersPointerEvents ? handleBoundaryMoveMouseDown : undefined}
          />
        </>
      ) : null}
      {data.boundary_type ? (
        <span
          style={{
            position: "absolute",
            top: 6,
            right: isEditable || isResizable ? 62 : 8,
            fontSize: 11,
            fontWeight: 700,
            color: boundaryStyle?.accent ?? "#334155",
            background: "rgba(255,255,255,0.9)",
            padding: "1px 6px",
            borderRadius: 999,
            pointerEvents: "none",
          }}
        >
          {boundaryStyle?.label ?? data.boundary_type}
        </span>
      ) : null}
      {isResizable ? (
        <span
          className="dfd-boundary-resize-control nodrag nopan"
          aria-label="Drag to resize trust boundary"
          title="Drag to resize trust boundary"
          onPointerDown={handleBoundaryPointerDown}
          onMouseDown={!prefersPointerEvents ? handleBoundaryMouseDown : undefined}
        >
          <span className="dfd-boundary-resize-control-icon" aria-hidden="true">
            ↘
          </span>
        </span>
      ) : null}
      {isEditable ? (
        <button
          type="button"
          className="dfd-boundary-edit-button nodrag nopan"
          onClick={(event) => {
            event.preventDefault();
            event.stopPropagation();
            data.onEdit?.(id);
          }}
        >
          Edit
        </button>
      ) : null}
    </div>
  );
}

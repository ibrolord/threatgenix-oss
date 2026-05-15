import type { CSSProperties, MouseEvent as ReactMouseEvent } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
} from "@xyflow/react";
import type { Edge, EdgeProps } from "@xyflow/react";

import type { EdgeProperties } from "../../types/api";

export interface SemanticFlowEdgeData extends Record<string, unknown> {
  flowLabel: string;
  displayLabel: string;
  properties: EdgeProperties;
  crossesBoundary?: boolean;
  riskState?: "normal" | "crossing" | "risky";
  missingMetadata?: string[];
  metadataPrompt?: string;
  onEdit?: (edgeId: string) => void;
  onOpenContextMenu?: (event: ReactMouseEvent<HTMLElement>, edgeId: string) => void;
  onOpenNodeContextMenu?: (event: ReactMouseEvent<HTMLElement>, nodeId: string) => void;
}

type SemanticFlowRenderableEdge = Edge<SemanticFlowEdgeData>;

const labelBaseStyle: CSSProperties = {
  position: "absolute",
  transform: "translate(-50%, -50%)",
  pointerEvents: "all",
};

export function SemanticFlowEdge({
  id,
  sourceX,
  sourceY,
  sourcePosition,
  targetX,
  targetY,
  targetPosition,
  markerEnd,
  style,
  selected,
  data,
}: EdgeProps<SemanticFlowRenderableEdge>): JSX.Element {
  const edgeData = (data ?? {}) as SemanticFlowEdgeData;
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const displayLabel = edgeData.displayLabel || "Add flow details";
  const missingMetadata = edgeData.missingMetadata ?? [];
  const metadataSummary = [
    edgeData.properties.protocol?.trim(),
    edgeData.properties.data_classification,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <>
      <BaseEdge id={id} path={edgePath} markerEnd={markerEnd} style={style} interactionWidth={24} />
      <EdgeLabelRenderer>
        <button
          type="button"
          className={[
            "dfd-edge-label-button",
            !edgeData.displayLabel ? "dfd-edge-label-button-placeholder" : "",
            edgeData.crossesBoundary ? "dfd-edge-label-button-boundary-crossing" : "",
            edgeData.riskState === "risky" ? "dfd-edge-label-button-risky" : "",
            selected ? "dfd-edge-label-button-selected" : "",
          ]
            .filter(Boolean)
            .join(" ")}
          style={{
            ...labelBaseStyle,
            transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
          }}
          onClick={(event) => {
            event.preventDefault();
            event.stopPropagation();
            edgeData.onEdit?.(id);
          }}
          onDoubleClick={(event) => {
            event.preventDefault();
            event.stopPropagation();
            edgeData.onEdit?.(id);
          }}
          onContextMenu={(event) => {
            event.preventDefault();
            event.stopPropagation();
            const overlappingNode = event.currentTarget.ownerDocument
              .elementsFromPoint(event.clientX, event.clientY)
              .map((element) =>
                element instanceof HTMLElement
                  ? element.closest<HTMLElement>(".react-flow__node[data-id]")
                  : null
              )
              .find((candidate) => candidate?.dataset.id)?.dataset.id;

            if (overlappingNode) {
              edgeData.onOpenNodeContextMenu?.(event, overlappingNode);
              return;
            }
            edgeData.onOpenContextMenu?.(event, id);
          }}
        >
          <span className="dfd-edge-label-title">{displayLabel}</span>
          {metadataSummary && (
            <span className="dfd-edge-label-summary dfd-edge-label-detail">{metadataSummary}</span>
          )}
          {edgeData.crossesBoundary && (
            <span
              className={`dfd-edge-label-chip dfd-edge-label-detail${edgeData.riskState === "risky" ? " dfd-edge-label-chip-risky" : ""}`}
            >
              {edgeData.riskState === "risky" ? "Risky crossing" : "Boundary crossing"}
            </span>
          )}
          {edgeData.properties.lifecycle_stage && (
            <span className="dfd-edge-label-chip dfd-edge-label-detail">
              {edgeData.properties.lifecycle_stage.replace(/_/g, " ")}
            </span>
          )}
          {missingMetadata.length > 0 && (
            <span className="dfd-edge-label-meta dfd-edge-label-detail">
              {edgeData.metadataPrompt ?? `Missing ${missingMetadata.join(", ")}`}
            </span>
          )}
        </button>
      </EdgeLabelRenderer>
    </>
  );
}

import { useEffect, useState, useMemo, useCallback, useRef } from "react";
import {
  ReactFlow,
  MarkerType,
  SelectionMode,
  useNodesState,
  useEdgesState,
} from "@xyflow/react";
import type {
  Node,
  Edge,
  Connection,
  NodeChange,
  ReactFlowInstance,
  ResizeParams,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";

import { api } from "../../api/client";
import type {
  DFDResponse,
  DFDEdgeResponse,
  DFDNodeResponse,
  DFDComponentTemplateResponse,
  TrustBoundaryResponse,
  AssumptionAnchorTarget,
  NodeType,
  NodeProperties,
  EdgeProperties,
  DFDBulkSave,
  DFDViewResponse,
  AssistantReference,
  BoundaryType,
} from "../../types/api";
import {
  type DFDNodeData,
  type FocusThreatsHandler,
  type OpenDecompositionHandler,
  type SpawnHandleClickHandler,
  type SpawnHandleSide,
} from "./DFDNodeTypes";
import { nodeTypes } from "./nodeTypes";
import {
  TrustBoundaryNode,
} from "./TrustBoundaryNode";
import {
  buildBoundaryNodes,
  DEFAULT_BOUNDARY_HEIGHT,
  DEFAULT_BOUNDARY_WIDTH,
  MIN_BOUNDARY_HEIGHT,
  MIN_BOUNDARY_WIDTH,
} from "./trustBoundaryGeometry";
import { AddNodeDialog } from "./AddNodeDialog";
import { NodeEditor } from "./NodeEditor";
import { EdgeEditor } from "./EdgeEditor";
import { TrustBoundaryEditor } from "./TrustBoundaryEditor";
import { DFDBulkEditDialog } from "./DFDBulkEditDialog";
import {
  SemanticFlowEdge,
  type SemanticFlowEdgeData,
} from "./SemanticFlowEdge";
import { DFDToolbar } from "./DFDToolbar";
import { DFDShortcutsDialog } from "./DFDShortcutsDialog";
import { DFDStencilPalette } from "./DFDStencilPalette";
import { DFDTemplateDialog } from "./DFDTemplateDialog";
import { CreateDFDWorkspaceDialog } from "./CreateDFDWorkspaceDialog";
import { dfdTemplates, materializeDFDTemplate, type DFDTemplateDefinition } from "./dfdTemplates";
import {
  suggestBoundaryDraftForSelection,
  suggestBoundaryDrafts,
} from "./boundarySuggestions";
import {
  buildNodePropertiesFromTemplate,
  formatTemplateOptionLabel,
} from "./componentTemplateUtils";
import { getDefaultNodeLabel } from "./dfdVisualRegistry";
import {
  getCanvasFooterHint,
  getHistoryShortcutAction,
  isShortcutHelpKey,
} from "./dfdInteractionUtils";

interface DFDCanvasProps {
  threatModelId: string;
  onAutoSaveComplete?: () => void;
  onAskAboutGraphObject?: (target: {
    kind: "node" | "edge" | "boundary";
    id: string;
    label: string;
  }) => void;
  onFocusThreatsForGraphObject?: (target: {
    kind: "node" | "edge";
    id: string;
    label: string;
  }) => void;
  onCreateAssumptionAnchor?: (target: AssumptionAnchorTarget) => void;
  highlightedReferences?: AssistantReference[];
  threatSignalsByNodeId?: Record<string, { count: number; highestSeverity: string | null }>;
  focusRequest?: { nonce: number; references: AssistantReference[] } | null;
}

type LoadState = "loading" | "empty" | "error" | "data";
type SaveStatus = "idle" | "saving" | "saved" | "error";
type AutoSaveStatus = "idle" | "saving" | "saved";
type SpawnMenuState = {
  nodeId: string;
  side: SpawnHandleSide;
  x: number;
  y: number;
};
type CanvasMenuState = {
  x: number;
  y: number;
  flowX: number;
  flowY: number;
};
type GraphContextMenuState = {
  kind: "node" | "edge" | "boundary";
  id: string;
  label: string;
  nodeType?: NodeType;
  x: number;
  y: number;
};
type CanvasViewport = {
  x: number;
  y: number;
  zoom: number;
};

type GraphHistorySnapshot = {
  payload: DFDBulkSave;
  signature: string;
};

const CANVAS_MIN_ZOOM = 0.1;
const FIT_VIEW_MIN_ZOOM = 0.15;
const CANVAS_MAX_ZOOM = 2;
const MAX_GRAPH_HISTORY = 100;

type EdgeEditorState =
  | {
      mode: "edit";
      id: string;
      label: string;
      properties: EdgeProperties;
      requireMetadata?: boolean;
    }
  | {
      mode: "create";
      sourceNodeId: string;
      targetNodeId: string;
      label: string;
      properties: EdgeProperties;
      requireMetadata: boolean;
    };
type EdgeData = SemanticFlowEdgeData;
type CanvasEdge = Edge<EdgeData>;
type EdgeRiskState = "normal" | "crossing" | "risky";

const NODE_WIDTH = 180;
const NODE_HEIGHT = 64;
const QUICK_ADD_OFFSET_X = NODE_WIDTH + 80;
const QUICK_ADD_MENU_OFFSET = 14;
const QUICK_ADD_MENU_WIDTH = 240;
const QUICK_ADD_MENU_EDGE_GAP = 12;
const DEFAULT_CANVAS_HEIGHT = 560;
const MIN_CANVAS_HEIGHT = 360;
const MAX_CANVAS_HEIGHT = 960;
const CANVAS_HEIGHT_STORAGE_KEY = "tg_dfd_canvas_height";
const STENCIL_PANEL_VISIBLE_STORAGE_KEY = "tg_dfd_stencil_panel_visible";
const BOUNDARY_CONTENT_PADDING = 20;
const DEFAULT_VIEWPORT: CanvasViewport = { x: 0, y: 0, zoom: 1 };
const COMPONENT_LAYOUT_MARGIN = 40;
const COMPONENT_LAYOUT_GAP_X = 140;
const COMPONENT_LAYOUT_GAP_Y = 120;
const TOP_LEVEL_LAYOUT_GAP_X = 220;
const TOP_LEVEL_LAYOUT_GAP_Y = 180;
const TOP_LEVEL_BOUNDARY_BUFFER = 56;
const TOP_LEVEL_NODE_BUFFER = 24;
const EDITABLE_VIEW_TYPES = new Set<DFDViewResponse["view_type"]>(["container", "decomposition", "workspace"]);
const DECOMPOSABLE_NODE_TYPES = new Set<NodeType>([
  "process",
  "api_gateway",
  "container",
  "serverless",
  "managed_service",
]);

function getActionErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error) {
    const message = error.message.trim();
    if (message) {
      return message;
    }
  }
  return fallback;
}

function composeQuickAddError(prefix: string, message: string): string {
  const trimmed = message.trim();
  if (!trimmed) {
    return prefix;
  }
  return trimmed.toLowerCase().startsWith(prefix.toLowerCase())
    ? trimmed
    : `${prefix} ${trimmed}`;
}

// Locked dagre config
type DagreLayoutConfig = {
  rankdir: "LR" | "TB";
  nodesep: number;
  ranksep: number;
  edgesep: number;
  marginx: number;
  marginy: number;
};

const DAGRE_CONFIG: DagreLayoutConfig = {
  rankdir: "LR" as const,
  nodesep: 80,
  ranksep: 120,
  edgesep: 30,
  marginx: 40,
  marginy: 40,
};

const DAGRE_COMPACT_CONFIG: DagreLayoutConfig = {
  rankdir: "TB" as const,
  nodesep: 56,
  ranksep: 76,
  edgesep: 24,
  marginx: 28,
  marginy: 28,
};

// Merge custom node types including trust boundary
const allNodeTypes = {
  ...nodeTypes,
  trustBoundary: TrustBoundaryNode,
};
const allEdgeTypes = {
  semanticFlow: SemanticFlowEdge,
};

function isEditableView(view: DFDViewResponse | null): boolean {
  return view === null || EDITABLE_VIEW_TYPES.has(view.view_type);
}

function buildViewChain(
  views: DFDViewResponse[],
  view: DFDViewResponse | null
): DFDViewResponse[] {
  if (!view) {
    return [];
  }
  const viewById = new Map(views.map((candidate) => [candidate.id, candidate]));
  const chain: DFDViewResponse[] = [];
  let current: DFDViewResponse | null = view;
  while (current) {
    chain.unshift(current);
    current = current.parent_view_id ? viewById.get(current.parent_view_id) ?? null : null;
  }
  return chain;
}

function clampCanvasHeight(height: number): number {
  return Math.max(MIN_CANVAS_HEIGHT, Math.min(MAX_CANVAS_HEIGHT, height));
}

function resolveCanvasNodeBoundaryMembership(nodes: Node[]): Map<string, string | null> {
  const boundaryNodes = nodes.filter((node) => node.type === "trustBoundary");
  const boundaryIds = new Set(boundaryNodes.map((boundaryNode) => boundaryNode.id));
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const nodeBoundaryMap = new Map<string, string | null>();

  for (const node of nodes) {
    if (node.type === "trustBoundary") {
      continue;
    }

    if (node.parentId && boundaryIds.has(node.parentId)) {
      nodeBoundaryMap.set(node.id, node.parentId);
      continue;
    }

    const absolutePosition = getAbsoluteNodePosition(node, nodeById);
    nodeBoundaryMap.set(node.id, findContainingBoundaryId(absolutePosition, boundaryNodes));
  }

  return nodeBoundaryMap;
}

function buildCanvasNodeBoundaryMap(nodes: Node[]): Map<string, string | null> {
  return resolveCanvasNodeBoundaryMembership(nodes);
}

function flattenNodesForReadOnlyLayout(nodes: Node[]): Node[] {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  return nodes
    .filter((node) => node.type !== "trustBoundary")
    .map((node) => ({
      ...node,
      parentId: undefined,
      extent: undefined,
      expandParent: false,
      position: getAbsoluteNodePosition(node, nodeById),
    }));
}

function buildDfdNodeBoundaryMap(dfd: DFDResponse): Map<string, string | null> {
  const nodeBoundaryMap = new Map<string, string | null>();
  for (const node of dfd.nodes) {
    nodeBoundaryMap.set(node.id, node.trust_boundary_id ?? null);
  }
  for (const boundary of dfd.trust_boundaries) {
    for (const nodeId of boundary.node_ids) {
      nodeBoundaryMap.set(nodeId, boundary.id);
    }
  }
  return nodeBoundaryMap;
}

function normalizeEdgeProperties(properties?: EdgeProperties | null): EdgeProperties {
  return {
    protocol: properties?.protocol || undefined,
    data_payload: properties?.data_payload || undefined,
    data_classification: properties?.data_classification || undefined,
    lifecycle_stage: properties?.lifecycle_stage || undefined,
    auth_mechanism: properties?.auth_mechanism || undefined,
    encryption_in_transit:
      typeof properties?.encryption_in_transit === "boolean"
        ? properties.encryption_in_transit
        : undefined,
    directionality: properties?.directionality || undefined,
    transfer_mode: properties?.transfer_mode || undefined,
    sequence_note: properties?.sequence_note || undefined,
    carries_credentials:
      typeof properties?.carries_credentials === "boolean"
        ? properties.carries_credentials
        : undefined,
    carries_pii:
      typeof properties?.carries_pii === "boolean" ? properties.carries_pii : undefined,
    carries_secrets:
      typeof properties?.carries_secrets === "boolean"
        ? properties.carries_secrets
        : undefined,
    rate_limited:
      typeof properties?.rate_limited === "boolean" ? properties.rate_limited : undefined,
    integrity_protected:
      typeof properties?.integrity_protected === "boolean"
        ? properties.integrity_protected
        : undefined,
    data_types: Array.isArray(properties?.data_types)
      ? properties.data_types.filter(Boolean)
      : [],
    tls_version: properties?.tls_version || undefined,
    is_response:
      typeof properties?.is_response === "boolean" ? properties.is_response : undefined,
    response_to_id: properties?.response_to_id ?? undefined,
    data_objects:
      Array.isArray(properties?.data_objects) && properties.data_objects.length > 0
        ? properties.data_objects
        : undefined,
    carries_financial_data:
      typeof properties?.carries_financial_data === "boolean"
        ? properties.carries_financial_data
        : undefined,
  };
}

function isSensitiveEdgeProperties(properties: EdgeProperties): boolean {
  return (
    properties.data_classification === "Confidential" ||
    properties.data_classification === "Restricted" ||
    properties.carries_credentials === true ||
    properties.carries_pii === true ||
    properties.carries_secrets === true ||
    properties.carries_financial_data === true
  );
}

function getEdgeMissingMetadata(
  flowLabel: string,
  properties: EdgeProperties,
  crossesBoundary: boolean
): string[] {
  const missing: string[] = [];
  if (!flowLabel.trim() && !properties.data_payload?.trim()) {
    missing.push("flow name");
  }
  if (!properties.protocol?.trim()) {
    missing.push("protocol");
  }
  if (crossesBoundary && !properties.data_classification) {
    missing.push("classification");
  }
  if (isSensitiveEdgeProperties(properties) && !properties.lifecycle_stage) {
    missing.push("lifecycle stage");
  }
  return missing;
}

function getEdgeRiskState(
  properties: EdgeProperties,
  crossesBoundary: boolean
): EdgeRiskState {
  if (!crossesBoundary) {
    return "normal";
  }
  if (
    properties.encryption_in_transit !== true ||
    !properties.protocol?.trim() ||
    !properties.data_classification ||
    properties.carries_credentials ||
    properties.carries_pii ||
    properties.carries_secrets
  ) {
    return "risky";
  }
  return "crossing";
}

function buildEdgeMetadataPrompt(missingMetadata: string[]): string {
  if (missingMetadata.length === 0) {
    return "";
  }
  return `Add ${missingMetadata.join(" + ")}`;
}

function buildEdgeDisplayLabel(flowLabel: string, properties: EdgeProperties): string {
  const primaryCandidate = flowLabel.trim() || properties.data_payload?.trim() || "";
  if (!primaryCandidate) {
    return "";
  }
  return primaryCandidate;
}

function getCanvasEdgeData(edge: CanvasEdge): EdgeData {
  const existing = edge.data;
  const flowLabel =
    existing?.flowLabel ?? (typeof edge.label === "string" ? edge.label : "");
  const properties = normalizeEdgeProperties(existing?.properties);
  return {
    flowLabel,
    displayLabel: existing?.displayLabel ?? buildEdgeDisplayLabel(flowLabel, properties),
    properties,
    crossesBoundary: existing?.crossesBoundary ?? false,
    riskState: existing?.riskState ?? "normal",
    missingMetadata: existing?.missingMetadata ?? [],
    metadataPrompt: existing?.metadataPrompt ?? "",
    onEdit: existing?.onEdit,
    onOpenContextMenu: existing?.onOpenContextMenu,
    onOpenNodeContextMenu: existing?.onOpenNodeContextMenu,
  };
}

function decorateCanvasEdge(
  edge: CanvasEdge,
  nodeBoundaryMap: Map<string, string | null>,
  callbacks: Pick<EdgeData, "onEdit" | "onOpenContextMenu" | "onOpenNodeContextMenu"> = {}
): CanvasEdge {
  const edgeData = getCanvasEdgeData(edge);
  const crossesBoundary =
    (nodeBoundaryMap.get(edge.source) ?? null) !== (nodeBoundaryMap.get(edge.target) ?? null);
  const missingMetadata = getEdgeMissingMetadata(
    edgeData.flowLabel,
    edgeData.properties,
    crossesBoundary
  );
  const riskState = getEdgeRiskState(edgeData.properties, crossesBoundary);
  const strokeColor =
    riskState === "risky"
      ? "#dc2626"
      : riskState === "crossing"
        ? "#d97706"
        : "#555";
  const strokeDasharray = riskState === "risky" ? "6 4" : undefined;

  return {
    ...edge,
    data: {
      ...edgeData,
      crossesBoundary,
      riskState,
      missingMetadata,
      metadataPrompt: buildEdgeMetadataPrompt(missingMetadata),
      onEdit: callbacks.onEdit ?? edgeData.onEdit,
      onOpenContextMenu: callbacks.onOpenContextMenu ?? edgeData.onOpenContextMenu,
      onOpenNodeContextMenu:
        callbacks.onOpenNodeContextMenu ?? edgeData.onOpenNodeContextMenu,
    },
    className: crossesBoundary
      ? riskState === "risky"
        ? "dfd-edge-boundary-crossing dfd-edge-boundary-crossing-risky"
        : "dfd-edge-boundary-crossing"
      : undefined,
    style: {
      stroke: strokeColor,
      strokeWidth: riskState === "risky" ? 3 : crossesBoundary ? 2.5 : 2,
      strokeDasharray,
    },
    markerEnd: { type: MarkerType.ArrowClosed, color: strokeColor },
  };
}

function buildReactFlowEdge(
  edge: DFDEdgeResponse,
  callbacks: Pick<EdgeData, "onEdit" | "onOpenContextMenu" | "onOpenNodeContextMenu"> = {},
  nodeBoundaryMap: Map<string, string | null> = new Map()
): CanvasEdge {
  const properties = normalizeEdgeProperties(edge.properties);
  const flowLabel = edge.label || "";
  const displayLabel = buildEdgeDisplayLabel(flowLabel, properties);
  return decorateCanvasEdge({
    id: edge.id,
    type: "semanticFlow",
    source: edge.source_node_id,
    target: edge.target_node_id,
    label: undefined,
    data: {
      flowLabel,
      displayLabel,
      properties,
      onEdit: callbacks.onEdit,
      onOpenContextMenu: callbacks.onOpenContextMenu,
      onOpenNodeContextMenu: callbacks.onOpenNodeContextMenu,
    },
  }, nodeBoundaryMap, callbacks);
}

function clampToRange(value: number, min: number, max: number): number {
  if (max < min) {
    return min;
  }
  return Math.min(Math.max(value, min), max);
}

function clampNodePositionToBoundary(
  position: { x: number; y: number },
  boundaryGeometry: { width: number; height: number }
): { x: number; y: number } {
  return {
    x: clampToRange(
      position.x,
      BOUNDARY_CONTENT_PADDING,
      Math.max(
        BOUNDARY_CONTENT_PADDING,
        boundaryGeometry.width - NODE_WIDTH - BOUNDARY_CONTENT_PADDING
      )
    ),
    y: clampToRange(
      position.y,
      BOUNDARY_CONTENT_PADDING,
      Math.max(
        BOUNDARY_CONTENT_PADDING,
        boundaryGeometry.height - NODE_HEIGHT - BOUNDARY_CONTENT_PADDING
      )
    ),
  };
}

function normalizeBoundaryNodes(nodes: Node[]): Node[] {
  const nextNodes = nodes.map((node) => ({
    ...node,
    position: { ...node.position },
    style: node.style ? { ...node.style } : node.style,
  }));
  const boundaryNodes = nextNodes.filter((node) => node.type === "trustBoundary");
  const nodeById = new Map(nextNodes.map((node) => [node.id, node]));

  for (const node of nextNodes) {
    if (node.type === "trustBoundary") {
      continue;
    }

    const absolutePosition = getAbsoluteNodePosition(node, nodeById);
    const inferredBoundaryId =
      node.parentId ?? findContainingBoundaryId(absolutePosition, boundaryNodes);
    if (!inferredBoundaryId) {
      node.parentId = undefined;
      node.extent = undefined;
      node.position = absolutePosition;
      continue;
    }

    const boundaryNode = boundaryNodes.find((candidate) => candidate.id === inferredBoundaryId);
    if (!boundaryNode) {
      node.parentId = undefined;
      node.extent = undefined;
      node.position = absolutePosition;
      continue;
    }

    node.parentId = inferredBoundaryId;
    node.extent = undefined;
    node.expandParent = false;
    node.position = clampNodePositionToBoundary(
      {
        x: absolutePosition.x - boundaryNode.position.x,
        y: absolutePosition.y - boundaryNode.position.y,
      },
      getBoundaryGeometry(boundaryNode)
    );
  }

  for (const boundaryNode of boundaryNodes) {
    const childNodes = nextNodes.filter((node) => node.parentId === boundaryNode.id);
    if (childNodes.length === 0) {
      continue;
    }

    let minX = Infinity;
    let minY = Infinity;
    for (const childNode of childNodes) {
      minX = Math.min(minX, childNode.position.x);
      minY = Math.min(minY, childNode.position.y);
    }

    const shiftX = minX < BOUNDARY_CONTENT_PADDING ? minX - BOUNDARY_CONTENT_PADDING : 0;
    const shiftY = minY < BOUNDARY_CONTENT_PADDING ? minY - BOUNDARY_CONTENT_PADDING : 0;

    if (shiftX !== 0 || shiftY !== 0) {
      boundaryNode.position = {
        x: boundaryNode.position.x + shiftX,
        y: boundaryNode.position.y + shiftY,
      };
      for (const childNode of childNodes) {
        childNode.position = {
          x: childNode.position.x - shiftX,
          y: childNode.position.y - shiftY,
        };
      }
    }

    let requiredWidth = MIN_BOUNDARY_WIDTH;
    let requiredHeight = MIN_BOUNDARY_HEIGHT;
    for (const childNode of childNodes) {
      requiredWidth = Math.max(
        requiredWidth,
        childNode.position.x + NODE_WIDTH + BOUNDARY_CONTENT_PADDING
      );
      requiredHeight = Math.max(
        requiredHeight,
        childNode.position.y + NODE_HEIGHT + BOUNDARY_CONTENT_PADDING
      );
    }

    boundaryNode.style = {
      ...(boundaryNode.style ?? {}),
      width: Math.max(
        getNodeDimension(boundaryNode.style?.width, DEFAULT_BOUNDARY_WIDTH),
        requiredWidth
      ),
      height: Math.max(
        getNodeDimension(boundaryNode.style?.height, DEFAULT_BOUNDARY_HEIGHT),
        requiredHeight
      ),
    };
  }

  return nextNodes;
}

function findContainingBoundaryId(
  absolutePosition: { x: number; y: number },
  boundaryNodes: Node[]
): string | null {
  const centerX = absolutePosition.x + NODE_WIDTH / 2;
  const centerY = absolutePosition.y + NODE_HEIGHT / 2;

  const candidate = boundaryNodes
    .map((boundaryNode) => ({
      id: boundaryNode.id,
      geometry: getBoundaryGeometry(boundaryNode),
    }))
    .filter(
      ({ geometry }) =>
        centerX >= geometry.x &&
        centerX <= geometry.x + geometry.width &&
        centerY >= geometry.y &&
        centerY <= geometry.y + geometry.height
    )
    .sort(
      (left, right) =>
        left.geometry.width * left.geometry.height -
        right.geometry.width * right.geometry.height
    )[0];

  return candidate?.id ?? null;
}

function attachNodeInteractionCallbacks(
  nodes: Node[],
  onHandleClick?: SpawnHandleClickHandler,
  onOpenDecomposition?: OpenDecompositionHandler,
  onFocusThreats?: FocusThreatsHandler,
  threatSignalsByNodeId: Record<string, { count: number; highestSeverity: string | null }> = {},
  onEditBoundary?: (boundaryId: string) => void,
  onMoveBoundaryStart?: (boundaryId: string) => void,
  onMoveBoundary?: (boundaryId: string, position: { x: number; y: number }) => void,
  onResizeBoundary?: (boundaryId: string, params: ResizeParams) => void
): Node[] {
  return nodes.map((node) =>
    node.type === "trustBoundary"
      ? {
          ...node,
          data: {
            ...(node.data as {
              label?: string;
              boundary_type?: BoundaryType;
              parent_boundary_id?: string | null;
              onMoveStart?: (boundaryId: string) => void;
              onMoveEnd?: (boundaryId: string, position: { x: number; y: number }) => void;
              onResizeEnd?: (boundaryId: string, params: ResizeParams) => void;
            }),
            onEdit: onEditBoundary,
            onMoveStart: onMoveBoundaryStart,
            onMoveEnd: onMoveBoundary,
            onResizeEnd: onResizeBoundary,
          },
        }
      : {
          ...node,
          extent: undefined,
          expandParent: false,
          data: {
            ...(node.data as DFDNodeData),
            onHandleClick,
            onFocusThreats,
            onOpenDecomposition: DECOMPOSABLE_NODE_TYPES.has(node.type as NodeType)
              ? onOpenDecomposition
              : undefined,
            threatCount: threatSignalsByNodeId[node.id]?.count ?? 0,
            highestThreatSeverity: threatSignalsByNodeId[node.id]?.highestSeverity ?? null,
          },
        }
  );
}

function getAbsoluteNodePosition(
  node: Node,
  nodeById: Map<string, Node>
): { x: number; y: number } {
  if (!node.parentId) return node.position;
  const parent = nodeById.get(node.parentId);
  if (!parent) return node.position;

  const parentPosition = getAbsoluteNodePosition(parent, nodeById);
  return {
    x: node.position.x + parentPosition.x,
    y: node.position.y + parentPosition.y,
  };
}

function collectSelectionMoveScope(
  nodes: Node[],
  options: {
    rootBoundaryIds: string[];
    extraNodeIds?: string[];
  }
): { boundaryIds: Set<string>; memberNodeIds: Set<string> } {
  const pendingBoundaryIds = [...options.rootBoundaryIds];
  const boundaryIds = new Set(options.rootBoundaryIds);
  while (pendingBoundaryIds.length > 0) {
    const currentBoundaryId = pendingBoundaryIds.shift();
    if (!currentBoundaryId) {
      continue;
    }

    for (const node of nodes) {
      if (node.type !== "trustBoundary") {
        continue;
      }
      const boundaryData = node.data as { parent_boundary_id?: string | null };
      if (boundaryData.parent_boundary_id !== currentBoundaryId || boundaryIds.has(node.id)) {
        continue;
      }
      boundaryIds.add(node.id);
      pendingBoundaryIds.push(node.id);
    }
  }

  const nodeBoundaryMap = resolveCanvasNodeBoundaryMembership(nodes);
  const extraNodeIds = new Set(options.extraNodeIds ?? []);
  const memberNodeIds = new Set(
    nodes
      .filter(
        (node) =>
          node.type !== "trustBoundary" &&
          (extraNodeIds.has(node.id) || boundaryIds.has(nodeBoundaryMap.get(node.id) ?? ""))
      )
      .map((node) => node.id)
  );

  return { boundaryIds, memberNodeIds };
}

function cloneNodesForDragSnapshot(nodes: Node[]): Node[] {
  return nodes.map((node) => ({
    ...node,
    position: { ...node.position },
    data:
      node.data && typeof node.data === "object"
        ? { ...(node.data as Record<string, unknown>) }
        : node.data,
    style: node.style ? { ...node.style } : node.style,
  }));
}

function buildSpawnNodeName(nodes: Node[], nodeType: NodeType, preferredBaseLabel?: string | null): string {
  const baseLabel = preferredBaseLabel?.trim() || getDefaultNodeLabel(nodeType);
  const existingLabels = new Set(
    nodes
      .filter((node) => node.type !== "trustBoundary")
      .map((node) => ((node.data as DFDNodeData).label || "").trim())
      .filter(Boolean)
  );

  if (!existingLabels.has(baseLabel)) {
    return baseLabel;
  }

  let suffix = 2;
  while (existingLabels.has(`${baseLabel} ${suffix}`)) {
    suffix += 1;
  }

  return `${baseLabel} ${suffix}`;
}

function getNodeDimension(value: unknown, fallback: number): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = Number.parseFloat(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return fallback;
}

function getBoundaryGeometry(boundaryNode: Node): {
  x: number;
  y: number;
  width: number;
  height: number;
} {
  return {
    x: boundaryNode.position.x,
    y: boundaryNode.position.y,
    width: getNodeDimension(boundaryNode.style?.width, DEFAULT_BOUNDARY_WIDTH),
    height: getNodeDimension(boundaryNode.style?.height, DEFAULT_BOUNDARY_HEIGHT),
  };
}

function buildBoundarySnapshot(nodes: Node[]): TrustBoundaryResponse[] {
  const dataNodes = nodes.filter((node) => node.type !== "trustBoundary");
  const nodeBoundaryMap = resolveCanvasNodeBoundaryMembership(nodes);

  return nodes
    .filter((node) => node.type === "trustBoundary")
    .map((boundary) => {
      const boundaryData = boundary.data as {
        label?: string;
        boundary_type?: BoundaryType;
        parent_boundary_id?: string | null;
      };
      return {
        id: boundary.id,
        name: (boundaryData.label || "Trust Boundary").trim(),
        node_ids: dataNodes
          .filter((node) => nodeBoundaryMap.get(node.id) === boundary.id)
          .map((node) => node.id),
        position_x: boundary.position.x,
        position_y: boundary.position.y,
        width: getNodeDimension(boundary.style?.width, DEFAULT_BOUNDARY_WIDTH),
        height: getNodeDimension(boundary.style?.height, DEFAULT_BOUNDARY_HEIGHT),
        boundary_type: boundaryData.boundary_type,
        parent_boundary_id: boundaryData.parent_boundary_id ?? null,
      };
    });
}

function buildBulkSavePayload(nodes: Node[], edges: CanvasEdge[]): DFDBulkSave {
  const dataNodes = nodes.filter((node) => node.type !== "trustBoundary");
  const boundaryNodes = nodes.filter((node) => node.type === "trustBoundary");
  const nodeBoundaryMap = resolveCanvasNodeBoundaryMembership(nodes);
  const boundaryPositionById = new Map(
    boundaryNodes.map((boundaryNode) => [boundaryNode.id, boundaryNode.position])
  );

  return {
    nodes: dataNodes
      .map((node) => {
        const resolvedBoundaryId = nodeBoundaryMap.get(node.id) ?? null;
        const parentPosition =
          node.parentId && resolvedBoundaryId === node.parentId
            ? boundaryPositionById.get(node.parentId)
            : undefined;
        const absolutePosition = parentPosition
          ? {
              x: node.position.x + parentPosition.x,
              y: node.position.y + parentPosition.y,
            }
          : node.position;

        const nodeData = node.data as DFDNodeData;

        return {
          id: node.id,
          node_type: node.type as NodeType,
          name: nodeData.label || "Unnamed",
          position_x: absolutePosition.x,
          position_y: absolutePosition.y,
          trust_boundary_id: resolvedBoundaryId,
          scan_target_url: nodeData.scan_target_url ?? null,
          scan_target_ports: nodeData.scan_target_ports ?? null,
          properties: normalizeNodeProperties((nodeData.properties ?? {}) as NodeProperties),
        };
      })
      .sort((left, right) => left.id.localeCompare(right.id)),
    edges: edges
      .map((edge) => {
        const edgeData = getCanvasEdgeData(edge);
        return {
          id: edge.id,
          source_node_id: edge.source,
          target_node_id: edge.target,
          label: edgeData.flowLabel || undefined,
          properties: edgeData.properties,
        };
      })
      .sort((left, right) => left.id.localeCompare(right.id)),
    trust_boundaries: boundaryNodes
      .map((boundary) => {
        const bData = boundary.data as { label?: string; boundary_type?: BoundaryType; parent_boundary_id?: string | null };
        return {
          id: boundary.id,
          name: bData.label || "Trust Boundary",
          node_ids: dataNodes
            .filter((node) => nodeBoundaryMap.get(node.id) === boundary.id)
            .map((node) => node.id)
            .sort((left, right) => left.localeCompare(right)),
          position_x: boundary.position.x,
          position_y: boundary.position.y,
          width: getNodeDimension(boundary.style?.width, DEFAULT_BOUNDARY_WIDTH),
          height: getNodeDimension(boundary.style?.height, DEFAULT_BOUNDARY_HEIGHT),
          boundary_type: bData.boundary_type,
          parent_boundary_id: bData.parent_boundary_id ?? undefined,
        };
      })
      .sort((left, right) => left.id.localeCompare(right.id)),
  };
}

function buildBulkSavePayloadFromDfd(dfd: DFDResponse): DFDBulkSave {
  return {
    nodes: [...dfd.nodes]
      .map((node) => ({
        id: node.id,
        node_type: node.node_type,
        name: node.name,
        position_x: node.position_x,
        position_y: node.position_y,
        trust_boundary_id: node.trust_boundary_id,
        scan_target_url: node.scan_target_url ?? null,
        scan_target_ports: node.scan_target_ports ?? null,
        properties: normalizeNodeProperties((node.properties ?? {}) as NodeProperties),
      }))
      .sort((left, right) => left.id.localeCompare(right.id)),
    edges: [...dfd.edges]
      .map((edge) => ({
        id: edge.id,
        source_node_id: edge.source_node_id,
        target_node_id: edge.target_node_id,
        label: edge.label || undefined,
        properties: normalizeEdgeProperties(edge.properties),
      }))
      .sort((left, right) => left.id.localeCompare(right.id)),
    trust_boundaries: [...dfd.trust_boundaries]
      .map((boundary) => ({
        id: boundary.id,
        name: boundary.name,
        node_ids: [...boundary.node_ids].sort((left, right) => left.localeCompare(right)),
        position_x: boundary.position_x,
        position_y: boundary.position_y,
        width: boundary.width,
        height: boundary.height,
        boundary_type: boundary.boundary_type,
        parent_boundary_id: boundary.parent_boundary_id ?? undefined,
      }))
      .sort((left, right) => left.id.localeCompare(right.id)),
  };
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey));
    return `{${entries
      .map(([key, entryValue]) => `${JSON.stringify(key)}:${stableStringify(entryValue)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function normalizeNetworkExposureValue(
  value: unknown
): NodeProperties["network_exposure"] | undefined {
  if (typeof value !== "string") {
    return value as NodeProperties["network_exposure"] | undefined;
  }

  switch (value.toLowerCase()) {
    case "public":
      return "internet";
    case "private":
      return "internal";
    case "isolated":
      return "vpc_private";
    case "internet":
    case "dmz":
    case "internal":
    case "vpc_private":
      return value.toLowerCase() as NodeProperties["network_exposure"];
    default:
      return undefined;
  }
}

function normalizeNodeProperties(
  properties: NodeProperties | Record<string, unknown> | null | undefined
): NodeProperties {
  const nextProperties = { ...(properties ?? {}) } as NodeProperties & Record<string, unknown>;
  if ("network_exposure" in nextProperties) {
    nextProperties.network_exposure = normalizeNetworkExposureValue(
      nextProperties.network_exposure
    );
  }
  return nextProperties;
}

function buildGraphSignature(payload: DFDBulkSave): string {
  return stableStringify(JSON.parse(JSON.stringify(payload)) as unknown);
}

function cloneBulkSavePayload(payload: DFDBulkSave): DFDBulkSave {
  return JSON.parse(JSON.stringify(payload)) as DFDBulkSave;
}

function createGraphHistorySnapshot(payload: DFDBulkSave): GraphHistorySnapshot {
  const clonedPayload = cloneBulkSavePayload(payload);
  return {
    payload: clonedPayload,
    signature: buildGraphSignature(clonedPayload),
  };
}

function materializeDfdResponseFromBulkSave(payload: DFDBulkSave): DFDResponse {
  return {
    nodes: payload.nodes.map((node) => ({
      id: node.id ?? "",
      node_type: node.node_type,
      name: node.name,
      position_x: node.position_x ?? 0,
      position_y: node.position_y ?? 0,
      trust_boundary_id: node.trust_boundary_id ?? null,
      scan_target_url: node.scan_target_url ?? null,
      scan_target_ports: node.scan_target_ports ?? null,
      properties: normalizeNodeProperties(
        (node.properties ?? {}) as NodeProperties
      ) as Record<string, unknown>,
    })),
    edges: payload.edges.map((edge) => ({
      id: edge.id ?? "",
      source_node_id: edge.source_node_id,
      target_node_id: edge.target_node_id,
      label: edge.label ?? "",
      properties: normalizeEdgeProperties(edge.properties),
    })),
    trust_boundaries: (payload.trust_boundaries ?? []).map((boundary) => ({
      id: boundary.id ?? "",
      name: boundary.name ?? "Trust Boundary",
      node_ids: [...(boundary.node_ids ?? [])],
      position_x: boundary.position_x ?? 0,
      position_y: boundary.position_y ?? 0,
      width: boundary.width ?? DEFAULT_BOUNDARY_WIDTH,
      height: boundary.height ?? DEFAULT_BOUNDARY_HEIGHT,
      boundary_type: boundary.boundary_type,
      parent_boundary_id: boundary.parent_boundary_id ?? null,
    })),
  };
}

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  return Boolean(
    target.closest(
      [
        "input",
        "textarea",
        "select",
        "[contenteditable='true']",
        "[role='textbox']",
      ].join(", ")
    )
  );
}

function autoLayoutCanvasNodes(
  nodes: Node[],
  edges: CanvasEdge[],
  onHandleClick?: SpawnHandleClickHandler,
  onOpenDecomposition?: OpenDecompositionHandler,
  onFocusThreats?: FocusThreatsHandler,
  threatSignalsByNodeId: Record<string, { count: number; highestSeverity: string | null }> = {},
  onEditBoundary?: (boundaryId: string) => void,
  onMoveBoundaryStart?: (boundaryId: string) => void,
  onMoveBoundary?: (boundaryId: string, position: { x: number; y: number }) => void,
  onResizeBoundary?: (boundaryId: string, params: ResizeParams) => void
): Node[] {
  const boundarySnapshots = buildBoundarySnapshot(nodes);
  const dataNodes = nodes.filter((node) => node.type !== "trustBoundary");
  const dataNodeById = new Map(dataNodes.map((node) => [node.id, node]));
  const boundaryMembershipByNodeId = new Map<string, string>();
  const layoutedNodes: Node[] = [];
  const boundaryNodes: Node[] = [];

  // Layout child members inside their own trust boundaries first so auto-layout
  // preserves containment instead of flattening the graph and rebuilding it later.
  for (const boundary of boundarySnapshots) {
    const memberNodes = boundary.node_ids
      .map((nodeId) => dataNodeById.get(nodeId))
      .filter((node): node is Node => Boolean(node))
      .map((node) => ({
        ...node,
        parentId: undefined,
        position: { ...node.position },
      }));

    if (memberNodes.length === 0) {
      const emptyBoundaryNode = buildBoundaryNodes([boundary], new Map(), "derive")[0];
      if (emptyBoundaryNode) {
        boundaryNodes.push(emptyBoundaryNode);
      }
      continue;
    }

    const memberNodeIds = new Set(memberNodes.map((node) => node.id));
    const memberEdges = edges.filter(
      (edge) => memberNodeIds.has(edge.source) && memberNodeIds.has(edge.target)
    );
    const localLayoutedNodes = applyPackedDagreLayout(memberNodes, memberEdges);
    const derivedBoundaryNode = buildBoundaryNodes(
      [boundary],
      new Map(localLayoutedNodes.map((node) => [node.id, node.position])),
      "derive"
    )[0];

    if (!derivedBoundaryNode) {
      continue;
    }

    const anchorX = boundary.position_x ?? derivedBoundaryNode.position.x;
    const anchorY = boundary.position_y ?? derivedBoundaryNode.position.y;
    const deltaX = anchorX - derivedBoundaryNode.position.x;
    const deltaY = anchorY - derivedBoundaryNode.position.y;

    boundaryNodes.push({
      ...derivedBoundaryNode,
      position: {
        x: derivedBoundaryNode.position.x + deltaX,
        y: derivedBoundaryNode.position.y + deltaY,
      },
    });

    for (const layoutedNode of localLayoutedNodes) {
      boundaryMembershipByNodeId.set(layoutedNode.id, boundary.id);
      layoutedNodes.push({
        ...layoutedNode,
        parentId: undefined,
        position: {
          x: layoutedNode.position.x + deltaX,
          y: layoutedNode.position.y + deltaY,
        },
      });
    }
  }

  const standaloneNodes = dataNodes
    .filter((node) => !boundaryMembershipByNodeId.has(node.id))
    .map((node) => ({
      ...node,
      parentId: undefined,
      position: { ...node.position },
    }));
  if (standaloneNodes.length > 0) {
    const standaloneNodeIds = new Set(standaloneNodes.map((node) => node.id));
    const standaloneEdges = edges.filter(
      (edge) => standaloneNodeIds.has(edge.source) && standaloneNodeIds.has(edge.target)
    );
    layoutedNodes.push(...applyPackedDagreLayout(standaloneNodes, standaloneEdges));
  }

  const repackedLayout = repackTopLevelLayoutItems(
    boundaryNodes,
    layoutedNodes,
    boundaryMembershipByNodeId
  );
  const boundaryNodeById = new Map(
    repackedLayout.boundaryNodes.map((node) => [node.id, node])
  );

  const groupedNodes = repackedLayout.layoutedNodes.map((node) => {
    const boundaryId = boundaryMembershipByNodeId.get(node.id);
    if (!boundaryId) return node;

    const boundaryNode = boundaryNodeById.get(boundaryId);
    if (!boundaryNode) return node;

    return {
      ...node,
      parentId: boundaryId,
      position: clampNodePositionToBoundary({
        x: node.position.x - boundaryNode.position.x,
        y: node.position.y - boundaryNode.position.y,
      }, getBoundaryGeometry(boundaryNode)),
    };
  });

  return attachNodeInteractionCallbacks(
    normalizeBoundaryNodes([...repackedLayout.boundaryNodes, ...groupedNodes]),
    onHandleClick,
    onOpenDecomposition,
    onFocusThreats,
    threatSignalsByNodeId,
    onEditBoundary,
    onMoveBoundaryStart,
    onMoveBoundary,
    onResizeBoundary
  );
}

function applyDagreLayout(
  nodes: Node[],
  edges: CanvasEdge[],
  graphConfig: DagreLayoutConfig = DAGRE_CONFIG
): Node[] {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph(graphConfig);

  // Only layout non-boundary nodes
  for (const node of nodes) {
    if (node.type === "trustBoundary") continue;
    g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  }

  for (const edge of edges) {
    g.setEdge(edge.source, edge.target);
  }

  dagre.layout(g);

  return nodes.map((node) => {
    if (node.type === "trustBoundary") return node;
    const pos = g.node(node.id);
    if (!pos) return node;
    return {
      ...node,
      position: {
        x: pos.x - NODE_WIDTH / 2,
        y: pos.y - NODE_HEIGHT / 2,
      },
    };
  });
}

function getNodeBounds(nodes: Node[]): {
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
  width: number;
  height: number;
} {
  if (nodes.length === 0) {
    return {
      minX: 0,
      minY: 0,
      maxX: 0,
      maxY: 0,
      width: 0,
      height: 0,
    };
  }

  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;

  for (const node of nodes) {
    minX = Math.min(minX, node.position.x);
    minY = Math.min(minY, node.position.y);
    maxX = Math.max(maxX, node.position.x + NODE_WIDTH);
    maxY = Math.max(maxY, node.position.y + NODE_HEIGHT);
  }

  return {
    minX,
    minY,
    maxX,
    maxY,
    width: maxX - minX,
    height: maxY - minY,
  };
}

function buildViewportForNodes(
  nodes: Node[],
  viewportWidth: number,
  viewportHeight: number,
  maxZoom: number,
  paddingRatio = 0.18
): CanvasViewport {
  const bounds = getNodeBounds(nodes);
  const width = Math.max(bounds.width, NODE_WIDTH);
  const height = Math.max(bounds.height, NODE_HEIGHT);
  const paddedWidth = width * (1 + paddingRatio * 2);
  const paddedHeight = height * (1 + paddingRatio * 2);
  const zoom = clampToRange(
    Math.min(viewportWidth / paddedWidth, viewportHeight / paddedHeight),
    FIT_VIEW_MIN_ZOOM,
    maxZoom
  );

  return {
    x: (viewportWidth - width * zoom) / 2 - bounds.minX * zoom,
    y: (viewportHeight - height * zoom) / 2 - bounds.minY * zoom,
    zoom,
  };
}

function buildLayoutComponents(nodes: Node[], edges: CanvasEdge[]): { nodes: Node[]; edges: CanvasEdge[] }[] {
  const dataNodes = nodes.filter((node) => node.type !== "trustBoundary");
  const nodeById = new Map(dataNodes.map((node) => [node.id, node]));
  const adjacency = new Map<string, Set<string>>();

  for (const node of dataNodes) {
    adjacency.set(node.id, new Set<string>());
  }

  for (const edge of edges) {
    if (!nodeById.has(edge.source) || !nodeById.has(edge.target)) {
      continue;
    }
    adjacency.get(edge.source)?.add(edge.target);
    adjacency.get(edge.target)?.add(edge.source);
  }

  const visited = new Set<string>();
  const components: { nodes: Node[]; edges: CanvasEdge[] }[] = [];

  for (const node of dataNodes) {
    if (visited.has(node.id)) {
      continue;
    }

    const stack = [node.id];
    const componentIds = new Set<string>();
    visited.add(node.id);

    while (stack.length > 0) {
      const currentId = stack.pop()!;
      componentIds.add(currentId);
      for (const neighborId of adjacency.get(currentId) ?? []) {
        if (visited.has(neighborId)) {
          continue;
        }
        visited.add(neighborId);
        stack.push(neighborId);
      }
    }

    const componentNodes = dataNodes.filter((candidate) => componentIds.has(candidate.id));
    const componentEdges = edges.filter(
      (edge) => componentIds.has(edge.source) && componentIds.has(edge.target)
    );
    components.push({ nodes: componentNodes, edges: componentEdges });
  }

  return components.sort((left, right) => {
    const leftBounds = getNodeBounds(left.nodes);
    const rightBounds = getNodeBounds(right.nodes);
    if (leftBounds.minX !== rightBounds.minX) {
      return leftBounds.minX - rightBounds.minX;
    }
    return leftBounds.minY - rightBounds.minY;
  });
}

function applyPackedDagreLayout(
  nodes: Node[],
  edges: CanvasEdge[],
  graphConfig: DagreLayoutConfig = DAGRE_CONFIG
): Node[] {
  const components = buildLayoutComponents(nodes, edges);
  if (components.length <= 1) {
    return applyDagreLayout(nodes, edges, graphConfig);
  }

  const targetColumns = Math.max(1, Math.round(Math.sqrt(components.length)));
  const maxRowWidth =
    COMPONENT_LAYOUT_MARGIN +
    targetColumns * (NODE_WIDTH * 2 + COMPONENT_LAYOUT_GAP_X);

  const packedNodes: Node[] = [];
  let cursorX = COMPONENT_LAYOUT_MARGIN;
  let cursorY = COMPONENT_LAYOUT_MARGIN;
  let rowHeight = 0;

  for (const component of components) {
    const layoutedComponentNodes = applyDagreLayout(
      component.nodes,
      component.edges,
      graphConfig
    );
    const bounds = getNodeBounds(layoutedComponentNodes);

    if (
      cursorX > COMPONENT_LAYOUT_MARGIN &&
      cursorX + bounds.width > maxRowWidth
    ) {
      cursorX = COMPONENT_LAYOUT_MARGIN;
      cursorY += rowHeight + COMPONENT_LAYOUT_GAP_Y;
      rowHeight = 0;
    }

    const deltaX = cursorX - bounds.minX;
    const deltaY = cursorY - bounds.minY;
    const translatedNodes = layoutedComponentNodes.map((node) => ({
      ...node,
      position: {
        x: node.position.x + deltaX,
        y: node.position.y + deltaY,
      },
    }));

    packedNodes.push(...translatedNodes);
    cursorX += bounds.width + COMPONENT_LAYOUT_GAP_X;
    rowHeight = Math.max(rowHeight, bounds.height);
  }

  return packedNodes;
}

type TopLevelLayoutItem = {
  id: string;
  kind: "boundary" | "node";
  position: { x: number; y: number };
  width: number;
  height: number;
  buffer: number;
  memberNodeIds: string[];
};

function repackTopLevelLayoutItems(
  boundaryNodes: Node[],
  layoutedNodes: Node[],
  boundaryMembershipByNodeId: Map<string, string>
): { boundaryNodes: Node[]; layoutedNodes: Node[] } {
  const nodeById = new Map(layoutedNodes.map((node) => [node.id, node]));
  const topLevelItems: TopLevelLayoutItem[] = [
    ...boundaryNodes.map((boundaryNode) => {
      const geometry = getBoundaryGeometry(boundaryNode);
      return {
        id: boundaryNode.id,
        kind: "boundary" as const,
        position: boundaryNode.position,
        width: geometry.width,
        height: geometry.height,
        buffer: TOP_LEVEL_BOUNDARY_BUFFER,
        memberNodeIds: layoutedNodes
          .filter((node) => boundaryMembershipByNodeId.get(node.id) === boundaryNode.id)
          .map((node) => node.id),
      };
    }),
    ...layoutedNodes
      .filter((node) => !boundaryMembershipByNodeId.has(node.id))
      .map((node) => ({
        id: node.id,
        kind: "node" as const,
        position: node.position,
        width: NODE_WIDTH,
        height: NODE_HEIGHT,
        buffer: TOP_LEVEL_NODE_BUFFER,
        memberNodeIds: [node.id],
      })),
  ];

  if (topLevelItems.length <= 1) {
    return { boundaryNodes, layoutedNodes };
  }

  const sortedItems = [...topLevelItems].sort((left, right) => {
    if (left.position.x !== right.position.x) {
      return left.position.x - right.position.x;
    }
    return left.position.y - right.position.y;
  });
  const targetColumns = Math.max(1, Math.round(Math.sqrt(sortedItems.length)));
  const widestItems = [...sortedItems]
    .sort(
      (left, right) =>
        right.width + right.buffer * 2 - (left.width + left.buffer * 2)
    )
    .slice(0, targetColumns);
  const maxRowWidth =
    COMPONENT_LAYOUT_MARGIN * 2 +
    widestItems.reduce(
      (total, item) => total + item.width + item.buffer * 2,
      0
    ) +
    Math.max(0, targetColumns - 1) * TOP_LEVEL_LAYOUT_GAP_X;

  const boundaryPositionOverrides = new Map<string, { x: number; y: number }>();
  const nodePositionOverrides = new Map<string, { x: number; y: number }>();
  let cursorX = COMPONENT_LAYOUT_MARGIN;
  let cursorY = COMPONENT_LAYOUT_MARGIN;
  let rowHeight = 0;

  for (const item of sortedItems) {
    const footprintWidth = item.width + item.buffer * 2;
    const footprintHeight = item.height + item.buffer * 2;

    if (
      cursorX > COMPONENT_LAYOUT_MARGIN &&
      cursorX + footprintWidth > maxRowWidth
    ) {
      cursorX = COMPONENT_LAYOUT_MARGIN;
      cursorY += rowHeight + TOP_LEVEL_LAYOUT_GAP_Y;
      rowHeight = 0;
    }

    const targetX = cursorX + item.buffer;
    const targetY = cursorY + item.buffer;
    const deltaX = targetX - item.position.x;
    const deltaY = targetY - item.position.y;

    if (item.kind === "boundary") {
      boundaryPositionOverrides.set(item.id, {
        x: item.position.x + deltaX,
        y: item.position.y + deltaY,
      });
    }

    for (const memberNodeId of item.memberNodeIds) {
      const memberNode = nodeById.get(memberNodeId);
      if (!memberNode) {
        continue;
      }
      nodePositionOverrides.set(memberNodeId, {
        x: memberNode.position.x + deltaX,
        y: memberNode.position.y + deltaY,
      });
    }

    cursorX += footprintWidth + TOP_LEVEL_LAYOUT_GAP_X;
    rowHeight = Math.max(rowHeight, footprintHeight);
  }

  return {
    boundaryNodes: boundaryNodes.map((boundaryNode) =>
      boundaryPositionOverrides.has(boundaryNode.id)
        ? {
            ...boundaryNode,
            position: boundaryPositionOverrides.get(boundaryNode.id)!,
          }
        : boundaryNode
    ),
    layoutedNodes: layoutedNodes.map((node) =>
      nodePositionOverrides.has(node.id)
        ? {
            ...node,
            position: nodePositionOverrides.get(node.id)!,
          }
        : node
    ),
  };
}

function convertDFDToReactFlow(
  dfd: DFDResponse,
  edgeCallbacks: Pick<EdgeData, "onEdit" | "onOpenContextMenu" | "onOpenNodeContextMenu">,
  threatSignalsByNodeId: Record<string, { count: number; highestSeverity: string | null }> = {}
): { nodes: Node[]; edges: CanvasEdge[] } {
  const nodeBoundaryMap = buildDfdNodeBoundaryMap(dfd);
  const edges: CanvasEdge[] = dfd.edges.map((edge) =>
    buildReactFlowEdge(edge, edgeCallbacks, nodeBoundaryMap)
  );
  const dataNodes: Node[] = dfd.nodes.map((n) => ({
    id: n.id,
    type: n.node_type,
    position: { x: n.position_x, y: n.position_y },
    data: {
      label: n.name,
      properties: normalizeNodeProperties((n.properties ?? {}) as NodeProperties),
      threatCount: threatSignalsByNodeId[n.id]?.count ?? 0,
      highestThreatSeverity: threatSignalsByNodeId[n.id]?.highestSeverity ?? null,
    },
  }));
  const positionMap = new Map<string, { x: number; y: number }>(
    dataNodes.map((node) => [node.id, node.position])
  );
  const boundaryNodes = buildBoundaryNodes(dfd.trust_boundaries, positionMap, "stored");
  const boundaryById = new Map(boundaryNodes.map((boundary) => [boundary.id, boundary]));
  const nodeToBoundary = new Map<string, string>();

  for (const node of dfd.nodes) {
    if (node.trust_boundary_id) {
      nodeToBoundary.set(node.id, node.trust_boundary_id);
    }
  }
  for (const boundary of dfd.trust_boundaries) {
    for (const nodeId of boundary.node_ids) {
      nodeToBoundary.set(nodeId, boundary.id);
    }
  }
  const finalDataNodes = dataNodes.map((node) => {
    const boundaryId =
      nodeToBoundary.get(node.id) ??
      findContainingBoundaryId(node.position, boundaryNodes);
    if (!boundaryId) return node;
    const boundary = boundaryById.get(boundaryId);
    if (!boundary) return node;
    return {
      ...node,
      parentId: boundaryId,
      extent: undefined,
      expandParent: false,
      position: clampNodePositionToBoundary({
        x: node.position.x - boundary.position.x,
        y: node.position.y - boundary.position.y,
      }, getBoundaryGeometry(boundary)),
    };
  });
  const allNodes: Node[] = [...boundaryNodes, ...finalDataNodes];

  return { nodes: allNodes, edges };
}

function applyViewVisibilityToNodes(
  currentNodes: Node[],
  view: DFDViewResponse | null
): Node[] {
  if (
    !view ||
    view.view_type === "container" ||
    view.view_type === "decomposition" ||
    view.view_type === "workspace"
  ) {
    return currentNodes.map((node) => ({ ...node, hidden: false }));
  }

  const visibleNodeIds = new Set(view.node_ids);
  const visibleBoundaryIds = new Set(view.boundary_ids);

  return currentNodes.map((node) => {
    const isVisible =
      node.type === "trustBoundary"
        ? visibleBoundaryIds.has(node.id)
        : visibleNodeIds.has(node.id);
    return {
      ...node,
      hidden: !isVisible,
      selected: isVisible ? node.selected : false,
    };
  });
}

function applyViewVisibilityToEdges(
  currentEdges: CanvasEdge[],
  view: DFDViewResponse | null
): CanvasEdge[] {
  if (
    !view ||
    view.view_type === "container" ||
    view.view_type === "decomposition" ||
    view.view_type === "workspace"
  ) {
    return currentEdges.map((edge) => ({ ...edge, hidden: false }));
  }

  const visibleEdgeIds = new Set(view.edge_ids);
  return currentEdges.map((edge) => ({
    ...edge,
    hidden: !visibleEdgeIds.has(edge.id),
    selected: visibleEdgeIds.has(edge.id) ? edge.selected : false,
  }));
}

function refreshEdgeVisuals(
  currentNodes: Node[],
  currentEdges: CanvasEdge[],
  callbacks: Pick<EdgeData, "onEdit" | "onOpenContextMenu" | "onOpenNodeContextMenu">,
  nodeBoundaryMap: Map<string, string | null> = buildCanvasNodeBoundaryMap(currentNodes)
): CanvasEdge[] {
  return currentEdges.map((edge) => decorateCanvasEdge(edge, nodeBoundaryMap, callbacks));
}

export function DFDCanvas({
  threatModelId,
  onAutoSaveComplete,
  onAskAboutGraphObject,
  onFocusThreatsForGraphObject,
  onCreateAssumptionAnchor,
  highlightedReferences,
  threatSignalsByNodeId = {},
  focusRequest = null,
}: DFDCanvasProps): JSX.Element {
  const [state, setState] = useState<LoadState>("loading");
  const [nodes, setNodes, onNodesChangeBase] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<CanvasEdge>([]);
  const [componentTemplates, setComponentTemplates] = useState<DFDComponentTemplateResponse[]>([]);
  const [saveStatus, setSaveStatus] = useState<SaveStatus>("idle");
  const [showStencilPanel, setShowStencilPanel] = useState<boolean>(() => {
    if (typeof window === "undefined") return true;
    return window.localStorage.getItem(STENCIL_PANEL_VISIBLE_STORAGE_KEY) !== "false";
  });
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [addDialogStartsInCustomMode, setAddDialogStartsInCustomMode] = useState(false);
  const [showTemplateDialog, setShowTemplateDialog] = useState(false);
  const [showShortcutsDialog, setShowShortcutsDialog] = useState(false);
  const [showCreateWorkspaceDialog, setShowCreateWorkspaceDialog] = useState(false);
  const [spawnMenu, setSpawnMenu] = useState<SpawnMenuState | null>(null);
  const [canvasMenu, setCanvasMenu] = useState<CanvasMenuState | null>(null);
  const [graphContextMenu, setGraphContextMenu] = useState<GraphContextMenuState | null>(null);
  const [quickAddError, setQuickAddError] = useState<string | null>(null);
  const [editingNode, setEditingNode] = useState<{
    id: string;
    name: string;
    type: NodeType;
    properties: NodeProperties;
    scan_target_url?: string | null;
    scan_target_ports?: string | null;
  } | null>(null);
  const [editingBoundary, setEditingBoundary] = useState<{
    id: string;
    name: string;
    boundary_type?: BoundaryType;
    width: number;
    height: number;
  } | null>(null);
  const [edgeEditorState, setEdgeEditorState] = useState<EdgeEditorState | null>(null);
  const [showBulkEditDialog, setShowBulkEditDialog] = useState(false);
  const [views, setViews] = useState<DFDViewResponse[]>([]);
  const [selectedViewId, setSelectedViewId] = useState<string | null>(null);
  const [createWorkspaceError, setCreateWorkspaceError] = useState<string | null>(null);
  const [creatingWorkspace, setCreatingWorkspace] = useState(false);
  const [autoSaveStatus, setAutoSaveStatus] = useState<AutoSaveStatus>("idle");
  const [snapToGrid, setSnapToGrid] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [spacePanActive, setSpacePanActive] = useState(false);
  const [undoDepth, setUndoDepth] = useState(0);
  const [redoDepth, setRedoDepth] = useState(0);
  const [viewport, setViewportState] = useState<CanvasViewport>(DEFAULT_VIEWPORT);
  const [canvasHeight, setCanvasHeight] = useState<number>(() => {
    if (typeof window === "undefined") {
      return DEFAULT_CANVAS_HEIGHT;
    }
    const storedHeight = window.localStorage.getItem(CANVAS_HEIGHT_STORAGE_KEY);
    const parsedHeight = storedHeight ? Number.parseInt(storedHeight, 10) : NaN;
    return Number.isFinite(parsedHeight)
      ? clampCanvasHeight(parsedHeight)
      : DEFAULT_CANVAS_HEIGHT;
  });
  const [isResizingCanvas, setIsResizingCanvas] = useState(false);
  const autoSaveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const autoSaveInFlightRef = useRef(false);
  const historyCaptureTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isInitialLoadRef = useRef(true);
  const skipAutoSavePassesRef = useRef(0);
  const canvasShellRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const flowSurfaceRef = useRef<HTMLDivElement | null>(null);
  const reactFlowRef = useRef<ReactFlowInstance<Node, CanvasEdge> | null>(null);
  const nodesRef = useRef<Node[]>([]);
  const edgesRef = useRef<CanvasEdge[]>([]);
  const dragSnapshotNodesRef = useRef<Node[] | null>(null);
  const persistedGraphSignatureRef = useRef<string | null>(null);
  const graphHistoryUndoRef = useRef<GraphHistorySnapshot[]>([]);
  const graphHistoryRedoRef = useRef<GraphHistorySnapshot[]>([]);
  const graphHistoryCurrentRef = useRef<GraphHistorySnapshot | null>(null);
  const suppressHistoryCaptureRef = useRef(false);
  const openDecompositionRef = useRef<(nodeId: string) => void>(() => {});
  const lastFocusRequestRef = useRef<number | null>(null);
  const pendingSnapshotFitRef = useRef(false);
  const applyDfdSnapshotRef = useRef<(dfd: DFDResponse) => void>(() => {});
  const viewportRef = useRef<CanvasViewport>(DEFAULT_VIEWPORT);
  const lastReadOnlyAutoFitViewRef = useRef<string | null>(null);
  const isReadOnlyViewRef = useRef(false);
  const spacePanActiveRef = useRef(false);
  const ignoreNodeDragStopUntilRef = useRef(0);

  const getFlowSurfaceRect = useCallback(
    () =>
      flowSurfaceRef.current?.getBoundingClientRect() ??
      canvasRef.current?.getBoundingClientRect() ??
      null,
    []
  );

  const closeSpawnMenu = useCallback(() => {
    setSpawnMenu(null);
    setCanvasMenu(null);
    setGraphContextMenu(null);
  }, []);

  const handleOpenCreateWorkspaceDialog = useCallback(() => {
    setCreateWorkspaceError(null);
    setShowCreateWorkspaceDialog(true);
  }, []);

  const loadComponentTemplates = useCallback(async () => {
    try {
      const nextTemplates = await api.getDFDComponentTemplates(threatModelId);
      setComponentTemplates(nextTemplates);
    } catch {
      setComponentTemplates([]);
    }
  }, [threatModelId]);

  useEffect(() => {
    nodesRef.current = nodes;
  }, [nodes]);

  useEffect(() => {
    edgesRef.current = edges;
  }, [edges]);

  useEffect(() => {
    let cancelled = false;

    async function hydrateComponentTemplates() {
      try {
        const nextTemplates = await api.getDFDComponentTemplates(threatModelId);
        if (cancelled) {
          return;
        }
        setComponentTemplates(nextTemplates);
      } catch {
        if (!cancelled) {
          setComponentTemplates([]);
        }
      }
    }

    void hydrateComponentTemplates();
    return () => {
      cancelled = true;
    };
  }, [threatModelId]);

  useEffect(() => {
    viewportRef.current = viewport;
  }, [viewport]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(CANVAS_HEIGHT_STORAGE_KEY, String(canvasHeight));
  }, [canvasHeight]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(
      STENCIL_PANEL_VISIBLE_STORAGE_KEY,
      showStencilPanel ? "true" : "false"
    );
  }, [showStencilPanel]);

  useEffect(() => {
    if (typeof document === "undefined") return;

    const handleFullscreenChange = () => {
      setIsFullscreen(document.fullscreenElement === canvasShellRef.current);
    };

    handleFullscreenChange();
    document.addEventListener("fullscreenchange", handleFullscreenChange);
    return () => {
      document.removeEventListener("fullscreenchange", handleFullscreenChange);
    };
  }, []);

  useEffect(() => {
    if (typeof document === "undefined") return;
    if (!isResizingCanvas) return;

    const previousUserSelect = document.body.style.userSelect;
    const previousCursor = document.body.style.cursor;
    document.body.style.userSelect = "none";
    document.body.style.cursor = "ns-resize";

    return () => {
      document.body.style.userSelect = previousUserSelect;
      document.body.style.cursor = previousCursor;
    };
  }, [isResizingCanvas]);

  const rememberPersistedGraph = useCallback((nextNodes: Node[], nextEdges: CanvasEdge[]) => {
    persistedGraphSignatureRef.current = buildGraphSignature(
      buildBulkSavePayload(nextNodes, nextEdges)
    );
  }, []);

  const handleResizeCanvasStart = useCallback(
    (event: React.MouseEvent<HTMLButtonElement>) => {
      event.preventDefault();
      event.stopPropagation();

      const shell = canvasShellRef.current;
      if (!shell) return;

      const shellTop = shell.getBoundingClientRect().top;
      setIsResizingCanvas(true);

      const handlePointerMove = (moveEvent: MouseEvent) => {
        setCanvasHeight(clampCanvasHeight(moveEvent.clientY - shellTop));
      };

      const stopResizing = () => {
        window.removeEventListener("mousemove", handlePointerMove);
        window.removeEventListener("mouseup", stopResizing);
        setIsResizingCanvas(false);
      };

      window.addEventListener("mousemove", handlePointerMove);
      window.addEventListener("mouseup", stopResizing);
    },
    []
  );

  const handleResetCanvasHeight = useCallback(() => {
    setCanvasHeight(DEFAULT_CANVAS_HEIGHT);
  }, []);

  const handleViewportChange = useCallback((nextViewport: CanvasViewport) => {
    viewportRef.current = nextViewport;
    setViewportState(nextViewport);
  }, []);

  const fitViewportToNodes = useCallback(
    (targetNodes: Node[], maxZoom: number) => {
      const flowSurface = flowSurfaceRef.current;
      if (!flowSurface || targetNodes.length === 0) {
        return;
      }
      const bounds = flowSurface.getBoundingClientRect();
      if (bounds.width <= 0 || bounds.height <= 0) {
        return;
      }
      const nextViewport = buildViewportForNodes(
        targetNodes,
        bounds.width,
        bounds.height,
        maxZoom
      );
      handleViewportChange(nextViewport);
      void reactFlowRef.current?.setViewport(nextViewport, { duration: 220 });
    },
    [handleViewportChange]
  );

  const syncHistoryDepthState = useCallback(() => {
    setUndoDepth(graphHistoryUndoRef.current.length);
    setRedoDepth(graphHistoryRedoRef.current.length);
  }, []);

  const resetGraphHistory = useCallback(
    (payload: DFDBulkSave) => {
      graphHistoryCurrentRef.current = createGraphHistorySnapshot(payload);
      graphHistoryUndoRef.current = [];
      graphHistoryRedoRef.current = [];
      suppressHistoryCaptureRef.current = false;
      syncHistoryDepthState();
    },
    [syncHistoryDepthState]
  );

  const handleToggleFullscreen = useCallback(async () => {
    if (typeof document === "undefined") return;
    const shell = canvasShellRef.current;
    if (!shell || typeof shell.requestFullscreen !== "function") {
      setQuickAddError("Full screen mode is not supported in this browser.");
      return;
    }

    try {
      if (document.fullscreenElement === shell) {
        await document.exitFullscreen();
      } else {
        await shell.requestFullscreen();
      }
      setQuickAddError(null);
    } catch {
      setQuickAddError("Could not toggle full screen mode.");
    }
  }, []);

  const openBoundaryEditor = useCallback((boundaryId: string) => {
    const boundaryNode = nodesRef.current.find(
      (node) => node.id === boundaryId && node.type === "trustBoundary"
    );
    if (!boundaryNode) {
      return;
    }
    const boundaryData = boundaryNode.data as { label?: string; boundary_type?: BoundaryType };
    setEditingBoundary({
      id: boundaryNode.id,
      name: boundaryData.label || "",
      boundary_type: boundaryData.boundary_type,
      width: getNodeDimension(boundaryNode.style?.width, DEFAULT_BOUNDARY_WIDTH),
      height: getNodeDimension(boundaryNode.style?.height, DEFAULT_BOUNDARY_HEIGHT),
    });
  }, []);

  const openEdgeEditor = useCallback(
    (edgeId: string) => {
      const edge = edgesRef.current.find((candidate) => candidate.id === edgeId);
      if (!edge) return;
      closeSpawnMenu();
      setQuickAddError(null);
      const edgeData = getCanvasEdgeData(edge);
      setEdgeEditorState({
        mode: "edit",
        id: edge.id,
        label: edgeData.flowLabel,
        properties: edgeData.properties,
        requireMetadata: edgeData.missingMetadata?.length ? true : false,
      });
    },
    [closeSpawnMenu]
  );

  const openNodeContextMenu = useCallback(
    (event: React.MouseEvent<HTMLElement>, nodeId: string) => {
      const node = nodesRef.current.find((candidate) => candidate.id === nodeId);
      if (!node) return;
      const containerRect = getFlowSurfaceRect();
      if (!containerRect) return;
      setQuickAddError(null);
      setSpawnMenu(null);
      setCanvasMenu(null);
      setGraphContextMenu({
        kind: node.type === "trustBoundary" ? "boundary" : "node",
        id: node.id,
        label:
          node.type === "trustBoundary"
            ? ((node.data as { label?: string }).label || "Trust Boundary")
            : ((node.data as DFDNodeData).label || "Unnamed"),
        nodeType: node.type === "trustBoundary" ? undefined : (node.type as NodeType),
        x: event.clientX - containerRect.left,
        y: event.clientY - containerRect.top,
      });
    },
    [getFlowSurfaceRect]
  );

  const openEdgeContextMenu = useCallback(
    (event: React.MouseEvent<HTMLElement>, edgeId: string) => {
      const edge = edgesRef.current.find((candidate) => candidate.id === edgeId);
      if (!edge) return;
      const containerRect = getFlowSurfaceRect();
      if (!containerRect) return;
      const edgeData = getCanvasEdgeData(edge);
      const displayLabel = buildEdgeDisplayLabel(edgeData.flowLabel, edgeData.properties);
      setQuickAddError(null);
      setSpawnMenu(null);
      setCanvasMenu(null);
      setGraphContextMenu({
        kind: "edge",
        id: edge.id,
        label: edgeData.flowLabel.trim()
          ? edgeData.flowLabel
          : displayLabel || `${edge.source} -> ${edge.target}`,
        x: event.clientX - containerRect.left,
        y: event.clientY - containerRect.top,
      });
    },
    [getFlowSurfaceRect]
  );

  const edgeInteractionCallbacks = useMemo(
    () => ({
      onEdit: openEdgeEditor,
      onOpenContextMenu: openEdgeContextMenu,
      onOpenNodeContextMenu: openNodeContextMenu,
    }),
    [openEdgeEditor, openEdgeContextMenu, openNodeContextMenu]
  );

  const containerView = useMemo(
    () =>
      views.find(
        (view) => view.view_type === "container" && !view.parent_view_id
      ) ?? null,
    [views]
  );
  const selectedView = useMemo(
    () =>
      views.find((view) => view.id === selectedViewId) ??
      containerView ??
      null,
    [views, selectedViewId, containerView]
  );
  const selectedViewChain = useMemo(
    () => buildViewChain(views, selectedView),
    [views, selectedView]
  );
  const topLevelViews = useMemo(
    () => views.filter((view) => !view.parent_view_id),
    [views]
  );
  const selectedTopLevelViewId =
    selectedViewChain[0]?.id ?? containerView?.id ?? null;
  const isReadOnlyView = !isEditableView(selectedView);
  const isDecompositionView = selectedView?.view_type === "decomposition";
  const currentWorkspaceDuplicateSourceId = selectedView?.id ?? containerView?.id ?? null;
  const activeViewId = selectedView?.id ?? containerView?.id ?? null;

  useEffect(() => {
    isReadOnlyViewRef.current = isReadOnlyView;
  }, [isReadOnlyView]);

  const groupedQuickAddTemplates = useMemo(() => {
    const groups = new Map<string, DFDComponentTemplateResponse[]>();
    for (const template of componentTemplates) {
      const groupName = template.group?.trim() || (template.built_in ? "Built-in" : "Custom");
      const groupItems = groups.get(groupName) ?? [];
      groupItems.push(template);
      groups.set(groupName, groupItems);
    }
    return [...groups.entries()];
  }, [componentTemplates]);
  const customComponentTemplates = useMemo(
    () => componentTemplates.filter((template) => !template.built_in),
    [componentTemplates]
  );
  const persistSnapshotImmediately = useCallback(
    async (nextNodes: Node[], nextEdges: CanvasEdge[]) => {
      if (isReadOnlyView) {
        return false;
      }

      setAutoSaveStatus("saving");
      setSaveStatus("saving");

      try {
        const savedDfd = await api.saveDFD(
          threatModelId,
          buildBulkSavePayload(nextNodes, nextEdges),
          activeViewId
        );
        persistedGraphSignatureRef.current = buildGraphSignature(
          buildBulkSavePayloadFromDfd(savedDfd)
        );
        setAutoSaveStatus("saved");
        setTimeout(() => setAutoSaveStatus("idle"), 2000);
        setSaveStatus("saved");
        setTimeout(() => setSaveStatus("idle"), 2000);
        onAutoSaveComplete?.();
        return true;
      } catch {
        setAutoSaveStatus("idle");
        setSaveStatus("error");
        setTimeout(() => setSaveStatus("idle"), 3000);
        return false;
      }
    },
    [activeViewId, isReadOnlyView, onAutoSaveComplete, threatModelId]
  );

  const handleBoundaryResizeEnd = useCallback(
    (boundaryId: string, params: ResizeParams) => {
      const nextNodes = normalizeBoundaryNodes(
        nodesRef.current.map((node) =>
          node.id === boundaryId
            ? {
                ...node,
                position: {
                  x: Number.isFinite(params.x) ? params.x : node.position.x,
                  y: Number.isFinite(params.y) ? params.y : node.position.y,
                },
                style: {
                  ...(node.style ?? {}),
                  width: Math.max(MIN_BOUNDARY_WIDTH, params.width),
                  height: Math.max(MIN_BOUNDARY_HEIGHT, params.height),
                },
              }
            : node
        )
      );
      const nextEdges = refreshEdgeVisuals(nextNodes, edgesRef.current, edgeInteractionCallbacks);

      skipAutoSavePassesRef.current = Math.max(skipAutoSavePassesRef.current, 2);
      setNodes(nextNodes);
      setEdges(nextEdges);
      setEditingBoundary((current) =>
        current?.id === boundaryId
          ? {
              ...current,
              width: Math.max(MIN_BOUNDARY_WIDTH, params.width),
              height: Math.max(MIN_BOUNDARY_HEIGHT, params.height),
            }
          : current
      );
      void persistSnapshotImmediately(nextNodes, nextEdges);
    },
    [edgeInteractionCallbacks, persistSnapshotImmediately, setEdges, setNodes]
  );

  const handleBoundaryMoveStart = useCallback(() => {
    dragSnapshotNodesRef.current = cloneNodesForDragSnapshot(nodesRef.current);
    ignoreNodeDragStopUntilRef.current = Date.now() + 250;
  }, []);

  const handleBoundaryMoveEnd = useCallback(
    (boundaryId: string, position: { x: number; y: number }) => {
      const currentNodes = nodesRef.current;
      const boundaryNode = currentNodes.find(
        (node) => node.id === boundaryId && node.type === "trustBoundary"
      );
      if (!boundaryNode) {
        return;
      }

      const nextBoundaryPosition = {
        x: Number.isFinite(position.x) ? position.x : boundaryNode.position.x,
        y: Number.isFinite(position.y) ? position.y : boundaryNode.position.y,
      };
      const deltaX = nextBoundaryPosition.x - boundaryNode.position.x;
      const deltaY = nextBoundaryPosition.y - boundaryNode.position.y;
      if (deltaX === 0 && deltaY === 0) {
        return;
      }

      const selectedBoundaryIds = currentNodes
        .filter((node) => node.type === "trustBoundary" && node.selected)
        .map((node) => node.id);
      const selectedDataNodeIds = currentNodes
        .filter((node) => node.type !== "trustBoundary" && node.selected)
        .map((node) => node.id);
      const useWholeSelection =
        selectedBoundaryIds.length > 0 && selectedBoundaryIds.includes(boundaryId);
      const snapshotNodes = dragSnapshotNodesRef.current;
      const baseNodes =
        useWholeSelection &&
        snapshotNodes &&
        snapshotNodes.some((snapshotNode) => snapshotNode.id === boundaryId)
          ? snapshotNodes
          : currentNodes;
      const { boundaryIds, memberNodeIds } = collectSelectionMoveScope(baseNodes, {
        rootBoundaryIds: useWholeSelection ? selectedBoundaryIds : [boundaryId],
        extraNodeIds: useWholeSelection ? selectedDataNodeIds : [],
      });
      const baseNodeById = new Map(baseNodes.map((node) => [node.id, node]));
      const nextNodes = normalizeBoundaryNodes(
        currentNodes.map((node) => {
          const baseNode = baseNodeById.get(node.id) ?? node;

          if (node.type === "trustBoundary" && boundaryIds.has(node.id)) {
            return {
              ...node,
              position: {
                x: baseNode.position.x + deltaX,
                y: baseNode.position.y + deltaY,
              },
            };
          }

          if (node.type !== "trustBoundary" && memberNodeIds.has(node.id)) {
            const absolutePosition = getAbsoluteNodePosition(baseNode, baseNodeById);
            return {
              ...node,
              parentId: undefined,
              extent: undefined,
              expandParent: false,
              position: {
                x: absolutePosition.x + deltaX,
                y: absolutePosition.y + deltaY,
              },
            };
          }

          return node;
        })
      );
      const nextEdges = refreshEdgeVisuals(nextNodes, edgesRef.current, edgeInteractionCallbacks);

      skipAutoSavePassesRef.current = Math.max(skipAutoSavePassesRef.current, 2);
      setNodes(nextNodes);
      setEdges(nextEdges);
      void persistSnapshotImmediately(nextNodes, nextEdges);
    },
    [edgeInteractionCallbacks, persistSnapshotImmediately, setEdges, setNodes]
  );

  const handleSpawnHandleClick = useCallback<SpawnHandleClickHandler>(
    (event, nodeId, side) => {
      const containerRect = getFlowSurfaceRect();
      if (!containerRect) return;
      setQuickAddError(null);
      setCanvasMenu(null);

      const nextMenu = {
        nodeId,
        side,
        x: event.clientX - containerRect.left,
        y: event.clientY - containerRect.top,
      };

      setSpawnMenu((current) =>
        current && current.nodeId === nodeId && current.side === side
          ? null
          : nextMenu
      );
    },
    [getFlowSurfaceRect]
  );

  const handleNodeDecompositionClick = useCallback<OpenDecompositionHandler>(
    (event, nodeId) => {
      event.preventDefault();
      event.stopPropagation();
      openDecompositionRef.current(nodeId);
    },
    []
  );

  const handleNodeThreatFocusClick = useCallback<FocusThreatsHandler>(
    (event, nodeId) => {
      event.preventDefault();
      event.stopPropagation();
      const node = nodesRef.current.find((candidate) => candidate.id === nodeId);
      if (!node) return;
      const label = ((node.data as DFDNodeData).label || "Unnamed").trim();
      onFocusThreatsForGraphObject?.({
        kind: "node",
        id: nodeId,
        label,
      });
    },
    [onFocusThreatsForGraphObject]
  );

  const buildCanvasNode = useCallback(
    (apiNode: DFDNodeResponse, existingNodes: Node[] = []): Node => {
      const boundaryNodes = existingNodes.filter((node) => node.type === "trustBoundary");
      const boundaryId =
        apiNode.trust_boundary_id ??
        findContainingBoundaryId(
          { x: apiNode.position_x, y: apiNode.position_y },
          boundaryNodes
        );
      const parentBoundary =
        boundaryId != null
          ? existingNodes.find(
              (node) => node.id === boundaryId && node.type === "trustBoundary"
            )
          : undefined;

      return {
        id: apiNode.id,
        type: apiNode.node_type,
        parentId: parentBoundary?.id,
        position: parentBoundary
          ? clampNodePositionToBoundary({
              x: apiNode.position_x - parentBoundary.position.x,
              y: apiNode.position_y - parentBoundary.position.y,
            }, getBoundaryGeometry(parentBoundary))
          : { x: apiNode.position_x, y: apiNode.position_y },
        extent: undefined,
        expandParent: false,
        data: {
          label: apiNode.name,
          properties: normalizeNodeProperties((apiNode.properties ?? {}) as NodeProperties),
          scan_target_url:
            apiNode.scan_target_url ??
            (((apiNode.properties ?? {}) as Record<string, unknown>).scan_target_url as
              | string
              | null
              | undefined) ??
            null,
          scan_target_ports:
            apiNode.scan_target_ports ??
            (((apiNode.properties ?? {}) as Record<string, unknown>).scan_target_ports as
              | string
              | null
              | undefined) ??
            null,
          onHandleClick: handleSpawnHandleClick,
          onFocusThreats: onFocusThreatsForGraphObject ? handleNodeThreatFocusClick : undefined,
          onOpenDecomposition:
            !isReadOnlyView && DECOMPOSABLE_NODE_TYPES.has(apiNode.node_type)
              ? handleNodeDecompositionClick
              : undefined,
          threatCount: threatSignalsByNodeId[apiNode.id]?.count ?? 0,
          highestThreatSeverity: threatSignalsByNodeId[apiNode.id]?.highestSeverity ?? null,
        },
      };
    },
    [
      handleNodeDecompositionClick,
      handleNodeThreatFocusClick,
      handleSpawnHandleClick,
      isReadOnlyView,
      onFocusThreatsForGraphObject,
      threatSignalsByNodeId,
    ]
  );

  const renderedGraph = useMemo(() => {
    if (!isReadOnlyView || !selectedView) {
      return { nodes, edges };
    }

    const visibleNodes = applyViewVisibilityToNodes(nodes, selectedView)
      .filter((node) => !node.hidden)
      .map((node) => ({ ...node, hidden: false }));
    const visibleEdges = applyViewVisibilityToEdges(edges, selectedView)
      .filter((edge) => !edge.hidden)
      .map((edge) => ({ ...edge, hidden: false }));

    if (visibleNodes.length === 0) {
      return { nodes: visibleNodes, edges: visibleEdges };
    }

    const visibleNodeBoundaryMap = buildCanvasNodeBoundaryMap(visibleNodes);
    const flattenedNodes = flattenNodesForReadOnlyLayout(visibleNodes);
    const compactDataNodes = applyPackedDagreLayout(
      flattenedNodes,
      visibleEdges,
      DAGRE_COMPACT_CONFIG
    );
    const compactBoundaryNodes = buildBoundaryNodes(
      buildBoundarySnapshot(visibleNodes),
      new Map(compactDataNodes.map((node) => [node.id, node.position])),
      "derive"
    );
    const compactNodes = attachNodeInteractionCallbacks(
      [...compactBoundaryNodes, ...compactDataNodes],
      undefined,
      undefined,
      onFocusThreatsForGraphObject ? handleNodeThreatFocusClick : undefined,
      threatSignalsByNodeId,
      undefined,
      undefined,
      undefined
    );

    return {
      nodes: compactNodes,
      edges: refreshEdgeVisuals(
        compactNodes,
        visibleEdges,
        edgeInteractionCallbacks,
        visibleNodeBoundaryMap
      ),
    };
  }, [
    edgeInteractionCallbacks,
    edges,
    handleNodeThreatFocusClick,
    isReadOnlyView,
    nodes,
    onFocusThreatsForGraphObject,
    selectedView,
    threatSignalsByNodeId,
  ]);
  const renderedNodes = renderedGraph.nodes;
  const renderedEdges = renderedGraph.edges;

  const applyGraphResponse = useCallback(
    (
      dfd: DFDResponse,
      options?: {
        rememberPersisted?: boolean;
        fitToView?: boolean;
        suppressAutoSavePasses?: number;
        resetHistory?: boolean;
      }
    ) => {
      const { nodes: rfNodes, edges: rfEdges } = convertDFDToReactFlow(
        dfd,
        edgeInteractionCallbacks,
        threatSignalsByNodeId
      );
      const payload = buildBulkSavePayloadFromDfd(dfd);
      pendingSnapshotFitRef.current = options?.fitToView ?? false;
      if (options?.rememberPersisted) {
        persistedGraphSignatureRef.current = buildGraphSignature(payload);
      }
      if ((options?.suppressAutoSavePasses ?? 0) > 0) {
        skipAutoSavePassesRef.current = Math.max(
          skipAutoSavePassesRef.current,
          options?.suppressAutoSavePasses ?? 0
        );
      }
      if (options?.resetHistory) {
        resetGraphHistory(payload);
      }
      setNodes(
        attachNodeInteractionCallbacks(
          normalizeBoundaryNodes(rfNodes),
          handleSpawnHandleClick,
          isReadOnlyView ? undefined : handleNodeDecompositionClick,
          onFocusThreatsForGraphObject ? handleNodeThreatFocusClick : undefined,
          threatSignalsByNodeId,
          isReadOnlyView ? undefined : openBoundaryEditor,
          isReadOnlyView ? undefined : handleBoundaryMoveStart,
          isReadOnlyView ? undefined : handleBoundaryMoveEnd,
          isReadOnlyView ? undefined : handleBoundaryResizeEnd
        )
      );
      setEdges(rfEdges);
      setState(
        dfd.nodes.length === 0 &&
          dfd.edges.length === 0 &&
          dfd.trust_boundaries.length === 0
          ? "empty"
          : "data"
      );
    },
    [
      edgeInteractionCallbacks,
      handleNodeDecompositionClick,
      handleNodeThreatFocusClick,
      handleSpawnHandleClick,
      handleBoundaryMoveStart,
      handleBoundaryMoveEnd,
      handleBoundaryResizeEnd,
      isReadOnlyView,
      onFocusThreatsForGraphObject,
      openBoundaryEditor,
      resetGraphHistory,
      setEdges,
      setNodes,
      threatSignalsByNodeId,
    ]
  );

  useEffect(() => {
    applyDfdSnapshotRef.current = (dfd: DFDResponse) => {
      applyGraphResponse(dfd, {
        rememberPersisted: true,
        fitToView: true,
        suppressAutoSavePasses: 2,
        resetHistory: true,
      });
    };
  }, [applyGraphResponse]);

  const acknowledgeServerMutation = useCallback((skipPasses = 1) => {
    skipAutoSavePassesRef.current = Math.max(
      skipAutoSavePassesRef.current,
      skipPasses
    );
    setAutoSaveStatus("saved");
    window.setTimeout(() => setAutoSaveStatus("idle"), 2000);
    void onAutoSaveComplete?.();
  }, [onAutoSaveComplete]);

  const loadDFD = useCallback(async (requestedViewId?: string | null) => {
    setState("loading");
    closeSpawnMenu();
    try {
      const nextViews = await api.getDFDViews(threatModelId).catch(() => []);
      const resolvedViewId =
        (requestedViewId &&
        nextViews.some((view) => view.id === requestedViewId)
          ? requestedViewId
          : selectedViewId &&
              nextViews.some((view) => view.id === selectedViewId)
            ? selectedViewId
            : nextViews.find((view) => view.view_type === "container")?.id ??
              nextViews[0]?.id ??
              null);
      const dfd = await api.getDFD(threatModelId, resolvedViewId);

      setViews(nextViews);
      setSelectedViewId(resolvedViewId);
      if (
        dfd.nodes.length === 0 &&
        dfd.edges.length === 0 &&
        dfd.trust_boundaries.length === 0
      ) {
        pendingSnapshotFitRef.current = false;
        const emptyPayload = buildBulkSavePayloadFromDfd(dfd);
        persistedGraphSignatureRef.current = buildGraphSignature(emptyPayload);
        resetGraphHistory(emptyPayload);
        setNodes([]);
        setEdges([]);
        setState("empty");
        return;
      }
      applyDfdSnapshotRef.current(dfd);
    } catch {
      setState("error");
    }
  }, [threatModelId, closeSpawnMenu, resetGraphHistory, selectedViewId, setEdges, setNodes]);

  const handleCreateWorkspace = useCallback(
    async (payload: { name: string; sourceViewId: string | null }) => {
      setCreatingWorkspace(true);
      setCreateWorkspaceError(null);
      try {
        const createdView = await api.createDFDWorkspaceView(threatModelId, {
          name: payload.name,
          source_view_id: payload.sourceViewId,
        });
        setShowCreateWorkspaceDialog(false);
        await loadDFD(createdView.id);
      } catch (error) {
        setCreateWorkspaceError(
          getActionErrorMessage(error, "Failed to create the new DFD workspace.")
        );
      } finally {
        setCreatingWorkspace(false);
      }
    },
    [loadDFD, threatModelId]
  );

  useEffect(() => {
    loadDFD();
  }, [loadDFD]);

  useEffect(() => {
    if (!pendingSnapshotFitRef.current || state !== "data" || !reactFlowRef.current) {
      return;
    }

    const animationFrame = window.requestAnimationFrame(() => {
      if (!pendingSnapshotFitRef.current || !reactFlowRef.current) {
        return;
      }
      pendingSnapshotFitRef.current = false;
      void reactFlowRef.current.fitView({
        padding: 0.2,
        minZoom: FIT_VIEW_MIN_ZOOM,
        maxZoom: 1.5,
      });
    });

    return () => window.cancelAnimationFrame(animationFrame);
  }, [edges, nodes, state]);

  useEffect(() => {
    if (!isReadOnlyView || !selectedView?.id || !reactFlowRef.current || renderedNodes.length === 0) {
      return;
    }
    if (lastReadOnlyAutoFitViewRef.current === selectedView.id) {
      return;
    }

    let secondAnimationFrame: number | null = null;
    const animationFrame = window.requestAnimationFrame(() => {
      secondAnimationFrame = window.requestAnimationFrame(() => {
        fitViewportToNodes(renderedNodes, 1.05);
        lastReadOnlyAutoFitViewRef.current = selectedView.id;
      });
    });

    return () => {
      window.cancelAnimationFrame(animationFrame);
      if (secondAnimationFrame !== null) {
        window.cancelAnimationFrame(secondAnimationFrame);
      }
    };
  }, [fitViewportToNodes, isReadOnlyView, renderedNodes, selectedView?.id]);

  useEffect(() => {
    if (!isReadOnlyView) {
      lastReadOnlyAutoFitViewRef.current = null;
    } else if (
      selectedView?.id &&
      lastReadOnlyAutoFitViewRef.current &&
      lastReadOnlyAutoFitViewRef.current !== selectedView.id
    ) {
      lastReadOnlyAutoFitViewRef.current = null;
    }
  }, [isReadOnlyView, selectedView?.id]);

  const handleSelectView = useCallback(
    (nextViewId: string | null) => {
      void loadDFD(nextViewId);
    },
    [loadDFD]
  );

  useEffect(() => {
    skipAutoSavePassesRef.current = Math.max(skipAutoSavePassesRef.current, 2);
    setNodes((currentNodes) => applyViewVisibilityToNodes(currentNodes, selectedView));
    setEdges((currentEdges) => applyViewVisibilityToEdges(currentEdges, selectedView));
  }, [selectedView, setNodes, setEdges]);

  const handleOpenDecomposition = useCallback(
    async (targetNodeId: string) => {
      if (isReadOnlyView || !activeViewId) {
        return;
      }
      closeSpawnMenu();
      setQuickAddError(null);

      const existingView = views.find(
        (view) =>
          view.view_type === "decomposition" &&
          view.parent_view_id === activeViewId &&
          view.parent_node_id === targetNodeId
      );
      if (existingView) {
        void loadDFD(existingView.id);
        return;
      }

      try {
        const createdView = await api.createDFDDecompositionView(threatModelId, {
          parent_node_id: targetNodeId,
          parent_view_id: activeViewId,
        });
        void loadDFD(createdView.id);
      } catch (error) {
        const message =
          error instanceof Error && error.message
            ? error.message
            : "Failed to open decomposition.";
        setQuickAddError(`Decomposition failed. ${message}`);
      }
    },
    [activeViewId, closeSpawnMenu, isReadOnlyView, loadDFD, threatModelId, views]
  );

  useEffect(() => {
    openDecompositionRef.current = (nodeId: string) => {
      void handleOpenDecomposition(nodeId);
    };
  }, [handleOpenDecomposition]);

  const reconcileDraggedNodes = useCallback(
    (draggedNodes: Node[]) => {
      if (draggedNodes.length === 0) {
        dragSnapshotNodesRef.current = null;
        return;
      }

      let reconciledNodes: Node[] = [];
      setNodes((currentNodes) => {
        const draggedNodeById = new Map(
          draggedNodes.map((draggedNode) => [draggedNode.id, draggedNode])
        );
        const postDragNodes = currentNodes.map((currentNode) => {
          const draggedNode = draggedNodeById.get(currentNode.id);
          if (!draggedNode) {
            return currentNode;
          }

          return {
            ...currentNode,
            position: draggedNode.position,
          };
        });
        const dragSnapshotNodes = dragSnapshotNodesRef.current;
        const selectedBoundaryIds =
          dragSnapshotNodes
            ?.filter((snapshotNode) => snapshotNode.type === "trustBoundary" && snapshotNode.selected)
            .map((snapshotNode) => snapshotNode.id) ?? [];

        if (dragSnapshotNodes && selectedBoundaryIds.length > 0) {
          const selectedDataNodeIds = dragSnapshotNodes
            .filter((snapshotNode) => snapshotNode.type !== "trustBoundary" && snapshotNode.selected)
            .map((snapshotNode) => snapshotNode.id);
          const dragSourceId =
            draggedNodes.find(
              (draggedNode) =>
                selectedDataNodeIds.includes(draggedNode.id) ||
                selectedBoundaryIds.includes(draggedNode.id)
            )?.id ?? draggedNodes[0]?.id;
          const snapshotNodeById = new Map(
            dragSnapshotNodes.map((snapshotNode) => [snapshotNode.id, snapshotNode])
          );
          const postDragNodeById = new Map(
            postDragNodes.map((postDragNode) => [postDragNode.id, postDragNode])
          );
          const snapshotDragSource = dragSourceId ? snapshotNodeById.get(dragSourceId) : null;
          const postDragSource = dragSourceId ? postDragNodeById.get(dragSourceId) : null;

          if (snapshotDragSource && postDragSource) {
            const snapshotAbsolutePosition = getAbsoluteNodePosition(
              snapshotDragSource,
              snapshotNodeById
            );
            const postDragAbsolutePosition = getAbsoluteNodePosition(
              postDragSource,
              postDragNodeById
            );
            const deltaX = postDragAbsolutePosition.x - snapshotAbsolutePosition.x;
            const deltaY = postDragAbsolutePosition.y - snapshotAbsolutePosition.y;

            if (deltaX !== 0 || deltaY !== 0) {
              const { boundaryIds, memberNodeIds } = collectSelectionMoveScope(
                dragSnapshotNodes,
                {
                  rootBoundaryIds: selectedBoundaryIds,
                  extraNodeIds: selectedDataNodeIds,
                }
              );

              reconciledNodes = normalizeBoundaryNodes(
                postDragNodes.map((currentNode) => {
                  const snapshotNode = snapshotNodeById.get(currentNode.id) ?? currentNode;

                  if (currentNode.type === "trustBoundary" && boundaryIds.has(currentNode.id)) {
                    return {
                      ...currentNode,
                      position: {
                        x: snapshotNode.position.x + deltaX,
                        y: snapshotNode.position.y + deltaY,
                      },
                    };
                  }

                  if (currentNode.type !== "trustBoundary" && memberNodeIds.has(currentNode.id)) {
                    const snapshotAbsoluteNodePosition = getAbsoluteNodePosition(
                      snapshotNode,
                      snapshotNodeById
                    );
                    return {
                      ...currentNode,
                      parentId: undefined,
                      extent: undefined,
                      expandParent: false,
                      position: {
                        x: snapshotAbsoluteNodePosition.x + deltaX,
                        y: snapshotAbsoluteNodePosition.y + deltaY,
                      },
                    };
                  }

                  return currentNode;
                })
              );
              return reconciledNodes;
            }
          }
        }

        let nextNodes = postDragNodes;

        for (const draggedNode of draggedNodes) {
          if (draggedNode.type === "trustBoundary") {
            continue;
          }

          const nodeById = new Map(
            nextNodes.map((currentNode) => [currentNode.id, currentNode])
          );
          const nextDraggedNode = nodeById.get(draggedNode.id);
          if (!nextDraggedNode) {
            continue;
          }

          const absolutePosition = getAbsoluteNodePosition(nextDraggedNode, nodeById);
          const centerX = absolutePosition.x + NODE_WIDTH / 2;
          const centerY = absolutePosition.y + NODE_HEIGHT / 2;
          const candidateBoundary = nextNodes
            .filter((candidate) => candidate.type === "trustBoundary")
            .map((boundaryNode) => ({
              node: boundaryNode,
              geometry: getBoundaryGeometry(boundaryNode),
            }))
            .filter(
              ({ geometry }) =>
                centerX >= geometry.x &&
                centerX <= geometry.x + geometry.width &&
                centerY >= geometry.y &&
                centerY <= geometry.y + geometry.height
            )
            .sort(
              (left, right) =>
                left.geometry.width * left.geometry.height -
                right.geometry.width * right.geometry.height
            )[0];
          const destinationBoundary = candidateBoundary;
          const nextParentId = destinationBoundary?.node.id;
          const nextPosition =
            !nextParentId || !destinationBoundary
              ? absolutePosition
              : clampNodePositionToBoundary(
                  {
                    x: absolutePosition.x - destinationBoundary.geometry.x,
                    y: absolutePosition.y - destinationBoundary.geometry.y,
                  },
                  destinationBoundary.geometry
                );

          nextNodes = nextNodes.map((currentNode) => {
            if (currentNode.id !== draggedNode.id) {
              return currentNode;
            }

            if (!nextParentId || !destinationBoundary) {
              return {
                ...currentNode,
                parentId: undefined,
                position: absolutePosition,
                extent: undefined,
              };
            }

            return {
              ...currentNode,
              parentId: nextParentId,
              extent: undefined,
              expandParent: false,
              position: nextPosition,
            };
          });
        }

        reconciledNodes = normalizeBoundaryNodes(nextNodes);
        return reconciledNodes;
      });
      if (reconciledNodes.length > 0) {
        setEdges((currentEdges) =>
          refreshEdgeVisuals(reconciledNodes, currentEdges, edgeInteractionCallbacks)
        );
      }
      dragSnapshotNodesRef.current = null;
    },
    [setEdges, setNodes, edgeInteractionCallbacks]
  );

  const handleNodesChange = useCallback(
    (changes: NodeChange<Node>[]) => {
      const positionChanges = changes.filter(
        (change): change is NodeChange<Node> & { id: string; type: "position"; dragging?: boolean } =>
          change.type === "position"
      );
      const changedNodeIds = positionChanges.map((change) => change.id);
      if (
        !dragSnapshotNodesRef.current &&
        positionChanges.some((change) => change.dragging === true)
      ) {
        dragSnapshotNodesRef.current = cloneNodesForDragSnapshot(nodesRef.current);
      }
      onNodesChangeBase(changes);
      if (positionChanges.some((change) => change.dragging === false) && changedNodeIds.length > 0) {
        queueMicrotask(() => {
          if (ignoreNodeDragStopUntilRef.current > Date.now()) {
            ignoreNodeDragStopUntilRef.current = 0;
            dragSnapshotNodesRef.current = null;
            return;
          }
          reconcileDraggedNodes(
            nodesRef.current.filter((node) => changedNodeIds.includes(node.id))
          );
        });
      }
    },
    [onNodesChangeBase, reconcileDraggedNodes]
  );

  // Block 7 + 9: Delete selected nodes/edges on Delete/Backspace
  const handleKeyDown = useCallback(
    async (event: React.KeyboardEvent) => {
      if (isReadOnlyView) return;
      if (event.key !== "Delete" && event.key !== "Backspace") return;

      // Don't trigger delete if user is typing in an input
      const target = event.target as HTMLElement;
      if (
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.tagName === "SELECT"
      ) {
        return;
      }

      closeSpawnMenu();

      const selectedNodes = nodes.filter(
        (n) => n.selected && n.type !== "trustBoundary"
      );
      const selectedBoundaryNodes = nodes.filter(
        (n) => n.selected && n.type === "trustBoundary"
      );
      const selectedEdges = edges.filter((e) => e.selected);

      // Block 7: Delete selected nodes
      for (const node of selectedNodes) {
        try {
          await api.deleteNode(threatModelId, node.id, activeViewId);
        } catch {
          // continue deleting others
        }
      }
      // Block 9: Delete selected edges
      for (const edge of selectedEdges) {
        try {
          await api.deleteEdge(threatModelId, edge.id, activeViewId);
        } catch {
          // continue deleting others
        }
      }

      for (const boundary of selectedBoundaryNodes) {
        try {
          await api.deleteBoundary(threatModelId, boundary.id, activeViewId);
        } catch {
          // continue deleting others
        }
      }
      let nextNodes = nodes;
      let nextEdges = edges;

      if (selectedNodes.length > 0) {
        const deletedIds = new Set(selectedNodes.map((node) => node.id));
        nextNodes = nextNodes.filter((node) => !deletedIds.has(node.id));
        nextEdges = nextEdges.filter(
          (edge) => !deletedIds.has(edge.source) && !deletedIds.has(edge.target)
        );
      }

      if (selectedEdges.length > 0) {
        const deletedEdgeIds = new Set(selectedEdges.map((edge) => edge.id));
        nextEdges = nextEdges.filter((edge) => !deletedEdgeIds.has(edge.id));
      }

      if (selectedBoundaryNodes.length > 0) {
        const deletedBoundaryIds = new Set(selectedBoundaryNodes.map((boundary) => boundary.id));
        const deletedBoundaryPositions = new Map(
          selectedBoundaryNodes.map((boundary) => [boundary.id, boundary.position])
        );
        nextNodes = nextNodes
          .filter((currentNode) => !deletedBoundaryIds.has(currentNode.id))
          .map((currentNode) => {
            if (!currentNode.parentId || !deletedBoundaryIds.has(currentNode.parentId)) {
              return currentNode;
            }
            const parentPosition = deletedBoundaryPositions.get(currentNode.parentId);
            return {
              ...currentNode,
              parentId: undefined,
              position: parentPosition
                ? {
                    x: currentNode.position.x + parentPosition.x,
                    y: currentNode.position.y + parentPosition.y,
                  }
                  : currentNode.position,
            };
          });
      }

      if (
        selectedNodes.length > 0 ||
        selectedEdges.length > 0 ||
        selectedBoundaryNodes.length > 0
      ) {
        nextEdges = refreshEdgeVisuals(nextNodes, nextEdges, edgeInteractionCallbacks);
        rememberPersistedGraph(nextNodes, nextEdges);
        setNodes(nextNodes);
        setEdges(nextEdges);
        acknowledgeServerMutation(2);
      }
    },
    [
      nodes,
      edges,
      isReadOnlyView,
      threatModelId,
      activeViewId,
      setNodes,
      setEdges,
      closeSpawnMenu,
      acknowledgeServerMutation,
      edgeInteractionCallbacks,
      rememberPersistedGraph,
    ]
  );

  // Block 8: Connect handler — create edge on drag between handles
  const handleConnect = useCallback(
    async (connection: Connection) => {
      if (isReadOnlyView) return;
      if (!connection.source || !connection.target) return;
      closeSpawnMenu();
      setQuickAddError(null);
      setEdgeEditorState({
        mode: "create",
        sourceNodeId: connection.source,
        targetNodeId: connection.target,
        label: "",
        properties: {},
        requireMetadata: true,
      });
    },
    [
      closeSpawnMenu,
      isReadOnlyView,
    ]
  );

  // Block 10: Node click handler — allow selection without forcing edit mode
  const handleNodeClick = useCallback(
    (_event: React.MouseEvent) => {
      closeSpawnMenu();
      setQuickAddError(null);
    },
    [closeSpawnMenu]
  );

  const handleNodeDoubleClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      if (isReadOnlyView) return;
      closeSpawnMenu();
      setQuickAddError(null);
      if (node.type === "trustBoundary") {
        openBoundaryEditor(node.id);
        return;
      }
      const nodeType = node.type as NodeType;
      const nodeData = node.data as DFDNodeData;
      setEditingNode({
        id: node.id,
        name: nodeData.label || "",
        type: nodeType,
        properties: nodeData.properties ?? {},
        scan_target_url: nodeData.scan_target_url ?? null,
        scan_target_ports: nodeData.scan_target_ports ?? null,
      });
    },
    [closeSpawnMenu, isReadOnlyView, openBoundaryEditor]
  );

  const handleEdgeDoubleClick = useCallback(
    (_event: React.MouseEvent, edge: CanvasEdge) => {
      openEdgeEditor(edge.id);
    },
    [openEdgeEditor]
  );

  // Block 6: Add node callback
  const handleNodeAdded = useCallback(
    (apiNode: DFDNodeResponse) => {
      const nextNodes = normalizeBoundaryNodes([
        ...nodesRef.current,
        buildCanvasNode(apiNode, nodesRef.current),
      ]);
      rememberPersistedGraph(nextNodes, edgesRef.current);
      setNodes(nextNodes);
      closeSpawnMenu();
      // Move to data state if we were in empty
      setState("data");
    },
    [setNodes, buildCanvasNode, closeSpawnMenu, rememberPersistedGraph]
  );

  const getViewportCenterPosition = useCallback(() => {
    const containerRect = getFlowSurfaceRect();
    const reactFlow = reactFlowRef.current;
    if (!containerRect || !reactFlow) {
      return { x: 140, y: 120 };
    }

    const flowPosition = reactFlow.screenToFlowPosition({
      x: containerRect.left + containerRect.width / 2,
      y: containerRect.top + containerRect.height / 2,
    });

    return {
      x: flowPosition.x - NODE_WIDTH / 2,
      y: flowPosition.y - NODE_HEIGHT / 2,
    };
  }, [getFlowSurfaceRect]);

  const handleCreateNodeFromPalette = useCallback(
    async (nodeType: NodeType) => {
      if (isReadOnlyView) return;
      closeSpawnMenu();
      setQuickAddError(null);
      const centerPosition = getViewportCenterPosition();
      const boundaryNodes = nodesRef.current.filter((node) => node.type === "trustBoundary");
      const trustBoundaryId = findContainingBoundaryId(centerPosition, boundaryNodes);

      try {
        const node = await api.createNode(
          threatModelId,
          {
            node_type: nodeType,
            name: buildSpawnNodeName(nodesRef.current, nodeType),
            position_x: centerPosition.x,
            position_y: centerPosition.y,
            trust_boundary_id: trustBoundaryId,
          },
          activeViewId
        );
        handleNodeAdded(node);
      } catch (error) {
        const message =
          error instanceof Error && error.message
            ? error.message
            : "Failed to create component.";
        setQuickAddError(`Component creation failed. ${message}`);
      }
    },
    [
      activeViewId,
      closeSpawnMenu,
      getViewportCenterPosition,
      handleNodeAdded,
      isReadOnlyView,
      threatModelId,
    ]
  );

  const handleCreateTemplateFromPalette = useCallback(
    async (template: DFDComponentTemplateResponse) => {
      if (isReadOnlyView) return;
      closeSpawnMenu();
      setQuickAddError(null);
      const centerPosition = getViewportCenterPosition();
      const boundaryNodes = nodesRef.current.filter((node) => node.type === "trustBoundary");
      const trustBoundaryId = findContainingBoundaryId(centerPosition, boundaryNodes);

      try {
        const node = await api.createNode(
          threatModelId,
          {
            node_type: template.semantic_node_type,
            name: buildSpawnNodeName(
              nodesRef.current,
              template.semantic_node_type,
              template.default_name || template.label
            ),
            position_x: centerPosition.x,
            position_y: centerPosition.y,
            trust_boundary_id: trustBoundaryId,
            properties: buildNodePropertiesFromTemplate(template),
          },
          activeViewId
        );
        handleNodeAdded(node);
      } catch (error) {
        const message =
          error instanceof Error && error.message
            ? error.message
            : "Failed to create component.";
        setQuickAddError(`Component creation failed. ${message}`);
      }
    },
    [
      activeViewId,
      closeSpawnMenu,
      getViewportCenterPosition,
      handleNodeAdded,
      isReadOnlyView,
      threatModelId,
    ]
  );

  // Block 10: Node updated callback
  const handleNodeSaved = useCallback(
    (updated: DFDNodeResponse) => {
      const nextNodes = nodesRef.current.map((node) =>
        node.id === updated.id
          ? {
              ...node,
              type: updated.node_type,
              data: {
                ...(node.data as DFDNodeData),
                label: updated.name,
                properties: (updated.properties ?? {}) as NodeProperties,
                scan_target_url: updated.scan_target_url ?? null,
                scan_target_ports: updated.scan_target_ports ?? null,
              },
            }
          : node
      );
      rememberPersistedGraph(nextNodes, edgesRef.current);
      setNodes(nextNodes);
      setEditingNode(null);
      acknowledgeServerMutation(1);
    },
    [setNodes, acknowledgeServerMutation, rememberPersistedGraph]
  );

  const handleEdgeSaved = useCallback(
    (updated: DFDEdgeResponse) => {
      const nextEdges = edgesRef.current.map((currentEdge) =>
        currentEdge.id === updated.id
          ? buildReactFlowEdge(updated, edgeInteractionCallbacks, buildCanvasNodeBoundaryMap(nodesRef.current))
          : currentEdge
      );
      rememberPersistedGraph(nodesRef.current, nextEdges);
      setEdges(nextEdges);
      setEdgeEditorState(null);
      acknowledgeServerMutation(1);
    },
    [setEdges, acknowledgeServerMutation, edgeInteractionCallbacks, rememberPersistedGraph]
  );

  const handleEdgeCreated = useCallback(
    (created: DFDEdgeResponse) => {
      const nextEdges = [
        ...edgesRef.current,
        buildReactFlowEdge(
          created,
          edgeInteractionCallbacks,
          buildCanvasNodeBoundaryMap(nodesRef.current)
        ),
      ];
      rememberPersistedGraph(nodesRef.current, nextEdges);
      setEdges(nextEdges);
      setEdgeEditorState(null);
      acknowledgeServerMutation(1);
    },
    [setEdges, acknowledgeServerMutation, edgeInteractionCallbacks, rememberPersistedGraph]
  );

  const handleQuickAddNode = useCallback(
    async (template: DFDComponentTemplateResponse) => {
      if (isReadOnlyView) return;
      const activeSpawnMenu = spawnMenu;
      if (!activeSpawnMenu && !canvasMenu) return;

      const createdNodeName = buildSpawnNodeName(
        nodes,
        template.semantic_node_type,
        template.default_name || template.label
      );
      const templateProperties = buildNodePropertiesFromTemplate(template);

      if (canvasMenu) {
        closeSpawnMenu();
        setQuickAddError(null);

        try {
          const createdNode = await api.createNode(threatModelId, {
            node_type: template.semantic_node_type,
            name: createdNodeName,
            position_x: canvasMenu.flowX,
            position_y: canvasMenu.flowY,
            properties: templateProperties,
          }, activeViewId);

          const nextNodes = [
            ...nodesRef.current,
            buildCanvasNode(createdNode, nodesRef.current),
          ];
          rememberPersistedGraph(nextNodes, edgesRef.current);
          acknowledgeServerMutation(1);
          setNodes(nextNodes);
          setState("data");
        } catch (error) {
          const message =
            error instanceof Error && error.message
              ? error.message
              : "Node creation failed. No changes were saved.";
          setQuickAddError(`Node creation failed. No changes were saved. ${message}`);
        }
        return;
      }

      if (!activeSpawnMenu) return;

      const originNode = nodes.find(
        (node) => node.id === activeSpawnMenu.nodeId && node.type !== "trustBoundary"
      );
      if (!originNode) {
        closeSpawnMenu();
        return;
      }

      const nodeById = new Map(nodes.map((node) => [node.id, node]));
      const originPosition = getAbsoluteNodePosition(originNode, nodeById);
      const xOffset =
        activeSpawnMenu.side === "source" ? QUICK_ADD_OFFSET_X : -QUICK_ADD_OFFSET_X;
      const originHandle = activeSpawnMenu.side;
      const trustBoundaryId =
        originHandle === "source" ? originNode.parentId ?? null : null;

      closeSpawnMenu();
      setQuickAddError(null);

      try {
        const quickAddResult = await api.quickAddNode(threatModelId, {
          origin_node_id: originNode.id,
          origin_handle: originHandle,
          node: {
            node_type: template.semantic_node_type,
            name: createdNodeName,
            position_x: originPosition.x + xOffset,
            position_y: originPosition.y,
            trust_boundary_id: trustBoundaryId,
            properties: templateProperties,
          },
          edge: {
            label: "",
          },
        }, activeViewId);

        const nextNodes = [
          ...nodesRef.current,
          buildCanvasNode(quickAddResult.node, nodesRef.current),
        ];
        const nextEdges = [
          ...edgesRef.current,
          buildReactFlowEdge(
            quickAddResult.edge,
            edgeInteractionCallbacks,
            buildCanvasNodeBoundaryMap(nextNodes)
          ),
        ];
        rememberPersistedGraph(nextNodes, nextEdges);
        acknowledgeServerMutation(2);
        setNodes(nextNodes);
        setEdges(nextEdges);
        setState("data");
        setQuickAddError(null);
        setEdgeEditorState({
          mode: "edit",
          id: quickAddResult.edge.id,
          label: quickAddResult.edge.label,
          properties: normalizeEdgeProperties(quickAddResult.edge.properties),
          requireMetadata: true,
        });
      } catch (error) {
        const message =
          error instanceof Error && error.message
            ? error.message
            : "Quick add failed. No changes were saved.";
        setQuickAddError(`Quick add failed. No changes were saved. ${message}`);
      }
    },
    [
      spawnMenu,
      nodes,
      threatModelId,
      activeViewId,
      closeSpawnMenu,
      buildCanvasNode,
      setNodes,
      setEdges,
      acknowledgeServerMutation,
      edgeInteractionCallbacks,
      canvasMenu,
      isReadOnlyView,
      rememberPersistedGraph,
    ]
  );

  // Block 11: Create trust boundary around the selection or as an empty box.
  const handleCreateBoundary = useCallback(async () => {
    if (isReadOnlyView) return;
    closeSpawnMenu();
    setQuickAddError(null);
    const selectedNodes = nodes.filter(
      (n) => n.selected && n.type !== "trustBoundary"
    );
    const suggestedBoundaryDraft =
      selectedNodes.length > 0
        ? suggestBoundaryDraftForSelection(selectedNodes)
        : null;
    const containerRect = getFlowSurfaceRect();
    const reactFlow = reactFlowRef.current;
    const centerPosition =
      containerRect && reactFlow
        ? reactFlow.screenToFlowPosition({
            x: containerRect.left + containerRect.width / 2,
            y: containerRect.top + containerRect.height / 2,
          })
        : { x: 140, y: 120 };

    try {
      await api.createBoundary(threatModelId, {
        name: suggestedBoundaryDraft?.name ?? "Trust Boundary",
        node_ids: selectedNodes.map((n) => n.id),
        boundary_type: suggestedBoundaryDraft?.boundaryType,
        ...(selectedNodes.length === 0
          ? {
              position_x: centerPosition.x - DEFAULT_BOUNDARY_WIDTH / 2,
              position_y: centerPosition.y - DEFAULT_BOUNDARY_HEIGHT / 2,
              width: DEFAULT_BOUNDARY_WIDTH,
              height: DEFAULT_BOUNDARY_HEIGHT,
            }
          : {}),
      }, activeViewId);
      // Reload DFD to get proper grouping
      await loadDFD(activeViewId);
    } catch (error) {
      const message = getActionErrorMessage(
        error,
        "Boundary creation failed. No changes were saved."
      );
      setQuickAddError(composeQuickAddError("Boundary creation failed.", message));
    }
  }, [
    nodes,
    threatModelId,
    activeViewId,
    loadDFD,
    closeSpawnMenu,
    getFlowSurfaceRect,
    isReadOnlyView,
  ]);

  const handleSuggestBoundaries = useCallback(async () => {
    if (isReadOnlyView || isDecompositionView) return;
    closeSpawnMenu();
    setQuickAddError(null);

    const suggestions = suggestBoundaryDrafts(nodes);
    if (suggestions.length === 0) {
      setQuickAddError(
        "No clear trust-boundary suggestions were found for ungrouped nodes."
      );
      return;
    }

    const createdBoundaryIds: string[] = [];
    try {
      for (const suggestion of suggestions) {
        const boundary = await api.createBoundary(
          threatModelId,
          {
            name: suggestion.name,
            node_ids: suggestion.nodeIds,
            boundary_type: suggestion.boundaryType,
          },
          activeViewId
        );
        createdBoundaryIds.push(boundary.id);
      }
      await loadDFD(activeViewId);
    } catch (error) {
      const message = getActionErrorMessage(error, "Boundary suggestion failed.");
      let rollbackFailed = false;

      if (createdBoundaryIds.length > 0) {
        const rollbackResults = await Promise.allSettled(
          createdBoundaryIds
            .slice()
            .reverse()
            .map((boundaryId) => api.deleteBoundary(threatModelId, boundaryId, activeViewId))
        );
        rollbackFailed = rollbackResults.some((result) => result.status === "rejected");
        await loadDFD(activeViewId);
      }

      if (rollbackFailed) {
        setQuickAddError(
          composeQuickAddError(
            "Boundary suggestion partially failed. Some suggested boundaries may still exist.",
            message
          )
        );
        return;
      }

      const failurePrefix =
        createdBoundaryIds.length > 0
          ? "Boundary suggestion failed and was rolled back. No changes were saved."
          : "Boundary suggestion failed.";
      setQuickAddError(composeQuickAddError(failurePrefix, message));
    }
  }, [
    nodes,
    threatModelId,
    activeViewId,
    loadDFD,
    closeSpawnMenu,
    isReadOnlyView,
    isDecompositionView,
  ]);

  // Block 12: Save DFD — convert ReactFlow state to DFDBulkSave format
  const handleSave = useCallback(async () => {
    if (isReadOnlyView) {
      return false;
    }
    setSaveStatus("saving");
    try {
      const bulkSave = buildBulkSavePayload(nodes, edges);
      const savedDfd = await api.saveDFD(threatModelId, bulkSave, activeViewId);
      persistedGraphSignatureRef.current = buildGraphSignature(
        buildBulkSavePayloadFromDfd(savedDfd)
      );
      const nextViews = await api.regenerateDFDViews(threatModelId).catch(() => views);
      setViews(nextViews);
      setSelectedViewId((current) => {
        if (current && nextViews.some((view) => view.id === current)) {
          return current;
        }
        return (
          nextViews.find((view) => view.view_type === "container")?.id ??
          nextViews[0]?.id ??
          null
        );
      });
      setSaveStatus("saved");
      // Reset status after 2 seconds
      setTimeout(() => setSaveStatus("idle"), 2000);
      return true;
    } catch {
      setSaveStatus("error");
      setTimeout(() => setSaveStatus("idle"), 3000);
      return false;
    }
  }, [nodes, edges, threatModelId, activeViewId, isReadOnlyView, views]);

  // Auto-save: debounced trigger that calls handleSave after 3 seconds of inactivity.
  // autoSaveInFlightRef prevents overlapping saves if a previous save is still in-progress.
  const triggerAutoSave = useCallback(() => {
    if (autoSaveTimerRef.current) {
      clearTimeout(autoSaveTimerRef.current);
    }
    autoSaveTimerRef.current = setTimeout(async () => {
      if (autoSaveInFlightRef.current) return;
      autoSaveInFlightRef.current = true;
      setAutoSaveStatus("saving");
      try {
        const saved = await handleSave();
        if (!saved) {
          setAutoSaveStatus("idle");
          return;
        }
        setAutoSaveStatus("saved");
        setTimeout(() => setAutoSaveStatus("idle"), 2000);
        onAutoSaveComplete?.();
      } catch {
        setAutoSaveStatus("idle");
      } finally {
        autoSaveInFlightRef.current = false;
      }
    }, 3000);
  }, [handleSave, onAutoSaveComplete]);

  const handleBoundarySaved = useCallback(
    (
      boundaryId: string,
      name: string,
      boundaryType: BoundaryType | undefined,
      width: number,
      height: number
    ) => {
      const nextNodes = normalizeBoundaryNodes(nodesRef.current.map((node) =>
        node.id === boundaryId
          ? {
              ...node,
              data: {
                ...(node.data as { label?: string; boundary_type?: BoundaryType }),
                label: name,
                boundary_type: boundaryType,
              },
              style: {
                ...(node.style ?? {}),
                width: Math.max(MIN_BOUNDARY_WIDTH, width),
                height: Math.max(MIN_BOUNDARY_HEIGHT, height),
              },
            }
          : node
      ));
      const nextEdges = refreshEdgeVisuals(nextNodes, edgesRef.current, edgeInteractionCallbacks);
      skipAutoSavePassesRef.current = Math.max(skipAutoSavePassesRef.current, 2);
      setNodes(nextNodes);
      setEdges(nextEdges);
      setEditingBoundary(null);
      void persistSnapshotImmediately(nextNodes, nextEdges);
    },
    [edgeInteractionCallbacks, persistSnapshotImmediately, setEdges, setNodes]
  );

  // Cleanup auto-save timer on unmount
  useEffect(() => {
    return () => {
      if (autoSaveTimerRef.current) {
        clearTimeout(autoSaveTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (!spawnMenu) return;

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeSpawnMenu();
      }
    };

    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [spawnMenu, closeSpawnMenu]);

  useEffect(() => {
    const container = canvasRef.current;
    if (!container) return;

    container
      .querySelectorAll(
        ".assistant-highlight-node, .assistant-highlight-edge, .assistant-highlight-boundary"
      )
      .forEach((element) => {
        element.classList.remove(
          "assistant-highlight-node",
          "assistant-highlight-edge",
          "assistant-highlight-boundary"
        );
      });

    if (!highlightedReferences || highlightedReferences.length === 0) {
      return;
    }

    const applyHighlight = (selector: string, className: string) => {
      const element = container.querySelector(selector);
      if (element) {
        element.classList.add(className);
      }
    };

    for (const reference of highlightedReferences) {
      const safeId = reference.id.replace(/"/g, '\\"');
      if (reference.kind === "node") {
        applyHighlight(`.react-flow__node[data-id="${safeId}"]`, "assistant-highlight-node");
        const parentBoundaryId =
          nodes.find((node) => node.id === reference.id && node.type !== "trustBoundary")?.parentId;
        if (parentBoundaryId) {
          const safeBoundaryId = parentBoundaryId.replace(/"/g, '\\"');
          applyHighlight(
            `.react-flow__node[data-id="${safeBoundaryId}"]`,
            "assistant-highlight-boundary"
          );
        }
      } else if (reference.kind === "boundary") {
        applyHighlight(`.react-flow__node[data-id="${safeId}"]`, "assistant-highlight-boundary");
      } else if (reference.kind === "edge") {
        applyHighlight(`.react-flow__edge[data-id="${safeId}"]`, "assistant-highlight-edge");
        const edge = edges.find((candidate) => candidate.id === reference.id);
        if (edge) {
          for (const nodeId of [edge.source, edge.target]) {
            const safeNodeId = nodeId.replace(/"/g, '\\"');
            applyHighlight(
              `.react-flow__node[data-id="${safeNodeId}"]`,
              "assistant-highlight-node"
            );
            const parentBoundaryId =
              nodes.find((node) => node.id === nodeId && node.type !== "trustBoundary")?.parentId;
            if (parentBoundaryId) {
              const safeBoundaryId = parentBoundaryId.replace(/"/g, '\\"');
              applyHighlight(
                `.react-flow__node[data-id="${safeBoundaryId}"]`,
                "assistant-highlight-boundary"
              );
            }
          }
        }
      }
    }
  }, [highlightedReferences, nodes, edges]);

  useEffect(() => {
    setNodes((currentNodes) => {
      let changed = false;
      const nextNodes = currentNodes.map((node) => {
        if (node.type === "trustBoundary") {
          return node;
        }

        const nextThreatCount = threatSignalsByNodeId[node.id]?.count ?? 0;
        const nextHighestSeverity =
          threatSignalsByNodeId[node.id]?.highestSeverity ?? null;
        const currentData = node.data as DFDNodeData;
        const nextFocusHandler = onFocusThreatsForGraphObject
          ? handleNodeThreatFocusClick
          : undefined;

        if (
          currentData.threatCount === nextThreatCount &&
          currentData.highestThreatSeverity === nextHighestSeverity &&
          currentData.onFocusThreats === nextFocusHandler
        ) {
          return node;
        }

        changed = true;
        return {
          ...node,
          data: {
            ...currentData,
            threatCount: nextThreatCount,
            highestThreatSeverity: nextHighestSeverity,
            onFocusThreats: nextFocusHandler,
          },
        };
      });

      return changed ? nextNodes : currentNodes;
    });
  }, [handleNodeThreatFocusClick, onFocusThreatsForGraphObject, setNodes, threatSignalsByNodeId]);

  useEffect(() => {
    if (!focusRequest || !reactFlowRef.current) {
      return;
    }
    if (lastFocusRequestRef.current === focusRequest.nonce) {
      return;
    }

    const referenceNodes = new Set<string>();
    const referenceBoundaries = new Set<string>();

    for (const reference of focusRequest.references) {
      if (reference.kind === "node") {
        referenceNodes.add(reference.id);
      } else if (reference.kind === "boundary") {
        referenceBoundaries.add(reference.id);
      } else if (reference.kind === "edge") {
        const edge = edges.find((candidate) => candidate.id === reference.id);
        if (edge) {
          referenceNodes.add(edge.source);
          referenceNodes.add(edge.target);
        }
      }
    }

    for (const nodeId of Array.from(referenceNodes)) {
      const parentBoundaryId =
        nodes.find((node) => node.id === nodeId && node.type !== "trustBoundary")?.parentId;
      if (parentBoundaryId) {
        referenceBoundaries.add(parentBoundaryId);
      }
    }

    const focusNodes = nodes.filter(
      (node) =>
        !node.hidden &&
        ((node.type === "trustBoundary" && referenceBoundaries.has(node.id)) ||
          (node.type !== "trustBoundary" && referenceNodes.has(node.id)))
    );

    if (focusNodes.length === 0) {
      return;
    }

    lastFocusRequestRef.current = focusRequest.nonce;
    window.requestAnimationFrame(() => {
      void reactFlowRef.current?.fitView({
        nodes: focusNodes,
        padding: 0.32,
        duration: 280,
        minZoom: FIT_VIEW_MIN_ZOOM,
        maxZoom: 1.35,
      });
    });
  }, [edges, focusRequest, nodes]);

  // Auto-save on nodes/edges changes (skip initial load)
  useEffect(() => {
    if (isInitialLoadRef.current) {
      isInitialLoadRef.current = false;
      return;
    }
    if (skipAutoSavePassesRef.current > 0) {
      skipAutoSavePassesRef.current -= 1;
      return;
    }
    if (state !== "data") return;
    const currentSignature = buildGraphSignature(buildBulkSavePayload(nodes, edges));
    if (persistedGraphSignatureRef.current === currentSignature) {
      return;
    }
    triggerAutoSave();
  }, [nodes, edges, triggerAutoSave, state]);

  useEffect(() => {
    if (state !== "data" && state !== "empty") {
      return;
    }

    const nextSnapshot = createGraphHistorySnapshot(buildBulkSavePayload(nodes, edges));
    if (suppressHistoryCaptureRef.current) {
      graphHistoryCurrentRef.current = nextSnapshot;
      suppressHistoryCaptureRef.current = false;
      syncHistoryDepthState();
      return;
    }

    if (historyCaptureTimerRef.current) {
      window.clearTimeout(historyCaptureTimerRef.current);
    }

    historyCaptureTimerRef.current = window.setTimeout(() => {
      const currentSnapshot = graphHistoryCurrentRef.current;
      if (!currentSnapshot) {
        graphHistoryCurrentRef.current = nextSnapshot;
        syncHistoryDepthState();
        return;
      }

      if (currentSnapshot.signature === nextSnapshot.signature) {
        return;
      }

      graphHistoryUndoRef.current = [...graphHistoryUndoRef.current, currentSnapshot].slice(
        -MAX_GRAPH_HISTORY
      );
      graphHistoryRedoRef.current = [];
      graphHistoryCurrentRef.current = nextSnapshot;
      syncHistoryDepthState();
    }, 140);

    return () => {
      if (historyCaptureTimerRef.current) {
        window.clearTimeout(historyCaptureTimerRef.current);
        historyCaptureTimerRef.current = null;
      }
    };
  }, [nodes, edges, state, syncHistoryDepthState]);

  const applyHistorySnapshot = useCallback(
    (snapshot: GraphHistorySnapshot) => {
      suppressHistoryCaptureRef.current = true;
      closeSpawnMenu();
      setQuickAddError(null);
      applyGraphResponse(materializeDfdResponseFromBulkSave(snapshot.payload), {
        rememberPersisted: false,
        fitToView: false,
        suppressAutoSavePasses: 0,
        resetHistory: false,
      });
    },
    [applyGraphResponse, closeSpawnMenu]
  );

  const handleUndo = useCallback(() => {
    if (isReadOnlyView) {
      return;
    }
    const previousSnapshot =
      graphHistoryUndoRef.current[graphHistoryUndoRef.current.length - 1];
    const currentSnapshot = graphHistoryCurrentRef.current;
    if (!previousSnapshot || !currentSnapshot) {
      return;
    }

    graphHistoryUndoRef.current = graphHistoryUndoRef.current.slice(0, -1);
    graphHistoryRedoRef.current = [...graphHistoryRedoRef.current, currentSnapshot].slice(
      -MAX_GRAPH_HISTORY
    );
    graphHistoryCurrentRef.current = previousSnapshot;
    syncHistoryDepthState();
    applyHistorySnapshot(previousSnapshot);
  }, [applyHistorySnapshot, isReadOnlyView, syncHistoryDepthState]);

  const handleRedo = useCallback(() => {
    if (isReadOnlyView) {
      return;
    }
    const nextSnapshot =
      graphHistoryRedoRef.current[graphHistoryRedoRef.current.length - 1];
    const currentSnapshot = graphHistoryCurrentRef.current;
    if (!nextSnapshot || !currentSnapshot) {
      return;
    }

    graphHistoryRedoRef.current = graphHistoryRedoRef.current.slice(0, -1);
    graphHistoryUndoRef.current = [...graphHistoryUndoRef.current, currentSnapshot].slice(
      -MAX_GRAPH_HISTORY
    );
    graphHistoryCurrentRef.current = nextSnapshot;
    syncHistoryDepthState();
    applyHistorySnapshot(nextSnapshot);
  }, [applyHistorySnapshot, isReadOnlyView, syncHistoryDepthState]);

  useEffect(() => {
    const handleWindowKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && showShortcutsDialog) {
        event.preventDefault();
        setShowShortcutsDialog(false);
        return;
      }

      if (isTypingTarget(event.target)) {
        return;
      }

      if (isShortcutHelpKey(event)) {
        event.preventDefault();
        setShowShortcutsDialog(true);
        return;
      }

      if (event.key === " " && !event.metaKey && !event.ctrlKey && !event.altKey) {
        spacePanActiveRef.current = true;
        setSpacePanActive(true);
        event.preventDefault();
        return;
      }

      const historyShortcut = getHistoryShortcutAction(event);
      if (historyShortcut === "undo") {
        event.preventDefault();
        handleUndo();
        return;
      }

      if (historyShortcut === "redo") {
        event.preventDefault();
        handleRedo();
      }
    };

    const handleWindowKeyUp = (event: KeyboardEvent) => {
      if (event.key !== " ") {
        return;
      }
      spacePanActiveRef.current = false;
      setSpacePanActive(false);
    };

    const handleWindowBlur = () => {
      spacePanActiveRef.current = false;
      setSpacePanActive(false);
    };

    window.addEventListener("keydown", handleWindowKeyDown);
    window.addEventListener("keyup", handleWindowKeyUp);
    window.addEventListener("blur", handleWindowBlur);
    return () => {
      window.removeEventListener("keydown", handleWindowKeyDown);
      window.removeEventListener("keyup", handleWindowKeyUp);
      window.removeEventListener("blur", handleWindowBlur);
    };
  }, [handleRedo, handleUndo, showShortcutsDialog]);

  // Block 13: Toolbar state — compute selection state
  const selectedDataNodeCount = useMemo(
    () => nodes.filter((n) => n.selected && n.type !== "trustBoundary").length,
    [nodes]
  );
  const selectedBoundaryCount = useMemo(
    () => nodes.filter((n) => n.selected && n.type === "trustBoundary").length,
    [nodes]
  );
  const selectedEdgeCount = useMemo(
    () => edges.filter((e) => e.selected).length,
    [edges]
  );
  const hasSelection =
    selectedDataNodeCount > 0 || selectedBoundaryCount > 0 || selectedEdgeCount > 0;
  const selectedBulkEditNodes = useMemo(
    () =>
      nodes
        .filter((node) => node.selected && node.type !== "trustBoundary")
        .map((node) => ({
          id: node.id,
          label: (node.data as DFDNodeData).label || "Unnamed",
        })),
    [nodes]
  );
  const selectedBulkEditEdges = useMemo(
    () =>
      edges
        .filter((edge) => edge.selected)
        .map((edge) => {
          const edgeData = getCanvasEdgeData(edge);
          return {
            id: edge.id,
            label: edgeData.flowLabel || edgeData.displayLabel || `${edge.source} -> ${edge.target}`,
          };
        }),
    [edges]
  );
  const canBulkEdit = selectedBulkEditNodes.length > 0 || selectedBulkEditEdges.length > 0;
  const visibleDataNodeCount = useMemo(
    () => nodes.filter((node) => node.type !== "trustBoundary" && !node.hidden).length,
    [nodes]
  );
  const visibleBoundaryCount = useMemo(
    () => nodes.filter((node) => node.type === "trustBoundary" && !node.hidden).length,
    [nodes]
  );
  const canSuggestBoundaries = useMemo(
    () =>
      !isDecompositionView &&
      nodes.some(
        (node) => node.type !== "trustBoundary" && !node.parentId && !node.hidden
      ),
    [nodes, isDecompositionView]
  );
  const visibleEdgeCount = useMemo(
    () => edges.filter((edge) => !edge.hidden).length,
    [edges]
  );
  const containerStyle = useMemo(
    () => ({ height: isFullscreen ? "100dvh" : `${canvasHeight}px` }),
    [canvasHeight, isFullscreen]
  );
  const containerClassName = `dfd-canvas-container${isFullscreen ? " dfd-canvas-container-fullscreen" : ""}`;
  const canvasFooterHint = getCanvasFooterHint({
    isReadOnlyView,
    isDecompositionView,
    isFullscreen,
  });

  // Block 13: Delete selected handler for toolbar button
  const handleDeleteSelected = useCallback(() => {
    // Simulate a keyboard delete event by reusing the same logic
    const syntheticEvent = {
      key: "Delete",
      target: { tagName: "DIV" },
    } as unknown as React.KeyboardEvent;
    handleKeyDown(syntheticEvent);
  }, [handleKeyDown]);

  const handleOpenBulkEdit = useCallback(() => {
    if (isReadOnlyView || !canBulkEdit) return;
    closeSpawnMenu();
    setQuickAddError(null);
    setShowBulkEditDialog(true);
  }, [canBulkEdit, closeSpawnMenu, isReadOnlyView]);

  const handleApplyBulkEdit = useCallback(
    async (changes: {
      nodeProperties?: Partial<NodeProperties>;
      edgeProperties?: Partial<EdgeProperties>;
    }) => {
      const updatedNodeResults = changes.nodeProperties
        ? await Promise.all(
            selectedBulkEditNodes.map(async (target) => {
              const currentNode = nodesRef.current.find((node) => node.id === target.id);
              if (!currentNode || currentNode.type === "trustBoundary") {
                return null;
              }
              const currentProperties =
                ((currentNode.data as DFDNodeData).properties ?? {}) as NodeProperties;
              return api.updateNode(threatModelId, target.id, {
                properties: {
                  ...currentProperties,
                  ...changes.nodeProperties,
                },
              }, activeViewId);
            })
          )
        : [];

      const updatedEdgeResults = changes.edgeProperties
        ? await Promise.all(
            selectedBulkEditEdges.map(async (target) => {
              const currentEdge = edgesRef.current.find((edge) => edge.id === target.id);
              if (!currentEdge) {
                return null;
              }
              const edgeData = getCanvasEdgeData(currentEdge);
              return api.updateEdge(threatModelId, target.id, {
                properties: {
                  ...edgeData.properties,
                  ...changes.edgeProperties,
                },
              }, activeViewId);
            })
          )
        : [];

      const updatedNodeMap = new Map(
        updatedNodeResults
          .filter((result): result is DFDNodeResponse => result !== null)
          .map((result) => [result.id, result])
      );
      const nextNodes = nodesRef.current.map((node) =>
        updatedNodeMap.has(node.id)
          ? {
              ...node,
              data: {
                ...(node.data as DFDNodeData),
                label: updatedNodeMap.get(node.id)?.name ?? (node.data as DFDNodeData).label,
                properties:
                  (updatedNodeMap.get(node.id)?.properties ?? {}) as NodeProperties,
              },
            }
          : node
      );

      const updatedEdgeMap = new Map(
        updatedEdgeResults
          .filter((result): result is DFDEdgeResponse => result !== null)
          .map((result) => [result.id, result])
      );
      let nextEdges = edgesRef.current.map((edge) =>
        updatedEdgeMap.has(edge.id)
          ? buildReactFlowEdge(
              updatedEdgeMap.get(edge.id) as DFDEdgeResponse,
              edgeInteractionCallbacks,
              buildCanvasNodeBoundaryMap(nextNodes)
            )
          : edge
      );
      nextEdges = refreshEdgeVisuals(nextNodes, nextEdges, edgeInteractionCallbacks);

      rememberPersistedGraph(nextNodes, nextEdges);
      setNodes(nextNodes);
      setEdges(nextEdges);
      setShowBulkEditDialog(false);
      acknowledgeServerMutation(2);
    },
    [
      acknowledgeServerMutation,
      edgeInteractionCallbacks,
      rememberPersistedGraph,
      selectedBulkEditEdges,
      selectedBulkEditNodes,
      setEdges,
      setNodes,
      threatModelId,
      activeViewId,
    ]
  );

  const handleOpenAddDialog = useCallback(() => {
    if (isReadOnlyView) return;
    closeSpawnMenu();
    setQuickAddError(null);
    setShowTemplateDialog(false);
    setAddDialogStartsInCustomMode(false);
    setShowAddDialog(true);
  }, [closeSpawnMenu, isReadOnlyView]);

  const handleOpenCustomComponentDialog = useCallback(() => {
    if (isReadOnlyView) return;
    closeSpawnMenu();
    setQuickAddError(null);
    setShowTemplateDialog(false);
    setAddDialogStartsInCustomMode(true);
    setShowAddDialog(true);
  }, [closeSpawnMenu, isReadOnlyView]);

  const handleOpenTemplateDialog = useCallback(() => {
    if (isReadOnlyView || isDecompositionView) return;
    closeSpawnMenu();
    setQuickAddError(null);
    setShowStencilPanel(false);
    setEditingNode(null);
    setShowTemplateDialog(true);
  }, [closeSpawnMenu, isReadOnlyView, isDecompositionView]);

  const handleApplyTemplate = useCallback(
    async (template: DFDTemplateDefinition) => {
      if (isReadOnlyView || isDecompositionView) return;
      closeSpawnMenu();
      setShowStencilPanel(false);
      setEditingNode(null);

      const hasExistingGraph =
        nodes.some((node) => node.type !== "trustBoundary") || edges.length > 0;
      if (
        hasExistingGraph &&
        !window.confirm(`Replace the current DFD with the "${template.name}" template?`)
      ) {
        return;
      }

      setSaveStatus("saving");

      try {
        const savedDfd = await api.saveDFD(
          threatModelId,
          materializeDFDTemplate(template),
          activeViewId
        );
        const nextViews = await api.regenerateDFDViews(threatModelId).catch(() => views);
        setViews(nextViews);
        setSelectedViewId(
          nextViews.find((view) => view.view_type === "container")?.id ??
            nextViews[0]?.id ??
            null
        );
        setShowTemplateDialog(false);
        applyGraphResponse(savedDfd, {
          rememberPersisted: true,
          fitToView: true,
          suppressAutoSavePasses: 2,
          resetHistory: false,
        });
        setSaveStatus("saved");
        setTimeout(() => setSaveStatus("idle"), 2000);
        onAutoSaveComplete?.();
      } catch {
        setSaveStatus("error");
        setTimeout(() => setSaveStatus("idle"), 3000);
      }
    },
    [
      nodes,
      edges,
      closeSpawnMenu,
      threatModelId,
      activeViewId,
      applyGraphResponse,
      onAutoSaveComplete,
      isReadOnlyView,
      isDecompositionView,
      views,
    ]
  );

  const handleZoomIn = useCallback(() => {
    reactFlowRef.current?.zoomIn();
  }, []);

  const handleZoomOut = useCallback(() => {
    reactFlowRef.current?.zoomOut();
  }, []);

  const handleFitView = useCallback(() => {
    fitViewportToNodes(renderedNodes, isReadOnlyView ? 1.05 : 1.5);
  }, [fitViewportToNodes, isReadOnlyView, renderedNodes]);

  const handleToggleSnap = useCallback(() => {
    setSnapToGrid((prev) => !prev);
  }, []);

  const handleAutoLayout = useCallback(() => {
    if (isReadOnlyView) return;
    closeSpawnMenu();
    setQuickAddError(null);
    setShowTemplateDialog(false);
    setNodes((currentNodes) =>
      autoLayoutCanvasNodes(
        currentNodes,
        edges,
        handleSpawnHandleClick,
        isReadOnlyView ? undefined : handleNodeDecompositionClick,
        onFocusThreatsForGraphObject ? handleNodeThreatFocusClick : undefined,
        threatSignalsByNodeId,
        isReadOnlyView ? undefined : openBoundaryEditor,
        isReadOnlyView ? undefined : handleBoundaryMoveStart,
        isReadOnlyView ? undefined : handleBoundaryMoveEnd,
        isReadOnlyView ? undefined : handleBoundaryResizeEnd
      )
    );
  }, [
    closeSpawnMenu,
    edges,
    handleBoundaryMoveStart,
    handleBoundaryMoveEnd,
    handleBoundaryResizeEnd,
    handleNodeDecompositionClick,
    handleNodeThreatFocusClick,
    handleSpawnHandleClick,
    isReadOnlyView,
    onFocusThreatsForGraphObject,
    openBoundaryEditor,
    setNodes,
    threatSignalsByNodeId,
  ]);

  const handlePaneClick = useCallback(() => {
    closeSpawnMenu();
    setQuickAddError(null);
  }, [closeSpawnMenu]);

  const handlePaneContextMenu = useCallback(
    (event: MouseEvent | React.MouseEvent<Element>) => {
      if (isReadOnlyView) return;
      event.preventDefault();
      const containerRect = getFlowSurfaceRect();
      const reactFlow = reactFlowRef.current;
      if (!containerRect || !reactFlow) return;

      const flowPosition = reactFlow.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      setQuickAddError(null);
      setSpawnMenu(null);
      setCanvasMenu({
        x: event.clientX - containerRect.left,
        y: event.clientY - containerRect.top,
        flowX: flowPosition.x,
        flowY: flowPosition.y,
      });
    },
    [getFlowSurfaceRect, isReadOnlyView]
  );

  const handleNodeContextMenu = useCallback(
    (event: React.MouseEvent, node: Node) => {
      event.preventDefault();
      event.stopPropagation();
      openNodeContextMenu(event as React.MouseEvent<HTMLElement>, node.id);
    },
    [openNodeContextMenu]
  );

  const handleEdgeContextMenu = useCallback(
    (event: React.MouseEvent, edge: CanvasEdge) => {
      openEdgeContextMenu(event as React.MouseEvent<HTMLElement>, edge.id);
    },
    [openEdgeContextMenu]
  );

  const flowSurfaceWidth = flowSurfaceRef.current?.getBoundingClientRect().width ?? null;
  const clampMenuLeft = (left: number) => {
    if (!flowSurfaceWidth || flowSurfaceWidth <= QUICK_ADD_MENU_WIDTH + QUICK_ADD_MENU_EDGE_GAP * 2) {
      return QUICK_ADD_MENU_EDGE_GAP;
    }
    return Math.min(
      Math.max(QUICK_ADD_MENU_EDGE_GAP, left),
      flowSurfaceWidth - QUICK_ADD_MENU_WIDTH - QUICK_ADD_MENU_EDGE_GAP
    );
  };
  const spawnMenuStyle = spawnMenu
    ? {
        left: clampMenuLeft(
          spawnMenu.side === "source"
            ? spawnMenu.x + QUICK_ADD_MENU_OFFSET
            : spawnMenu.x - QUICK_ADD_MENU_OFFSET - QUICK_ADD_MENU_WIDTH
        ),
        top: spawnMenu.y,
        transform: "translateY(-50%)",
      }
    : canvasMenu
      ? {
          left: clampMenuLeft(canvasMenu.x),
          top: canvasMenu.y,
          transform: "translate(0, 0)",
        }
      : undefined;

  const memoizedNodeTypes = useMemo(() => allNodeTypes, []);
  const memoizedEdgeTypes = useMemo(() => allEdgeTypes, []);
  const viewBreadcrumbs =
    isDecompositionView && selectedViewChain.length > 0 ? (
      <div className="dfd-view-breadcrumbs" aria-label="DFD decomposition path">
        {selectedViewChain.map((view, index) => (
          <span key={view.id} className="dfd-view-breadcrumb-segment">
            {index > 0 && <span className="dfd-view-breadcrumb-separator">/</span>}
            <button
              type="button"
              className={`dfd-view-breadcrumb${view.id === selectedView?.id ? " dfd-view-breadcrumb-active" : ""}`}
              onClick={() => handleSelectView(view.id)}
            >
              {view.name}
            </button>
          </span>
        ))}
      </div>
    ) : null;
  const viewTabs =
    topLevelViews.length > 0 ? (
      <div className="dfd-view-tabs-shell">
        <div className="dfd-view-tabs" role="tablist" aria-label="DFD views">
          {topLevelViews.map((view) => (
            <button
              key={view.id}
              type="button"
              role="tab"
              aria-selected={selectedTopLevelViewId === view.id}
              className={`dfd-view-tab${selectedTopLevelViewId === view.id ? " dfd-view-tab-active" : ""}${view.view_type === "workspace" ? " dfd-view-tab-workspace" : ""}`}
              onClick={() => handleSelectView(view.id)}
            >
              {view.name}
            </button>
          ))}
        </div>
        <button
          type="button"
          className="dfd-view-create-btn"
          onClick={handleOpenCreateWorkspaceDialog}
          disabled={creatingWorkspace}
        >
          {creatingWorkspace ? "Creating..." : "New DFD"}
        </button>
      </div>
    ) : null;

  if (state === "loading") {
    return (
      <div
        className={containerClassName}
        id={`dfd-canvas-${threatModelId}`}
        ref={canvasShellRef}
        style={containerStyle}
      >
        <div className="dfd-state-message">
          <div className="dfd-spinner" />
          <p>Loading DFD...</p>
        </div>
      </div>
    );
  }

  if (state === "empty") {
    return (
      <div
        className={containerClassName}
        id={`dfd-canvas-${threatModelId}`}
        ref={canvasShellRef}
        style={containerStyle}
      >
        {viewTabs}
        {viewBreadcrumbs}
        <DFDToolbar
          onOpenTemplates={handleOpenTemplateDialog}
          onAddNode={handleOpenAddDialog}
          onTogglePalette={() => setShowStencilPanel((current) => !current)}
          onShowShortcuts={() => setShowShortcutsDialog(true)}
          onUndo={handleUndo}
          onRedo={handleRedo}
          onAutoLayout={handleAutoLayout}
          onBulkEdit={handleOpenBulkEdit}
          onDeleteSelected={handleDeleteSelected}
          onCreateBoundary={handleCreateBoundary}
          onSuggestBoundaries={handleSuggestBoundaries}
          onSave={handleSave}
          onToggleFullscreen={handleToggleFullscreen}
          isFullscreen={isFullscreen}
          saveStatus={saveStatus}
          autoSaveStatus={autoSaveStatus}
          hasNodes={false}
          hasSelection={false}
          canCreateBoundary={true}
          canSuggestBoundaries={canSuggestBoundaries}
          canBulkEdit={false}
          readOnly={false}
          disableTemplates={isDecompositionView}
          paletteVisible={showStencilPanel}
          canUndo={undoDepth > 0}
          canRedo={redoDepth > 0}
        />
        {quickAddError && (
          <div className="dfd-inline-error" role="alert">
            {quickAddError}
          </div>
        )}
        {showStencilPanel && !isReadOnlyView ? (
          <DFDStencilPalette
            readOnly={isReadOnlyView}
            customTemplates={customComponentTemplates}
            onHide={() => setShowStencilPanel(false)}
            onCreateNode={(nodeType) => {
              void handleCreateNodeFromPalette(nodeType);
            }}
            onCreateTemplate={(template) => {
              void handleCreateTemplateFromPalette(template);
            }}
            onCreateBoundary={() => {
              void handleCreateBoundary();
            }}
            onCreateCustom={handleOpenCustomComponentDialog}
          />
        ) : null}
          <div className="dfd-state-message">
            <p>
              {isDecompositionView
                ? "This decomposition is empty. Add the first internal component or branch from the seeded interfaces."
                : selectedView?.view_type === "workspace"
                  ? "This DFD workspace is empty. Add the first component, load a template, or duplicate another view when you create the next tab."
                  : "No DFD generated yet. Upload a document, load a starter template, or add nodes manually."}
            </p>
          </div>
        {showTemplateDialog && (
          <DFDTemplateDialog
            templates={dfdTemplates}
            applying={saveStatus === "saving"}
            onApply={(template) => {
              void handleApplyTemplate(template);
            }}
            onClose={() => setShowTemplateDialog(false)}
          />
        )}
        {showShortcutsDialog && (
          <DFDShortcutsDialog
            isReadOnlyView={isReadOnlyView}
            isDecompositionView={isDecompositionView}
            onClose={() => setShowShortcutsDialog(false)}
          />
        )}

        {showAddDialog && (
          <AddNodeDialog
            threatModelId={threatModelId}
            viewId={activeViewId}
            initialShowCustomForm={addDialogStartsInCustomMode}
            onNodeAdded={handleNodeAdded}
            onTemplatesChanged={() => {
              void loadComponentTemplates();
            }}
            onClose={() => {
              setShowAddDialog(false);
              setAddDialogStartsInCustomMode(false);
            }}
          />
        )}

        {showCreateWorkspaceDialog && (
          <CreateDFDWorkspaceDialog
            currentViewName={selectedView?.name ?? containerView?.name ?? null}
            currentViewId={currentWorkspaceDuplicateSourceId}
            saving={creatingWorkspace}
            error={createWorkspaceError}
            onCreate={handleCreateWorkspace}
            onClose={() => {
              if (creatingWorkspace) {
                return;
              }
              setCreateWorkspaceError(null);
              setShowCreateWorkspaceDialog(false);
            }}
          />
        )}
      </div>
    );
  }

  if (state === "error") {
    return (
      <div
        className={containerClassName}
        id={`dfd-canvas-${threatModelId}`}
        ref={canvasShellRef}
        style={containerStyle}
      >
        <div className="dfd-state-message dfd-state-error">
          <p>Failed to load DFD. Try refreshing.</p>
        </div>
      </div>
    );
  }

  return (
    <div
      className={containerClassName}
      id={`dfd-canvas-${threatModelId}`}
      ref={canvasShellRef}
      onKeyDown={handleKeyDown}
      style={containerStyle}
      tabIndex={0}
    >
      {viewTabs}
      {viewBreadcrumbs}
      <DFDToolbar
        onOpenTemplates={handleOpenTemplateDialog}
        onAddNode={handleOpenAddDialog}
        onTogglePalette={() => setShowStencilPanel((current) => !current)}
        onShowShortcuts={() => setShowShortcutsDialog(true)}
        onUndo={handleUndo}
        onRedo={handleRedo}
        onAutoLayout={handleAutoLayout}
        onBulkEdit={handleOpenBulkEdit}
        onDeleteSelected={handleDeleteSelected}
        onCreateBoundary={handleCreateBoundary}
        onSuggestBoundaries={handleSuggestBoundaries}
        onSave={handleSave}
        onZoomIn={handleZoomIn}
        onZoomOut={handleZoomOut}
        onFitView={handleFitView}
        onToggleSnap={handleToggleSnap}
        onToggleFullscreen={handleToggleFullscreen}
        isFullscreen={isFullscreen}
        snapToGrid={snapToGrid}
        saveStatus={saveStatus}
        autoSaveStatus={autoSaveStatus}
        hasNodes={nodes.some((node) => node.type !== "trustBoundary")}
        hasSelection={hasSelection}
        canCreateBoundary={true}
        canSuggestBoundaries={canSuggestBoundaries}
        canBulkEdit={canBulkEdit}
        readOnly={isReadOnlyView}
        disableTemplates={isDecompositionView}
        paletteVisible={showStencilPanel}
        canUndo={undoDepth > 0}
        canRedo={redoDepth > 0}
      />
      {quickAddError && (
        <div className="dfd-inline-error" role="alert">
          {quickAddError}
        </div>
      )}
      <div className="dfd-canvas-stage" ref={canvasRef}>
      {showStencilPanel && !isReadOnlyView ? (
        <DFDStencilPalette
          readOnly={isReadOnlyView}
          customTemplates={customComponentTemplates}
          onHide={() => setShowStencilPanel(false)}
          onCreateNode={(nodeType) => {
            void handleCreateNodeFromPalette(nodeType);
          }}
          onCreateTemplate={(template) => {
            void handleCreateTemplateFromPalette(template);
          }}
          onCreateBoundary={() => {
            void handleCreateBoundary();
          }}
          onCreateCustom={handleOpenCustomComponentDialog}
        />
      ) : null}
        <div
          className={`dfd-flow-surface${spacePanActive ? " dfd-flow-surface-pan-ready" : ""}`}
          ref={flowSurfaceRef}
          data-testid="dfd-flow-surface"
        >
          <ReactFlow
            proOptions={{ hideAttribution: true }}
            nodes={renderedNodes}
            edges={renderedEdges}
            onNodesChange={handleNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={memoizedNodeTypes}
            edgeTypes={memoizedEdgeTypes}
            nodesDraggable={!isReadOnlyView}
            nodesConnectable={!isReadOnlyView}
            elementsSelectable={true}
            zoomOnScroll
            onConnect={handleConnect}
            onPaneClick={handlePaneClick}
            onPaneContextMenu={handlePaneContextMenu}
            onNodeClick={handleNodeClick}
            onNodeDoubleClick={handleNodeDoubleClick}
            onEdgeDoubleClick={handleEdgeDoubleClick}
            onNodeContextMenu={handleNodeContextMenu}
            onEdgeContextMenu={handleEdgeContextMenu}
            onInit={(instance) => {
              reactFlowRef.current = instance;
              if (pendingSnapshotFitRef.current) {
                window.requestAnimationFrame(() => {
                  if (!pendingSnapshotFitRef.current || !reactFlowRef.current) {
                    return;
                  }
                  pendingSnapshotFitRef.current = false;
                  void reactFlowRef.current.fitView({
                    padding: 0.2,
                    minZoom: FIT_VIEW_MIN_ZOOM,
                    maxZoom: 1.5,
                  });
                });
              }
            }}
            viewport={viewport}
            minZoom={CANVAS_MIN_ZOOM}
            maxZoom={CANVAS_MAX_ZOOM}
            onViewportChange={handleViewportChange}
            selectionKeyCode={["Shift", "s", "S"]}
            selectionOnDrag={false}
            selectionMode={SelectionMode.Partial}
            multiSelectionKeyCode={["Meta", "Control", "Shift"]}
            selectNodesOnDrag={false}
            panActivationKeyCode="Space"
            panOnDrag={true}
            snapToGrid={snapToGrid}
            snapGrid={[20, 20]}
          />

          {(spawnMenu || canvasMenu) && spawnMenuStyle && (
            <>
              <div className="dfd-spawn-menu-backdrop" onClick={closeSpawnMenu} />
              <div
                className="dfd-spawn-menu"
                role="menu"
                aria-label={spawnMenu ? "Quick add DFD node" : "Add DFD node"}
                style={spawnMenuStyle}
                onClick={(event) => event.stopPropagation()}
              >
                {groupedQuickAddTemplates.map(([groupName, groupTemplates]) => (
                  <div key={groupName} className="dfd-spawn-menu-group">
                    <div className="dfd-spawn-menu-group-label">{groupName}</div>
                    {groupTemplates.map((template) => (
                      <button
                        key={template.id}
                        type="button"
                        className="dfd-spawn-menu-option"
                        onClick={() => {
                          void handleQuickAddNode(template);
                        }}
                        title={formatTemplateOptionLabel(template)}
                      >
                        {template.label}
                      </button>
                    ))}
                  </div>
                ))}
              </div>
            </>
          )}

          {graphContextMenu && (
            <>
              <div className="dfd-spawn-menu-backdrop" onClick={closeSpawnMenu} />
              <div
                className="dfd-graph-context-menu"
                style={{ left: graphContextMenu.x, top: graphContextMenu.y }}
              >
                {graphContextMenu.kind === "edge" && (
                  <button
                    type="button"
                    className="dfd-spawn-menu-option"
                    onClick={() => {
                      openEdgeEditor(graphContextMenu.id);
                      closeSpawnMenu();
                    }}
                  >
                    Edit Flow
                  </button>
                )}
                {onFocusThreatsForGraphObject &&
                  (graphContextMenu.kind === "node" || graphContextMenu.kind === "edge") && (
                  <button
                    type="button"
                    className="dfd-spawn-menu-option"
                    onClick={() => {
                      const focusKind =
                        graphContextMenu.kind === "edge" ? "edge" : "node";
                      onFocusThreatsForGraphObject?.({
                        kind: focusKind,
                        id: graphContextMenu.id,
                        label: graphContextMenu.label,
                      });
                      closeSpawnMenu();
                    }}
                  >
                    Show Related Threats
                  </button>
                )}
                {graphContextMenu.kind === "node" &&
                  graphContextMenu.nodeType &&
                  !isReadOnlyView &&
                  DECOMPOSABLE_NODE_TYPES.has(graphContextMenu.nodeType) && (
                    <button
                      type="button"
                      className="dfd-spawn-menu-option"
                      onClick={() => {
                        void handleOpenDecomposition(graphContextMenu.id);
                      }}
                    >
                      Open Decomposition
                    </button>
                  )}
                {!isDecompositionView && (
                  <button
                    type="button"
                    className="dfd-spawn-menu-option"
                    onClick={() => {
                      onAskAboutGraphObject?.({
                        kind: graphContextMenu.kind,
                        id: graphContextMenu.id,
                        label: graphContextMenu.label,
                      });
                      closeSpawnMenu();
                    }}
                  >
                    Ask AI About “{graphContextMenu.label}”
                  </button>
                )}
                <button
                  type="button"
                  className="dfd-spawn-menu-option"
                  onClick={() => {
                    onCreateAssumptionAnchor?.({
                      kind: graphContextMenu.kind,
                      id: graphContextMenu.id,
                      label: graphContextMenu.label,
                    });
                    closeSpawnMenu();
                  }}
                >
                  Add Assumption
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      <div className="dfd-canvas-footer">
        <span className="dfd-canvas-footer-primary">
          {visibleDataNodeCount} nodes · {visibleEdgeCount} flows · {visibleBoundaryCount} boundaries
          {hasSelection
            ? ` · ${selectedDataNodeCount + selectedEdgeCount + selectedBoundaryCount} selected`
            : ""}
        </span>
        <span className="dfd-canvas-footer-hint">{canvasFooterHint}</span>
      </div>
      {!isFullscreen && (
        <button
          type="button"
          className={`dfd-canvas-resize-handle${isResizingCanvas ? " dfd-canvas-resize-handle-active" : ""}`}
          onMouseDown={handleResizeCanvasStart}
          onDoubleClick={handleResetCanvasHeight}
          title="Drag to resize the DFD workspace. Double-click to reset."
          aria-label="Resize DFD workspace"
        >
          <span className="dfd-canvas-resize-grip" />
        </button>
      )}

      {showAddDialog && (
        <AddNodeDialog
          threatModelId={threatModelId}
          viewId={activeViewId}
          initialShowCustomForm={addDialogStartsInCustomMode}
          onNodeAdded={handleNodeAdded}
          onTemplatesChanged={() => {
            void loadComponentTemplates();
          }}
          onClose={() => {
            setShowAddDialog(false);
            setAddDialogStartsInCustomMode(false);
          }}
        />
      )}

      {showTemplateDialog && (
        <DFDTemplateDialog
          templates={dfdTemplates}
          applying={saveStatus === "saving"}
          onApply={(template) => {
            void handleApplyTemplate(template);
          }}
          onClose={() => setShowTemplateDialog(false)}
        />
      )}

      {showShortcutsDialog && (
        <DFDShortcutsDialog
          isReadOnlyView={isReadOnlyView}
          isDecompositionView={isDecompositionView}
          onClose={() => setShowShortcutsDialog(false)}
        />
      )}

      {showCreateWorkspaceDialog && (
        <CreateDFDWorkspaceDialog
          currentViewName={selectedView?.name ?? containerView?.name ?? null}
          currentViewId={currentWorkspaceDuplicateSourceId}
          saving={creatingWorkspace}
          error={createWorkspaceError}
          onCreate={handleCreateWorkspace}
          onClose={() => {
            if (creatingWorkspace) {
              return;
            }
            setCreateWorkspaceError(null);
            setShowCreateWorkspaceDialog(false);
          }}
        />
      )}

      {editingNode && (
        <NodeEditor
          threatModelId={threatModelId}
          viewId={activeViewId}
          nodeId={editingNode.id}
          initialName={editingNode.name}
          initialType={editingNode.type}
          initialProperties={editingNode.properties}
          initialScanTargetUrl={editingNode.scan_target_url}
          initialScanTargetPorts={editingNode.scan_target_ports}
          onSaved={handleNodeSaved}
          onClose={() => setEditingNode(null)}
        />
      )}

      {editingBoundary && (
        <TrustBoundaryEditor
          boundaryId={editingBoundary.id}
          initialName={editingBoundary.name}
          initialBoundaryType={editingBoundary.boundary_type}
          initialWidth={editingBoundary.width}
          initialHeight={editingBoundary.height}
          onSaved={handleBoundarySaved}
          onClose={() => setEditingBoundary(null)}
        />
      )}

      {showBulkEditDialog && (
        <DFDBulkEditDialog
          nodeTargets={selectedBulkEditNodes}
          edgeTargets={selectedBulkEditEdges}
          onApply={handleApplyBulkEdit}
          onClose={() => setShowBulkEditDialog(false)}
        />
      )}

      {edgeEditorState?.mode === "edit" && (
        <EdgeEditor
          mode="edit"
          threatModelId={threatModelId}
          viewId={activeViewId}
          edgeId={edgeEditorState.id}
          initialLabel={edgeEditorState.label}
          initialProperties={edgeEditorState.properties}
          requireMetadata={edgeEditorState.requireMetadata}
          onSaved={handleEdgeSaved}
          onClose={() => setEdgeEditorState(null)}
        />
      )}

      {edgeEditorState?.mode === "create" && (
        <EdgeEditor
          mode="create"
          threatModelId={threatModelId}
          viewId={activeViewId}
          sourceNodeId={edgeEditorState.sourceNodeId}
          targetNodeId={edgeEditorState.targetNodeId}
          initialLabel={edgeEditorState.label}
          initialProperties={edgeEditorState.properties}
          requireMetadata={edgeEditorState.requireMetadata}
          onSaved={handleEdgeCreated}
          onClose={() => setEdgeEditorState(null)}
        />
      )}
    </div>
  );
}

export { type DFDCanvasProps };

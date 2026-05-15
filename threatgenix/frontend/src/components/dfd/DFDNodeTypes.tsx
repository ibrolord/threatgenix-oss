import { Handle, Position } from "@xyflow/react";
import type { Node, NodeProps } from "@xyflow/react";
import type { ComponentShape, NodeProperties } from "../../types/api";

export type SpawnHandleSide = "source" | "target";

export type SpawnHandleClickHandler = (
  event: React.MouseEvent<HTMLElement>,
  nodeId: string,
  side: SpawnHandleSide
) => void;

export type OpenDecompositionHandler = (
  event: React.MouseEvent<HTMLElement>,
  nodeId: string
) => void;

export type FocusThreatsHandler = (
  event: React.MouseEvent<HTMLElement>,
  nodeId: string
) => void;

export type DFDNodeData = {
  label: string;
  properties?: NodeProperties;
  scan_target_url?: string | null;
  scan_target_ports?: string | null;
  onHandleClick?: SpawnHandleClickHandler;
  onOpenDecomposition?: OpenDecompositionHandler;
  onFocusThreats?: FocusThreatsHandler;
  threatCount?: number;
  highestThreatSeverity?: string | null;
};

export type ProcessNodeType = Node<DFDNodeData, "process">;
export type DataStoreNodeType = Node<DFDNodeData, "data_store">;
export type ExternalEntityNodeType = Node<DFDNodeData, "external_entity">;
export type HumanActorNodeType = Node<DFDNodeData, "human_actor">;
export type IAMRoleNodeType = Node<DFDNodeData, "iam_role">;
export type ManagedServiceNodeType = Node<DFDNodeData, "managed_service">;
export type APIGatewayNodeType = Node<DFDNodeData, "api_gateway">;
export type ContainerNodeType = Node<DFDNodeData, "container">;
export type ServerlessNodeType = Node<DFDNodeData, "serverless">;

const NODE_WIDTH = 180;
const NODE_HEIGHT = 64;

const baseStyle: React.CSSProperties = {
  width: NODE_WIDTH,
  height: NODE_HEIGHT,
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
  justifyContent: "center",
  position: "relative",
  color: "#fff",
  fontSize: 14,
  fontWeight: 600,
  overflow: "visible",
  padding: "6px 12px",
  boxSizing: "border-box",
};

const surfaceStyleBase: React.CSSProperties = {
  position: "absolute",
  inset: 0,
  boxSizing: "border-box",
  zIndex: 0,
  pointerEvents: "none",
};

const nameLabelStyle: React.CSSProperties = {
  position: "relative",
  zIndex: 1,
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  maxWidth: "100%",
  lineHeight: 1.2,
};

const typeLabelStyle: React.CSSProperties = {
  position: "relative",
  zIndex: 1,
  fontSize: 10,
  fontWeight: 400,
  opacity: 0.7,
  lineHeight: 1.2,
  marginTop: 2,
};

const nodeSummaryStyle: React.CSSProperties = {
  position: "relative",
  zIndex: 1,
  fontSize: 9,
  fontWeight: 700,
  opacity: 0.92,
  lineHeight: 1.2,
  marginTop: 4,
  maxWidth: "100%",
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};

const DEFAULT_SHAPES_BY_NODE_TYPE: Record<string, ComponentShape> = {
  process: "rounded_rect",
  data_store: "cylinder",
  external_entity: "square",
  human_actor: "pill",
  iam_role: "hexagon",
  managed_service: "cloud",
  api_gateway: "gateway",
  container: "stacked",
  serverless: "diamond",
};

function humanizePropertyValue(value: string | undefined): string | null {
  if (!value) {
    return null;
  }
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function resolveComponentShape(nodeType: string, properties?: NodeProperties): ComponentShape {
  return properties?.component_shape ?? DEFAULT_SHAPES_BY_NODE_TYPE[nodeType] ?? "rounded_rect";
}

function resolveComponentTypeLabel(
  fallbackLabel: string,
  properties?: NodeProperties,
  preferredLabel?: string | null
): string {
  if (properties?.component_label?.trim()) {
    return properties.component_label.trim();
  }
  if (preferredLabel?.trim()) {
    return preferredLabel.trim();
  }
  return fallbackLabel;
}

function buildNodeSurfaceStyle(
  shape: ComponentShape,
  base: React.CSSProperties
): React.CSSProperties {
  const shapeStyle: React.CSSProperties = {};

  switch (shape) {
    case "square":
      shapeStyle.borderRadius = 0;
      break;
    case "pill":
      shapeStyle.borderRadius = 999;
      break;
    case "cylinder":
      shapeStyle.borderRadius = 20;
      shapeStyle.borderTop = "4px double rgba(255,255,255,0.72)";
      shapeStyle.borderBottom = "4px double rgba(255,255,255,0.72)";
      break;
    case "hexagon":
      shapeStyle.clipPath = "polygon(18% 0%, 82% 0%, 100% 50%, 82% 100%, 18% 100%, 0% 50%)";
      break;
    case "cloud":
      shapeStyle.borderRadius = 26;
      break;
    case "stacked":
      shapeStyle.borderRadius = 8;
      shapeStyle.boxShadow = base.boxShadow
        ? `${base.boxShadow}, 8px 8px 0 rgba(15,23,42,0.18)`
        : "8px 8px 0 rgba(15,23,42,0.18)";
      break;
    case "diamond":
      shapeStyle.clipPath = "polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%)";
      break;
    case "gateway":
      shapeStyle.clipPath = "polygon(12% 0%, 88% 0%, 100% 100%, 0% 100%)";
      break;
    case "queue":
      shapeStyle.borderRadius = 18;
      shapeStyle.borderLeft = "4px double rgba(255,255,255,0.65)";
      shapeStyle.borderRight = "4px double rgba(255,255,255,0.65)";
      break;
    case "rounded_rect":
    default:
      shapeStyle.borderRadius = 10;
      break;
  }

  return {
    ...surfaceStyleBase,
    ...base,
    ...shapeStyle,
  };
}

function NodeSurface({
  shape,
  style,
}: {
  shape: ComponentShape;
  style: React.CSSProperties;
}) {
  return <div aria-hidden="true" style={buildNodeSurfaceStyle(shape, style)} />;
}

function requiredMetadataFields(nodeType: string): (keyof NodeProperties)[] {
  const common: (keyof NodeProperties)[] = [
    "data_classification",
    "authentication_type",
    "network_exposure",
    "privilege_level",
  ];
  if (nodeType === "container") {
    return [
      ...common,
      "runtime_type",
      "isolation_boundary",
      "input_validation",
      "logging_level",
      "responsibility",
    ];
  }
  if (["process", "api_gateway", "container", "serverless", "managed_service"].includes(nodeType)) {
    return [...common, "runtime_type", "input_validation", "logging_level"];
  }
  if (nodeType === "data_store") {
    return [...common, "store_type", "store_purpose", "encryption_at_rest", "backup_strategy"];
  }
  if (["external_entity", "human_actor", "iam_role"].includes(nodeType)) {
    return [...common, "entity_scope", "entity_kind", "trust_level"];
  }
  return common;
}

function getMetadataState(nodeType: string, properties?: NodeProperties) {
  const required = requiredMetadataFields(nodeType);
  const filledCount = required.filter((field) => {
    const value = properties?.[field];
    if (typeof value === "boolean") return true;
    return value !== undefined && value !== null && String(value).trim() !== "";
  }).length;
  if (filledCount === required.length) {
    return {
      state: "complete",
      title: "Security metadata complete",
      helperText: "",
    };
  }
  if (filledCount === 0) {
    return {
      state: "missing",
      title: "Security metadata missing",
      helperText: `Add ${required.length} security details`,
    };
  }
  const missingCount = required.length - filledCount;
  return {
    state: "partial",
    title: "Security metadata partially complete",
    helperText: `${missingCount} detail${missingCount === 1 ? "" : "s"} missing`,
  };
}

function MetadataPrompt({ helperText }: { helperText: string }) {
  if (!helperText) {
    return null;
  }
  return (
    <span className="dfd-node-metadata-prompt" style={{ position: "relative", zIndex: 1 }}>
      {helperText}
    </span>
  );
}

function ThreatBadge({
  nodeId,
  threatCount = 0,
  highestThreatSeverity,
  onFocusThreats,
}: {
  nodeId: string;
  threatCount?: number;
  highestThreatSeverity?: string | null;
  onFocusThreats?: FocusThreatsHandler;
}) {
  if (!threatCount) {
    return null;
  }

  const severityClass =
    highestThreatSeverity === "Critical" || highestThreatSeverity === "High"
      ? "dfd-node-threat-badge-high"
      : highestThreatSeverity === "Medium"
        ? "dfd-node-threat-badge-medium"
        : "dfd-node-threat-badge-low";

  return (
    <button
      type="button"
      className={`dfd-node-threat-badge ${severityClass}`}
      aria-label={`${threatCount} related threat${threatCount === 1 ? "" : "s"}. Show related threats.`}
      title={`${threatCount} related threat${threatCount === 1 ? "" : "s"}. Show related threats.`}
      onClick={(event) => {
        event.preventDefault();
        event.stopPropagation();
        onFocusThreats?.(event, nodeId);
      }}
    >
      {threatCount}
    </button>
  );
}

function DecompositionButton({
  nodeId,
  onOpenDecomposition,
}: {
  nodeId: string;
  onOpenDecomposition?: OpenDecompositionHandler;
}) {
  if (!onOpenDecomposition) {
    return null;
  }
  return (
    <button
      type="button"
      className="dfd-node-decompose-button"
      aria-label="Open decomposition"
      title="Open decomposition"
      onClick={(event) => {
        event.preventDefault();
        event.stopPropagation();
        onOpenDecomposition(event, nodeId);
      }}
    >
      Open
    </button>
  );
}

interface DFDHandleProps {
  nodeId: string;
  side: SpawnHandleSide;
  onHandleClick?: SpawnHandleClickHandler;
}

function DFDHandle({ nodeId, side, onHandleClick }: DFDHandleProps) {
  const spawnTitle =
    side === "source"
      ? "Add or connect a downstream node"
      : "Add or connect an upstream node";
  const positionClass = side === "source" ? "right" : "left";
  const connectTitle =
    side === "source"
      ? "Drag from this connector to create a downstream flow"
      : "Drag to this connector to attach an upstream flow";

  return (
    <>
      <Handle
        className={`dfd-node-handle dfd-node-handle-${positionClass}`}
        type={side}
        position={side === "source" ? Position.Right : Position.Left}
        aria-label={connectTitle}
        title={connectTitle}
      />
      {onHandleClick ? (
        <button
          type="button"
          className={`dfd-node-spawn-button dfd-node-spawn-button-${positionClass}`}
          aria-label={spawnTitle}
          title={spawnTitle}
          onClick={(event) => {
            event.preventDefault();
            event.stopPropagation();
            onHandleClick(event, nodeId, side);
          }}
        >
          <span className="dfd-node-spawn-button-symbol" aria-hidden="true">
            +
          </span>
        </button>
      ) : null}
    </>
  );
}

function NodeFrame({
  id,
  data,
  nodeType,
  fallbackTypeLabel,
  style,
  preferredTypeLabel,
  extraContent,
  metadataProperties,
}: {
  id: string;
  data: DFDNodeData;
  nodeType: string;
  fallbackTypeLabel: string;
  style: React.CSSProperties;
  preferredTypeLabel?: string | null;
  extraContent?: React.ReactNode;
  metadataProperties?: NodeProperties;
}) {
  const label = data.label || "Unnamed";
  const metadata = getMetadataState(nodeType, metadataProperties ?? data.properties);
  const shape = resolveComponentShape(nodeType, data.properties);
  const typeLabel = resolveComponentTypeLabel(fallbackTypeLabel, data.properties, preferredTypeLabel);

  return (
    <div style={baseStyle} title={label}>
      <NodeSurface shape={shape} style={style} />
      <DecompositionButton nodeId={id} onOpenDecomposition={data.onOpenDecomposition} />
      <ThreatBadge
        nodeId={id}
        threatCount={data.threatCount}
        highestThreatSeverity={data.highestThreatSeverity}
        onFocusThreats={data.onFocusThreats}
      />
      <span
        className={`dfd-node-metadata-indicator dfd-node-metadata-indicator-${metadata.state}`}
        title={metadata.title}
      />
      <DFDHandle nodeId={id} side="target" onHandleClick={data.onHandleClick} />
      <span style={nameLabelStyle}>{label}</span>
      <span style={typeLabelStyle}>{typeLabel}</span>
      {extraContent}
      <MetadataPrompt helperText={metadata.helperText} />
      <DFDHandle nodeId={id} side="source" onHandleClick={data.onHandleClick} />
    </div>
  );
}

export function ProcessNode({ id, data }: NodeProps<ProcessNodeType>) {
  return (
    <NodeFrame
      id={id}
      data={data}
      nodeType="process"
      fallbackTypeLabel="Process"
      style={{ background: "#2563eb", boxShadow: "0 2px 8px rgba(37,99,235,0.25)" }}
    />
  );
}

export function DataStoreNode({ id, data }: NodeProps<DataStoreNodeType>) {
  return (
    <NodeFrame
      id={id}
      data={data}
      nodeType="data_store"
      fallbackTypeLabel="Data Store"
      style={{ background: "#475569", boxShadow: "0 2px 8px rgba(71,85,105,0.25)" }}
    />
  );
}

export function ExternalEntityNode({ id, data }: NodeProps<ExternalEntityNodeType>) {
  return (
    <NodeFrame
      id={id}
      data={data}
      nodeType="external_entity"
      fallbackTypeLabel="External Entity"
      style={{ background: "#374151", boxShadow: "0 2px 8px rgba(55,65,81,0.25)" }}
    />
  );
}

export function HumanActorNode({ id, data }: NodeProps<HumanActorNodeType>) {
  return (
    <NodeFrame
      id={id}
      data={data}
      nodeType="human_actor"
      fallbackTypeLabel="Human Actor"
      metadataProperties={{ ...data.properties, entity_kind: "human" }}
      style={{
        background: "#3b3b84",
        border: "2px solid rgba(255,255,255,0.35)",
        boxShadow: "0 2px 8px rgba(59,59,132,0.28)",
      }}
    />
  );
}

export function IAMRoleNode({ id, data }: NodeProps<IAMRoleNodeType>) {
  return (
    <NodeFrame
      id={id}
      data={data}
      nodeType="iam_role"
      fallbackTypeLabel="IAM Role"
      style={{
        background: "#1e3a5f",
        border: "2px solid #3b82f6",
        boxShadow: "0 2px 8px rgba(59,130,246,0.3)",
      }}
    />
  );
}

export function ManagedServiceNode({ id, data }: NodeProps<ManagedServiceNodeType>) {
  return (
    <NodeFrame
      id={id}
      data={data}
      nodeType="managed_service"
      fallbackTypeLabel="Managed Service"
      preferredTypeLabel={data.properties?.service_name}
      style={{
        background: "#4a1d96",
        border: "2px solid #8b5cf6",
        boxShadow: "0 2px 8px rgba(139,92,246,0.3)",
      }}
    />
  );
}

export function APIGatewayNode({ id, data }: NodeProps<APIGatewayNodeType>) {
  return (
    <NodeFrame
      id={id}
      data={data}
      nodeType="api_gateway"
      fallbackTypeLabel="API Gateway"
      style={{
        background: "#0f4c5c",
        border: "2px solid #0d9488",
        boxShadow: "0 2px 8px rgba(13,148,136,0.3)",
      }}
    />
  );
}

export function ContainerNode({ id, data }: NodeProps<ContainerNodeType>) {
  const workloadLabel =
    data.properties?.service_name ||
    humanizePropertyValue(data.properties?.runtime_type) ||
    "Container Workload";
  const summaryBits = [
    data.properties?.network_exposure === "internet" || data.properties?.internet_facing
      ? "Public"
      : humanizePropertyValue(data.properties?.network_exposure),
    humanizePropertyValue(data.properties?.isolation_boundary),
    humanizePropertyValue(data.properties?.privilege_level),
  ]
    .filter((value): value is string => Boolean(value))
    .slice(0, 2);
  const responsibilityLabel = humanizePropertyValue(data.properties?.responsibility);

  return (
    <NodeFrame
      id={id}
      data={data}
      nodeType="container"
      fallbackTypeLabel="Container Workload"
      style={{
        ...baseStyle,
        background: "#7c2d12",
        border: "2px dashed #f97316",
        boxShadow: "0 2px 8px rgba(249,115,22,0.3)",
      }}
      extraContent={
        <>
          <span style={nodeSummaryStyle}>
            {workloadLabel}
            {summaryBits.length > 0 ? ` · ${summaryBits.join(" · ")}` : ""}
          </span>
          {responsibilityLabel ? (
            <span style={{ ...typeLabelStyle, opacity: 0.9 }}>
              {responsibilityLabel} responsibility
            </span>
          ) : null}
        </>
      }
    />
  );
}

export function ServerlessNode({ id, data }: NodeProps<ServerlessNodeType>) {
  return (
    <NodeFrame
      id={id}
      data={data}
      nodeType="serverless"
      fallbackTypeLabel="Function"
      preferredTypeLabel={data.properties?.function_name}
      style={{
        background: "#713f12",
        border: "2px solid #eab308",
        boxShadow: "0 2px 8px rgba(234,179,8,0.3)",
      }}
    />
  );
}

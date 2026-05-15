import type { CSSProperties } from "react";
import type { NodeProperties, NodeType } from "../../types/api";
import {
  APIGatewayIcon,
  ContainerIcon,
  DataStoreIcon,
  ExternalEntityIcon,
  HumanActorIcon,
  IAMRoleIcon,
  ManagedServiceIcon,
  ProcessIcon,
  ServerlessIcon,
  TrustBoundaryIcon,
  type DFDIconComponent,
} from "./dfdIcons";

export type DFDPaletteGroupKey = "core" | "infrastructure";

export interface DFDPaletteGroup {
  key: DFDPaletteGroupKey;
  title: string;
  description: string;
}

export interface DFDNodeTypeOption {
  value: NodeType;
  label: string;
  groupKey: DFDPaletteGroupKey;
}

export interface DFDNodeTypeOptionGroup extends DFDPaletteGroup {
  options: DFDNodeTypeOption[];
}

interface DFDVisualBase {
  label: string;
  shortLabel: string;
  description: string;
  groupKey: DFDPaletteGroupKey;
  accentColor: string;
  tintColor: string;
  Icon: DFDIconComponent;
}

export interface DFDNodeVisualConfig extends DFDVisualBase {
  nodeType: NodeType;
  nodeStyle: CSSProperties;
}

export interface DFDNodeStencilConfig extends DFDVisualBase {
  key: NodeType | "trust_boundary";
  kind: "node";
  nodeType: NodeType;
}

export interface DFDTrustBoundaryStencilConfig extends DFDVisualBase {
  key: "trust_boundary";
  kind: "trust_boundary";
}

export type DFDPaletteStencilConfig = DFDNodeStencilConfig | DFDTrustBoundaryStencilConfig;

export const DFD_PALETTE_GROUPS: DFDPaletteGroup[] = [
  {
    key: "core",
    title: "Core",
    description: "Primary threat-model building blocks used across the diagram.",
  },
  {
    key: "infrastructure",
    title: "Infrastructure",
    description: "Execution and access surfaces that shape runtime exposure.",
  },
];

export const DFD_NODE_VISUALS: Record<NodeType, DFDNodeVisualConfig> = {
  process: {
    nodeType: "process",
    label: "Process",
    shortLabel: "P",
    description: "Service, worker, function, or gateway that transforms data.",
    groupKey: "core",
    accentColor: "#1d4ed8",
    tintColor: "#dbeafe",
    Icon: ProcessIcon,
    nodeStyle: {
      background: "#2563eb",
      borderRadius: 10,
      boxShadow: "0 2px 8px rgba(37,99,235,0.25)",
    },
  },
  data_store: {
    nodeType: "data_store",
    label: "Data Store",
    shortLabel: "DS",
    description: "Database, cache, secret store, backup, or log repository.",
    groupKey: "core",
    accentColor: "#475569",
    tintColor: "#e2e8f0",
    Icon: DataStoreIcon,
    nodeStyle: {
      background: "#475569",
      borderTop: "4px double rgba(255,255,255,0.7)",
      borderBottom: "4px double rgba(255,255,255,0.7)",
      borderLeft: "none",
      borderRight: "none",
      boxShadow: "0 2px 8px rgba(71,85,105,0.25)",
    },
  },
  external_entity: {
    nodeType: "external_entity",
    label: "External Entity",
    shortLabel: "EE",
    description: "System or SaaS outside the modeled control boundary.",
    groupKey: "core",
    accentColor: "#374151",
    tintColor: "#e5e7eb",
    Icon: ExternalEntityIcon,
    nodeStyle: {
      background: "#374151",
      borderRadius: 0,
      boxShadow: "0 2px 8px rgba(55,65,81,0.25)",
    },
  },
  human_actor: {
    nodeType: "human_actor",
    label: "Human Actor",
    shortLabel: "HA",
    description: "User, operator, analyst, or administrator interacting directly.",
    groupKey: "core",
    accentColor: "#4f46e5",
    tintColor: "#e0e7ff",
    Icon: HumanActorIcon,
    nodeStyle: {
      background: "#3b3b84",
      borderRadius: 999,
      border: "2px solid rgba(255,255,255,0.35)",
      boxShadow: "0 2px 8px rgba(59,59,132,0.28)",
    },
  },
  iam_role: {
    nodeType: "iam_role",
    label: "IAM Role",
    shortLabel: "IAM",
    description: "Principal, workload identity, or assumed execution role.",
    groupKey: "infrastructure",
    accentColor: "#3b82f6",
    tintColor: "#dbeafe",
    Icon: IAMRoleIcon,
    nodeStyle: {
      background: "#1e3a5f",
      border: "2px solid #3b82f6",
      borderRadius: 10,
      boxShadow: "0 2px 8px rgba(59,130,246,0.3)",
    },
  },
  managed_service: {
    nodeType: "managed_service",
    label: "Managed Service",
    shortLabel: "MS",
    description: "Cloud-managed platform dependency such as RDS or object storage.",
    groupKey: "infrastructure",
    accentColor: "#8b5cf6",
    tintColor: "#ede9fe",
    Icon: ManagedServiceIcon,
    nodeStyle: {
      background: "#4a1d96",
      border: "2px solid #8b5cf6",
      borderRadius: 10,
      boxShadow: "0 2px 8px rgba(139,92,246,0.3)",
    },
  },
  api_gateway: {
    nodeType: "api_gateway",
    label: "API Gateway",
    shortLabel: "GW",
    description: "Ingress tier, load balancer, reverse proxy, or API management surface.",
    groupKey: "infrastructure",
    accentColor: "#0d9488",
    tintColor: "#ccfbf1",
    Icon: APIGatewayIcon,
    nodeStyle: {
      background: "#0f4c5c",
      border: "2px solid #0d9488",
      borderRadius: 4,
      boxShadow: "0 2px 8px rgba(13,148,136,0.3)",
    },
  },
  container: {
    nodeType: "container",
    label: "Container",
    shortLabel: "CT",
    description: "Pod, task, service container, or workload sandbox.",
    groupKey: "infrastructure",
    accentColor: "#f97316",
    tintColor: "#ffedd5",
    Icon: ContainerIcon,
    nodeStyle: {
      background: "#7c2d12",
      border: "2px dashed #f97316",
      borderRadius: 6,
      boxShadow: "0 2px 8px rgba(249,115,22,0.3)",
    },
  },
  serverless: {
    nodeType: "serverless",
    label: "Serverless",
    shortLabel: "FN",
    description: "Short-lived function or event-triggered compute.",
    groupKey: "infrastructure",
    accentColor: "#eab308",
    tintColor: "#fef3c7",
    Icon: ServerlessIcon,
    nodeStyle: {
      background: "#713f12",
      border: "2px solid #eab308",
      borderRadius: 10,
      boxShadow: "0 2px 8px rgba(234,179,8,0.3)",
    },
  },
};

function createNodeStencil(nodeType: NodeType): DFDNodeStencilConfig {
  return {
    key: nodeType,
    kind: "node",
    ...DFD_NODE_VISUALS[nodeType],
  };
}

export const DFD_PALETTE_STENCILS: DFDPaletteStencilConfig[] = [
  createNodeStencil("process"),
  createNodeStencil("data_store"),
  createNodeStencil("external_entity"),
  createNodeStencil("human_actor"),
  {
    key: "trust_boundary",
    kind: "trust_boundary",
    label: "Trust Boundary",
    shortLabel: "TB",
    description: "Create an explicit trust-zone transition on the canvas.",
    groupKey: "core",
    accentColor: "#1d4ed8",
    tintColor: "#dbeafe",
    Icon: TrustBoundaryIcon,
  },
  createNodeStencil("api_gateway"),
  createNodeStencil("container"),
  createNodeStencil("serverless"),
  createNodeStencil("managed_service"),
  createNodeStencil("iam_role"),
];

export function getNodeVisualConfig(nodeType: NodeType): DFDNodeVisualConfig {
  return DFD_NODE_VISUALS[nodeType];
}

export function getDefaultNodeLabel(nodeType: NodeType): string {
  return DFD_NODE_VISUALS[nodeType].label;
}

export function getNodeTypeDisplayLabel(
  nodeType: NodeType,
  properties?: NodeProperties
): string {
  if (nodeType === "managed_service") {
    return properties?.service_name?.trim() || DFD_NODE_VISUALS.managed_service.label;
  }
  if (nodeType === "serverless") {
    return properties?.function_name?.trim() || "Function";
  }
  return DFD_NODE_VISUALS[nodeType].label;
}

export function getStencilPaletteGroups(): Array<DFDPaletteGroup & { items: DFDPaletteStencilConfig[] }> {
  return DFD_PALETTE_GROUPS.map((group) => ({
    ...group,
    items: DFD_PALETTE_STENCILS.filter((item) => item.groupKey === group.key),
  }));
}

export const DFD_NODE_TYPE_OPTIONS: DFDNodeTypeOption[] = Object.values(DFD_NODE_VISUALS).map((config) => ({
  value: config.nodeType,
  label: config.label,
  groupKey: config.groupKey,
}));

export const DFD_NODE_TYPE_OPTION_GROUPS: DFDNodeTypeOptionGroup[] = DFD_PALETTE_GROUPS.map((group) => ({
  ...group,
  options: DFD_NODE_TYPE_OPTIONS.filter((option) => option.groupKey === group.key),
}));

export const DFD_QUICK_ADD_NODE_OPTIONS: DFDNodeTypeOption[] = DFD_NODE_TYPE_OPTIONS.filter(
  (option) => option.groupKey === "core"
);

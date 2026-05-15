import type { Node } from "@xyflow/react";
import type { BoundaryType, NodeProperties, NodeType } from "../../types/api";

type SuggestionKey =
  | "restricted_data"
  | "control_plane"
  | "third_party"
  | "public_edge"
  | "shared_cloud";

const SUGGESTION_PRIORITY: SuggestionKey[] = [
  "restricted_data",
  "control_plane",
  "third_party",
  "public_edge",
  "shared_cloud",
];

export interface BoundarySuggestionDraft {
  key: SuggestionKey;
  name: string;
  boundaryType: BoundaryType;
  nodeIds: string[];
}

const CLOUD_NODE_TYPES = new Set<NodeType>([
  "iam_role",
  "managed_service",
  "api_gateway",
  "container",
  "serverless",
]);

function nodeProperties(node: Node): NodeProperties {
  return ((node.data as { properties?: NodeProperties } | undefined)?.properties ?? {}) as NodeProperties;
}

function nodeType(node: Node): NodeType | null {
  return node.type && node.type !== "trustBoundary" ? (node.type as NodeType) : null;
}

function isSensitiveNode(properties: NodeProperties, currentType: NodeType): boolean {
  return (
    properties.handles_financial_data === true ||
    properties.stores_credentials === true ||
    properties.stores_secrets === true ||
    properties.handles_sensitive_data === true ||
    properties.data_classification === "Restricted" ||
    (properties.data_classification === "Confidential" && currentType === "data_store")
  );
}

function isPrivilegedNode(properties: NodeProperties, currentType: NodeType): boolean {
  return (
    currentType === "iam_role" ||
    properties.privilege_level === "privileged" ||
    properties.privilege_level === "admin" ||
    properties.privilege_level === "system"
  );
}

function isThirdPartyNode(properties: NodeProperties, currentType: NodeType): boolean {
  return (
    properties.entity_scope === "external" &&
    currentType !== "human_actor" &&
    (currentType === "external_entity" ||
      properties.entity_kind === "saas" ||
      properties.entity_kind === "api" ||
      properties.entity_kind === "service" ||
      properties.entity_kind === "system")
  );
}

function isPublicEdgeNode(properties: NodeProperties, currentType: NodeType): boolean {
  return (
    currentType === "api_gateway" ||
    properties.internet_facing === true ||
    properties.network_exposure === "internet" ||
    properties.network_exposure === "dmz"
  );
}

function isSharedCloudNode(properties: NodeProperties, currentType: NodeType): boolean {
  return (
    CLOUD_NODE_TYPES.has(currentType) &&
    (properties.responsibility === "provider" || properties.responsibility === "shared")
  );
}

function classifyNode(node: Node): SuggestionKey | null {
  const currentType = nodeType(node);
  if (!currentType) {
    return null;
  }
  const properties = nodeProperties(node);

  if (isSensitiveNode(properties, currentType)) {
    return "restricted_data";
  }
  if (isPrivilegedNode(properties, currentType)) {
    return "control_plane";
  }
  if (isThirdPartyNode(properties, currentType)) {
    return "third_party";
  }
  if (isPublicEdgeNode(properties, currentType)) {
    return "public_edge";
  }
  if (isSharedCloudNode(properties, currentType)) {
    return "shared_cloud";
  }
  return null;
}

function draftForKey(key: SuggestionKey, nodes: Node[]): BoundarySuggestionDraft {
  switch (key) {
    case "restricted_data": {
      const usePciLabel = nodes.some((node) => {
        const properties = nodeProperties(node);
        return properties.handles_financial_data === true || properties.stores_credentials === true;
      });
      return {
        key,
        name: usePciLabel ? "PCI / Restricted Data Zone" : "Restricted Data Zone",
        boundaryType: "regulatory",
        nodeIds: nodes.map((node) => node.id),
      };
    }
    case "control_plane":
      return {
        key,
        name: "Privileged Control Plane",
        boundaryType: "privilege",
        nodeIds: nodes.map((node) => node.id),
      };
    case "third_party":
      return {
        key,
        name: "Third-Party Services",
        boundaryType: "organizational",
        nodeIds: nodes.map((node) => node.id),
      };
    case "public_edge":
      return {
        key,
        name: "Public Edge / DMZ",
        boundaryType: "network",
        nodeIds: nodes.map((node) => node.id),
      };
    case "shared_cloud":
      return {
        key,
        name: "Provider / Shared Cloud Services",
        boundaryType: "cloud",
        nodeIds: nodes.map((node) => node.id),
      };
  }
}

export function suggestBoundaryDraftForSelection(
  nodes: Node[]
): Pick<BoundarySuggestionDraft, "name" | "boundaryType"> | null {
  const dataNodes = nodes.filter((node) => node.type !== "trustBoundary");
  if (dataNodes.length === 0) {
    return null;
  }

  const classifications = dataNodes
    .map((node) => classifyNode(node))
    .filter((value): value is SuggestionKey => value !== null);

  if (classifications.length !== dataNodes.length) {
    return null;
  }

  const firstKey = classifications[0];
  if (!firstKey) {
    return null;
  }
  if (!classifications.every((value) => value === firstKey)) {
    return null;
  }

  const draft = draftForKey(firstKey, dataNodes);
  return {
    name: draft.name,
    boundaryType: draft.boundaryType,
  };
}

export function suggestBoundaryDrafts(nodes: Node[]): BoundarySuggestionDraft[] {
  const groups = new Map<SuggestionKey, Node[]>();

  for (const node of nodes) {
    if (node.type === "trustBoundary" || node.parentId) {
      continue;
    }
    const suggestionKey = classifyNode(node);
    if (!suggestionKey) {
      continue;
    }
    const existing = groups.get(suggestionKey) ?? [];
    existing.push(node);
    groups.set(suggestionKey, existing);
  }

  return SUGGESTION_PRIORITY
    .map((key) => {
      const groupedNodes = groups.get(key);
      if (!groupedNodes || groupedNodes.length === 0) {
        return null;
      }
      return draftForKey(key, groupedNodes);
    })
    .filter((draft): draft is BoundarySuggestionDraft => draft !== null);
}

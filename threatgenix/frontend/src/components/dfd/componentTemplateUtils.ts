import type {
  DFDComponentTemplateDraft,
  DFDComponentTemplateResponse,
  NodeProperties,
  NodeType,
} from "../../types/api";

export const DEFAULT_TEMPLATE_ID_BY_NODE_TYPE: Record<NodeType, string> = {
  process: "builtin-process",
  data_store: "builtin-data-store",
  external_entity: "builtin-external-entity",
  human_actor: "builtin-human-actor",
  iam_role: "builtin-iam-role",
  managed_service: "builtin-managed-service",
  api_gateway: "builtin-api-gateway",
  container: "builtin-container",
  serverless: "builtin-serverless",
};

export function findTemplateForNode(
  templates: DFDComponentTemplateResponse[],
  nodeType: NodeType,
  properties?: NodeProperties
): DFDComponentTemplateResponse | null {
  const explicitId = properties?.component_template_id;
  if (explicitId) {
    const explicitMatch = templates.find((template) => template.id === explicitId);
    if (explicitMatch) {
      return explicitMatch;
    }
  }

  const label = properties?.component_label?.trim();
  if (label) {
    const labelMatch = templates.find(
      (template) =>
        template.semantic_node_type === nodeType &&
        template.label.trim().toLowerCase() === label.toLowerCase()
    );
    if (labelMatch) {
      return labelMatch;
    }
  }

  return null;
}

export function buildNodePropertiesFromTemplate(
  template: DFDComponentTemplateDraft | DFDComponentTemplateResponse,
  existingProperties?: NodeProperties
): NodeProperties {
  return {
    ...(template.default_properties ?? {}),
    ...(existingProperties ?? {}),
    component_template_id: "id" in template ? template.id : existingProperties?.component_template_id,
    component_label: template.label,
    component_shape: template.shape,
    component_description: template.description ?? undefined,
  };
}

export function formatTemplateOptionLabel(template: DFDComponentTemplateResponse): string {
  const group = template.group?.trim() || (template.built_in ? "Built-in" : "Custom");
  return `${template.label} · ${group}`;
}

export function getTemplateSemanticTypeLabel(
  template: Pick<DFDComponentTemplateDraft, "semantic_node_type" | "semantic_type_label">
): string {
  return template.semantic_type_label?.trim() || humanizeNodeType(template.semantic_node_type);
}

export function humanizeNodeType(nodeType: NodeType): string {
  switch (nodeType) {
    case "process":
      return "Process";
    case "data_store":
      return "Data Store";
    case "external_entity":
      return "External Entity";
    case "human_actor":
      return "Human Actor";
    case "iam_role":
      return "IAM Role";
    case "managed_service":
      return "Managed Service";
    case "api_gateway":
      return "API Gateway";
    case "container":
      return "Container";
    case "serverless":
      return "Serverless";
    default:
      return nodeType;
  }
}

import type {
  DFDPropertyOptionField,
  DFDPropertyOptionResponse,
  NodeProperties,
} from "../../types/api";

export type SelectOption = { value: string; label: string };

export type PropertySelectChoice = {
  value: string;
  label: string;
  canonicalValue: string;
  custom: boolean;
  optionId?: string;
};

export const PROPERTY_OPTION_CONFIG: Record<
  DFDPropertyOptionField,
  { label: string; baseOptions: SelectOption[] }
> = {
  data_classification: {
    label: "Data Classification",
    baseOptions: [
      { value: "Public", label: "Public" },
      { value: "Internal", label: "Internal" },
      { value: "Confidential", label: "Confidential" },
      { value: "Restricted", label: "Restricted" },
    ],
  },
  authentication_type: {
    label: "Authentication",
    baseOptions: [
      { value: "none", label: "None" },
      { value: "api_key", label: "API Key" },
      { value: "oauth2", label: "OAuth 2" },
      { value: "mtls", label: "mTLS" },
      { value: "saml", label: "SAML" },
      { value: "jwt", label: "JWT" },
    ],
  },
  authorization_model: {
    label: "Authorization Model",
    baseOptions: [
      { value: "none", label: "None" },
      { value: "rbac", label: "RBAC" },
      { value: "abac", label: "ABAC" },
      { value: "acl", label: "ACL" },
      { value: "policy", label: "Policy" },
    ],
  },
  network_exposure: {
    label: "Network Exposure",
    baseOptions: [
      { value: "internet", label: "Internet" },
      { value: "dmz", label: "DMZ" },
      { value: "internal", label: "Internal" },
      { value: "vpc_private", label: "VPC Private" },
    ],
  },
  privilege_level: {
    label: "Privilege Level",
    baseOptions: [
      { value: "standard", label: "Standard" },
      { value: "elevated", label: "Elevated" },
      { value: "privileged", label: "Privileged" },
      { value: "admin", label: "Admin" },
      { value: "system", label: "System" },
    ],
  },
  runtime_type: {
    label: "Runtime Type",
    baseOptions: [
      { value: "service", label: "Service" },
      { value: "worker", label: "Worker" },
      { value: "function", label: "Function" },
      { value: "job", label: "Job" },
      { value: "gateway", label: "Gateway" },
      { value: "container", label: "Container" },
    ],
  },
  isolation_boundary: {
    label: "Isolation Boundary",
    baseOptions: [
      { value: "shared_host", label: "Shared Host" },
      { value: "container", label: "Container" },
      { value: "sandbox", label: "Sandbox" },
      { value: "dedicated_host", label: "Dedicated Host" },
      { value: "managed_service", label: "Managed Service" },
    ],
  },
  input_validation: {
    label: "Input Validation",
    baseOptions: [
      { value: "none", label: "None" },
      { value: "partial", label: "Partial" },
      { value: "strict", label: "Strict" },
    ],
  },
  logging_level: {
    label: "Logging Level",
    baseOptions: [
      { value: "none", label: "None" },
      { value: "errors_only", label: "Errors Only" },
      { value: "audit", label: "Audit" },
      { value: "full", label: "Full" },
    ],
  },
  encryption_at_rest: {
    label: "Encryption at Rest",
    baseOptions: [
      { value: "none", label: "None" },
      { value: "application_level", label: "Application-Level" },
      { value: "transparent", label: "Transparent" },
      { value: "hsm", label: "HSM-backed" },
    ],
  },
  backup_strategy: {
    label: "Backup Strategy",
    baseOptions: [
      { value: "none", label: "None" },
      { value: "local", label: "Local" },
      { value: "geo_redundant", label: "Geo-Redundant" },
    ],
  },
  entity_scope: {
    label: "Entity Scope",
    baseOptions: [
      { value: "internal", label: "Internal" },
      { value: "external", label: "External" },
    ],
  },
  entity_kind: {
    label: "Entity Kind",
    baseOptions: [
      { value: "human", label: "Human" },
      { value: "device", label: "Device" },
      { value: "system", label: "System" },
      { value: "saas", label: "SaaS" },
      { value: "api", label: "API" },
      { value: "service", label: "Service" },
    ],
  },
  trust_level: {
    label: "Trust Level",
    baseOptions: [
      { value: "untrusted", label: "Untrusted" },
      { value: "semi_trusted", label: "Semi-Trusted" },
      { value: "trusted", label: "Trusted" },
      { value: "privileged", label: "Privileged" },
    ],
  },
  responsibility: {
    label: "Responsibility",
    baseOptions: [
      { value: "provider", label: "Provider-Managed" },
      { value: "customer", label: "Customer-Managed" },
      { value: "shared", label: "Shared" },
    ],
  },
};

export const PROPERTY_OPTION_FIELDS = Object.entries(PROPERTY_OPTION_CONFIG).map(
  ([field, config]) => ({
    field: field as DFDPropertyOptionField,
    label: config.label,
  })
);

export function getBasePropertyOptions(field: DFDPropertyOptionField): SelectOption[] {
  return PROPERTY_OPTION_CONFIG[field].baseOptions;
}

export function getPropertyFieldLabel(field: DFDPropertyOptionField): string {
  return PROPERTY_OPTION_CONFIG[field].label;
}

export function getBuiltinPropertyOptionLabel(
  field: DFDPropertyOptionField,
  canonicalValue: string
): string {
  return (
    PROPERTY_OPTION_CONFIG[field].baseOptions.find((option) => option.value === canonicalValue)?.label ??
    canonicalValue
  );
}

export function buildPropertySelectChoices(
  field: DFDPropertyOptionField,
  customOptions: DFDPropertyOptionResponse[]
): PropertySelectChoice[] {
  const builtInChoices = PROPERTY_OPTION_CONFIG[field].baseOptions.map((option) => ({
    value: option.value,
    label: option.label,
    canonicalValue: option.value,
    custom: false,
  }));

  const customChoices = customOptions
    .filter((option) => option.field === field)
    .map((option) => {
      const builtinLabel = getBuiltinPropertyOptionLabel(field, option.canonical_value);
      return {
        value: `custom:${option.id}`,
        label:
          option.label === builtinLabel
            ? option.label
            : `${option.label} (${builtinLabel})`,
        canonicalValue: option.canonical_value,
        custom: true,
        optionId: option.id,
      };
    });

  return [...builtInChoices, ...customChoices];
}

export function resolvePropertySelectValue(
  field: DFDPropertyOptionField,
  properties: NodeProperties,
  customOptions: DFDPropertyOptionResponse[]
): string {
  const canonicalValue = properties[field] as string | undefined;
  if (!canonicalValue) {
    return "";
  }

  const displayLabel = properties.property_display_labels?.[field]?.trim();
  if (displayLabel) {
    const match = customOptions.find(
      (option) =>
        option.field === field &&
        option.canonical_value === canonicalValue &&
        option.label.trim().toLowerCase() === displayLabel.toLowerCase()
    );
    if (match) {
      return `custom:${match.id}`;
    }
  }

  if (!PROPERTY_OPTION_CONFIG[field].baseOptions.some((option) => option.value === canonicalValue)) {
    const canonicalMatches = customOptions.filter(
      (option) => option.field === field && option.canonical_value === canonicalValue
    );
    const firstCanonicalMatch = canonicalMatches[0];
    if (canonicalMatches.length === 1 && firstCanonicalMatch) {
      return `custom:${firstCanonicalMatch.id}`;
    }
    const labelMatch = canonicalMatches.find(
      (option) => option.label.trim().toLowerCase() === canonicalValue.toLowerCase()
    );
    if (labelMatch) {
      return `custom:${labelMatch.id}`;
    }
  }

  return canonicalValue;
}

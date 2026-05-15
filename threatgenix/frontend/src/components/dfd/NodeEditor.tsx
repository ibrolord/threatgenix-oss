import { useCallback, useEffect, useMemo, useState } from "react";
import type {
  DFDComponentTemplateResponse,
  DFDNodeResponse,
  DFDPropertyOptionField,
  DFDPropertyOptionResponse,
  DFDPropertyOptionSuggestResponse,
  NodeProperties,
  NodeType,
  SecurityControl,
} from "../../types/api";
import { api } from "../../api/client";
import {
  buildNodePropertiesFromTemplate,
  DEFAULT_TEMPLATE_ID_BY_NODE_TYPE,
  findTemplateForNode,
  formatTemplateOptionLabel,
  getTemplateSemanticTypeLabel,
  humanizeNodeType,
} from "./componentTemplateUtils";
import {
  buildPropertySelectChoices,
  getBasePropertyOptions,
  getBuiltinPropertyOptionLabel,
  getPropertyFieldLabel,
  PROPERTY_OPTION_FIELDS,
  resolvePropertySelectValue,
} from "./propertyOptionUtils";
import { CustomSelectField } from "./CustomSelectField";

interface NodeEditorProps {
  threatModelId: string;
  viewId?: string | null;
  nodeId: string;
  initialName: string;
  initialType: NodeType;
  initialProperties: NodeProperties;
  initialScanTargetUrl?: string | null;
  initialScanTargetPorts?: string | null;
  onSaved: (updated: DFDNodeResponse) => void;
  onClose: () => void;
}

type PropDef = [keyof NodeProperties, string];
type PropertyOptionDraftForm = {
  field: DFDPropertyOptionField;
  label: string;
  canonical_value: string;
  description: string;
  ai_generated: boolean;
  rationale: string;
};

const PROCESS_LIKE_TYPES = new Set<NodeType>([
  "process",
  "managed_service",
  "api_gateway",
  "container",
  "serverless",
]);

const EXTERNAL_LIKE_TYPES = new Set<NodeType>(["external_entity", "human_actor", "iam_role"]);
const CLOUD_NODE_TYPES = new Set<NodeType>([
  "iam_role",
  "managed_service",
  "api_gateway",
  "container",
  "serverless",
]);

const DEFAULT_PROPERTY_OPTION_FIELD: DFDPropertyOptionField = "authentication_type";

const DEFAULT_PROPERTY_OPTION_DRAFT: PropertyOptionDraftForm = {
  field: DEFAULT_PROPERTY_OPTION_FIELD,
  label: "",
  canonical_value: getBasePropertyOptions(DEFAULT_PROPERTY_OPTION_FIELD)[0]?.value ?? "",
  description: "",
  ai_generated: false,
  rationale: "",
};

const EXTRA_CHECKBOXES: Record<string, PropDef[]> = {
  common: [
    ["internet_facing", "Internet-Facing"],
    ["uses_encryption", "Uses Encryption"],
    ["handles_sensitive_data", "Handles Sensitive Data"],
  ],
  process: [
    ["uses_auth", "Uses Authentication"],
    ["validates_input", "Validates Input"],
    ["handles_pii", "Handles PII"],
    ["handles_financial_data", "Handles Financial Data"],
  ],
  data_store: [
    ["stores_credentials", "Stores Credentials"],
    ["stores_secrets", "Stores Secrets"],
    ["encrypted_at_rest", "Encrypted at Rest (Legacy Rule Signal)"],
    ["has_backup", "Has Backup (Legacy Rule Signal)"],
  ],
  external: [
    ["trusted", "Trusted (Legacy Rule Signal)"],
    ["authenticated", "Authenticated (Legacy Rule Signal)"],
  ],
};

function renderTextInput(
  id: string,
  label: string,
  value: string | undefined,
  placeholder: string,
  onChange: (value: string) => void
) {
  return (
    <div className="form-field" key={id}>
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        type="text"
        value={value ?? ""}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
      />
    </div>
  );
}

function normalizeOptionalText(value: string): string | null {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function NodeEditor({
  threatModelId,
  viewId = null,
  nodeId,
  initialName,
  initialType,
  initialProperties,
  initialScanTargetUrl = null,
  initialScanTargetPorts = null,
  onSaved,
  onClose,
}: NodeEditorProps): JSX.Element {
  const [name, setName] = useState(initialName);
  const [nodeType, setNodeType] = useState<NodeType>(initialType);
  const [properties, setProperties] = useState<NodeProperties>({ ...initialProperties });
  const [scanTargetUrl, setScanTargetUrl] = useState(initialScanTargetUrl ?? "");
  const [scanTargetPorts, setScanTargetPorts] = useState(initialScanTargetPorts ?? "");
  const [templates, setTemplates] = useState<DFDComponentTemplateResponse[]>([]);
  const [propertyOptions, setPropertyOptions] = useState<DFDPropertyOptionResponse[]>([]);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>(
    initialProperties.component_template_id ?? DEFAULT_TEMPLATE_ID_BY_NODE_TYPE[initialType]
  );
  const [templatesLoading, setTemplatesLoading] = useState(true);
  const [propertyOptionsLoading, setPropertyOptionsLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingPropertyOption, setSavingPropertyOption] = useState(false);
  const [deletingPropertyOptionId, setDeletingPropertyOptionId] = useState<string | null>(null);
  const [suggestingPropertyOption, setSuggestingPropertyOption] = useState(false);
  const [propertyOptionDraft, setPropertyOptionDraft] =
    useState<PropertyOptionDraftForm>(DEFAULT_PROPERTY_OPTION_DRAFT);
  const [propertyOptionPrompt, setPropertyOptionPrompt] = useState("");
  const [propertyOptionSuggestion, setPropertyOptionSuggestion] =
    useState<DFDPropertyOptionSuggestResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isProcessLike = PROCESS_LIKE_TYPES.has(nodeType);
  const isDataStore = nodeType === "data_store";
  const isExternalLike = EXTERNAL_LIKE_TYPES.has(nodeType);

  useEffect(() => {
    if (nodeType !== "human_actor") {
      return;
    }
    setProperties((prev) => {
      const nextDisplayLabels = { ...(prev.property_display_labels ?? {}) };
      delete nextDisplayLabels.entity_kind;
      return {
        ...prev,
        entity_kind: "human",
        property_display_labels:
          Object.keys(nextDisplayLabels).length > 0 ? nextDisplayLabels : undefined,
      };
    });
  }, [nodeType]);

  useEffect(() => {
    setPropertyOptionDraft((current) => {
      const baseOptions = getBasePropertyOptions(current.field);
      if (current.canonical_value.trim()) {
        return current;
      }
      return {
        ...current,
        canonical_value: baseOptions[0]?.value ?? "",
      };
    });
  }, [propertyOptionDraft.field]);

  useEffect(() => {
    let cancelled = false;

    async function loadEditorCatalogs() {
      setTemplatesLoading(true);
      setPropertyOptionsLoading(true);
      try {
        const [nextTemplates, nextPropertyOptions] = await Promise.all([
          api.getDFDComponentTemplates(threatModelId),
          api.getDFDPropertyOptions(threatModelId),
        ]);
        if (cancelled) return;
        setTemplates(nextTemplates);
        setPropertyOptions(nextPropertyOptions);
        const resolvedTemplate = findTemplateForNode(nextTemplates, initialType, initialProperties);
        if (resolvedTemplate) {
          setSelectedTemplateId(resolvedTemplate.id);
          setNodeType(resolvedTemplate.semantic_node_type);
          setProperties((current) => buildNodePropertiesFromTemplate(resolvedTemplate, current));
        } else {
          setSelectedTemplateId(DEFAULT_TEMPLATE_ID_BY_NODE_TYPE[initialType]);
          setNodeType(initialType);
        }
      } catch (e: unknown) {
        if (cancelled) return;
        const msg = e instanceof Error ? e.message : "Failed to load component templates.";
        setError(msg);
      } finally {
        if (!cancelled) {
          setTemplatesLoading(false);
          setPropertyOptionsLoading(false);
        }
      }
    }

    void loadEditorCatalogs();
    return () => {
      cancelled = true;
    };
  }, [initialProperties, initialType, threatModelId]);

  const setTextProp = useCallback((key: keyof NodeProperties, value: string) => {
    setProperties((prev) => ({ ...prev, [key]: value || undefined }));
  }, []);

  const setEnumProp = useCallback((key: keyof NodeProperties, value: string) => {
    const normalizedValue = value.trim();
    setProperties((prev) => {
      const nextDisplayLabels = { ...(prev.property_display_labels ?? {}) };
      delete nextDisplayLabels[String(key)];
      return {
        ...prev,
        [key]: normalizedValue || undefined,
        property_display_labels:
          Object.keys(nextDisplayLabels).length > 0 ? nextDisplayLabels : undefined,
      };
    });
  }, []);

  const toggleProp = useCallback((key: keyof NodeProperties) => {
    setProperties((prev) => ({ ...prev, [key]: !prev[key] }));
  }, []);

  const handlePropertySelectChange = useCallback(
    (field: DFDPropertyOptionField, rawValue: string) => {
      if (!rawValue) {
        setProperties((prev) => {
          const nextDisplayLabels = { ...(prev.property_display_labels ?? {}) };
          delete nextDisplayLabels[field];
          return {
            ...prev,
            [field]: undefined,
            property_display_labels:
              Object.keys(nextDisplayLabels).length > 0 ? nextDisplayLabels : undefined,
          };
        });
        return;
      }

      if (!rawValue.startsWith("custom:")) {
        setEnumProp(field as keyof NodeProperties, rawValue);
        return;
      }

      const optionId = rawValue.slice("custom:".length);
      const selectedOption = propertyOptions.find((option) => option.id === optionId && option.field === field);
      if (!selectedOption) {
        setEnumProp(field as keyof NodeProperties, "");
        return;
      }

      setProperties((prev) => ({
        ...prev,
        [field]: selectedOption.canonical_value,
        property_display_labels: {
          ...(prev.property_display_labels ?? {}),
          [field]: selectedOption.label,
        },
      }));
    },
    [propertyOptions, setEnumProp]
  );

  const applySuggestedPropertyOption = useCallback(
    (option: DFDPropertyOptionSuggestResponse["option"]) => {
      setPropertyOptionDraft({
        field: option.field,
        label: option.label,
        canonical_value: option.canonical_value,
        description: option.description ?? "",
        ai_generated: option.ai_generated ?? false,
        rationale: option.rationale ?? "",
      });
    },
    []
  );

  const handleCreatePropertyOption = useCallback(async () => {
    if (!propertyOptionDraft.label.trim()) {
      setError("Alias label is required.");
      return;
    }

    setSavingPropertyOption(true);
    setError(null);
    try {
      const created = await api.createDFDPropertyOption(threatModelId, {
        field: propertyOptionDraft.field,
        label: propertyOptionDraft.label.trim(),
        canonical_value: propertyOptionDraft.canonical_value,
        description: propertyOptionDraft.description.trim() || undefined,
        ai_generated: propertyOptionDraft.ai_generated,
        rationale: propertyOptionDraft.rationale.trim() || undefined,
      });
      setPropertyOptions((current) =>
        [...current, created].sort((a, b) =>
          a.field === b.field ? a.label.localeCompare(b.label) : a.field.localeCompare(b.field)
        )
      );
      setPropertyOptionDraft({
        field: created.field,
        label: "",
        canonical_value: getBasePropertyOptions(created.field)[0]?.value ?? "",
        description: "",
        ai_generated: false,
        rationale: "",
      });
      setPropertyOptionPrompt("");
      setPropertyOptionSuggestion(null);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to save dropdown alias.";
      setError(msg);
    } finally {
      setSavingPropertyOption(false);
    }
  }, [propertyOptionDraft, threatModelId]);

  const handleSuggestPropertyOption = useCallback(async () => {
    const prompt = propertyOptionPrompt.trim();
    if (!prompt) {
      setError("Describe the dropdown alias you want AI to draft.");
      return;
    }

    setSuggestingPropertyOption(true);
    setError(null);
    try {
      const response = await api.suggestDFDPropertyOption(threatModelId, {
        field: propertyOptionDraft.field,
        prompt,
      });
      setPropertyOptionSuggestion(response);
      applySuggestedPropertyOption(response.option);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to generate dropdown alias.";
      setError(msg);
    } finally {
      setSuggestingPropertyOption(false);
    }
  }, [applySuggestedPropertyOption, propertyOptionDraft.field, propertyOptionPrompt, threatModelId]);

  const handleDeletePropertyOption = useCallback(
    async (optionId: string) => {
      setDeletingPropertyOptionId(optionId);
      setError(null);
      try {
        await api.deleteDFDPropertyOption(threatModelId, optionId);
        setPropertyOptions((current) => current.filter((option) => option.id !== optionId));
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Failed to delete dropdown alias.";
        setError(msg);
      } finally {
        setDeletingPropertyOptionId(null);
      }
    },
    [threatModelId]
  );

  const handleSave = useCallback(async () => {
    if (!name.trim()) {
      setError("Name is required.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const updated = await api.updateNode(threatModelId, nodeId, {
        name: name.trim(),
        node_type: nodeType,
        scan_target_url: normalizeOptionalText(scanTargetUrl),
        scan_target_ports: normalizeOptionalText(scanTargetPorts),
        properties: nodeType === "human_actor" ? { ...properties, entity_kind: "human" } : properties,
      }, viewId);
      onSaved(updated);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to update node.";
      setError(msg);
    } finally {
      setSaving(false);
    }
  }, [threatModelId, viewId, nodeId, name, nodeType, scanTargetUrl, scanTargetPorts, properties, onSaved]);

  const extraCheckboxes = useMemo(() => {
    const defs: PropDef[] = [...(EXTRA_CHECKBOXES.common ?? [])];
    if (isProcessLike) defs.push(...(EXTRA_CHECKBOXES.process ?? []));
    if (isDataStore) defs.push(...(EXTRA_CHECKBOXES.data_store ?? []));
    if (isExternalLike) defs.push(...(EXTRA_CHECKBOXES.external ?? []));
    return defs;
  }, [isProcessLike, isDataStore, isExternalLike]);

  const groupedTemplates = useMemo(() => {
    const groups = new Map<string, DFDComponentTemplateResponse[]>();
    for (const template of templates) {
      const groupName = template.group?.trim() || (template.built_in ? "Built-in" : "Custom");
      const groupItems = groups.get(groupName) ?? [];
      groupItems.push(template);
      groups.set(groupName, groupItems);
    }
    return [...groups.entries()];
  }, [templates]);

  const selectedTemplate = useMemo(
    () => templates.find((template) => template.id === selectedTemplateId) ?? null,
    [selectedTemplateId, templates]
  );

  const customPropertyOptionsForDraftField = useMemo(
    () =>
      propertyOptions.filter((option) => option.field === propertyOptionDraft.field),
    [propertyOptionDraft.field, propertyOptions]
  );

  const handleTemplateChange = useCallback(
    (templateId: string) => {
      setSelectedTemplateId(templateId);
      const nextTemplate = templates.find((template) => template.id === templateId);
      if (!nextTemplate) {
        return;
      }
      setNodeType(nextTemplate.semantic_node_type);
      setProperties((current) => buildNodePropertiesFromTemplate(nextTemplate, current));
    },
    [templates]
  );

  const renderPropertySelect = useCallback(
    (
      id: string,
      field: DFDPropertyOptionField,
      value: string | undefined
    ) =>
      (
        <CustomSelectField
          id={id}
          key={id}
          label={getPropertyFieldLabel(field)}
          value={value}
          options={buildPropertySelectChoices(field, propertyOptions)}
          onChange={(nextValue) => handlePropertySelectChange(field, nextValue ?? "")}
          disabled={propertyOptionsLoading}
          customPlaceholder={`Enter a custom ${getPropertyFieldLabel(field).toLowerCase()}`}
        />
      ),
    [handlePropertySelectChange, propertyOptions, propertyOptionsLoading]
  );

  return (
    <div className="dfd-dialog-overlay" onClick={onClose}>
      <div className="dfd-dialog dfd-dialog-wide" onClick={(event) => event.stopPropagation()}>
        <h3 className="dfd-dialog-title">Edit Node</h3>
        <p className="dfd-dialog-copy">
          Capture the security-relevant metadata for this DFD object, not just its label.
        </p>

        <div className="dfd-node-editor-grid">
          <div className="form-field">
            <label htmlFor="edit-node-name">Name</label>
            <input
              id="edit-node-name"
              type="text"
              value={name}
              onChange={(event) => setName(event.target.value)}
              autoFocus
            />
          </div>

          <div className="form-field">
            <label htmlFor="edit-node-type">Component Stencil</label>
            <select
              id="edit-node-type"
              value={selectedTemplateId}
              onChange={(event) => handleTemplateChange(event.target.value)}
              disabled={templatesLoading}
            >
              {groupedTemplates.map(([groupName, groupTemplates]) => (
                <optgroup key={groupName} label={groupName}>
                  {groupTemplates.map((template) => (
                    <option key={template.id} value={template.id}>
                      {formatTemplateOptionLabel(template)}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
            <span className="dfd-component-template-hint">
              Underlying semantic type: {selectedTemplate ? getTemplateSemanticTypeLabel(selectedTemplate) : humanizeNodeType(nodeType)}
            </span>
          </div>

          {renderPropertySelect(
            "prop-data-classification",
            "data_classification",
            resolvePropertySelectValue("data_classification", properties, propertyOptions)
          )}
          {renderPropertySelect(
            "prop-auth-type",
            "authentication_type",
            resolvePropertySelectValue("authentication_type", properties, propertyOptions)
          )}
          {renderPropertySelect(
            "prop-authz-model",
            "authorization_model",
            resolvePropertySelectValue("authorization_model", properties, propertyOptions)
          )}
          {renderPropertySelect(
            "prop-network-exposure",
            "network_exposure",
            resolvePropertySelectValue("network_exposure", properties, propertyOptions)
          )}
          {renderPropertySelect(
            "prop-privilege-level",
            "privilege_level",
            resolvePropertySelectValue("privilege_level", properties, propertyOptions)
          )}

          {isProcessLike && (
            <>
              {renderPropertySelect(
                "prop-runtime-type",
                "runtime_type",
                resolvePropertySelectValue("runtime_type", properties, propertyOptions)
              )}
              {renderPropertySelect(
                "prop-isolation-boundary",
                "isolation_boundary",
                resolvePropertySelectValue("isolation_boundary", properties, propertyOptions)
              )}
              {renderPropertySelect(
                "prop-input-validation",
                "input_validation",
                resolvePropertySelectValue("input_validation", properties, propertyOptions)
              )}
              {renderPropertySelect(
                "prop-logging-level",
                "logging_level",
                resolvePropertySelectValue("logging_level", properties, propertyOptions)
              )}
              {renderTextInput(
                "prop-accepted-input",
                "Accepted Input",
                properties.accepted_input,
                "e.g. JSON API requests, signed callbacks",
                (value) => setTextProp("accepted_input", value)
              )}
            </>
          )}

          {isDataStore && (
            <>
              {renderPropertySelect(
                "prop-encryption-at-rest",
                "encryption_at_rest",
                resolvePropertySelectValue("encryption_at_rest", properties, propertyOptions)
              )}
              {renderPropertySelect(
                "prop-backup-strategy",
                "backup_strategy",
                resolvePropertySelectValue("backup_strategy", properties, propertyOptions)
              )}
              {renderTextInput(
                "prop-store-type",
                "Store Type",
                properties.store_type,
                "e.g. PostgreSQL, Redis, S3 bucket",
                (value) => setTextProp("store_type", value)
              )}
              {renderTextInput(
                "prop-store-purpose",
                "Store Purpose",
                properties.store_purpose,
                "e.g. customer profiles, audit log, secrets",
                (value) => setTextProp("store_purpose", value)
              )}
              {renderTextInput(
                "prop-read-access-scope",
                "Read Access Scope",
                properties.read_access_scope,
                "e.g. API only, analysts, admins",
                (value) => setTextProp("read_access_scope", value)
              )}
              {renderTextInput(
                "prop-write-access-scope",
                "Write Access Scope",
                properties.write_access_scope,
                "e.g. app writes only, async workers",
                (value) => setTextProp("write_access_scope", value)
              )}
              {renderTextInput(
                "prop-integrity-controls",
                "Integrity Controls",
                properties.integrity_controls,
                "e.g. append-only log, checksums, WAL",
                (value) => setTextProp("integrity_controls", value)
              )}
            </>
          )}

          {isExternalLike && (
            <>
              {renderPropertySelect(
                "prop-entity-scope",
                "entity_scope",
                resolvePropertySelectValue("entity_scope", properties, propertyOptions)
              )}
              {nodeType === "human_actor" ? (
                <div className="form-field">
                  <label htmlFor="prop-entity-kind-human">Entity Kind</label>
                  <input id="prop-entity-kind-human" type="text" value="Human" disabled />
                </div>
              ) : (
                renderPropertySelect(
                  "prop-entity-kind",
                  "entity_kind",
                  resolvePropertySelectValue("entity_kind", properties, propertyOptions)
                )
              )}
              {renderPropertySelect(
                "prop-trust-level",
                "trust_level",
                resolvePropertySelectValue("trust_level", properties, propertyOptions)
              )}
            </>
          )}

          {nodeType === "managed_service" &&
            renderTextInput(
              "prop-service-name",
              "Service Name",
              properties.service_name,
              "e.g. S3, RDS, SQS",
              (value) => setTextProp("service_name", value)
            )}
          {nodeType === "serverless" &&
            renderTextInput(
              "prop-function-name",
              "Function Name",
              properties.function_name,
              "e.g. process-payment",
              (value) => setTextProp("function_name", value)
            )}
          {CLOUD_NODE_TYPES.has(nodeType) &&
            renderPropertySelect(
              "prop-responsibility",
              "responsibility",
              resolvePropertySelectValue("responsibility", properties, propertyOptions)
            )}
        </div>

        <section className="node-properties-section">
          <h4>Vulnerability Scan Target</h4>
          <p className="dfd-dialog-copy">
            Attach the reachable URL or host for validation scans against this modeled component.
          </p>
          <div className="dfd-node-editor-grid">
            <div className="form-field">
              <label htmlFor="edit-node-scan-target-url">Target URL</label>
              <input
                id="edit-node-scan-target-url"
                type="text"
                value={scanTargetUrl}
                onChange={(event) => setScanTargetUrl(event.target.value)}
                placeholder="https://api.example.com"
              />
            </div>
            <div className="form-field">
              <label htmlFor="edit-node-scan-target-ports">Ports</label>
              <input
                id="edit-node-scan-target-ports"
                type="text"
                value={scanTargetPorts}
                onChange={(event) => setScanTargetPorts(event.target.value)}
                placeholder="443, 8443"
              />
            </div>
          </div>
        </section>

        <section className="node-properties-section">
          <h4>Security Controls</h4>
          <p className="dfd-dialog-copy">
            List controls actively protecting this component. These inform rule suppression and report context.
          </p>
          <div className="dfd-node-security-controls">
            {(properties.security_controls ?? []).map((ctrl: SecurityControl, i: number) => (
              <div key={i} className="dfd-node-security-control-row">
                <span className="dfd-node-security-control-type">{ctrl.control_type}:</span>
                <span className="dfd-node-security-control-name">{ctrl.name}</span>
                {ctrl.covers.length > 0 && (
                  <span className="dfd-node-security-control-covers">Covers: {ctrl.covers.join(", ")}</span>
                )}
                <button
                  type="button"
                  className="dfd-node-security-control-remove"
                  onClick={() => {
                    const updated = [...(properties.security_controls ?? [])];
                    updated.splice(i, 1);
                    setProperties((prev) => ({ ...prev, security_controls: updated.length > 0 ? updated : undefined }));
                  }}
                >
                  Remove
                </button>
              </div>
            ))}
            <button
              type="button"
              className="btn-secondary-sm"
              onClick={() => {
                const type = prompt("Control type (e.g. WAF, SIEM, HSM, MFA):");
                if (!type?.trim()) return;
                const name = prompt(`${type} implementation name (e.g. AWS WAF, Splunk):`);
                if (!name?.trim()) return;
                const newControl: SecurityControl = { control_type: type.trim(), name: name.trim(), covers: [] };
                setProperties((prev) => ({
                  ...prev,
                  security_controls: [...(prev.security_controls ?? []), newControl],
                }));
              }}
            >
              + Add Control
            </button>
          </div>
        </section>

        <section className="node-properties-section">
          <h4>Dropdown Aliases</h4>
          <p className="dfd-dialog-copy">
            Save reusable dropdown entries for this threat model. You can map to a built-in value or define a fully custom stored value.
          </p>
          <div className="dfd-component-template-section">
            <div className="dfd-component-template-grid">
              <div className="form-field">
                <label htmlFor="property-option-field">Field</label>
                <select
                  id="property-option-field"
                  value={propertyOptionDraft.field}
                  onChange={(event) =>
                    setPropertyOptionDraft((current) => ({
                      ...current,
                      field: event.target.value as DFDPropertyOptionField,
                    }))
                  }
                >
                  {PROPERTY_OPTION_FIELDS.map((option) => (
                    <option key={option.field} value={option.field}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="form-field">
                <label htmlFor="property-option-label">Alias Label</label>
                <input
                  id="property-option-label"
                  type="text"
                  value={propertyOptionDraft.label}
                  onChange={(event) =>
                    setPropertyOptionDraft((current) => ({
                      ...current,
                      label: event.target.value,
                    }))
                  }
                  placeholder="OIDC / Cognito"
                />
              </div>
              <CustomSelectField
                id="property-option-canonical"
                label="Stored Value"
                value={propertyOptionDraft.canonical_value}
                options={getBasePropertyOptions(propertyOptionDraft.field)}
                onChange={(value) =>
                  setPropertyOptionDraft((current) => ({
                    ...current,
                    canonical_value: value ?? "",
                  }))
                }
                allowEmpty={false}
                customPlaceholder="Enter the raw value to persist for this dropdown"
              />
              <div className="form-field dfd-component-template-grid-full">
                <label htmlFor="property-option-description">Description</label>
                <textarea
                  id="property-option-description"
                  value={propertyOptionDraft.description}
                  onChange={(event) =>
                    setPropertyOptionDraft((current) => ({
                      ...current,
                      description: event.target.value,
                    }))
                  }
                  rows={2}
                  placeholder="Optional note explaining where this label is used."
                />
              </div>
              <div className="dfd-component-template-actions dfd-component-template-grid-full">
                <button
                  type="button"
                  className="btn-create"
                  onClick={() => {
                    void handleCreatePropertyOption();
                  }}
                  disabled={savingPropertyOption || !propertyOptionDraft.label.trim()}
                >
                  {savingPropertyOption ? "Saving..." : "Save Alias"}
                </button>
              </div>
            </div>

            <div className="dfd-component-template-section">
              <div className="dfd-component-template-section-header">
                <strong>AI Draft</strong>
                {propertyOptionSuggestion?.degraded_reason && (
                  <span className="dfd-component-template-hint">
                    {propertyOptionSuggestion.degraded_reason}
                  </span>
                )}
              </div>
              <div className="form-field">
                <label htmlFor="property-option-prompt">
                  Describe the alias for {getPropertyFieldLabel(propertyOptionDraft.field)}
                </label>
                <textarea
                  id="property-option-prompt"
                  value={propertyOptionPrompt}
                  onChange={(event) => setPropertyOptionPrompt(event.target.value)}
                  rows={2}
                  placeholder="Suggest a dropdown alias for OIDC through Cognito."
                />
              </div>
              <div className="dfd-component-template-actions">
                <button
                  type="button"
                  className="btn-create"
                  onClick={() => {
                    void handleSuggestPropertyOption();
                  }}
                  disabled={suggestingPropertyOption || !propertyOptionPrompt.trim()}
                >
                  {suggestingPropertyOption ? "Thinking..." : "Suggest Alias"}
                </button>
              </div>
              {propertyOptionSuggestion && (
                <div className="dfd-component-template-preview">
                  <div className="dfd-component-template-preview-header">
                    <strong>{propertyOptionSuggestion.option.label}</strong>
                    <span>
                      {getPropertyFieldLabel(propertyOptionSuggestion.option.field)} ·{" "}
                      {getBuiltinPropertyOptionLabel(
                        propertyOptionSuggestion.option.field,
                        propertyOptionSuggestion.option.canonical_value
                      )}
                    </span>
                  </div>
                  {propertyOptionSuggestion.option.description && (
                    <p className="dfd-component-template-preview-copy">
                      {propertyOptionSuggestion.option.description}
                    </p>
                  )}
                  {propertyOptionSuggestion.option.rationale && (
                    <p className="dfd-component-template-preview-rationale">
                      {propertyOptionSuggestion.option.rationale}
                    </p>
                  )}
                </div>
              )}
            </div>

            <div className="dfd-property-options-list">
              {customPropertyOptionsForDraftField.length === 0 ? (
                <div className="dfd-property-options-empty">
                  No custom aliases yet for {getPropertyFieldLabel(propertyOptionDraft.field)}.
                </div>
              ) : (
                customPropertyOptionsForDraftField.map((option) => (
                  <div key={option.id} className="dfd-property-option-row">
                    <div className="dfd-property-option-copy">
                      <strong>{option.label}</strong>
                      <span>
                        Stores {getBuiltinPropertyOptionLabel(option.field, option.canonical_value)}
                      </span>
                    </div>
                    <button
                      type="button"
                      className="btn-triage btn-triage-cancel"
                      onClick={() => {
                        void handleDeletePropertyOption(option.id);
                      }}
                      disabled={deletingPropertyOptionId === option.id}
                    >
                      {deletingPropertyOptionId === option.id ? "Deleting..." : "Delete"}
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </section>

        <section className="node-properties-section">
          <h4>Additional Signals</h4>
          <p className="dfd-dialog-copy">
            These flags preserve compatibility with the current rules engine while the richer metadata model rolls in.
          </p>
          <div className="dfd-node-editor-checkbox-grid">
            {extraCheckboxes.map(([key, label]) => (
              <div key={key} className="prop-checkbox-row">
                <input
                  type="checkbox"
                  id={`prop-${String(key)}`}
                  checked={!!properties[key]}
                  onChange={() => toggleProp(key)}
                />
                <label htmlFor={`prop-${String(key)}`}>{label}</label>
              </div>
            ))}
          </div>
        </section>

        {error && <p className="form-error">{error}</p>}

        <div className="dfd-dialog-actions">
          <button className="btn-triage btn-triage-cancel" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button className="btn-create" onClick={handleSave} disabled={saving || !name.trim()}>
            {saving ? "Saving..." : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

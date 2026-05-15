import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../../api/client";
import type {
  ComponentShape,
  DFDComponentTemplateDraft,
  DFDComponentTemplateResponse,
  DFDComponentTemplateSuggestResponse,
  DFDNodeResponse,
  NodeType,
} from "../../types/api";
import {
  buildNodePropertiesFromTemplate,
  DEFAULT_TEMPLATE_ID_BY_NODE_TYPE,
  formatTemplateOptionLabel,
  getTemplateSemanticTypeLabel,
} from "./componentTemplateUtils";
import { CustomSelectField } from "./CustomSelectField";

interface AddNodeDialogProps {
  threatModelId: string;
  viewId?: string | null;
  initialShowCustomForm?: boolean;
  onNodeAdded: (node: DFDNodeResponse) => void;
  onTemplatesChanged?: () => void;
  onClose: () => void;
}

type TemplateDraftForm = {
  label: string;
  semantic_node_type: NodeType;
  semantic_type_label: string;
  shape: ComponentShape;
  description: string;
  group: string;
  default_name: string;
  default_properties: DFDComponentTemplateDraft["default_properties"];
  ai_generated: boolean;
  rationale: string;
};

const SHAPE_OPTIONS: { value: ComponentShape; label: string }[] = [
  { value: "rounded_rect", label: "Rounded Rectangle" },
  { value: "square", label: "Square" },
  { value: "pill", label: "Pill" },
  { value: "cylinder", label: "Cylinder" },
  { value: "hexagon", label: "Hexagon" },
  { value: "cloud", label: "Cloud" },
  { value: "stacked", label: "Stacked" },
  { value: "diamond", label: "Diamond" },
  { value: "gateway", label: "Gateway" },
  { value: "queue", label: "Queue" },
];

const NODE_TYPE_OPTIONS: { value: NodeType; label: string }[] = [
  { value: "process", label: "Process" },
  { value: "data_store", label: "Data Store" },
  { value: "external_entity", label: "External Entity" },
  { value: "human_actor", label: "Human Actor" },
  { value: "iam_role", label: "IAM Role" },
  { value: "managed_service", label: "Managed Service" },
  { value: "api_gateway", label: "API Gateway" },
  { value: "container", label: "Container" },
  { value: "serverless", label: "Serverless" },
];

const DEFAULT_TEMPLATE_DRAFT: TemplateDraftForm = {
  label: "",
  semantic_node_type: "process",
  semantic_type_label: "",
  shape: "rounded_rect",
  description: "",
  group: "Custom",
  default_name: "",
  default_properties: {},
  ai_generated: false,
  rationale: "",
};
export function AddNodeDialog({
  threatModelId,
  viewId = null,
  initialShowCustomForm = false,
  onNodeAdded,
  onTemplatesChanged,
  onClose,
}: AddNodeDialogProps): JSX.Element {
  const [templates, setTemplates] = useState<DFDComponentTemplateResponse[]>([]);
  const [templatesLoading, setTemplatesLoading] = useState(true);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>("builtin-process");
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [showCustomForm, setShowCustomForm] = useState(initialShowCustomForm);
  const [customDraft, setCustomDraft] = useState<TemplateDraftForm>(DEFAULT_TEMPLATE_DRAFT);
  const [semanticTypeCustomMode, setSemanticTypeCustomMode] = useState(false);
  const [savingTemplate, setSavingTemplate] = useState(false);
  const [deletingTemplateId, setDeletingTemplateId] = useState<string | null>(null);

  const [aiPrompt, setAiPrompt] = useState("");
  const [suggesting, setSuggesting] = useState(false);
  const [suggestion, setSuggestion] = useState<DFDComponentTemplateSuggestResponse | null>(null);

  const loadTemplates = useCallback(async () => {
    setTemplatesLoading(true);
    try {
      const nextTemplates = await api.getDFDComponentTemplates(threatModelId);
      setTemplates(nextTemplates);
      setSelectedTemplateId((current) => {
        if (nextTemplates.some((template) => template.id === current)) {
          return current;
        }
        return DEFAULT_TEMPLATE_ID_BY_NODE_TYPE.process;
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to load component templates.";
      setError(msg);
    } finally {
      setTemplatesLoading(false);
    }
  }, [threatModelId]);

  useEffect(() => {
    void loadTemplates();
  }, [loadTemplates]);

  const selectedTemplate = useMemo(
    () => templates.find((template) => template.id === selectedTemplateId) ?? null,
    [templates, selectedTemplateId]
  );

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

  const customTemplates = useMemo(
    () => templates.filter((template) => !template.built_in),
    [templates]
  );

  const applySuggestedTemplate = useCallback((draft: DFDComponentTemplateDraft) => {
    setCustomDraft({
      label: draft.label,
      semantic_node_type: draft.semantic_node_type,
      semantic_type_label: draft.semantic_type_label ?? "",
      shape: draft.shape,
      description: draft.description ?? "",
      group: draft.group ?? "Custom",
      default_name: draft.default_name ?? draft.label,
      default_properties: draft.default_properties ?? {},
      ai_generated: draft.ai_generated ?? false,
      rationale: draft.rationale ?? "",
    });
    setShowCustomForm(true);
  }, []);

  const handleAdd = useCallback(async () => {
    if (!selectedTemplate) {
      setError("Choose a component stencil first.");
      return;
    }

    const resolvedName = name.trim() || selectedTemplate.default_name?.trim() || selectedTemplate.label;
    if (!resolvedName) {
      setError("Name is required.");
      return;
    }

    setSaving(true);
    setError(null);

    try {
      const node = await api.createNode(
        threatModelId,
        {
          node_type: selectedTemplate.semantic_node_type,
          name: resolvedName,
          position_x: 100,
          position_y: 100,
          properties: buildNodePropertiesFromTemplate(selectedTemplate),
        },
        viewId
      );
      onNodeAdded(node);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to create node.";
      setError(msg);
    } finally {
      setSaving(false);
    }
  }, [name, onNodeAdded, selectedTemplate, threatModelId, viewId]);

  const handleCreateTemplate = useCallback(async () => {
    if (!customDraft.label.trim()) {
      setError("Stencil label is required.");
      return;
    }

    setSavingTemplate(true);
    setError(null);
    try {
      const created = await api.createDFDComponentTemplate(threatModelId, {
        label: customDraft.label.trim(),
        description: customDraft.description.trim() || undefined,
        semantic_node_type: customDraft.semantic_node_type,
        semantic_type_label: customDraft.semantic_type_label.trim() || undefined,
        shape: customDraft.shape,
        group: customDraft.group.trim() || "Custom",
        default_name: customDraft.default_name.trim() || customDraft.label.trim(),
        default_properties: customDraft.default_properties ?? {},
        ai_generated: customDraft.ai_generated,
        rationale: customDraft.rationale.trim() || undefined,
      });
      setTemplates((current) => [...current, created].sort((a, b) => a.label.localeCompare(b.label)));
      setSelectedTemplateId(created.id);
      setShowCustomForm(false);
      setCustomDraft(DEFAULT_TEMPLATE_DRAFT);
      setSemanticTypeCustomMode(false);
      setSuggestion(null);
      onTemplatesChanged?.();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to create component stencil.";
      setError(msg);
    } finally {
      setSavingTemplate(false);
    }
  }, [customDraft, onTemplatesChanged, threatModelId]);

  const handleSuggestTemplate = useCallback(async () => {
    const prompt = aiPrompt.trim();
    if (!prompt) {
      setError("Describe the component you want AI to draft.");
      return;
    }

    setSuggesting(true);
    setError(null);
    try {
      const response = await api.suggestDFDComponentTemplate(threatModelId, { prompt });
      setSuggestion(response);
      applySuggestedTemplate(response.template);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to generate AI suggestion.";
      setError(msg);
    } finally {
      setSuggesting(false);
    }
  }, [aiPrompt, applySuggestedTemplate, threatModelId]);

  const handleDeleteTemplate = useCallback(
    async (templateId: string) => {
      setDeletingTemplateId(templateId);
      setError(null);
      try {
        await api.deleteDFDComponentTemplate(threatModelId, templateId);
        setTemplates((current) => current.filter((template) => template.id !== templateId));
        setSelectedTemplateId((current) =>
          current === templateId ? DEFAULT_TEMPLATE_ID_BY_NODE_TYPE.process : current
        );
        onTemplatesChanged?.();
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Failed to delete component stencil.";
        setError(msg);
      } finally {
        setDeletingTemplateId(null);
      }
    },
    [onTemplatesChanged, threatModelId]
  );

  return (
    <div className="dfd-dialog-overlay" onClick={onClose}>
      <div className="dfd-dialog dfd-dialog-wide" onClick={(e) => e.stopPropagation()}>
        <h3 className="dfd-dialog-title">Add DFD Component</h3>

        <div className="dfd-dialog-copy">
          Choose a stencil, create a custom one, or have AI draft a reusable component for this threat model.
        </div>

        <div className="form-field">
          <label htmlFor="add-node-template">Component Stencil</label>
          <select
            id="add-node-template"
            value={selectedTemplateId}
            onChange={(event) => setSelectedTemplateId(event.target.value)}
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
        </div>

        {selectedTemplate && (
          <div className="dfd-component-template-preview">
            <div className="dfd-component-template-preview-header">
              <strong>{selectedTemplate.label}</strong>
              <span>{getTemplateSemanticTypeLabel(selectedTemplate)} · {selectedTemplate.shape}</span>
            </div>
            {selectedTemplate.description && (
              <p className="dfd-component-template-preview-copy">{selectedTemplate.description}</p>
            )}
          </div>
        )}

        <div className="form-field">
          <label htmlFor="add-node-name">Name</label>
          <input
            id="add-node-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={selectedTemplate?.default_name || "Enter node name"}
            autoFocus
          />
        </div>

        <div className="dfd-component-template-section">
          <div className="dfd-component-template-section-header">
            <strong>Custom Stencil</strong>
            <button
              type="button"
              className="btn-triage btn-triage-cancel"
              onClick={() => setShowCustomForm((current) => !current)}
            >
              {showCustomForm ? "Hide" : "Create Custom Stencil"}
            </button>
          </div>

          {showCustomForm && (
            <div className="dfd-component-template-grid">
              <div className="form-field">
                <label htmlFor="custom-stencil-label">Label</label>
                <input
                  id="custom-stencil-label"
                  type="text"
                  value={customDraft.label}
                  onChange={(event) =>
                    setCustomDraft((current) => ({ ...current, label: event.target.value }))
                  }
                  placeholder="Kafka Broker"
                />
              </div>
              <CustomSelectField
                id="custom-stencil-type"
                label="Semantic Type"
                value={customDraft.semantic_type_label.trim() || customDraft.semantic_node_type}
                options={NODE_TYPE_OPTIONS}
                onChange={(value) =>
                  setCustomDraft((current) => {
                    const nextValue = value?.trim() ?? "";
                    const builtinMatch = NODE_TYPE_OPTIONS.some((option) => option.value === nextValue);
                    return {
                      ...current,
                      semantic_node_type: builtinMatch
                        ? (nextValue as NodeType)
                        : current.semantic_node_type,
                      semantic_type_label: builtinMatch ? "" : nextValue,
                    };
                  })
                }
                onCustomModeChange={setSemanticTypeCustomMode}
                allowEmpty={false}
                customPlaceholder="Enter the custom semantic type label"
              />
              {semanticTypeCustomMode ? (
                <div className="form-field">
                  <label htmlFor="custom-stencil-base-type">Underlying Behavior</label>
                  <select
                    id="custom-stencil-base-type"
                    value={customDraft.semantic_node_type}
                    onChange={(event) =>
                      setCustomDraft((current) => ({
                        ...current,
                        semantic_node_type: event.target.value as NodeType,
                      }))
                    }
                  >
                    {NODE_TYPE_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                  <span className="dfd-component-template-hint">
                    The custom semantic type is a user-facing label. Node behavior still maps to a supported DFD type.
                  </span>
                </div>
              ) : null}
              <div className="form-field">
                <label htmlFor="custom-stencil-shape">Shape</label>
                <select
                  id="custom-stencil-shape"
                  value={customDraft.shape}
                  onChange={(event) =>
                    setCustomDraft((current) => ({
                      ...current,
                      shape: event.target.value as ComponentShape,
                    }))
                  }
                >
                  {SHAPE_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="form-field dfd-component-template-grid-full">
                <label htmlFor="custom-stencil-description">Description</label>
                <textarea
                  id="custom-stencil-description"
                  value={customDraft.description}
                  onChange={(event) =>
                    setCustomDraft((current) => ({
                      ...current,
                      description: event.target.value,
                    }))
                  }
                  rows={3}
                  placeholder="Reusable payment processor or stream broker stencil for this model."
                />
              </div>
              <div className="dfd-component-template-actions dfd-component-template-grid-full">
                <button
                  type="button"
                  className="btn-create"
                  onClick={() => {
                    void handleCreateTemplate();
                  }}
                  disabled={savingTemplate || !customDraft.label.trim()}
                >
                  {savingTemplate ? "Saving..." : "Save Stencil"}
                </button>
              </div>
            </div>
          )}

          <div className="dfd-property-options-list">
            {customTemplates.length === 0 ? (
              <div className="dfd-property-options-empty">
                No custom stencils yet for this threat model.
              </div>
            ) : (
              customTemplates.map((template) => (
                <div key={template.id} className="dfd-property-option-row">
                  <div className="dfd-property-option-copy">
                    <strong>{template.label}</strong>
                    <span>
                      {getTemplateSemanticTypeLabel(template)} · {template.shape}
                    </span>
                  </div>
                  <button
                    type="button"
                    className="btn-triage btn-triage-cancel"
                    onClick={() => {
                      void handleDeleteTemplate(template.id);
                    }}
                    disabled={deletingTemplateId === template.id}
                  >
                    {deletingTemplateId === template.id ? "Deleting..." : "Delete"}
                  </button>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="dfd-component-template-section">
          <div className="dfd-component-template-section-header">
            <strong>AI Draft</strong>
            {suggestion?.degraded_reason && (
              <span className="dfd-component-template-hint">{suggestion.degraded_reason}</span>
            )}
          </div>
          <div className="form-field">
            <label htmlFor="ai-stencil-prompt">Describe the component</label>
            <textarea
              id="ai-stencil-prompt"
              value={aiPrompt}
              onChange={(event) => setAiPrompt(event.target.value)}
              rows={3}
              placeholder="Suggest a stencil for a Kafka broker that handles internal payment events."
            />
          </div>
          <div className="dfd-component-template-actions">
            <button
              type="button"
              className="btn-create"
              onClick={() => {
                void handleSuggestTemplate();
              }}
              disabled={suggesting || !aiPrompt.trim()}
            >
              {suggesting ? "Thinking..." : "Suggest with AI"}
            </button>
          </div>
          {suggestion && (
            <div className="dfd-component-template-preview">
              <div className="dfd-component-template-preview-header">
                <strong>{suggestion.template.label}</strong>
                <span>
                  {getTemplateSemanticTypeLabel(suggestion.template)} · {suggestion.template.shape}
                </span>
              </div>
              {suggestion.template.description && (
                <p className="dfd-component-template-preview-copy">
                  {suggestion.template.description}
                </p>
              )}
              {suggestion.template.rationale && (
                <p className="dfd-component-template-preview-rationale">
                  {suggestion.template.rationale}
                </p>
              )}
            </div>
          )}
        </div>

        {error && <p className="form-error">{error}</p>}

        <div className="dfd-dialog-actions">
          <button
            className="btn-triage btn-triage-cancel"
            onClick={onClose}
            disabled={saving}
          >
            Cancel
          </button>
          <button
            className="btn-create"
            onClick={() => {
              void handleAdd();
            }}
            disabled={saving || templatesLoading || !selectedTemplate}
          >
            {saving ? "Adding..." : "Add"}
          </button>
        </div>
      </div>
    </div>
  );
}

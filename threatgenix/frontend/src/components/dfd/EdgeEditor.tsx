import { useCallback, useMemo, useState } from "react";

import { api } from "../../api/client";
import type { DFDEdgeResponse, EdgeProperties } from "../../types/api";
import { CustomSelectField } from "./CustomSelectField";

type EdgeEditorProps =
  | {
      mode: "edit";
      threatModelId: string;
      viewId?: string | null;
      edgeId: string;
      initialLabel: string;
      initialProperties: EdgeProperties;
      requireMetadata?: boolean;
      onSaved: (updated: DFDEdgeResponse) => void;
      onClose: () => void;
    }
  | {
      mode: "create";
      threatModelId: string;
      viewId?: string | null;
      sourceNodeId: string;
      targetNodeId: string;
      initialLabel?: string;
      initialProperties?: EdgeProperties;
      requireMetadata?: boolean;
      onSaved: (updated: DFDEdgeResponse) => void;
      onClose: () => void;
    };

const DATA_CLASSIFICATION_OPTIONS = [
  { value: "", label: "-- Not set --" },
  { value: "Public", label: "Public" },
  { value: "Internal", label: "Internal" },
  { value: "Confidential", label: "Confidential" },
  { value: "Restricted", label: "Restricted" },
] as const;

const LIFECYCLE_STAGE_OPTIONS = [
  { value: "", label: "-- Not set --" },
  { value: "ingress", label: "Ingress" },
  { value: "processing", label: "Processing" },
  { value: "storage", label: "Storage" },
  { value: "egress", label: "Egress" },
  { value: "replication", label: "Replication" },
  { value: "backup", label: "Backup" },
  { value: "analytics", label: "Analytics" },
  { value: "notification", label: "Notification" },
] as const;

const DIRECTIONALITY_OPTIONS = [
  { value: "", label: "-- Not set --" },
  { value: "request", label: "Request" },
  { value: "response", label: "Response" },
  { value: "event", label: "Event" },
  { value: "bidirectional", label: "Bidirectional" },
] as const;

const TRANSFER_MODE_OPTIONS = [
  { value: "", label: "-- Not set --" },
  { value: "synchronous", label: "Synchronous" },
  { value: "asynchronous", label: "Asynchronous" },
  { value: "batch", label: "Batch" },
  { value: "streaming", label: "Streaming" },
  { value: "near_real_time", label: "Near Real-Time" },
] as const;

const TLS_VERSION_OPTIONS = [
  { value: "", label: "Not specified" },
  { value: "none", label: "None (cleartext)" },
  { value: "tls_1_0", label: "TLS 1.0 (deprecated)" },
  { value: "tls_1_1", label: "TLS 1.1 (deprecated)" },
  { value: "tls_1_2", label: "TLS 1.2" },
  { value: "tls_1_3", label: "TLS 1.3 (recommended)" },
  { value: "other", label: "Other" },
] as const;

function normalizeProperties(initialProperties?: EdgeProperties): EdgeProperties {
  return {
    ...initialProperties,
    data_types: initialProperties?.data_types ?? [],
  };
}

function buildRequestProperties(properties: EdgeProperties): EdgeProperties {
  return {
    protocol: properties.protocol?.trim() || undefined,
    data_payload: properties.data_payload?.trim() || undefined,
    data_classification: properties.data_classification || undefined,
    lifecycle_stage: properties.lifecycle_stage || undefined,
    auth_mechanism: properties.auth_mechanism?.trim() || undefined,
    encryption_in_transit:
      typeof properties.encryption_in_transit === "boolean"
        ? properties.encryption_in_transit
        : undefined,
    directionality: properties.directionality || undefined,
    transfer_mode: properties.transfer_mode || undefined,
    sequence_note: properties.sequence_note?.trim() || undefined,
    carries_credentials:
      typeof properties.carries_credentials === "boolean"
        ? properties.carries_credentials
        : undefined,
    carries_pii:
      typeof properties.carries_pii === "boolean"
        ? properties.carries_pii
        : undefined,
    carries_secrets:
      typeof properties.carries_secrets === "boolean"
        ? properties.carries_secrets
        : undefined,
    rate_limited:
      typeof properties.rate_limited === "boolean"
        ? properties.rate_limited
        : undefined,
    integrity_protected:
      typeof properties.integrity_protected === "boolean"
        ? properties.integrity_protected
        : undefined,
    data_types: properties.data_types?.filter(Boolean) ?? [],
    tls_version: properties.tls_version || undefined,
    is_response:
      typeof properties.is_response === "boolean"
        ? properties.is_response
        : undefined,
    response_to_id: properties.response_to_id ?? undefined,
    data_objects:
      properties.data_objects && properties.data_objects.length > 0
        ? properties.data_objects
        : undefined,
    carries_financial_data:
      typeof properties.carries_financial_data === "boolean"
        ? properties.carries_financial_data
        : undefined,
  };
}

export function EdgeEditor(props: EdgeEditorProps): JSX.Element {
  const initialLabel = props.mode === "edit" ? props.initialLabel : props.initialLabel ?? "";
  const initialProperties =
    props.mode === "edit" ? props.initialProperties : props.initialProperties ?? {};
  const [label, setLabel] = useState(initialLabel);
  const [properties, setProperties] = useState<EdgeProperties>(normalizeProperties(initialProperties));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const updateProperty = useCallback(
    (key: keyof EdgeProperties, value: EdgeProperties[keyof EdgeProperties]) => {
      setProperties((current) => ({
        ...current,
        [key]: value,
      }));
    },
    []
  );

  const handleSave = useCallback(async () => {
    if (props.requireMetadata) {
      if (!label.trim()) {
        setError("A flow name is required.");
        return;
      }
      if (!properties.protocol?.trim()) {
        setError("A protocol is required for new flows.");
        return;
      }
    }

    setSaving(true);
    setError(null);
    try {
      const requestProperties = buildRequestProperties(properties);
      const updated =
        props.mode === "edit"
          ? await api.updateEdge(props.threatModelId, props.edgeId, {
              label: label.trim(),
              properties: requestProperties,
            }, props.viewId)
          : await api.createEdge(props.threatModelId, {
              source_node_id: props.sourceNodeId,
              target_node_id: props.targetNodeId,
              label: label.trim(),
              properties: requestProperties,
            }, props.viewId);
      props.onSaved(updated);
    } catch (caughtError) {
      const message =
        caughtError instanceof Error
          ? caughtError.message
          : props.mode === "edit"
            ? "Failed to update flow."
            : "Failed to create flow.";
      setError(message);
    } finally {
      setSaving(false);
    }
  }, [label, properties, props]);

  const semanticPreview = useMemo(() => {
    const headline = label.trim() || properties.data_payload?.trim() || "Data Flow";
    const details = [properties.protocol?.trim(), properties.data_classification].filter(Boolean);
    return details.length > 0 ? `${headline} · ${details.join(" · ")}` : headline;
  }, [label, properties.data_payload, properties.protocol, properties.data_classification]);

  const title = props.mode === "edit" ? "Edit Flow" : "Create Flow";
  const copy =
    props.mode === "edit"
      ? "Capture what moves across this edge and how it is transported so the DFD stays threat-model-ready."
      : "Name the new flow and declare its protocol before it is added to the DFD.";
  const saveLabel =
    props.mode === "edit" ? (saving ? "Saving..." : "Save") : saving ? "Creating..." : "Create Flow";

  return (
    <div className="dfd-dialog-overlay" onClick={props.onClose}>
      <div className="dfd-dialog dfd-edge-dialog" onClick={(event) => event.stopPropagation()}>
        <h3 className="dfd-dialog-title">{title}</h3>
        <p className="dfd-edge-dialog-copy">{copy}</p>

        <div className="form-field">
          <label htmlFor="edit-edge-label">Flow Name</label>
          <input
            id="edit-edge-label"
            type="text"
            value={label}
            onChange={(event) => setLabel(event.target.value)}
            autoFocus
            placeholder="e.g. Customer profile lookup"
          />
        </div>

        <div className="dfd-edge-fields-grid">
          <div className="form-field">
            <label htmlFor="edit-edge-protocol">Protocol</label>
            <input
              id="edit-edge-protocol"
              type="text"
              value={properties.protocol ?? ""}
              onChange={(event) => updateProperty("protocol", event.target.value || undefined)}
              placeholder="e.g. HTTPS, SQL, Kafka"
            />
          </div>

          <CustomSelectField
            id="edit-edge-classification"
            label="Data Classification"
            value={properties.data_classification}
            options={DATA_CLASSIFICATION_OPTIONS.filter((option) => option.value)}
            onChange={(value) => updateProperty("data_classification", value)}
            customPlaceholder="Enter a custom data classification"
          />

          <CustomSelectField
            id="edit-edge-lifecycle-stage"
            label="Lifecycle Stage"
            value={properties.lifecycle_stage}
            options={LIFECYCLE_STAGE_OPTIONS.filter((option) => option.value)}
            onChange={(value) => updateProperty("lifecycle_stage", value)}
            customPlaceholder="Enter a custom lifecycle stage"
          />

          <div className="form-field">
            <label htmlFor="edit-edge-payload">Data Payload</label>
            <input
              id="edit-edge-payload"
              type="text"
              value={properties.data_payload ?? ""}
              onChange={(event) => updateProperty("data_payload", event.target.value || undefined)}
              placeholder="e.g. JWT claims, payment details"
            />
          </div>

          <div className="form-field">
            <label htmlFor="edit-edge-auth">Auth Mechanism</label>
            <input
              id="edit-edge-auth"
              type="text"
              value={properties.auth_mechanism ?? ""}
              onChange={(event) => updateProperty("auth_mechanism", event.target.value || undefined)}
              placeholder="e.g. mTLS, OAuth2, API key"
            />
          </div>

          <CustomSelectField
            id="edit-edge-directionality"
            label="Directionality"
            value={properties.directionality}
            options={DIRECTIONALITY_OPTIONS.filter((option) => option.value)}
            onChange={(value) => updateProperty("directionality", value)}
            customPlaceholder="Enter a custom flow directionality"
          />

          <CustomSelectField
            id="edit-edge-transfer-mode"
            label="Transfer Mode"
            value={properties.transfer_mode}
            options={TRANSFER_MODE_OPTIONS.filter((option) => option.value)}
            onChange={(value) => updateProperty("transfer_mode", value)}
            customPlaceholder="Enter a custom transfer mode"
          />

          <div className="form-field">
            <label htmlFor="edit-edge-sequence-note">Sequence / Order</label>
            <input
              id="edit-edge-sequence-note"
              type="text"
              value={properties.sequence_note ?? ""}
              onChange={(event) => updateProperty("sequence_note", event.target.value || undefined)}
              placeholder="e.g. Step 1 of 3, callback after settlement"
            />
          </div>

          <div className="dfd-edge-checkbox-row">
            <input
              id="edit-edge-encryption"
              type="checkbox"
              checked={!!properties.encryption_in_transit}
              onChange={(event) => updateProperty("encryption_in_transit", event.target.checked)}
            />
            <label htmlFor="edit-edge-encryption">Encrypted in transit</label>
          </div>

          <div className="dfd-custom-select-stack">
            <CustomSelectField
              id="edit-edge-tls-version"
              label="TLS Version"
              value={properties.tls_version}
              options={TLS_VERSION_OPTIONS.filter((option) => option.value)}
              onChange={(value) => updateProperty("tls_version", value)}
              emptyOptionLabel="Not specified"
              customPlaceholder="Enter a custom TLS or transport version"
            />
            {(properties.tls_version === "tls_1_0" || properties.tls_version === "tls_1_1") && (
              <p className="form-field-warning">
                Deprecated — PCI DSS 4.0 prohibits TLS 1.0/1.1 in CDE
              </p>
            )}
          </div>

          <div className="dfd-edge-checkbox-row">
            <input
              id="edit-edge-integrity"
              type="checkbox"
              checked={!!properties.integrity_protected}
              onChange={(event) => updateProperty("integrity_protected", event.target.checked)}
            />
            <label htmlFor="edit-edge-integrity">Integrity protected</label>
          </div>

          <div className="dfd-edge-checkbox-row">
            <input
              id="edit-edge-rate-limited"
              type="checkbox"
              checked={!!properties.rate_limited}
              onChange={(event) => updateProperty("rate_limited", event.target.checked)}
            />
            <label htmlFor="edit-edge-rate-limited">Rate limited</label>
          </div>

          <div className="dfd-edge-checkbox-row">
            <input
              id="edit-edge-carries-credentials"
              type="checkbox"
              checked={!!properties.carries_credentials}
              onChange={(event) => updateProperty("carries_credentials", event.target.checked)}
            />
            <label htmlFor="edit-edge-carries-credentials">Carries credentials</label>
          </div>

          <div className="dfd-edge-checkbox-row">
            <input
              id="edit-edge-carries-pii"
              type="checkbox"
              checked={!!properties.carries_pii}
              onChange={(event) => updateProperty("carries_pii", event.target.checked)}
            />
            <label htmlFor="edit-edge-carries-pii">Carries PII</label>
          </div>

          <div className="dfd-edge-checkbox-row">
            <input
              id="edit-edge-carries-financial"
              type="checkbox"
              checked={!!properties.carries_financial_data}
              onChange={(event) => updateProperty("carries_financial_data", event.target.checked)}
            />
            <label htmlFor="edit-edge-carries-financial">Carries financial data</label>
          </div>

          <div className="dfd-edge-checkbox-row">
            <input
              id="edit-edge-carries-secrets"
              type="checkbox"
              checked={!!properties.carries_secrets}
              onChange={(event) => updateProperty("carries_secrets", event.target.checked)}
            />
            <label htmlFor="edit-edge-carries-secrets">Carries secrets</label>
          </div>

          <div className="dfd-edge-checkbox-row">
            <input
              id="edit-edge-is-response"
              type="checkbox"
              checked={!!properties.is_response}
              onChange={(event) => updateProperty("is_response", event.target.checked)}
            />
            <label htmlFor="edit-edge-is-response">This is a response flow</label>
          </div>
        </div>

        <div className="dfd-edge-preview">
          <span className="dfd-edge-preview-label">Canvas label preview</span>
          <strong>{semanticPreview}</strong>
        </div>

        {error && <p className="form-error">{error}</p>}

        <div className="dfd-dialog-actions">
          <button
            className="btn-triage btn-triage-cancel"
            onClick={props.onClose}
            disabled={saving}
          >
            Cancel
          </button>
          <button className="btn-create" onClick={() => void handleSave()} disabled={saving}>
            {saveLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

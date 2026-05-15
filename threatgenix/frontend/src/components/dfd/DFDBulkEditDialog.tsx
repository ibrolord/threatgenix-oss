import { useMemo, useState } from "react";

import type { EdgeProperties, NodeProperties } from "../../types/api";
import { CustomSelectField, type CustomSelectOption } from "./CustomSelectField";

interface BulkEditNodeTarget {
  id: string;
  label: string;
}

interface BulkEditEdgeTarget {
  id: string;
  label: string;
}

interface DFDBulkEditDialogProps {
  nodeTargets: BulkEditNodeTarget[];
  edgeTargets: BulkEditEdgeTarget[];
  onApply: (changes: {
    nodeProperties?: Partial<NodeProperties>;
    edgeProperties?: Partial<EdgeProperties>;
  }) => Promise<void>;
  onClose: () => void;
}

const UNCHANGED = "__UNCHANGED__";
const BOOLEAN_OPTIONS = [
  { value: UNCHANGED, label: "Leave unchanged" },
  { value: "true", label: "Yes" },
  { value: "false", label: "No" },
] as const;

const DATA_CLASSIFICATION_OPTIONS: CustomSelectOption[] = [
  { value: UNCHANGED, label: "Leave unchanged" },
  { value: "Public", label: "Public" },
  { value: "Internal", label: "Internal" },
  { value: "Confidential", label: "Confidential" },
  { value: "Restricted", label: "Restricted" },
];

const AUTHENTICATION_OPTIONS: CustomSelectOption[] = [
  { value: UNCHANGED, label: "Leave unchanged" },
  { value: "none", label: "None" },
  { value: "api_key", label: "API Key" },
  { value: "oauth2", label: "OAuth 2" },
  { value: "mtls", label: "mTLS" },
  { value: "saml", label: "SAML" },
  { value: "jwt", label: "JWT" },
];

const NETWORK_EXPOSURE_OPTIONS: CustomSelectOption[] = [
  { value: UNCHANGED, label: "Leave unchanged" },
  { value: "internet", label: "Internet" },
  { value: "dmz", label: "DMZ" },
  { value: "internal", label: "Internal" },
  { value: "vpc_private", label: "VPC Private" },
];

const PRIVILEGE_OPTIONS: CustomSelectOption[] = [
  { value: UNCHANGED, label: "Leave unchanged" },
  { value: "standard", label: "Standard" },
  { value: "elevated", label: "Elevated" },
  { value: "privileged", label: "Privileged" },
  { value: "admin", label: "Admin" },
  { value: "system", label: "System" },
];

const INPUT_VALIDATION_OPTIONS: CustomSelectOption[] = [
  { value: UNCHANGED, label: "Leave unchanged" },
  { value: "none", label: "None" },
  { value: "partial", label: "Partial" },
  { value: "strict", label: "Strict" },
];

const LOGGING_OPTIONS: CustomSelectOption[] = [
  { value: UNCHANGED, label: "Leave unchanged" },
  { value: "none", label: "None" },
  { value: "errors_only", label: "Errors Only" },
  { value: "audit", label: "Audit" },
  { value: "full", label: "Full" },
];

const TRANSFER_MODE_OPTIONS: CustomSelectOption[] = [
  { value: UNCHANGED, label: "Leave unchanged" },
  { value: "synchronous", label: "Synchronous" },
  { value: "asynchronous", label: "Asynchronous" },
  { value: "batch", label: "Batch" },
  { value: "streaming", label: "Streaming" },
  { value: "near_real_time", label: "Near Real-Time" },
];

function parseTriState(value: string): boolean | undefined {
  if (value === UNCHANGED) return undefined;
  return value === "true";
}

export function DFDBulkEditDialog({
  nodeTargets,
  edgeTargets,
  onApply,
  onClose,
}: DFDBulkEditDialogProps): JSX.Element {
  const [nodeClassification, setNodeClassification] = useState(UNCHANGED);
  const [nodeAuthType, setNodeAuthType] = useState(UNCHANGED);
  const [nodeExposure, setNodeExposure] = useState(UNCHANGED);
  const [nodePrivilege, setNodePrivilege] = useState(UNCHANGED);
  const [nodeInputValidation, setNodeInputValidation] = useState(UNCHANGED);
  const [nodeLoggingLevel, setNodeLoggingLevel] = useState(UNCHANGED);
  const [edgeProtocol, setEdgeProtocol] = useState("");
  const [edgeClassification, setEdgeClassification] = useState(UNCHANGED);
  const [edgeAuthMechanism, setEdgeAuthMechanism] = useState("");
  const [edgeTransferMode, setEdgeTransferMode] = useState(UNCHANGED);
  const [edgeEncrypted, setEdgeEncrypted] = useState<string>(UNCHANGED);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const nodeSummary = useMemo(
    () => nodeTargets.slice(0, 3).map((item) => item.label).join(", "),
    [nodeTargets]
  );
  const edgeSummary = useMemo(
    () => edgeTargets.slice(0, 3).map((item) => item.label).join(", "),
    [edgeTargets]
  );

  const handleApply = async () => {
    const nodeProperties: Partial<NodeProperties> = {};
    const edgeProperties: Partial<EdgeProperties> = {};

    if (nodeClassification !== UNCHANGED && nodeClassification.trim()) {
      nodeProperties.data_classification = nodeClassification as NodeProperties["data_classification"];
    }
    if (nodeAuthType !== UNCHANGED && nodeAuthType.trim()) {
      nodeProperties.authentication_type = nodeAuthType as NodeProperties["authentication_type"];
    }
    if (nodeExposure !== UNCHANGED && nodeExposure.trim()) {
      nodeProperties.network_exposure = nodeExposure as NodeProperties["network_exposure"];
    }
    if (nodePrivilege !== UNCHANGED && nodePrivilege.trim()) {
      nodeProperties.privilege_level = nodePrivilege as NodeProperties["privilege_level"];
    }
    if (nodeInputValidation !== UNCHANGED && nodeInputValidation.trim()) {
      nodeProperties.input_validation = nodeInputValidation as NodeProperties["input_validation"];
    }
    if (nodeLoggingLevel !== UNCHANGED && nodeLoggingLevel.trim()) {
      nodeProperties.logging_level = nodeLoggingLevel as NodeProperties["logging_level"];
    }

    if (edgeProtocol.trim()) {
      edgeProperties.protocol = edgeProtocol.trim();
    }
    if (edgeClassification !== UNCHANGED && edgeClassification.trim()) {
      edgeProperties.data_classification =
        edgeClassification as EdgeProperties["data_classification"];
    }
    if (edgeAuthMechanism.trim()) {
      edgeProperties.auth_mechanism = edgeAuthMechanism.trim();
    }
    if (edgeTransferMode !== UNCHANGED && edgeTransferMode.trim()) {
      edgeProperties.transfer_mode = edgeTransferMode as EdgeProperties["transfer_mode"];
    }
    const parsedEncrypted = parseTriState(edgeEncrypted);
    if (parsedEncrypted !== undefined) {
      edgeProperties.encryption_in_transit = parsedEncrypted;
    }

    if (
      nodeTargets.length > 0 &&
      Object.keys(nodeProperties).length === 0 &&
      edgeTargets.length === 0
    ) {
      setError("Choose at least one node property to apply.");
      return;
    }
    if (
      edgeTargets.length > 0 &&
      Object.keys(edgeProperties).length === 0 &&
      nodeTargets.length === 0
    ) {
      setError("Choose at least one flow property to apply.");
      return;
    }
    if (
      Object.keys(nodeProperties).length === 0 &&
      Object.keys(edgeProperties).length === 0
    ) {
      setError("Choose at least one change to apply.");
      return;
    }

    setSaving(true);
    setError(null);
    try {
      await onApply({
        nodeProperties: Object.keys(nodeProperties).length > 0 ? nodeProperties : undefined,
        edgeProperties: Object.keys(edgeProperties).length > 0 ? edgeProperties : undefined,
      });
      onClose();
    } catch (caughtError) {
      const message =
        caughtError instanceof Error ? caughtError.message : "Bulk update failed.";
      setError(message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="dfd-dialog-overlay" onClick={onClose}>
      <div className="dfd-dialog dfd-dialog-wide" onClick={(event) => event.stopPropagation()}>
        <h3 className="dfd-dialog-title">Bulk Edit DFD Metadata</h3>
        <p className="dfd-dialog-copy">
          Apply the same security metadata to the selected nodes and flows in one pass.
        </p>

        {nodeTargets.length > 0 && (
          <section className="bulk-edit-section">
            <h4>Nodes ({nodeTargets.length})</h4>
            <p className="bulk-edit-targets">
              {nodeSummary}
              {nodeTargets.length > 3 ? ` + ${nodeTargets.length - 3} more` : ""}
            </p>
            <div className="dfd-node-editor-grid">
              <CustomSelectField
                id="bulk-node-classification"
                label="Data Classification"
                value={nodeClassification}
                options={DATA_CLASSIFICATION_OPTIONS}
                onChange={(value) => setNodeClassification(value ?? "")}
                allowEmpty={false}
                customPlaceholder="Enter a custom data classification"
              />
              <CustomSelectField
                id="bulk-node-auth"
                label="Authentication Type"
                value={nodeAuthType}
                options={AUTHENTICATION_OPTIONS}
                onChange={(value) => setNodeAuthType(value ?? "")}
                allowEmpty={false}
                customPlaceholder="Enter a custom authentication type"
              />
              <CustomSelectField
                id="bulk-node-exposure"
                label="Network Exposure"
                value={nodeExposure}
                options={NETWORK_EXPOSURE_OPTIONS}
                onChange={(value) => setNodeExposure(value ?? "")}
                allowEmpty={false}
                customPlaceholder="Enter a custom network exposure"
              />
              <CustomSelectField
                id="bulk-node-privilege"
                label="Privilege Level"
                value={nodePrivilege}
                options={PRIVILEGE_OPTIONS}
                onChange={(value) => setNodePrivilege(value ?? "")}
                allowEmpty={false}
                customPlaceholder="Enter a custom privilege level"
              />
              <CustomSelectField
                id="bulk-node-validation"
                label="Input Validation"
                value={nodeInputValidation}
                options={INPUT_VALIDATION_OPTIONS}
                onChange={(value) => setNodeInputValidation(value ?? "")}
                allowEmpty={false}
                customPlaceholder="Enter a custom validation level"
              />
              <CustomSelectField
                id="bulk-node-logging"
                label="Logging Level"
                value={nodeLoggingLevel}
                options={LOGGING_OPTIONS}
                onChange={(value) => setNodeLoggingLevel(value ?? "")}
                allowEmpty={false}
                customPlaceholder="Enter a custom logging level"
              />
            </div>
          </section>
        )}

        {edgeTargets.length > 0 && (
          <section className="bulk-edit-section">
            <h4>Flows ({edgeTargets.length})</h4>
            <p className="bulk-edit-targets">
              {edgeSummary}
              {edgeTargets.length > 3 ? ` + ${edgeTargets.length - 3} more` : ""}
            </p>
            <div className="dfd-node-editor-grid">
              <div className="form-field">
                <label htmlFor="bulk-edge-protocol">Protocol</label>
                <input
                  id="bulk-edge-protocol"
                  type="text"
                  value={edgeProtocol}
                  onChange={(event) => setEdgeProtocol(event.target.value)}
                  placeholder="e.g. HTTPS, gRPC, Kafka"
                />
              </div>
              <CustomSelectField
                id="bulk-edge-classification"
                label="Data Classification"
                value={edgeClassification}
                options={DATA_CLASSIFICATION_OPTIONS}
                onChange={(value) => setEdgeClassification(value ?? "")}
                allowEmpty={false}
                customPlaceholder="Enter a custom data classification"
              />
              <div className="form-field">
                <label htmlFor="bulk-edge-auth">Auth Mechanism</label>
                <input
                  id="bulk-edge-auth"
                  type="text"
                  value={edgeAuthMechanism}
                  onChange={(event) => setEdgeAuthMechanism(event.target.value)}
                  placeholder="e.g. mTLS, OAuth2"
                />
              </div>
              <CustomSelectField
                id="bulk-edge-transfer"
                label="Transfer Mode"
                value={edgeTransferMode}
                options={TRANSFER_MODE_OPTIONS}
                onChange={(value) => setEdgeTransferMode(value ?? "")}
                allowEmpty={false}
                customPlaceholder="Enter a custom transfer mode"
              />
              <div className="form-field">
                <label htmlFor="bulk-edge-encryption">Encrypted in Transit</label>
                <select id="bulk-edge-encryption" value={edgeEncrypted} onChange={(event) => setEdgeEncrypted(event.target.value)}>
                  {BOOLEAN_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </section>
        )}

        {error && <p className="form-error">{error}</p>}

        <div className="dfd-dialog-actions">
          <button className="btn-triage btn-triage-cancel" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button className="btn-create" onClick={() => void handleApply()} disabled={saving}>
            {saving ? "Applying..." : "Apply Changes"}
          </button>
        </div>
      </div>
    </div>
  );
}

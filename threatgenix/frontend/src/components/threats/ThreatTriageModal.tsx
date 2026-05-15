import { useState, useEffect } from "react";
import type { ThreatResponse, ThreatTriageRequest, ThreatAuditEntry, DFDNodeResponse } from "../../types/api";
import { api } from "../../api/client";

interface ThreatTriageModalProps {
  threat: ThreatResponse;
  threatModelId: string;
  onClose: () => void;
  onTriaged: (updated: ThreatResponse) => void;
  onAskAboutThreat?: (threat: ThreatResponse) => void;
}

const STRIDE_COLORS: Record<string, string> = {
  Spoofing: "stride-spoofing",
  Tampering: "stride-tampering",
  Repudiation: "stride-repudiation",
  "Information Disclosure": "stride-info-disclosure",
  "Denial of Service": "stride-dos",
  "Elevation of Privilege": "stride-eop",
};

const SEVERITY_CLASSES: Record<string, string> = {
  Critical: "severity-critical",
  High: "severity-high",
  Medium: "severity-medium",
  Low: "severity-low",
};

const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"] as const;
type ThreatSeverity = (typeof SEVERITY_OPTIONS)[number];

const STATUS_CLASSES: Record<string, string> = {
  Open: "status-open",
  "In Progress": "status-in-progress",
  Mitigated: "status-mitigated",
  Accepted: "status-accepted",
  Dismissed: "status-dismissed",
};

const TRIAGE_STATUSES = [
  "Open",
  "In Progress",
  "Mitigated",
  "Accepted",
  "Dismissed",
] as const;

function normalizeThreatStatus(status: string): ThreatTriageRequest["status"] | null {
  return TRIAGE_STATUSES.find((candidate) => candidate === status) ?? null;
}

const CONTROL_EFFECTIVENESS_OPTIONS = [
  { value: "none", label: "None" },
  { value: "partial", label: "Partial" },
  { value: "substantial", label: "Substantial" },
  { value: "full", label: "Full" },
] as const;

const RESIDUAL_RISK_CLASSES: Record<string, string> = {
  Critical: "residual-risk-critical",
  High: "residual-risk-high",
  Medium: "residual-risk-medium",
  Low: "residual-risk-low",
  Negligible: "residual-risk-negligible",
};

function deriveResidualRiskLevel(
  severity: string,
  controlEffectiveness: "none" | "partial" | "substantial" | "full"
): "Critical" | "High" | "Medium" | "Low" | "Negligible" {
  const matrix = {
    Critical: {
      none: "Critical",
      partial: "High",
      substantial: "Medium",
      full: "Low",
    },
    High: {
      none: "High",
      partial: "Medium",
      substantial: "Low",
      full: "Negligible",
    },
    Medium: {
      none: "Medium",
      partial: "Low",
      substantial: "Low",
      full: "Negligible",
    },
    Low: {
      none: "Low",
      partial: "Low",
      substantial: "Negligible",
      full: "Negligible",
    },
  } as const;

  const row = matrix[severity as keyof typeof matrix];
  if (!row) return "Medium";
  return row[controlEffectiveness];
}

export function ThreatTriageModal({
  threat,
  threatModelId,
  onClose,
  onTriaged,
  onAskAboutThreat,
}: ThreatTriageModalProps) {
  const [dismissReason, setDismissReason] = useState(threat.dismiss_reason ?? "");
  const [showDismissInput, setShowDismissInput] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [auditHistory, setAuditHistory] = useState<ThreatAuditEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [mitigationPlan, setMitigationPlan] = useState(threat.mitigation_plan ?? "");
  const [mitigationOwner, setMitigationOwner] = useState(threat.mitigation_owner ?? "");
  const [dueDate, setDueDate] = useState(threat.due_date ?? "");
  const [mitigationNotes, setMitigationNotes] = useState(threat.mitigation_notes ?? "");
  const [severity, setSeverity] = useState<ThreatSeverity>(threat.severity as ThreatSeverity);
  const [controlEffectiveness, setControlEffectiveness] = useState<
    "none" | "partial" | "substantial" | "full"
  >(threat.control_effectiveness ?? "none");
  const [dfdNodes, setDfdNodes] = useState<DFDNodeResponse[]>([]);

  // Fetch DFD nodes once so we can show human-readable names for affected node IDs
  useEffect(() => {
    if (threat.affected_node_ids.length === 0) return;
    let cancelled = false;
    api.getDFD(threatModelId).then((dfd) => {
      if (!cancelled) setDfdNodes(dfd.nodes);
    }).catch(() => { /* non-critical */ });
    return () => { cancelled = true; };
  }, [threatModelId, threat.affected_node_ids.length]);

  useEffect(() => {
    setDismissReason("");
    setShowDismissInput(false);
    setError(null);
    setMitigationPlan(threat.mitigation_plan ?? "");
    setMitigationOwner(threat.mitigation_owner ?? "");
    setDueDate(threat.due_date ?? "");
    setMitigationNotes(threat.mitigation_notes ?? "");
    setSeverity(threat.severity as ThreatSeverity);
    setControlEffectiveness(threat.control_effectiveness ?? "none");
  }, [threat]);

  useEffect(() => {
    setDismissReason(threat.dismiss_reason ?? "");
    setMitigationPlan(threat.mitigation_plan ?? "");
    setMitigationOwner(threat.mitigation_owner ?? "");
    setDueDate(threat.due_date ?? "");
    setMitigationNotes(threat.mitigation_notes ?? "");
    setSeverity(threat.severity as ThreatSeverity);
    setShowDismissInput(threat.status === "Dismissed");
    setError(null);
  }, [threat]);

  useEffect(() => {
    let cancelled = false;
    setHistoryLoading(true);
    api
      .getThreatHistory(threatModelId, threat.id)
      .then((entries) => {
        if (!cancelled) setAuditHistory(entries);
      })
      .catch(() => {
        if (!cancelled) setAuditHistory([]);
      })
      .finally(() => {
        if (!cancelled) setHistoryLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [threatModelId, threat.id, threat.status]);

  function buildTriageRequest(
    status: "Open" | "In Progress" | "Mitigated" | "Accepted" | "Dismissed"
  ): ThreatTriageRequest {
    const acceptanceRationale =
      mitigationNotes.trim() ||
      mitigationPlan.trim() ||
      "Accepted from threat triage.";
    return {
      status,
      severity,
      dismiss_reason: status === "Dismissed" ? dismissReason.trim() || null : null,
      mitigation_plan: mitigationPlan.trim() || null,
      mitigation_owner: mitigationOwner.trim() || null,
      due_date: dueDate || null,
      mitigation_notes: mitigationNotes.trim() || null,
      control_effectiveness: controlEffectiveness,
      risk_acceptance:
        status === "Accepted"
          ? {
              accepted_by: mitigationOwner.trim() || null,
              expires_at: dueDate ? `${dueDate}T00:00:00Z` : null,
              acceptance_rationale: acceptanceRationale,
              compensating_control: mitigationPlan.trim() || null,
            }
          : undefined,
    };
  }

  const residualRiskLevel =
    threat.residual_risk_level &&
    controlEffectiveness === threat.control_effectiveness &&
    severity === threat.severity
      ? threat.residual_risk_level
      : deriveResidualRiskLevel(severity, controlEffectiveness);

  async function submitTriage(
    status: "Open" | "In Progress" | "Mitigated" | "Accepted" | "Dismissed"
  ) {
    if (status === "Dismissed" && !dismissReason.trim()) {
      setError("A dismiss reason is required.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const updated = await api.triageThreat(threatModelId, threat.id, buildTriageRequest(status));
      onTriaged(updated);
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : "Triage failed";
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  async function handleSaveDetails() {
    const normalizedStatus = normalizeThreatStatus(threat.status);
    if (!normalizedStatus) {
      setError(`Unsupported threat status: ${threat.status}`);
      return;
    }
    await submitTriage(normalizedStatus);
  }

  return (
    <div className="triage-modal-overlay" onClick={onClose}>
      <div className="triage-modal" onClick={(e) => e.stopPropagation()}>
        <div className="triage-modal-header">
          <h3>{threat.display_id}</h3>
          <div className="triage-modal-header-actions">
            {onAskAboutThreat && (
              <button
                type="button"
                className="triage-modal-ask-ai"
                onClick={() => onAskAboutThreat(threat)}
              >
                Ask AI
              </button>
            )}
            <button className="triage-modal-close" onClick={onClose}>
              &times;
            </button>
          </div>
        </div>

        <div className="triage-modal-body">
          <p className="triage-modal-description">{threat.description}</p>

          {threat.relevance_rationale && (
            <div className="triage-modal-section triage-modal-rationale">
              <h4>Why This Matters</h4>
              <p className="triage-rationale-text">{threat.relevance_rationale}</p>
            </div>
          )}

          <div className="triage-modal-badges">
            <span className={`threat-badge ${STRIDE_COLORS[threat.stride_category] ?? ""}`}>
              {threat.stride_category}
            </span>
            <span className={`threat-badge ${SEVERITY_CLASSES[severity] ?? ""}`}>
              {severity}
            </span>
            <span className={`threat-badge ${STATUS_CLASSES[threat.status] ?? ""}`}>
              {threat.status}
            </span>
            <span className={`threat-badge ${RESIDUAL_RISK_CLASSES[residualRiskLevel] ?? ""}`}>
              Residual {residualRiskLevel}
            </span>
          </div>

          {threat.compliance_controls.length > 0 && (
            <div className="triage-modal-section">
              <h4>Compliance Controls</h4>
              {Object.entries(
                threat.compliance_controls.reduce<Record<string, typeof threat.compliance_controls>>(
                  (groups, control) => {
                    const fw = control.framework;
                    if (!groups[fw]) groups[fw] = [];
                    groups[fw].push(control);
                    return groups;
                  },
                  {},
                ),
              ).map(([framework, controls]) => (
                <div key={framework} style={{ marginBottom: "0.5rem" }}>
                  <strong>{framework}</strong>
                  <ul className="triage-modal-controls-list" style={{ marginTop: "0.25rem" }}>
                    {controls.map((c) => (
                      <li key={`${c.framework}-${c.control_id}`}>
                        {c.control_id} &mdash; {c.control_name}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}

          {threat.affected_node_ids.length > 0 && (
            <div className="triage-modal-section">
              <h4>Affected Nodes</h4>
              <ul className="triage-modal-controls-list">
                {threat.affected_node_ids.map((nid) => {
                  const node = dfdNodes.find((n) => n.id === nid);
                  return (
                    <li key={nid}>
                      {node ? (
                        <><strong>{node.name}</strong> <span style={{ color: "var(--c-text-muted, #94a3b8)", fontSize: "0.8em" }}>({node.node_type})</span></>
                      ) : (
                        nid
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          <div className="triage-modal-section">
            <h4>Notes & Mitigation</h4>
            <div className="triage-modal-field-grid">
              <div className="triage-modal-field-span">
                <label htmlFor="mitigation-plan">Mitigation Plan</label>
                <textarea
                  id="mitigation-plan"
                  className="triage-dismiss-input"
                  placeholder="Describe the mitigation strategy..."
                  value={mitigationPlan}
                  onChange={(e) => setMitigationPlan(e.target.value)}
                  rows={3}
                  style={{ width: "100%", resize: "vertical" }}
                />
              </div>
              <div>
                <label htmlFor="mitigation-owner">Owner</label>
                <input
                  id="mitigation-owner"
                  className="triage-dismiss-input"
                  type="text"
                  placeholder="Who is responsible?"
                  value={mitigationOwner}
                  onChange={(e) => setMitigationOwner(e.target.value)}
                />
              </div>
              <div>
                <label htmlFor="due-date">Due Date</label>
                <input
                  id="due-date"
                  className="triage-dismiss-input"
                  type="date"
                  value={dueDate}
                  onChange={(e) => setDueDate(e.target.value)}
                />
              </div>
              <div>
                <label htmlFor="severity">Severity</label>
                <select
                  id="severity"
                  className="triage-dismiss-input"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as ThreatSeverity)}
                >
                  {SEVERITY_OPTIONS.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="control-effectiveness">Control Effectiveness</label>
                <select
                  id="control-effectiveness"
                  className="triage-dismiss-input"
                  value={controlEffectiveness}
                  onChange={(e) =>
                    setControlEffectiveness(
                      e.target.value as "none" | "partial" | "substantial" | "full"
                    )
                  }
                >
                  {CONTROL_EFFECTIVENESS_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="residual-risk">Residual Risk</label>
                <div id="residual-risk" className="triage-modal-readonly">
                  <span className={`threat-badge ${RESIDUAL_RISK_CLASSES[residualRiskLevel] ?? ""}`}>
                    {residualRiskLevel}
                  </span>
                </div>
              </div>
              {threat.status === "Dismissed" && (
                <div className="triage-modal-field-span">
                  <label htmlFor="dismiss-reason-inline">Dismiss Reason</label>
                  <input
                    id="dismiss-reason-inline"
                    className="triage-dismiss-input"
                    type="text"
                    placeholder="Why is this threat being dismissed?"
                    value={dismissReason}
                    onChange={(e) => setDismissReason(e.target.value)}
                  />
                </div>
              )}
              <div className="triage-modal-save-row">
                <button
                  type="button"
                  className="btn-triage btn-triage-save"
                  disabled={loading}
                  onClick={handleSaveDetails}
                >
                  {loading ? "Saving..." : "Save Details"}
                </button>
                <span className="triage-modal-save-hint">
                  Saves severity, notes, owner, due date, and plan without changing the current status.
                </span>
              </div>
              <div className="triage-modal-field-span">
                <label htmlFor="mitigation-notes">Notes</label>
                <textarea
                  id="mitigation-notes"
                  className="triage-dismiss-input"
                  placeholder="Additional notes..."
                  value={mitigationNotes}
                  onChange={(e) => setMitigationNotes(e.target.value)}
                  rows={2}
                  style={{ width: "100%", resize: "vertical" }}
                />
              </div>
            </div>
          </div>

          {showDismissInput && (
            <div className="triage-modal-section">
              <label htmlFor="dismiss-reason">Dismiss Reason (required)</label>
              <input
                id="dismiss-reason"
                className="triage-dismiss-input"
                type="text"
                placeholder="Why is this threat being dismissed?"
                value={dismissReason}
                onChange={(e) => setDismissReason(e.target.value)}
              />
            </div>
          )}

          {error && <p className="triage-modal-error">{error}</p>}
        </div>

        <div className="triage-modal-actions">
          {!showDismissInput ? (
            <>
              {threat.status !== "Open" && (
                <button
                  className="btn-triage btn-triage-reopen"
                  disabled={loading}
                  onClick={() => submitTriage("Open")}
                  style={{ background: "#475569" }}
                >
                  {loading ? "Saving..." : "Reopen"}
                </button>
              )}
              <button
                className="btn-triage btn-triage-in-progress"
                disabled={loading}
                onClick={() => submitTriage("In Progress")}
                style={{ background: "#2563eb" }}
              >
                {loading ? "Saving..." : "In Progress"}
              </button>
              <button
                className="btn-triage btn-triage-mitigated"
                disabled={loading}
                onClick={() => submitTriage("Mitigated")}
                style={{ background: "#059669" }}
              >
                {loading ? "Saving..." : "Mitigated"}
              </button>
              <button
                className="btn-triage btn-triage-accept"
                disabled={loading}
                onClick={() => submitTriage("Accepted")}
              >
                {loading ? "Saving..." : "Accept Risk"}
              </button>
              <button
                className="btn-triage btn-triage-dismiss"
                disabled={loading}
                onClick={() => setShowDismissInput(true)}
              >
                Dismiss
              </button>
            </>
          ) : (
            <>
              <button
                className="btn-triage btn-triage-dismiss"
                disabled={loading}
                onClick={() => submitTriage("Dismissed")}
              >
                {loading ? "Saving..." : "Confirm Dismiss"}
              </button>
              <button
                className="btn-triage btn-triage-cancel"
                disabled={loading}
                onClick={() => {
                  setShowDismissInput(false);
                  setDismissReason("");
                  setError(null);
                }}
              >
                Cancel
              </button>
            </>
          )}
        </div>

        <div
          className="triage-modal-section"
          style={{
            padding: "1rem 1.5rem",
            borderTop: "1px solid rgba(255,255,255,0.08)",
          }}
        >
          <h4 style={{ margin: "0 0 0.75rem 0" }}>Audit History</h4>
          <div
            style={{
              borderTop: "1px solid rgba(255,255,255,0.15)",
              paddingTop: "0.75rem",
            }}
          >
            {historyLoading ? (
              <p style={{ color: "rgba(255,255,255,0.5)", margin: 0 }}>
                Loading history...
              </p>
            ) : auditHistory.length === 0 ? (
              <p style={{ color: "rgba(255,255,255,0.5)", margin: 0 }}>
                No history yet
              </p>
            ) : (
              <ul
                style={{
                  listStyle: "none",
                  padding: 0,
                  margin: 0,
                  display: "flex",
                  flexDirection: "column",
                  gap: "0.75rem",
                }}
              >
                {auditHistory.map((entry) => {
                  const date = new Date(entry.changed_at);
                  const formatted = date.toLocaleDateString("en-US", {
                    year: "numeric",
                    month: "short",
                    day: "numeric",
                  }) +
                    " " +
                    date.toLocaleTimeString("en-US", {
                      hour: "numeric",
                      minute: "2-digit",
                    });

                  return (
                    <li
                      key={entry.id}
                      style={{
                        paddingBottom: "0.75rem",
                        borderBottom: "1px solid rgba(255,255,255,0.06)",
                      }}
                    >
                      <div
                        style={{
                          color: "rgba(255,255,255,0.5)",
                          fontSize: "0.8rem",
                          marginBottom: "0.25rem",
                        }}
                      >
                        {formatted} &mdash; {entry.changed_by}
                      </div>
                      <div style={{ fontSize: "0.9rem" }}>
                        {entry.action}
                        {entry.old_status && entry.new_status
                          ? `: ${entry.old_status} \u2192 ${entry.new_status}`
                          : entry.new_status
                            ? `: \u2192 ${entry.new_status}`
                            : ""}
                      </div>
                      {entry.reason && (
                        <div
                          style={{
                            color: "rgba(255,255,255,0.6)",
                            fontSize: "0.85rem",
                            marginTop: "0.15rem",
                          }}
                        >
                          Reason: {entry.reason}
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

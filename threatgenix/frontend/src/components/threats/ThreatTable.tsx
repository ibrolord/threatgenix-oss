import { useState, useMemo, useCallback, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import type { AssistantReference, ThreatResponse, ThreatScanStatus } from "../../types/api";

interface ThreatTableProps {
  threats: ThreatResponse[];
  loading: boolean;
  threatModelId?: string;
  onThreatQuickTriage?: (threat: ThreatResponse) => void;
  selectedIds?: Set<string>;
  onSelectionChange?: (ids: Set<string>) => void;
  onAskAboutThreat?: (threat: ThreatResponse) => void;
  onFocusThreat?: (threat: ThreatResponse) => void;
  highlightedReferences?: AssistantReference[];
}

type SortKey =
  | "display_id"
  | "description"
  | "stride_category"
  | "severity"
  | "source"
  | "status"
  | "residual_risk_level"
  | "mitigation_owner"
  | "due_date";
type SortDir = "asc" | "desc";

const SEVERITY_ORDER: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

const RESIDUAL_RISK_ORDER: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Negligible: 4,
};

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

const STATUS_CLASSES: Record<string, string> = {
  Open: "status-open",
  "In Progress": "status-in-progress",
  Mitigated: "status-mitigated",
  Accepted: "status-accepted",
  Dismissed: "status-dismissed",
};

const RESIDUAL_RISK_CLASSES: Record<string, string> = {
  Critical: "residual-risk-critical",
  High: "residual-risk-high",
  Medium: "residual-risk-medium",
  Low: "residual-risk-low",
  Negligible: "residual-risk-negligible",
};

const SCAN_STATUS_STYLES: Partial<Record<ThreatScanStatus, { background: string; color: string; label: string }>> = {
  confirmed:    { background: "#d1fae5", color: "#065f46", label: "Confirmed" },
  mitigated:    { background: "#dbeafe", color: "#1e40af", label: "Mitigated" },
  unverifiable: { background: "#f3f4f6", color: "#6b7280", label: "?" },
  not_found:    { background: "#fef3c7", color: "#92400e", label: "Not Found" },
};

function compareThreatField(a: ThreatResponse, b: ThreatResponse, key: SortKey): number {
  if (key === "severity") {
    return (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
  }
  if (key === "residual_risk_level") {
    return (
      (RESIDUAL_RISK_ORDER[a.residual_risk_level ?? ""] ?? 99) -
      (RESIDUAL_RISK_ORDER[b.residual_risk_level ?? ""] ?? 99)
    );
  }
  const av = (a[key] as string | null) ?? "";
  const bv = (b[key] as string | null) ?? "";
  return av.localeCompare(bv);
}

function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max) + "...";
}

/**
 * Strip unresolved Jinja-style template placeholders (e.g. {source_name},
 * {edge_label}) that appear when a threat was created via the catalog without
 * a live DFD context. Collapses the resulting double-spaces.
 */
function cleanDescription(text: string): string {
  const cleaned = text.replace(/\s*\{[a-z_]+\}\s*/g, " ").replace(/\s{2,}/g, " ").trim();
  return cleaned || "No description available.";
}

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: "display_id", label: "ID" },
  { key: "description", label: "Description" },
  { key: "stride_category", label: "STRIDE" },
  { key: "severity", label: "Severity" },
  { key: "source", label: "Source" },
  { key: "status", label: "Status" },
  { key: "residual_risk_level", label: "Residual Risk" },
  { key: "mitigation_owner", label: "Owner" },
  { key: "due_date", label: "Due Date" },
];

export function ThreatTable({
  threats,
  loading,
  threatModelId,
  onThreatQuickTriage,
  selectedIds,
  onSelectionChange,
  onAskAboutThreat,
  onFocusThreat,
  highlightedReferences,
}: ThreatTableProps) {
  const navigate = useNavigate();
  const [sortKey, setSortKey] = useState<SortKey>("display_id");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [contextMenu, setContextMenu] = useState<{
    threat: ThreatResponse;
    x: number;
    y: number;
  } | null>(null);

  const selectable = selectedIds !== undefined && onSelectionChange !== undefined;
  const highlightedThreatIds = useMemo(
    () =>
      new Set(
        (highlightedReferences ?? [])
          .filter((reference) => reference.kind === "threat")
          .map((reference) => reference.id)
      ),
    [highlightedReferences]
  );

  const sorted = useMemo(() => {
    const copy = [...threats];
    copy.sort((a, b) => {
      const cmp = compareThreatField(a, b, sortKey);
      return sortDir === "asc" ? cmp : -cmp;
    });
    return copy;
  }, [threats, sortKey, sortDir]);

  const allSelected = selectable && threats.length > 0 && threats.every((t) => selectedIds!.has(t.id));

  const handleSelectAll = useCallback(() => {
    if (!onSelectionChange) return;
    if (allSelected) {
      onSelectionChange(new Set());
    } else {
      onSelectionChange(new Set(threats.map((t) => t.id)));
    }
  }, [threats, allSelected, onSelectionChange]);

  const handleToggle = useCallback(
    (threatId: string) => {
      if (!onSelectionChange || !selectedIds) return;
      const next = new Set(selectedIds);
      if (next.has(threatId)) {
        next.delete(threatId);
      } else {
        next.add(threatId);
      }
      onSelectionChange(next);
    },
    [selectedIds, onSelectionChange]
  );

  const handleOpenThreatDetail = useCallback(
    (threat: ThreatResponse) => {
      if (!threatModelId) return;
      navigate(`/threat-models/${threatModelId}/threats/${threat.id}`);
    },
    [navigate, threatModelId]
  );

  function handleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  }

  useEffect(() => {
    const highlightedId = Array.from(highlightedThreatIds)[0];
    if (!highlightedId) return;
    const row = document.querySelector(
      `[data-threat-id="${highlightedId}"]`
    ) as HTMLElement | null;
    row?.scrollIntoView({ block: "nearest" });
  }, [highlightedThreatIds]);

  if (loading) {
    return (
      <div className="threat-table-loading">
        <div className="dfd-spinner" />
        <span>Loading threats...</span>
      </div>
    );
  }

  if (threats.length === 0) {
    return (
      <div className="threat-table-empty">
        No threats generated yet. Click &quot;Generate Threats&quot; to analyze.
      </div>
    );
  }

  return (
    <div className="threat-table-wrapper">
      <table className="threat-table">
        <thead>
          <tr>
            {selectable && (
              <th className="threat-table-th threat-table-col-check">
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={handleSelectAll}
                  aria-label="Select all threats"
                />
              </th>
            )}
            {COLUMNS.map((col) => (
              <th
                key={col.key}
                className={`threat-table-th ${col.key === "display_id" ? "threat-table-col-id" : ""} ${col.key === "description" ? "threat-table-col-desc" : ""}`}
                onClick={() => handleSort(col.key)}
              >
                {col.label}
                {sortKey === col.key && (
                  <span className="threat-table-sort-icon">
                    {sortDir === "asc" ? " \u25B2" : " \u25BC"}
                  </span>
                )}
              </th>
            ))}
            <th className="threat-table-th">Scan</th>
            <th className="threat-table-th">Actions</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((threat) => (
            <tr
              key={threat.id}
              data-threat-id={threat.id}
              className={`threat-table-row${selectable && selectedIds!.has(threat.id) ? " threat-table-row-selected" : ""}${highlightedThreatIds.has(threat.id) ? " threat-table-row-highlighted" : ""}`}
              onClick={() => handleOpenThreatDetail(threat)}
              onContextMenu={(event) => {
                event.preventDefault();
                setContextMenu({
                  threat,
                  x: event.clientX,
                  y: event.clientY,
                });
              }}
            >
              {selectable && (
                <td className="threat-table-col-check" onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    checked={selectedIds!.has(threat.id)}
                    onChange={() => handleToggle(threat.id)}
                    aria-label={`Select ${threat.display_id}`}
                  />
                </td>
              )}
              <td className="threat-table-col-id">
                <div className="threat-table-id-cell">
                  {threatModelId ? (
                    <Link
                      to={`/threat-models/${threatModelId}/threats/${threat.id}`}
                      className="threat-table-detail-link"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {threat.display_id}
                    </Link>
                  ) : (
                    threat.display_id
                  )}
                  <div className="threat-table-actions">
                    {onThreatQuickTriage ? (
                      <button
                        type="button"
                        className="threat-table-secondary-action"
                        title={`Open quick triage for ${threat.display_id}`}
                        onClick={(event) => {
                          event.stopPropagation();
                          onThreatQuickTriage(threat);
                        }}
                      >
                        Quick Triage
                      </button>
                    ) : null}
                    {(threat.affected_node_ids.length > 0 || threat.affected_edge_ids.length > 0) && (
                      <button
                        type="button"
                        className="threat-table-show-dfd"
                        title={`Highlight the affected graph elements for ${threat.display_id}`}
                        onClick={(event) => {
                          event.stopPropagation();
                          onFocusThreat?.(threat);
                        }}
                      >
                        Show on DFD
                      </button>
                    )}
                  </div>
                </div>
              </td>
              <td className="threat-table-col-desc" title={cleanDescription(threat.description)}>
                {truncate(cleanDescription(threat.description), 100)}
              </td>
              <td>
                <span className={`threat-badge ${STRIDE_COLORS[threat.stride_category] ?? ""}`}>
                  {threat.stride_category}
                </span>
              </td>
              <td>
                <span className={`threat-badge ${SEVERITY_CLASSES[threat.severity] ?? ""}`}>
                  {threat.severity}
                </span>
              </td>
              <td>
                {threat.source}
                {threat.provider_managed && (
                  <span
                    className="threat-badge"
                    style={{
                      marginLeft: 4,
                      background: "#1e3a5f",
                      color: "#93c5fd",
                      fontSize: "0.7rem",
                    }}
                    title="This threat applies to provider-managed infrastructure. Verify coverage under your cloud provider's shared responsibility model."
                  >
                    Provider
                  </span>
                )}
              </td>
              <td>
                <span className={`threat-badge ${STATUS_CLASSES[threat.status] ?? ""}`}>
                  {threat.status}
                </span>
              </td>
              <td>
                {threat.residual_risk_level ? (
                  <span
                    className={`threat-badge ${RESIDUAL_RISK_CLASSES[threat.residual_risk_level] ?? ""}`}
                  >
                    {threat.residual_risk_level}
                  </span>
                ) : (
                  ""
                )}
              </td>
              <td>{threat.mitigation_owner ?? ""}</td>
              <td>{threat.due_date ?? ""}</td>
              <td>
                {threat.scan_status != null && (() => {
                  const style = SCAN_STATUS_STYLES[threat.scan_status];
                  if (!style) return null;
                  return (
                    <span
                      style={{
                        display: "inline-block",
                        padding: "2px 6px",
                        borderRadius: "4px",
                        fontSize: "11px",
                        fontWeight: 600,
                        background: style.background,
                        color: style.color,
                      }}
                    >
                      {style.label}
                    </span>
                  );
                })()}
              </td>
              <td onClick={(event) => event.stopPropagation()}>
                <div className="threat-table-actions">
                  <button
                    type="button"
                    className="threat-table-action threat-table-action-secondary"
                    onClick={() => onThreatQuickTriage?.(threat)}
                  >
                    {threat.mitigation_notes?.trim() ? "View Notes" : "Add Notes"}
                  </button>
                  {threatModelId ? (
                    <button
                      type="button"
                      className="threat-table-action threat-table-action-secondary"
                      onClick={() =>
                        navigate(`/threat-models/${threatModelId}/threats/${threat.id}?validate=1`)
                      }
                    >
                      Validate
                    </button>
                  ) : null}
                  <button
                    type="button"
                    className="threat-table-action threat-table-action-primary"
                    onClick={() => onAskAboutThreat?.(threat)}
                  >
                    Ask AI
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {contextMenu && (
        <>
          <div className="dfd-spawn-menu-backdrop" onClick={() => setContextMenu(null)} />
          <div
            className="dfd-graph-context-menu threat-context-menu"
            style={{ left: contextMenu.x, top: contextMenu.y }}
          >
            {threatModelId ? (
              <button
                type="button"
                className="dfd-spawn-menu-option"
                onClick={() => {
                  handleOpenThreatDetail(contextMenu.threat);
                  setContextMenu(null);
                }}
              >
                Open Detail
              </button>
            ) : null}
            {onThreatQuickTriage ? (
              <button
                type="button"
                className="dfd-spawn-menu-option"
                onClick={() => {
                  onThreatQuickTriage(contextMenu.threat);
                  setContextMenu(null);
                }}
              >
                Quick Triage
              </button>
            ) : null}
            <button
              type="button"
              className="dfd-spawn-menu-option"
              onClick={() => {
                onAskAboutThreat?.(contextMenu.threat);
                setContextMenu(null);
              }}
            >
              Ask AI About “{contextMenu.threat.display_id}”
            </button>
            {(contextMenu.threat.affected_node_ids.length > 0 ||
              contextMenu.threat.affected_edge_ids.length > 0) && (
              <button
                type="button"
                className="dfd-spawn-menu-option"
                onClick={() => {
                  onFocusThreat?.(contextMenu.threat);
                  setContextMenu(null);
                }}
              >
                Show on DFD
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}

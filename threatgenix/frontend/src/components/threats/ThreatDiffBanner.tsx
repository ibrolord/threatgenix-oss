import { useState } from "react";
import type { ThreatDiffResponse } from "../../types/api";

interface ThreatDiffBannerProps {
  diff: ThreatDiffResponse | null;
  isLoading: boolean;
  onReanalyze: () => void;
  reanalyzing: boolean;
}

const styles = {
  banner: {
    background: "linear-gradient(135deg, #0f2b3d 0%, #0d3044 50%, #0a2a3a 100%)",
    border: "1px solid #1a4a5e",
    borderRadius: "8px",
    padding: "14px 18px",
    margin: "12px 0",
    color: "#d1e8f0",
    fontSize: "0.9rem",
    lineHeight: 1.5,
  } as React.CSSProperties,
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "12px",
  } as React.CSSProperties,
  summaryText: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    fontWeight: 500,
    color: "#e2f1f8",
  } as React.CSSProperties,
  bolt: {
    fontSize: "1.1rem",
  } as React.CSSProperties,
  addedCount: {
    color: "#6ee7b7",
    fontWeight: 600,
  } as React.CSSProperties,
  removedCount: {
    color: "#93c5fd",
    fontWeight: 600,
  } as React.CSSProperties,
  reanalyzeBtn: {
    background: "#1d6a8a",
    color: "#e2f1f8",
    border: "1px solid #2a7d9e",
    borderRadius: "6px",
    padding: "6px 16px",
    cursor: "pointer",
    fontSize: "0.85rem",
    fontWeight: 500,
    whiteSpace: "nowrap" as const,
    transition: "background 0.15s",
  } as React.CSSProperties,
  reanalyzeBtnDisabled: {
    background: "#163a4d",
    color: "#7a9aad",
    cursor: "not-allowed",
    border: "1px solid #1a4a5e",
  } as React.CSSProperties,
  toggleBtn: {
    background: "none",
    border: "none",
    color: "#7ab8d4",
    cursor: "pointer",
    fontSize: "0.85rem",
    padding: "4px 0",
    marginTop: "6px",
  } as React.CSSProperties,
  detailList: {
    marginTop: "10px",
    paddingLeft: "4px",
    display: "flex",
    flexDirection: "column" as const,
    gap: "4px",
  } as React.CSSProperties,
  detailItem: {
    fontSize: "0.85rem",
    color: "#b0d0e0",
    lineHeight: 1.4,
  } as React.CSSProperties,
  addedLabel: {
    color: "#6ee7b7",
    fontWeight: 500,
    marginRight: "4px",
  } as React.CSSProperties,
  removedLabel: {
    color: "#93c5fd",
    fontWeight: 500,
    marginRight: "4px",
  } as React.CSSProperties,
  severity: {
    color: "#fbbf24",
    fontSize: "0.8rem",
  } as React.CSSProperties,
  hint: {
    background: "#0f1f2e",
    border: "1px solid #1a3344",
    borderRadius: "8px",
    padding: "12px 16px",
    margin: "12px 0",
    color: "#6b8fa8",
    fontSize: "0.85rem",
    textAlign: "center" as const,
  } as React.CSSProperties,
  loadingDot: {
    display: "inline-block",
    width: "6px",
    height: "6px",
    borderRadius: "50%",
    background: "#7ab8d4",
    marginRight: "8px",
    animation: "pulse 1.2s infinite",
  } as React.CSSProperties,
} as const;

function truncate(text: string, maxLen: number): string {
  return text.length > maxLen ? text.slice(0, maxLen) + "..." : text;
}

export function ThreatDiffBanner({
  diff,
  isLoading,
  onReanalyze,
  reanalyzing,
}: ThreatDiffBannerProps) {
  const [expanded, setExpanded] = useState(false);

  // No baseline yet — show hint
  if (diff !== null && !diff.has_baseline) {
    return (
      <div style={styles.hint}>
        Run your first analysis to enable suggestions
      </div>
    );
  }

  // Loading state
  if (isLoading) {
    return (
      <div style={styles.banner}>
        <div style={styles.summaryText}>
          <span style={styles.loadingDot} />
          Checking for threat changes...
        </div>
      </div>
    );
  }

  // No diff or no changes
  if (!diff) return null;

  const { added, removed } = diff;
  const totalChanges = diff.counts.added + diff.counts.removed;

  const summaryParts: string[] = [];
  if (diff.counts.added > 0) summaryParts.push(`+${diff.counts.added} new`);
  if (diff.counts.removed > 0) summaryParts.push(`-${diff.counts.removed} mitigated`);

  const btnStyle = reanalyzing
    ? { ...styles.reanalyzeBtn, ...styles.reanalyzeBtnDisabled }
    : styles.reanalyzeBtn;

  return (
    <div style={styles.banner}>
      <div style={styles.header}>
        <div style={styles.summaryText}>
          <span style={styles.bolt}>&#x26A1;</span>
          <span>
            Your edits changed{" "}
            <strong>{totalChanges} threat{totalChanges !== 1 ? "s" : ""}</strong>
            :{" "}
            {diff.counts.added > 0 && (
              <span style={styles.addedCount}>+{diff.counts.added} new</span>
            )}
            {diff.counts.added > 0 && diff.counts.removed > 0 && ", "}
            {diff.counts.removed > 0 && (
              <span style={styles.removedCount}>-{diff.counts.removed} mitigated</span>
            )}
          </span>
        </div>
        <button
          style={btnStyle}
          onClick={onReanalyze}
          disabled={reanalyzing}
        >
          {reanalyzing ? "Analyzing..." : "Full Analysis (+ AI)"}
        </button>
      </div>

      {(added.length > 0 || removed.length > 0) && (
        <button
          style={styles.toggleBtn}
          onClick={() => setExpanded((e) => !e)}
        >
          {expanded ? "\u25BE Hide details" : "\u25B8 Show details"}
        </button>
      )}

      {expanded && (
        <div style={styles.detailList}>
          {added.map((t, i) => (
            <div key={`added-${i}`} style={styles.detailItem}>
              <span style={styles.addedLabel}>{"\u25B8"} New:</span>
              {t.rule_id} <span style={styles.severity}>({t.severity})</span>
              {" \u2014 "}
              {truncate(t.description, 60)}
            </div>
          ))}
          {removed.map((t, i) => (
            <div key={`removed-${i}`} style={styles.detailItem}>
              <span style={styles.removedLabel}>{"\u25B8"} Mitigated:</span>
              {t.rule_id}
              {" \u2014 "}
              {truncate(t.description, 60)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

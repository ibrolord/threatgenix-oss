import { useEffect, useState, useCallback } from "react";
import type { ResidualRiskSummary, ThreatSummary } from "../../types/api";
import { api } from "../../api/client";

interface ThreatDashboardProps {
  threatModelId: string;
  refreshKey: number;
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];
const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#ca8a04",
  Low: "#16a34a",
};

const STATUS_COLORS: Record<string, string> = {
  Open: "#dc2626",
  Accepted: "#16a34a",
  Dismissed: "#6b7280",
};

const RESIDUAL_RISK_ORDER = ["Critical", "High", "Medium", "Low", "Negligible"] as const;
const RESIDUAL_RISK_COLORS: Record<string, string> = {
  Critical: "#b91c1c",
  High: "#ea580c",
  Medium: "#ca8a04",
  Low: "#2563eb",
  Negligible: "#0f766e",
};

const STRIDE_LABELS = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
];

const STRIDE_SHORT: Record<string, string> = {
  "Information Disclosure": "Info Disclosure",
  "Denial of Service": "Denial of Service",
  "Elevation of Privilege": "Privilege Escalation",
};

function Bar({ label, count, max, color }: { label: string; count: number; max: number; color: string }) {
  const pct = max > 0 ? (count / max) * 100 : 0;
  return (
    <div className="dash-bar-row">
      <span className="dash-bar-label">{label}</span>
      <div className="dash-bar-track">
        <div className="dash-bar-fill" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className="dash-bar-count">{count}</span>
    </div>
  );
}

export function ThreatDashboard({ threatModelId, refreshKey }: ThreatDashboardProps): JSX.Element | null {
  const [summary, setSummary] = useState<ThreatSummary | null>(null);
  const [residualSummary, setResidualSummary] = useState<ResidualRiskSummary | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchSummary = useCallback(() => {
    setLoading(true);
    Promise.all([
      api.getThreatsSummary(threatModelId),
      api.getResidualRiskSummary(threatModelId).catch(() => null),
    ])
      .then(([threatSummary, residual]) => {
        setSummary(threatSummary);
        setResidualSummary(residual);
      })
      .catch(() => {
        setSummary(null);
        setResidualSummary(null);
      })
      .finally(() => setLoading(false));
  }, [threatModelId]);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary, refreshKey]);

  if (loading && !summary) return null;
  if (!summary || summary.total === 0) return null;

  const maxSeverity = Math.max(...SEVERITY_ORDER.map((s) => summary.by_severity[s] ?? 0), 1);
  const maxStride = Math.max(...STRIDE_LABELS.map((s) => summary.by_stride[s] ?? 0), 1);
  const maxResidual = residualSummary
    ? Math.max(...RESIDUAL_RISK_ORDER.map((level) => residualSummary.by_level[level] ?? 0), 1)
    : 1;

  return (
    <div className="threat-dashboard">
      <div className="dash-card dash-total">
        <div className="dash-total-number">{summary.total}</div>
        <div className="dash-total-label">Total Threats</div>
      </div>

      <div className="dash-card dash-card-severity">
        <h4>By Severity</h4>
        {SEVERITY_ORDER.map((s) => (
          <Bar
            key={s}
            label={s}
            count={summary.by_severity[s] ?? 0}
            max={maxSeverity}
            color={SEVERITY_COLORS[s] ?? "#6b7280"}
          />
        ))}
      </div>

      <div className="dash-card">
        <h4>By Status</h4>
        <div className="dash-status-row">
          {Object.entries(summary.by_status).map(([status, count]) => (
            <div key={status} className="dash-status-chip">
              <span
                className="dash-status-dot"
                style={{ backgroundColor: STATUS_COLORS[status] ?? "#6b7280" }}
              />
              <span className="dash-status-count">{count}</span>
              <span className="dash-status-label">{status}</span>
            </div>
          ))}
        </div>
      </div>

      {residualSummary && residualSummary.total > 0 && (
        <div className="dash-card">
          <h4>Residual Risk</h4>
          {RESIDUAL_RISK_ORDER.map((level) => (
            <Bar
              key={level}
              label={level}
              count={residualSummary.by_level[level] ?? 0}
              max={maxResidual}
              color={RESIDUAL_RISK_COLORS[level] ?? "#6b7280"}
            />
          ))}
        </div>
      )}

      <div className="dash-card dash-stride">
        <h4>By STRIDE Category</h4>
        {STRIDE_LABELS.map((s) => (
          <Bar
            key={s}
            label={STRIDE_SHORT[s] ?? s}
            count={summary.by_stride[s] ?? 0}
            max={maxStride}
            color="#3b82f6"
          />
        ))}
      </div>
    </div>
  );
}

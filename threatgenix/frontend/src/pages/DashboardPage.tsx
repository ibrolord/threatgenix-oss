import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import type { PortfolioSummary, PortfolioTrendResponse } from "../types/api";
import { api } from "../api/client";
import { classificationColor } from "../utils/classification";
import { useAuth } from "../auth/useAuth";

const styles = {
  container: {
    maxWidth: "1100px",
    margin: "0 auto",
  } as React.CSSProperties,
  panel: {
    background: "#1e293b",
    borderRadius: "12px",
    padding: "1.25rem",
  } as React.CSSProperties,
  panelTitle: {
    margin: "0 0 1rem",
    color: "#f8fafc",
    fontSize: "1rem",
  } as React.CSSProperties,
  panelCopy: {
    color: "#b8c7db",
    fontSize: "0.9rem",
    lineHeight: 1.55,
  } as React.CSSProperties,
  trendBar: (height: number) =>
    ({
      flex: 1,
      minHeight: "12px",
      height: `${height}px`,
      borderRadius: "999px",
      background: "linear-gradient(180deg, #60a5fa 0%, #1d4ed8 100%)",
    }) as React.CSSProperties,
  badge: (color: string) =>
    ({
      display: "inline-block",
      padding: "2px 8px",
      borderRadius: "4px",
      fontSize: "0.8rem",
      fontWeight: 600,
      background: color,
      color: "#fff",
    }) as React.CSSProperties,
};

function DashboardPage() {
  const { user } = useAuth();
  const [summary, setSummary] = useState<PortfolioSummary | null>(null);
  const [trends, setTrends] = useState<PortfolioTrendResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [archivingId, setArchivingId] = useState<string | null>(null);
  const navigate = useNavigate();

  const loadDashboard = useCallback((showLoading = false) => {
    if (showLoading) setLoading(true);
    setError(null);
    return Promise.all([api.getPortfolioSummary(), api.getPortfolioTrends()])
      .then(([summaryResponse, trendResponse]) => {
        setSummary(summaryResponse);
        setTrends(trendResponse);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    void loadDashboard(true);
  }, [loadDashboard]);

  if (loading) return <div className="page-loading"><div className="dfd-spinner" /><span>Loading dashboard...</span></div>;
  if (error) return <p className="error">Failed to load dashboard: {error}</p>;
  if (!summary) return <p className="error">No data available.</p>;

  const highCount =
    (summary.threats_by_severity["Critical"] ?? 0) +
    (summary.threats_by_severity["High"] ?? 0);
  const totalThreats = summary.total_threats;
  const openCount = summary.threats_by_status["Open"] ?? 0;
  const triagePercent =
    totalThreats > 0 ? Math.round(((totalThreats - openCount) / totalThreats) * 100) : 0;
  const trendMax = Math.max(
    1,
    ...(trends?.points.map((point) => point.high_risk_threat_count + point.review_events + point.control_events) ?? [1]),
  );

  const models = [...summary.recent_models].sort(
    (a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime()
  );

  const isEmpty = summary.total_models === 0;
  const hasElevatedThreats = highCount > 0;
  const hasStrongTriageProgress = triagePercent >= 80;
  const subscriptionTier = user?.organization_subscription_tier?.trim();
  const tierLabel = subscriptionTier
    ? `${subscriptionTier.charAt(0).toUpperCase()}${subscriptionTier.slice(1)} SaaS`
    : user?.organization_id
      ? "Organization SaaS"
      : "Personal pilot";

  function handleExportDashboard() {
    if (!summary) return;
    const rows: string[] = [];
    rows.push("Metric,Value");
    rows.push(`Total Models,${summary.total_models}`);
    rows.push(`Total Findings,${totalThreats}`);
    rows.push(`Critical + High,${highCount}`);
    rows.push(`Triage Progress,${triagePercent}%`);
    rows.push(`Avg Threats / Model,${summary.total_models > 0 ? (totalThreats / summary.total_models).toFixed(1) : "0"}`);
    rows.push("");
    rows.push("Severity,Count");
    for (const [sev, count] of Object.entries(summary.threats_by_severity)) {
      rows.push(`${sev},${count}`);
    }
    rows.push("");
    rows.push("STRIDE Category,Count");
    for (const [cat, count] of Object.entries(summary.threats_by_stride)) {
      rows.push(`${cat},${count}`);
    }
    rows.push("");
    rows.push("Application,Classification,Findings,Updated");
    for (const m of models) {
      rows.push(`"${m.system_name}",${m.data_classification},${m.threat_count},${new Date(m.updated_at).toLocaleDateString()}`);
    }
    const blob = new Blob([rows.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threatgenix-portfolio-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function handleArchiveModel(model: PortfolioSummary["recent_models"][number]) {
    const confirmed = window.confirm(
      `Archive ${model.system_name}? It will be removed from active portfolio lists.`
    );
    if (!confirmed) return;

    setActionError(null);
    setArchivingId(model.id);
    try {
      await api.archiveThreatModel(model.id);
      await loadDashboard();
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : "Failed to archive security review.";
      setActionError(message);
    } finally {
      setArchivingId(null);
    }
  }

  return (
    <div style={styles.container} className="dashboard-page">
      <div className="dashboard-header">
        <div className="dashboard-title-group">
          <p className="dashboard-kicker">Security Reviews</p>
          <h2 className="dashboard-title">Review Portfolio</h2>
          <p className="dashboard-subtitle">
            Track active review scope, evidence pressure, and the next decision surface to open.
          </p>
          <div className="dashboard-saas-context" aria-label="Workspace context">
            <span>{user?.organization_name || "Personal pilot workspace"}</span>
            <span>{tierLabel}</span>
            <span>{user?.role || "User"}</span>
            <span>AI boundary: review Settings</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          {!isEmpty && (
            <button
              className="btn-export"
              onClick={handleExportDashboard}
              title="Export portfolio summary as CSV for budget justification"
            >
              Export CSV
            </button>
          )}
          <button
            className="btn-create"
            onClick={() => navigate("/new")}
            title="Start a new evidence-backed security review"
          >
            Start Review
          </button>
        </div>
      </div>

      {!isEmpty && (
        <div className="dashboard-cards-row">
          <div className="dashboard-summary-card">
            <div className="dashboard-summary-label">Total Models</div>
            <div className="dashboard-summary-value">{summary.total_models}</div>
          </div>
          <div className="dashboard-summary-card">
            <div className="dashboard-summary-label">Total Findings</div>
            <div className="dashboard-summary-value">{totalThreats}</div>
          </div>
          <div className={`dashboard-summary-card ${hasElevatedThreats ? "dashboard-summary-card-critical" : ""}`}>
            <div className={`dashboard-summary-label ${hasElevatedThreats ? "dashboard-summary-label-critical" : ""}`}>
              Critical + High
            </div>
            <div className={`dashboard-summary-value ${hasElevatedThreats ? "dashboard-summary-value-critical" : ""}`}>
              {highCount}
            </div>
          </div>
          <div className={`dashboard-summary-card ${hasStrongTriageProgress ? "dashboard-summary-card-success" : ""}`}>
            <div className="dashboard-summary-label">Triage Progress</div>
            <div className={`dashboard-summary-value ${hasStrongTriageProgress ? "dashboard-summary-value-success" : ""}`}>
              {triagePercent}%
            </div>
          </div>
          <div className="dashboard-summary-card">
            <div className="dashboard-summary-label">Avg Threats / Model</div>
            <div className="dashboard-summary-value">
              {summary.total_models > 0
                ? (totalThreats / summary.total_models).toFixed(1)
                : "0"}
            </div>
          </div>
        </div>
      )}

      {!isEmpty && trends && trends.points.length > 0 && (
        <section style={styles.panel}>
          <h3 style={styles.panelTitle}>Trend Activity</h3>
          <p style={{ ...styles.panelCopy, textAlign: "left", marginBottom: "1rem" }}>{trends.latest_summary}</p>
          <div style={{ display: "flex", alignItems: "flex-end", gap: "0.75rem", minHeight: "160px" }}>
            {trends.points.map((point) => {
              const weighted = point.high_risk_threat_count + point.review_events + point.control_events;
              const height = Math.max(18, Math.round((weighted / trendMax) * 120));
              return (
                <div key={point.date} style={{ flex: 1, display: "grid", gap: "0.5rem", justifyItems: "center" }}>
                  <div style={styles.trendBar(height)} title={`${point.date}: ${weighted} activity weight`} />
                  <div style={{ color: "#94a3b8", fontSize: "0.75rem" }}>{point.date.slice(5)}</div>
                  <div style={{ color: "#e2e8f0", fontSize: "0.8rem", textAlign: "center" }}>
                    {point.snapshot_count} ver · {point.review_events} rev
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {isEmpty ? (
        <div className="dashboard-empty-state">
          <div className="dashboard-empty-icon">🛡️</div>
          <h3 className="dashboard-empty-title">
            Start Your First Security Review
          </h3>
          <p className="dashboard-empty-copy">
            Begin with a repo, PR, architecture document, or formal review scope.
            ThreatGenix will organize evidence, model the system, and surface
            ship/fix/verify decisions.
          </p>
          <button
            className="btn-create"
            onClick={() => navigate("/new")}
            title="Start your first security review"
          >
            Start Review
          </button>
        </div>
      ) : (
        <div className="dashboard-table-shell">
          {actionError && <p className="dashboard-action-error">{actionError}</p>}
          <table className="dashboard-model-table">
            <thead>
              <tr>
                <th>Application</th>
                <th>Classification</th>
                <th>Findings</th>
                <th data-col="updated">Updated</th>
                <th data-col="actions">Actions</th>
              </tr>
            </thead>
            <tbody>
              {models.map((m) => (
                <tr
                  key={m.id}
                  className="dashboard-model-row"
                  onClick={() => navigate(`/threat-models/${m.id}`)}
                >
                  <td className="dashboard-model-name-cell">
                    <Link
                      to={`/threat-models/${m.id}`}
                      className="dashboard-model-link"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {m.system_name}
                    </Link>
                  </td>
                  <td>
                    <span style={styles.badge(classificationColor(m.data_classification))}>
                      {m.data_classification}
                    </span>
                  </td>
                  <td>{m.threat_count}</td>
                  <td data-col="updated">
                    {new Date(m.updated_at).toLocaleDateString()}
                  </td>
                  <td className="dashboard-model-actions" data-col="actions">
                    <button
                      type="button"
                      className="dashboard-archive-btn"
                      onClick={(event) => {
                        event.stopPropagation();
                        void handleArchiveModel(m);
                      }}
                      disabled={archivingId === m.id}
                      aria-label={`Archive ${m.system_name}`}
                      title="Archive this security review"
                    >
                      {archivingId === m.id ? "Archiving..." : "Archive"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default DashboardPage;

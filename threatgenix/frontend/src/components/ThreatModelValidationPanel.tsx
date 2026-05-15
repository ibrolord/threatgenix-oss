import { useEffect, useMemo, useState } from "react";

import { api } from "../api/client";
import type {
  ArchitectureValidationSummary,
  AttackPathResponse,
  ScanCorrelationSummaryResponse,
} from "../types/api";

interface ThreatModelValidationPanelProps {
  threatModelId: string;
  refreshToken?: number;
}

function scoreTone(score: number): "good" | "warn" | "bad" {
  if (score >= 80) return "good";
  if (score >= 60) return "warn";
  return "bad";
}

function mappedEvidenceTone(summary: ArchitectureValidationSummary): "good" | "warn" {
  if (summary.discovered_components === 0) return "warn";
  return summary.mapped_discovered_components >= summary.discovered_components ? "good" : "warn";
}

function repositoryCoverageCopy(summary: ArchitectureValidationSummary): string {
  if (summary.discovered_repository_components === 0) {
    return "No repository components have been discovered from evidence yet.";
  }
  return "Repository evidence is mapped into the DFD.";
}

function cloudCoverageCopy(summary: ArchitectureValidationSummary): string {
  if (summary.discovered_cloud_services === 0) {
    return "No cloud services have been discovered from evidence yet.";
  }
  return "Cloud evidence is mapped into the DFD.";
}

export function ThreatModelValidationPanel({
  threatModelId,
  refreshToken = 0,
}: ThreatModelValidationPanelProps): JSX.Element {
  const [summary, setSummary] = useState<ArchitectureValidationSummary | null>(null);
  const [scanCorrelation, setScanCorrelation] = useState<ScanCorrelationSummaryResponse | null>(null);
  const [attackPaths, setAttackPaths] = useState<AttackPathResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const [nextSummary, latestCorrelation, nextAttackPaths] = await Promise.all([
          api.getValidationSummary(threatModelId),
          api
            .getLatestScanCorrelation(threatModelId)
            .catch((caught) => {
              if (caught instanceof Error && caught.message.includes("404")) {
                return null;
              }
              throw caught;
            }),
          api.getAttackPaths(threatModelId).catch((caught) => {
            if (caught instanceof Error && caught.message.includes("404")) {
              return [];
            }
            throw caught;
          }),
        ]);
        if (!cancelled) {
          setSummary(nextSummary);
          setScanCorrelation(latestCorrelation);
          setAttackPaths(nextAttackPaths);
        }
      } catch (caught) {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : "Failed to load validation summary");
          setScanCorrelation(null);
          setAttackPaths([]);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [threatModelId, refreshToken]);

  const metricCards = useMemo(() => {
    if (!summary) return [];
    return [
      { label: "Completeness", value: `${summary.completeness_score}%`, tone: scoreTone(summary.completeness_score) },
      { label: "Modeled Nodes", value: `${summary.modeled_components}`, tone: "good" as const },
      {
        label: "Discovered Components",
        value: `${summary.discovered_components}`,
        tone: summary.discovered_components > 0 ? ("good" as const) : ("warn" as const),
      },
      {
        label: "Mapped Evidence",
        value: `${summary.mapped_discovered_components}`,
        tone: mappedEvidenceTone(summary),
      },
      { label: "Latest Scan", value: summary.latest_scan_status ?? "none", tone: summary.latest_scan_status === "completed" ? "good" as const : "warn" as const },
      { label: "Correlated Findings", value: `${summary.correlated_scan_results}`, tone: summary.correlated_scan_results > 0 ? "good" as const : "warn" as const },
    ];
  }, [summary]);

  const sections = summary
    ? [
        { title: "Drift Flags", items: summary.drift_flags, empty: "No repository or cloud drift signals." },
        {
          title: "Unmapped Repository Components",
          items: summary.unmapped_repository_components,
          empty: repositoryCoverageCopy(summary),
        },
        {
          title: "Unmapped Cloud Services",
          items: summary.unmapped_cloud_services,
          empty: cloudCoverageCopy(summary),
        },
        { title: "Nodes Missing Scan Targets", items: summary.nodes_without_scan_targets, empty: "Every eligible node has a scan target." },
        { title: "Unvalidated Threats", items: summary.unvalidated_threats, empty: "Open threats are correlated to scan results." },
      ]
    : [];

  return (
    <section className="tm-section tm-validation-panel">
      <div className="tm-section-header">
        <div>
          <h4>Architecture Validation</h4>
          <p>Cross-check the DFD against evidence, scans, and unresolved drift signals.</p>
        </div>
      </div>

      {loading ? <p className="tm-muted">Loading architecture validation…</p> : null}
      {error ? <div className="tm-error-banner">{error}</div> : null}

      {summary ? (
        <>
          <div className="tm-validation-metrics">
            {metricCards.map((metric) => (
              <article key={metric.label} className={`tm-validation-card tm-validation-${metric.tone}`}>
                <span>{metric.label}</span>
                <strong>{metric.value}</strong>
              </article>
            ))}
          </div>

          <div className="tm-list">
            {sections.map((section) => (
              <article key={section.title} className="tm-list-item">
                <div className="tm-list-item-header">
                  <strong>{section.title}</strong>
                  <span className="tm-chip">{section.items.length}</span>
                </div>
                {section.items.length === 0 ? (
                  <p className="tm-muted">{section.empty}</p>
                ) : (
                  <ul className="tm-bullet-list">
                    {section.items.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                )}
              </article>
            ))}

            <article className="tm-list-item">
              <div className="tm-list-item-header">
                <strong>Latest Scan Correlation</strong>
                <span className="tm-chip">{scanCorrelation?.total_correlations ?? 0}</span>
              </div>
              {scanCorrelation ? (
                <div style={{ display: "grid", gap: "0.8rem" }}>
                  <div className="tm-validation-metrics">
                    <article className="tm-validation-card tm-validation-good">
                      <span>Confirmed</span>
                      <strong>{scanCorrelation.confirmed_count}</strong>
                    </article>
                    <article className="tm-validation-card tm-validation-warn">
                      <span>Mitigated</span>
                      <strong>{scanCorrelation.mitigated_count}</strong>
                    </article>
                    <article className="tm-validation-card tm-validation-warn">
                      <span>Not Found</span>
                      <strong>{scanCorrelation.not_found_count}</strong>
                    </article>
                    <article className="tm-validation-card tm-validation-bad">
                      <span>Unverifiable</span>
                      <strong>{scanCorrelation.unverifiable_count}</strong>
                    </article>
                  </div>
                  <p className="tm-muted" style={{ margin: 0 }}>
                    Latest completed scan:{" "}
                    {scanCorrelation.scan_completed_at
                      ? new Date(scanCorrelation.scan_completed_at).toLocaleString()
                      : "unknown"}
                  </p>
                  {scanCorrelation.entries.length > 0 ? (
                    <ul className="tm-bullet-list">
                      {scanCorrelation.entries.slice(0, 5).map((entry) => (
                        <li key={entry.threat_id}>
                          <strong>{entry.threat_display_id}</strong> {entry.scan_status}
                          {entry.matched_targets.length > 0
                            ? ` at ${entry.matched_targets.slice(0, 2).join(", ")}`
                            : ""}
                          {entry.templates.length > 0
                            ? ` via ${entry.templates.slice(0, 2).join(", ")}`
                            : ""}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="tm-muted" style={{ margin: 0 }}>
                      The latest completed scan did not return any correlated threat results.
                    </p>
                  )}
                </div>
              ) : (
                <p className="tm-muted">Run a completed scan to populate threat-correlation evidence.</p>
              )}
            </article>

            <article className="tm-list-item">
              <div className="tm-list-item-header">
                <strong>Attack Paths</strong>
                <span className="tm-chip">{attackPaths.length}</span>
              </div>
              {attackPaths.length > 0 ? (
                <div style={{ display: "grid", gap: "0.8rem" }}>
                  {attackPaths.map((path) => (
                    <div key={path.id} className="tm-note-card">
                      <div className="tm-list-item-header">
                        <strong>{path.title}</strong>
                        <span className="tm-chip">score {path.risk_score}</span>
                      </div>
                      <p className="tm-muted" style={{ margin: 0 }}>{path.summary}</p>
                      <p className="tm-muted" style={{ margin: 0 }}>
                        Path: {path.path_nodes.map((step) => step.label).join(" -> ")}
                      </p>
                      <p className="tm-muted" style={{ margin: 0 }}>
                        Boundary crossings: {path.boundary_crossings}
                      </p>
                      <ul className="tm-bullet-list">
                        {path.supporting_threats.map((threat) => (
                          <li key={threat.id}>
                            <strong>{threat.display_id}</strong> · {threat.severity} · {threat.stride_category}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="tm-muted">No meaningful ingress-to-target attack chains are currently modeled.</p>
              )}
            </article>
          </div>
        </>
      ) : null}
    </section>
  );
}

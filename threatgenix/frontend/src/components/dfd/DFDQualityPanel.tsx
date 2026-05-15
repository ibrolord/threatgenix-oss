import type { DFDQualityGateSummary } from "../../types/api";

interface DFDQualityPanelProps {
  summary: DFDQualityGateSummary | null;
  loading?: boolean;
}

export function DFDQualityPanel({
  summary,
  loading = false,
}: DFDQualityPanelProps): JSX.Element {
  if (loading) {
    return (
      <section className="tm-section">
        <h3>DFD Quality Gates</h3>
        <div className="dfd-quality-panel">
          <p className="dfd-quality-empty">Checking DFD quality…</p>
        </div>
      </section>
    );
  }

  if (!summary || summary.results.length === 0) {
    return (
      <section className="tm-section">
        <h3>DFD Quality Gates</h3>
        <div className="dfd-quality-panel">
          <p className="dfd-quality-empty">
            No blocking or warning DFD quality gates are currently open.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="tm-section">
      <div className="dfd-quality-header">
        <h3>DFD Quality Gates</h3>
        <div className="dfd-quality-summary">
          <span className="dfd-quality-chip dfd-quality-chip-block">
            {summary.blocking_count} blocking
          </span>
          <span className="dfd-quality-chip dfd-quality-chip-warn">
            {summary.warning_count} warnings
          </span>
        </div>
      </div>
      <div className="dfd-quality-panel">
        {summary.results.map((result) => (
          <article
            key={result.gate_id}
            className={`dfd-quality-item dfd-quality-item-${result.severity}`}
          >
            <div className="dfd-quality-item-head">
              <strong>{result.title}</strong>
              <span className={`dfd-quality-chip dfd-quality-chip-${result.severity}`}>
                {result.severity === "block" ? "Blocking" : "Warning"}
              </span>
            </div>
            <p>{result.message}</p>
            {(result.affected_node_ids.length > 0 ||
              result.affected_edge_ids.length > 0 ||
              result.affected_boundary_ids.length > 0) && (
              <p className="dfd-quality-affected">
                Affects {result.affected_node_ids.length} node
                {result.affected_node_ids.length === 1 ? "" : "s"}, {result.affected_edge_ids.length} edge
                {result.affected_edge_ids.length === 1 ? "" : "s"}, {result.affected_boundary_ids.length} boundar
                {result.affected_boundary_ids.length === 1 ? "y" : "ies"}.
              </p>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}

import { useMemo, useState } from "react";
import type { FC } from "react";

import type { ScanFinding } from "../../types/api";

export interface ThreatCorrelationViewProps {
  findings: ScanFinding[];
}

const UNCATEGORIZED = "Unclassified";

interface GroupedFindings {
  category: string;
  findings: ScanFinding[];
}

function groupByStride(findings: ScanFinding[]): GroupedFindings[] {
  const groups = new Map<string, ScanFinding[]>();
  for (const finding of findings) {
    const key = finding.bound_stride_category || UNCATEGORIZED;
    const bucket = groups.get(key);
    if (bucket) {
      bucket.push(finding);
    } else {
      groups.set(key, [finding]);
    }
  }
  return Array.from(groups.entries()).map(([category, bucket]) => ({
    category,
    findings: bucket,
  }));
}

const ThreatCorrelationView: FC<ThreatCorrelationViewProps> = ({ findings }) => {
  const [showSuppressed, setShowSuppressed] = useState(false);

  const { activeGroups, suppressedCount } = useMemo(() => {
    const active: ScanFinding[] = [];
    let suppressed = 0;
    for (const finding of findings) {
      if (finding.false_positive) {
        suppressed += 1;
        if (showSuppressed) {
          active.push(finding);
        }
      } else {
        active.push(finding);
      }
    }
    return {
      activeGroups: groupByStride(active),
      suppressedCount: suppressed,
    };
  }, [findings, showSuppressed]);

  if (findings.length === 0) {
    return null;
  }

  return (
    <section
      className="validation-lab-panel validation-lab-panel-full"
      aria-label="Threat correlation by STRIDE category"
    >
      <div className="validation-lab-panel-header">
        <div>
          <p className="validation-lab-kicker">Threat correlation</p>
          <h2>Evidence grouped by STRIDE category</h2>
        </div>
        {suppressedCount > 0 ? (
          <button
            type="button"
            className="tm-secondary-btn"
            onClick={() => setShowSuppressed((v) => !v)}
          >
            {showSuppressed
              ? `Hide suppressed (${suppressedCount})`
              : `Show suppressed (${suppressedCount})`}
          </button>
        ) : null}
      </div>

      {activeGroups.length === 0 ? (
        <p className="validation-lab-empty-text">
          No findings to correlate.
        </p>
      ) : (
        <div className="validation-lab-correlation-groups">
          {activeGroups.map((group) => (
            <article key={group.category} className="validation-lab-correlation-group">
              <header className="validation-lab-correlation-group-header">
                <h3>{group.category}</h3>
                <span className="validation-lab-correlation-count">
                  {group.findings.length} finding{group.findings.length === 1 ? "" : "s"}
                </span>
              </header>
              <ul className="validation-lab-correlation-list">
                {group.findings.map((finding) => {
                  const isLowConfidence = finding.binding_confidence === "low";
                  const isSuppressed = !!finding.false_positive;
                  const itemClass = [
                    "validation-lab-correlation-item",
                    isLowConfidence ? "validation-lab-correlation-item-muted" : "",
                    isSuppressed ? "validation-lab-correlation-item-suppressed" : "",
                  ]
                    .filter(Boolean)
                    .join(" ");
                  return (
                    <li key={finding.id} className={itemClass}>
                      <div className="validation-lab-correlation-title">
                        {finding.template_name}
                        {isLowConfidence ? (
                          <span className="validation-lab-correlation-low"> (low confidence)</span>
                        ) : null}
                      </div>
                      <div className="validation-lab-correlation-badges">
                        {finding.tool_name ? (
                          <span className="tm-tag">{finding.tool_name}</span>
                        ) : null}
                        <span className={`tm-tag tm-tag-${(finding.severity || "unknown").toLowerCase()}`}>
                          {finding.severity}
                        </span>
                        {finding.binding_confidence ? (
                          <span className="tm-tag">{finding.binding_confidence} confidence</span>
                        ) : null}
                        {finding.attack_technique ? (
                          <span className="tm-tag tm-tag-attack">{finding.attack_technique}</span>
                        ) : null}
                        {isSuppressed ? (
                          <span className="tm-tag tm-tag-muted">suppressed</span>
                        ) : null}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </article>
          ))}
        </div>
      )}
    </section>
  );
};

export default ThreatCorrelationView;

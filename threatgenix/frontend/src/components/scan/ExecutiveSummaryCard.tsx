import type { FC } from "react";

export interface ExecutiveSummaryCardProps {
  confirmed: number;
  suppressed: number;
  newThreats: number;
  highConfidence: number;
}

type Tone = "critical" | "success" | undefined;

interface Stat {
  label: string;
  value: number;
  tone: Tone;
}

/**
 * Single-row executive summary of binder output: how many findings were
 * confirmed by evidence, surfaced as new threats, were high-confidence, and
 * were suppressed as low-signal noise. Reuses the existing dashboard
 * stat-card classes (dashboard-cards-row / dashboard-summary-card / -label /
 * -value plus the -critical and -success tone modifiers) so it inherits the
 * design system without introducing new CSS.
 */
const ExecutiveSummaryCard: FC<ExecutiveSummaryCardProps> = ({
  confirmed,
  suppressed,
  newThreats,
  highConfidence,
}) => {
  const stats: Stat[] = [
    { label: "Threats Confirmed by Evidence", value: confirmed, tone: confirmed > 0 ? "success" : undefined },
    { label: "New Threats Found", value: newThreats, tone: newThreats > 0 ? "critical" : undefined },
    { label: "High Confidence", value: highConfidence, tone: undefined },
    { label: "Suppressed (Low Signal)", value: suppressed, tone: undefined },
  ];

  return (
    <section
      className="validation-lab-panel validation-lab-panel-full"
      aria-label="Executive summary"
    >
      <div className="validation-lab-panel-header">
        <div>
          <p className="validation-lab-kicker">Executive summary</p>
          <h2>Evidence-bound threat overview</h2>
        </div>
      </div>
      <div className="dashboard-cards-row">
        {stats.map((stat) => {
          const cardClass = stat.tone
            ? `dashboard-summary-card dashboard-summary-card-${stat.tone}`
            : "dashboard-summary-card";
          const labelClass = stat.tone === "critical"
            ? "dashboard-summary-label dashboard-summary-label-critical"
            : "dashboard-summary-label";
          const valueClass = stat.tone
            ? `dashboard-summary-value dashboard-summary-value-${stat.tone}`
            : "dashboard-summary-value";
          return (
            <div key={stat.label} className={cardClass}>
              <div className={labelClass}>{stat.label}</div>
              <div className={valueClass}>{stat.value}</div>
            </div>
          );
        })}
      </div>
    </section>
  );
};

export default ExecutiveSummaryCard;

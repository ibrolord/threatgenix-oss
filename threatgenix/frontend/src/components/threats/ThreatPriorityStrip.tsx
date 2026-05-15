import type { ThreatResponse } from "../../types/api";

interface ThreatPriorityStripProps {
  threats: ThreatResponse[];
  onThreatClick: (threat: ThreatResponse) => void;
}

const STRIDE_SHORT: Record<string, string> = {
  Spoofing: "Spoof",
  Tampering: "Tamper",
  Repudiation: "Repud",
  "Information Disclosure": "InfoDisc",
  "Denial of Service": "DoS",
  "Elevation of Privilege": "EoP",
};

const STRIDE_COLORS: Record<string, string> = {
  Spoofing: "stride-spoofing",
  Tampering: "stride-tampering",
  Repudiation: "stride-repudiation",
  "Information Disclosure": "stride-info-disclosure",
  "Denial of Service": "stride-dos",
  "Elevation of Privilege": "stride-eop",
};

const QUALIFICATION_CLASSES: Record<string, string> = {
  Priority: "qualification-priority",
  Investigate: "qualification-investigate",
  Review: "qualification-review",
  "Low Signal": "qualification-low-signal",
};

export function ThreatPriorityStrip({ threats, onThreatClick }: ThreatPriorityStripProps) {
  const top = threats
    .filter((t) => t.status === "Open" && t.qualification_score !== null)
    .sort((a, b) => (b.qualification_score ?? 0) - (a.qualification_score ?? 0))
    .slice(0, 5);

  if (top.length === 0) return null;

  return (
    <div className="priority-strip">
      <div className="priority-strip-header">
        <span className="priority-strip-title">Top threats to investigate</span>
        <span className="priority-strip-subtitle">Open · sorted by qualification score</span>
      </div>
      <div className="priority-strip-cards">
        {top.map((threat) => (
          <button
            key={threat.id}
            className="priority-card"
            onClick={() => onThreatClick(threat)}
            title={threat.description}
          >
            <div className="priority-card-header">
              <span className="priority-card-id">{threat.display_id}</span>
              {threat.qualification_label && (
                <span className={`threat-badge ${QUALIFICATION_CLASSES[threat.qualification_label] ?? ""}`}>
                  {threat.qualification_label}
                </span>
              )}
            </div>
            <p className="priority-card-desc">
              {threat.description.length > 70
                ? threat.description.slice(0, 70) + "…"
                : threat.description}
            </p>
            <div className="priority-card-footer">
              <span className={`threat-badge ${STRIDE_COLORS[threat.stride_category] ?? ""}`}>
                {STRIDE_SHORT[threat.stride_category] ?? threat.stride_category}
              </span>
              <span className="priority-card-score">
                Score {threat.qualification_score}
              </span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

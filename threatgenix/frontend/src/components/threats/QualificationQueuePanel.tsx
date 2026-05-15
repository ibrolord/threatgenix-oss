import { useCallback, useEffect, useRef, useState } from "react";
import type {
  FalsePositiveReason,
  QualificationProgressResponse,
  ThreatClusterResponse,
  ThreatResponse,
} from "../../types/api";
import { api } from "../../api/client";

interface QualificationQueuePanelProps {
  threatModelId: string;
  onClose: () => void;
  onThreatUpdated: (updated: ThreatResponse) => void;
}

const FALSE_POSITIVE_REASONS: { value: FalsePositiveReason; label: string }[] = [
  { value: "compensating_control", label: "Compensating control in place" },
  { value: "not_applicable", label: "Not applicable to this architecture" },
  { value: "duplicate", label: "Duplicate of another threat" },
  { value: "architecture_mismatch", label: "Architecture mismatch" },
  { value: "accepted_risk", label: "Accepted risk" },
  { value: "other", label: "Other" },
];

const SCORE_LABELS: Record<number, string> = {
  0: "No risk",
  25: "Low",
  50: "Medium",
  75: "High",
  100: "Critical",
};

function scoreToBucket(score: number): string {
  if (score >= 70) return "Priority";
  if (score >= 45) return "Investigate";
  if (score >= 20) return "Review";
  return "Low Signal";
}

function blendScores(autoScore: number, analystScore: number): number {
  return Math.min(100, Math.max(0, Math.round(autoScore * 0.4 + analystScore * 0.6)));
}

export function QualificationQueuePanel({
  threatModelId,
  onClose,
  onThreatUpdated,
}: QualificationQueuePanelProps) {
  const [currentThreat, setCurrentThreat] = useState<ThreatResponse | null>(null);
  const [progress, setProgress] = useState<QualificationProgressResponse | null>(null);
  const [clusters, setClusters] = useState<ThreatClusterResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);

  const [analystScore, setAnalystScore] = useState(50);
  const [rationale, setRationale] = useState("");
  const [showDismissReasons, setShowDismissReasons] = useState(false);
  const [selectedFPReason, setSelectedFPReason] = useState<FalsePositiveReason | null>(null);

  const sliderRef = useRef<HTMLInputElement>(null);

  const fetchNext = useCallback(async () => {
    setLoading(true);
    setShowDismissReasons(false);
    setSelectedFPReason(null);
    setRationale("");
    try {
      const [next, prog, clusterList] = await Promise.all([
        api.getQualificationNext(threatModelId),
        api.getQualificationProgress(threatModelId),
        api.listClusters(threatModelId),
      ]);
      setCurrentThreat(next);
      setProgress(prog);
      setClusters(clusterList);
      if (next) {
        // Seed slider from auto_score or existing qualification_score
        const seed = next.auto_score ?? next.qualification_score ?? 50;
        setAnalystScore(seed);
      } else {
        setDone(true);
      }
    } finally {
      setLoading(false);
    }
  }, [threatModelId]);

  useEffect(() => {
    fetchNext();
  }, [fetchNext]);

  const handleAction = useCallback(
    async (action: "confirm" | "dismiss" | "defer") => {
      if (!currentThreat || submitting) return;
      if (action === "dismiss" && !selectedFPReason) {
        setShowDismissReasons(true);
        return;
      }
      setSubmitting(true);
      try {
        const updated = await api.qualifyThreat(threatModelId, currentThreat.id, {
          analyst_score: analystScore,
          action,
          analyst_score_rationale: rationale || null,
          false_positive_reason: action === "dismiss" ? selectedFPReason : null,
        });
        onThreatUpdated(updated);
        await fetchNext();
      } finally {
        setSubmitting(false);
      }
    },
    [
      analystScore,
      currentThreat,
      fetchNext,
      onThreatUpdated,
      rationale,
      selectedFPReason,
      submitting,
      threatModelId,
    ],
  );

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (submitting || loading) return;
      // Don't fire shortcuts when typing in textarea
      if (e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLInputElement) return;

      switch (e.key) {
        case "1": setAnalystScore(25); break;
        case "2": setAnalystScore(50); break;
        case "3": setAnalystScore(75); break;
        case "4": setAnalystScore(100); break;
        case "Enter": void handleAction("confirm"); break;
        case "d":
        case "D":
          setShowDismissReasons((v) => !v);
          break;
        case "s":
        case "S":
          void handleAction("defer");
          break;
        case "Escape":
          onClose();
          break;
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [handleAction, loading, onClose, submitting]);

  const clusterForThreat = currentThreat
    ? clusters.find((c) => c.id === currentThreat.cluster_id)
    : null;

  const blended = currentThreat
    ? blendScores(currentThreat.auto_score ?? currentThreat.qualification_score ?? 0, analystScore)
    : 0;

  if (loading && !currentThreat && !done) {
    return (
      <div className="qualification-panel">
        <div className="qualification-panel-loading">Loading qualification queue…</div>
      </div>
    );
  }

  if (done || (!loading && !currentThreat)) {
    return (
      <div className="qualification-panel">
        <div className="qualification-panel-header">
          <button className="qual-close-btn" onClick={onClose}>← Back to threats</button>
          <span className="qual-title">Qualification Complete</span>
        </div>
        <div className="qualification-complete">
          {progress && (
            <>
              <div className="qual-complete-stat">{progress.qualified} threats qualified</div>
              <div className="qual-complete-sub">
                {progress.clusters_resolved} of {progress.cluster_count} clusters resolved
              </div>
            </>
          )}
          <button className="qual-btn-confirm" onClick={onClose}>Return to Threat Table</button>
        </div>
      </div>
    );
  }

  if (!currentThreat) return null;

  const autoScore = currentThreat.auto_score ?? currentThreat.qualification_score ?? 0;

  return (
    <div className="qualification-panel">
      {/* Header with progress */}
      <div className="qualification-panel-header">
        <button className="qual-close-btn" onClick={onClose}>← Back</button>
        <span className="qual-title">Qualify Threats</span>
        {progress && (
          <div className="qual-progress-bar-wrap">
            <div className="qual-progress-bar">
              <div
                className="qual-progress-fill"
                style={{ width: `${progress.progress_pct}%` }}
              />
            </div>
            <span className="qual-progress-label">
              {progress.qualified} / {progress.total_open} ({progress.progress_pct}%)
            </span>
          </div>
        )}
        <span className="qual-shortcuts-hint" title="Keyboard shortcuts: 1-4 score, Enter confirm, D dismiss, S skip, Esc close">?</span>
      </div>

      <div className="qualification-body">
        {/* Left: Threat context */}
        <div className="qual-threat-context">
          <div className="qual-threat-header">
            <span className="qual-display-id">{currentThreat.display_id}</span>
            <span className={`threat-badge stride-${currentThreat.stride_category.toLowerCase().replace(/\s+/g, "-")}`}>
              {currentThreat.stride_category}
            </span>
            <span className={`threat-badge severity-${currentThreat.severity.toLowerCase()}`}>
              {currentThreat.severity}
            </span>
            {currentThreat.source !== "Rules" && (
              <span className="threat-badge source-badge">{currentThreat.source}</span>
            )}
          </div>

          <p className="qual-description">{currentThreat.description}</p>

          {currentThreat.relevance_rationale && (
            <div className="qual-rationale-box">
              <span className="qual-rationale-label">Why This Matters</span>
              <p className="qual-rationale-text">{currentThreat.relevance_rationale}</p>
            </div>
          )}

          {/* Cluster indicator */}
          {clusterForThreat && (
            <div className="qual-cluster-badge">
              <span className="qual-cluster-icon">⬡</span>
              <span>
                Cluster: <strong>{clusterForThreat.cluster_label}</strong>
                {" "}({clusterForThreat.threat_count} threats)
              </span>
            </div>
          )}

          {/* Scan status */}
          {currentThreat.scan_status && (
            <div className={`qual-scan-badge qual-scan-${currentThreat.scan_status}`}>
              Scan: {currentThreat.scan_status}
            </div>
          )}

          {/* Compliance controls */}
          {currentThreat.qualification_note && (
            <div className="qual-note-box">
              <span className="qual-note-label">Previous note</span>
              <p className="qual-note-text">{currentThreat.qualification_note}</p>
            </div>
          )}
        </div>

        {/* Right: Qualification controls */}
        <div className="qual-controls">
          <div className="qual-score-section">
            <div className="qual-score-row">
              <span className="qual-score-label">Auto Score</span>
              <span className="qual-score-value qual-score-auto">{autoScore}</span>
            </div>

            <div className="qual-analyst-score-section">
              <label className="qual-score-label" htmlFor="analyst-score-slider">
                Analyst Score
              </label>
              <div className="qual-slider-wrap">
                <input
                  id="analyst-score-slider"
                  ref={sliderRef}
                  type="range"
                  min={0}
                  max={100}
                  step={1}
                  value={analystScore}
                  onChange={(e) => setAnalystScore(Number(e.target.value))}
                  className="qual-slider"
                />
                <div className="qual-slider-ticks">
                  {[0, 25, 50, 75, 100].map((v) => (
                    <button
                      key={v}
                      className={`qual-tick-btn ${analystScore === v ? "active" : ""}`}
                      onClick={() => setAnalystScore(v)}
                    >
                      {SCORE_LABELS[v]}
                    </button>
                  ))}
                </div>
              </div>
              <div className="qual-score-display">
                <span className="qual-score-value">{analystScore}</span>
                <span className="qual-score-bucket">{scoreToBucket(analystScore)}</span>
              </div>
            </div>

            <div className="qual-blend-row">
              <span className="qual-blend-label">Final (blended)</span>
              <span className={`qual-blend-value qual-blend-${scoreToBucket(blended).toLowerCase().replace(" ", "-")}`}>
                {blended} · {scoreToBucket(blended)}
              </span>
            </div>
          </div>

          <div className="qual-rationale-section">
            <label className="qual-score-label" htmlFor="qual-rationale">
              Rationale <span className="qual-optional">(optional)</span>
            </label>
            <textarea
              id="qual-rationale"
              className="qual-rationale-input"
              placeholder="Why did you set this score?"
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              maxLength={1000}
              rows={3}
            />
          </div>

          {/* Action buttons */}
          <div className="qual-actions">
            <button
              className="qual-btn-confirm"
              onClick={() => handleAction("confirm")}
              disabled={submitting}
              title="Confirm and next (Enter)"
            >
              {submitting ? "Saving…" : "Confirm →"}
            </button>
            <button
              className="qual-btn-defer"
              onClick={() => handleAction("defer")}
              disabled={submitting}
              title="Skip for now (S)"
            >
              Skip
            </button>
            <button
              className="qual-btn-dismiss"
              onClick={() => setShowDismissReasons((v) => !v)}
              disabled={submitting}
              title="Dismiss as false positive (D)"
            >
              Dismiss
            </button>
          </div>

          {showDismissReasons && (
            <div className="qual-fp-reasons">
              <span className="qual-fp-label">False positive reason:</span>
              {FALSE_POSITIVE_REASONS.map(({ value, label }) => (
                <button
                  key={value}
                  className={`qual-fp-option ${selectedFPReason === value ? "selected" : ""}`}
                  onClick={() => setSelectedFPReason(value)}
                >
                  {label}
                </button>
              ))}
              {selectedFPReason && (
                <button
                  className="qual-btn-dismiss-confirm"
                  onClick={() => handleAction("dismiss")}
                  disabled={submitting}
                >
                  Confirm Dismiss
                </button>
              )}
            </div>
          )}

          <div className="qual-shortcuts-legend">
            <span>1–4 score</span>
            <span>Enter confirm</span>
            <span>S skip</span>
            <span>D dismiss</span>
            <span>Esc close</span>
          </div>
        </div>
      </div>
    </div>
  );
}

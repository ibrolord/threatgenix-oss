import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../api/client";
import type {
  ThreatModelControlCreate,
  ThreatModelControlResponse,
  ThreatModelReviewResponse,
  ThreatModelVersionDiffResponse,
  ThreatModelVersionResponse,
  ThreatResponse,
} from "../types/api";

interface ThreatModelGovernancePanelProps {
  threatModelId: string;
  refreshToken?: number;
  threats: ThreatResponse[];
}

const CONTROL_CATEGORIES = ["preventive", "detective", "corrective", "compensating"] as const;
const CONTROL_STATUSES = ["planned", "implemented", "partial", "deferred"] as const;
const REVIEW_STATUSES = ["pending", "approved", "changes_requested"] as const;

function formatRelativeDate(value: string): string {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function emptyControlForm(): ThreatModelControlCreate {
  return {
    title: "",
    description: "",
    category: "preventive",
    status: "planned",
    owner: "",
    evidence: "",
    mapped_threat_ids: [],
  };
}

export function ThreatModelGovernancePanel({
  threatModelId,
  refreshToken = 0,
  threats,
}: ThreatModelGovernancePanelProps): JSX.Element {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [versions, setVersions] = useState<ThreatModelVersionResponse[]>([]);
  const [reviews, setReviews] = useState<ThreatModelReviewResponse[]>([]);
  const [controls, setControls] = useState<ThreatModelControlResponse[]>([]);
  const [diff, setDiff] = useState<ThreatModelVersionDiffResponse | null>(null);
  const [versionName, setVersionName] = useState("");
  const [versionDescription, setVersionDescription] = useState("");
  const [leftSnapshotId, setLeftSnapshotId] = useState("");
  const [rightSnapshotId, setRightSnapshotId] = useState("");
  const [reviewSnapshotId, setReviewSnapshotId] = useState("");
  const [reviewTitle, setReviewTitle] = useState("");
  const [reviewAssignee, setReviewAssignee] = useState("");
  const [reviewCommentDrafts, setReviewCommentDrafts] = useState<Record<string, string>>({});
  const [controlForm, setControlForm] = useState<ThreatModelControlCreate>(emptyControlForm());

  const threatOptions = useMemo(
    () =>
      threats.map((threat) => ({
        id: threat.id,
        label: `${threat.display_id} · ${threat.description}`,
      })),
    [threats]
  );

  const loadGovernance = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [loadedVersions, loadedReviews, loadedControls] = await Promise.all([
        api.getModelVersions(threatModelId),
        api.getModelReviews(threatModelId),
        api.getControlLibrary(threatModelId),
      ]);
      setVersions(loadedVersions);
      setReviews(loadedReviews);
      setControls(loadedControls);
      setLeftSnapshotId((current) =>
        loadedVersions.some((version) => version.id === current) ? current : (loadedVersions[0]?.id ?? "")
      );
      setRightSnapshotId((current) =>
        current && loadedVersions.some((version) => version.id === current) ? current : ""
      );
      setReviewSnapshotId((current) =>
        loadedVersions.some((version) => version.id === current) ? current : (loadedVersions[0]?.id ?? "")
      );
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to load governance");
    } finally {
      setLoading(false);
    }
  }, [threatModelId]);

  useEffect(() => {
    void loadGovernance();
  }, [loadGovernance, refreshToken]);

  const handleCreateSnapshot = async () => {
    if (!versionName.trim()) {
      setError("Snapshot name is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await api.createModelVersion(threatModelId, {
        name: versionName.trim(),
        description: versionDescription.trim(),
      });
      setVersions((current) => [created, ...current]);
      setVersionName("");
      setVersionDescription("");
      setLeftSnapshotId(created.id);
      if (!reviewSnapshotId) {
        setReviewSnapshotId(created.id);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to create snapshot");
    } finally {
      setBusy(false);
    }
  };

  const handleDiff = async () => {
    if (!leftSnapshotId) {
      setError("Choose a baseline snapshot first.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const nextDiff = await api.diffModelVersions(threatModelId, {
        left_snapshot_id: leftSnapshotId,
        right_snapshot_id: rightSnapshotId || null,
      });
      setDiff(nextDiff);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to compare versions");
    } finally {
      setBusy(false);
    }
  };

  const handleCreateReview = async () => {
    if (!reviewSnapshotId || !reviewTitle.trim()) {
      setError("Pick a snapshot and add a review title.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await api.createModelReview(threatModelId, {
        snapshot_id: reviewSnapshotId,
        title: reviewTitle.trim(),
        assignee: reviewAssignee.trim() || null,
      });
      setReviews((current) => [created, ...current]);
      setReviewTitle("");
      setReviewAssignee("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to create review");
    } finally {
      setBusy(false);
    }
  };

  const handleReviewUpdate = async (
    reviewId: string,
    patch: { status?: "pending" | "approved" | "changes_requested"; assignee?: string | null; comment?: string | null }
  ) => {
    setBusy(true);
    setError(null);
    try {
      const updated = await api.updateModelReview(threatModelId, reviewId, patch);
      setReviews((current) => current.map((review) => (review.id === reviewId ? updated : review)));
      if (patch.comment) {
        setReviewCommentDrafts((current) => ({ ...current, [reviewId]: "" }));
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to update review");
    } finally {
      setBusy(false);
    }
  };

  const handleCreateControl = async () => {
    if (!controlForm.title.trim()) {
      setError("Control title is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await api.createControlLibraryEntry(threatModelId, {
        ...controlForm,
        title: controlForm.title.trim(),
        description: controlForm.description?.trim() ?? "",
        owner: controlForm.owner?.trim() || null,
        evidence: controlForm.evidence?.trim() || null,
      });
      setControls((current) => [created, ...current]);
      setControlForm(emptyControlForm());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to create control");
    } finally {
      setBusy(false);
    }
  };

  const handleQuickControlPatch = async (
    controlId: string,
    patch: Partial<ThreatModelControlCreate>
  ) => {
    setBusy(true);
    setError(null);
    try {
      const updated = await api.updateControlLibraryEntry(threatModelId, controlId, patch);
      setControls((current) => current.map((control) => (control.id === controlId ? updated : control)));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to update control");
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteControl = async (controlId: string) => {
    if (!window.confirm("Delete this control library entry?")) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.deleteControlLibraryEntry(threatModelId, controlId);
      setControls((current) => current.filter((control) => control.id !== controlId));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to delete control");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="tm-inspector-stack">
      <section className="tm-section tm-governance-panel">
        <div className="tm-section-header">
          <div>
            <h4>Governance</h4>
            <p>Snapshots, review sign-off, and reusable controls for this model.</p>
          </div>
          <button type="button" className="tm-secondary-btn" onClick={() => void loadGovernance()} disabled={busy}>
            Refresh
          </button>
        </div>

        {loading ? <p className="tm-muted">Loading governance data…</p> : null}
        {error ? <div className="tm-error-banner">{error}</div> : null}

        <div className="tm-governance-grid">
          <div className="tm-governance-card">
            <h5>Named Snapshots</h5>
            <div className="tm-field-list">
              <input
                className="tm-text-input"
                placeholder="Version name"
                value={versionName}
                onChange={(event) => setVersionName(event.target.value)}
              />
              <textarea
                className="tm-textarea-input"
                placeholder="What changed in this version?"
                rows={3}
                value={versionDescription}
                onChange={(event) => setVersionDescription(event.target.value)}
              />
              <button type="button" className="tm-primary-btn" onClick={handleCreateSnapshot} disabled={busy}>
                Save Snapshot
              </button>
            </div>
            <div className="tm-list">
              {versions.length === 0 ? <p className="tm-muted">No saved snapshots yet.</p> : null}
              {versions.map((version) => (
                <article key={version.id} className="tm-list-item">
                  <div className="tm-list-item-header">
                    <strong>{version.name}</strong>
                    <span className="tm-chip">{version.threat_count} threats</span>
                  </div>
                  <p className="tm-muted">
                    {version.node_count} nodes · {version.edge_count} flows · {version.boundary_count} boundaries
                  </p>
                  <p className="tm-muted">
                    {formatRelativeDate(version.created_at)} · {version.created_by}
                  </p>
                </article>
              ))}
            </div>
          </div>

          <div className="tm-governance-card">
            <h5>Visual Diff</h5>
            <div className="tm-field-list">
              <label className="tm-label">
                Baseline
                <select className="tm-select-input" value={leftSnapshotId} onChange={(event) => setLeftSnapshotId(event.target.value)}>
                  <option value="">Choose snapshot</option>
                  {versions.map((version) => (
                    <option key={version.id} value={version.id}>
                      {version.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className="tm-label">
                Compare to
                <select className="tm-select-input" value={rightSnapshotId} onChange={(event) => setRightSnapshotId(event.target.value)}>
                  <option value="">Current model</option>
                  {versions
                    .filter((version) => version.id !== leftSnapshotId)
                    .map((version) => (
                      <option key={version.id} value={version.id}>
                        {version.name}
                      </option>
                    ))}
                </select>
              </label>
              <button type="button" className="tm-primary-btn" onClick={handleDiff} disabled={busy || !leftSnapshotId}>
                Compare
              </button>
            </div>
            {diff ? (
              <div className="tm-diff-panel">
                <div className="tm-diff-summary">
                  <span className="tm-chip">{diff.left_label}</span>
                  <span className="tm-muted">→</span>
                  <span className="tm-chip">{diff.right_label}</span>
                </div>
                <div className="tm-diff-metrics">
                  <span className="tm-diff-metric">Nodes {diff.node_delta >= 0 ? "+" : ""}{diff.node_delta}</span>
                  <span className="tm-diff-metric">Flows {diff.edge_delta >= 0 ? "+" : ""}{diff.edge_delta}</span>
                  <span className="tm-diff-metric">Boundaries {diff.boundary_delta >= 0 ? "+" : ""}{diff.boundary_delta}</span>
                  <span className="tm-diff-metric">Threats {diff.threat_delta >= 0 ? "+" : ""}{diff.threat_delta}</span>
                </div>
                <div className="tm-inline-columns">
                  <div>
                    <h6>Added Nodes</h6>
                    <ul>{diff.added_nodes.map((item) => <li key={item}>{item}</li>)}</ul>
                  </div>
                  <div>
                    <h6>Removed Nodes</h6>
                    <ul>{diff.removed_nodes.map((item) => <li key={item}>{item}</li>)}</ul>
                  </div>
                  <div>
                    <h6>Added Threats</h6>
                    <ul>{diff.added_threats.map((item) => <li key={item}>{item}</li>)}</ul>
                  </div>
                  <div>
                    <h6>Removed Threats</h6>
                    <ul>{diff.removed_threats.map((item) => <li key={item}>{item}</li>)}</ul>
                  </div>
                </div>
              </div>
            ) : (
              <p className="tm-muted">Compare a saved version against the current model or another snapshot.</p>
            )}
          </div>
        </div>

        <div className="tm-governance-grid">
          <div className="tm-governance-card">
            <h5>Reviews & Sign-Off</h5>
            <div className="tm-field-list">
              <label className="tm-label">
                Snapshot
                <select className="tm-select-input" value={reviewSnapshotId} onChange={(event) => setReviewSnapshotId(event.target.value)}>
                  <option value="">Choose snapshot</option>
                  {versions.map((version) => (
                    <option key={version.id} value={version.id}>
                      {version.name}
                    </option>
                  ))}
                </select>
              </label>
              <input
                className="tm-text-input"
                placeholder="Review title"
                value={reviewTitle}
                onChange={(event) => setReviewTitle(event.target.value)}
              />
              <input
                className="tm-text-input"
                placeholder="Assignee email"
                value={reviewAssignee}
                onChange={(event) => setReviewAssignee(event.target.value)}
              />
              <button type="button" className="tm-primary-btn" onClick={handleCreateReview} disabled={busy}>
                Create Review
              </button>
            </div>
            <div className="tm-list">
              {reviews.length === 0 ? <p className="tm-muted">No review workflow has been opened yet.</p> : null}
              {reviews.map((review) => (
                <article key={review.id} className="tm-list-item">
                  <div className="tm-list-item-header">
                    <strong>{review.title}</strong>
                    <span className={`tm-status-pill tm-status-${review.status.replace("_", "-")}`}>
                      {review.status.replace("_", " ")}
                    </span>
                  </div>
                  <p className="tm-muted">
                    Snapshot {versions.find((version) => version.id === review.snapshot_id)?.name ?? review.snapshot_id}
                  </p>
                  <p className="tm-muted">
                    Assignee: {review.assignee ?? "Unassigned"} · Updated {formatRelativeDate(review.updated_at)}
                  </p>
                  {review.signed_off_at ? (
                    <p className="tm-muted">Signed off {formatRelativeDate(review.signed_off_at)}</p>
                  ) : null}
                  <div className="tm-inline-row">
                    {REVIEW_STATUSES.map((status) => (
                      <button
                        key={status}
                        type="button"
                        className="tm-secondary-btn"
                        disabled={busy || review.status === status}
                        onClick={() => void handleReviewUpdate(review.id, { status })}
                      >
                        {status === "changes_requested" ? "Request changes" : status}
                      </button>
                    ))}
                  </div>
                  <textarea
                    className="tm-textarea-input"
                    rows={2}
                    placeholder="Add review note"
                    value={reviewCommentDrafts[review.id] ?? ""}
                    onChange={(event) =>
                      setReviewCommentDrafts((current) => ({ ...current, [review.id]: event.target.value }))
                    }
                  />
                  <button
                    type="button"
                    className="tm-secondary-btn"
                    disabled={busy || !(reviewCommentDrafts[review.id] ?? "").trim()}
                    onClick={() =>
                      void handleReviewUpdate(review.id, {
                        comment: (reviewCommentDrafts[review.id] ?? "").trim(),
                      })
                    }
                  >
                    Add Comment
                  </button>
                  {review.comments.length > 0 ? (
                    <div className="tm-comment-list">
                      {review.comments.map((comment) => (
                        <div key={comment.id} className="tm-comment-item">
                          <strong>{comment.author}</strong>
                          <span>{formatRelativeDate(comment.created_at)}</span>
                          <p>{comment.comment}</p>
                        </div>
                      ))}
                    </div>
                  ) : null}
                </article>
              ))}
            </div>
          </div>

          <div className="tm-governance-card">
            <h5>Control Library</h5>
            <div className="tm-field-list">
              <input
                className="tm-text-input"
                placeholder="Control title"
                value={controlForm.title}
                onChange={(event) => setControlForm((current) => ({ ...current, title: event.target.value }))}
              />
              <textarea
                className="tm-textarea-input"
                rows={2}
                placeholder="What does this control do?"
                value={controlForm.description}
                onChange={(event) => setControlForm((current) => ({ ...current, description: event.target.value }))}
              />
              <div className="tm-inline-columns">
                <label className="tm-label">
                  Category
                  <select
                    className="tm-select-input"
                    value={controlForm.category}
                    onChange={(event) =>
                      setControlForm((current) => ({
                        ...current,
                        category: event.target.value as ThreatModelControlCreate["category"],
                      }))
                    }
                  >
                    {CONTROL_CATEGORIES.map((category) => (
                      <option key={category} value={category}>
                        {category}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="tm-label">
                  Status
                  <select
                    className="tm-select-input"
                    value={controlForm.status}
                    onChange={(event) =>
                      setControlForm((current) => ({
                        ...current,
                        status: event.target.value as ThreatModelControlCreate["status"],
                      }))
                    }
                  >
                    {CONTROL_STATUSES.map((status) => (
                      <option key={status} value={status}>
                        {status}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <input
                className="tm-text-input"
                placeholder="Owner"
                value={controlForm.owner ?? ""}
                onChange={(event) => setControlForm((current) => ({ ...current, owner: event.target.value }))}
              />
              <input
                className="tm-text-input"
                placeholder="Evidence link or note"
                value={controlForm.evidence ?? ""}
                onChange={(event) => setControlForm((current) => ({ ...current, evidence: event.target.value }))}
              />
              <label className="tm-label">
                Mapped Threats
                <select
                  className="tm-select-input tm-multi-select"
                  multiple
                  value={controlForm.mapped_threat_ids}
                  onChange={(event) =>
                    setControlForm((current) => ({
                      ...current,
                      mapped_threat_ids: Array.from(event.target.selectedOptions, (option) => option.value),
                    }))
                  }
                >
                  {threatOptions.map((threat) => (
                    <option key={threat.id} value={threat.id}>
                      {threat.label}
                    </option>
                  ))}
                </select>
              </label>
              <button type="button" className="tm-primary-btn" onClick={handleCreateControl} disabled={busy}>
                Add Control
              </button>
            </div>
            <div className="tm-list">
              {controls.length === 0 ? <p className="tm-muted">No model-level controls registered yet.</p> : null}
              {controls.map((control) => (
                <article key={control.id} className="tm-list-item">
                  <div className="tm-list-item-header">
                    <strong>{control.title}</strong>
                    <span className={`tm-status-pill tm-status-${control.status}`}>{control.status}</span>
                  </div>
                  <p>{control.description || "No description captured yet."}</p>
                  <p className="tm-muted">
                    {control.category} · Owner: {control.owner ?? "Unassigned"} · {control.mapped_threat_ids.length} mapped threats
                  </p>
                  {control.evidence ? <p className="tm-muted">Evidence: {control.evidence}</p> : null}
                  <div className="tm-inline-columns">
                    <label className="tm-label">
                      Status
                      <select
                        className="tm-select-input"
                        value={control.status}
                        onChange={(event) =>
                          void handleQuickControlPatch(control.id, {
                            status: event.target.value as ThreatModelControlCreate["status"],
                          })
                        }
                      >
                        {CONTROL_STATUSES.map((status) => (
                          <option key={status} value={status}>
                            {status}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="tm-label">
                      Owner
                      <input
                        className="tm-text-input"
                        defaultValue={control.owner ?? ""}
                        onBlur={(event) => {
                          if ((control.owner ?? "") !== event.target.value) {
                            void handleQuickControlPatch(control.id, { owner: event.target.value });
                          }
                        }}
                      />
                    </label>
                  </div>
                  <button type="button" className="tm-danger-btn" onClick={() => void handleDeleteControl(control.id)} disabled={busy}>
                    Delete Control
                  </button>
                </article>
              ))}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

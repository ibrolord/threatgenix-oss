import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../api/client";
import type {
  ThreatModelAssignmentCreate,
  ThreatModelAssignmentResponse,
  ThreatModelAssignmentStatus,
  ThreatModelCollaboratorCreate,
  ThreatModelCollaboratorResponse,
  ThreatModelNotificationResponse,
  ThreatModelReviewResponse,
  ThreatResponse,
} from "../types/api";

interface ThreatModelCollaborationPanelProps {
  threatModelId: string;
  refreshToken?: number;
  threats: ThreatResponse[];
}

function emptyInvite(): ThreatModelCollaboratorCreate {
  return { email: "", role: "viewer" };
}

function emptyAssignment(): ThreatModelAssignmentCreate {
  return {
    title: "",
    description: "",
    assignee: "",
    priority: "medium",
    due_date: null,
    threat_id: null,
    review_id: null,
    anchor_kind: null,
    anchor_id: null,
    anchor_label: null,
  };
}

export function ThreatModelCollaborationPanel({
  threatModelId,
  refreshToken = 0,
  threats,
}: ThreatModelCollaborationPanelProps): JSX.Element {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [collaborators, setCollaborators] = useState<ThreatModelCollaboratorResponse[]>([]);
  const [assignments, setAssignments] = useState<ThreatModelAssignmentResponse[]>([]);
  const [notifications, setNotifications] = useState<ThreatModelNotificationResponse[]>([]);
  const [reviews, setReviews] = useState<ThreatModelReviewResponse[]>([]);
  const [inviteForm, setInviteForm] = useState<ThreatModelCollaboratorCreate>(emptyInvite());
  const [assignmentForm, setAssignmentForm] = useState<ThreatModelAssignmentCreate>(emptyAssignment());
  const [assignmentCommentDrafts, setAssignmentCommentDrafts] = useState<Record<string, string>>({});

  const threatOptions = useMemo(
    () => threats.map((threat) => ({ id: threat.id, label: `${threat.display_id} · ${threat.description}` })),
    [threats],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextCollaborators, nextAssignments, nextNotifications, nextReviews] = await Promise.all([
        api.getCollaborators(threatModelId),
        api.getAssignments(threatModelId),
        api.getNotifications(threatModelId),
        api.getModelReviews(threatModelId),
      ]);
      setCollaborators(nextCollaborators);
      setAssignments(nextAssignments);
      setNotifications(nextNotifications);
      setReviews(nextReviews);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to load collaboration data");
    } finally {
      setLoading(false);
    }
  }, [threatModelId]);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const handleInvite = async () => {
    if (!inviteForm.email.trim()) {
      setError("Collaborator email is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await api.createCollaborator(threatModelId, {
        email: inviteForm.email.trim(),
        role: inviteForm.role,
      });
      setCollaborators((current) => [...current.filter((item) => item.role === "owner"), created, ...current.filter((item) => item.role !== "owner")]);
      setInviteForm(emptyInvite());
      void load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to add collaborator");
    } finally {
      setBusy(false);
    }
  };

  const handleCollaboratorPatch = async (
    collaboratorId: string,
    patch: { role?: ThreatModelCollaboratorResponse["role"]; status?: ThreatModelCollaboratorResponse["status"] },
  ) => {
    setBusy(true);
    setError(null);
    try {
      const updated = await api.updateCollaborator(threatModelId, collaboratorId, patch);
      setCollaborators((current) => current.map((item) => (item.id === collaboratorId ? updated : item)));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to update collaborator");
    } finally {
      setBusy(false);
    }
  };

  const handleCreateAssignment = async () => {
    if (!assignmentForm.title.trim() || !assignmentForm.assignee.trim()) {
      setError("Assignment title and assignee are required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await api.createAssignment(threatModelId, {
        ...assignmentForm,
        title: assignmentForm.title.trim(),
        description: assignmentForm.description?.trim() ?? "",
        assignee: assignmentForm.assignee.trim(),
      });
      setAssignments((current) => [created, ...current]);
      setAssignmentForm(emptyAssignment());
      void load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to create assignment");
    } finally {
      setBusy(false);
    }
  };

  const handleAssignmentStatus = async (assignmentId: string, status: ThreatModelAssignmentStatus) => {
    setBusy(true);
    setError(null);
    try {
      const updated = await api.updateAssignment(threatModelId, assignmentId, { status });
      setAssignments((current) => current.map((item) => (item.id === assignmentId ? updated : item)));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to update assignment");
    } finally {
      setBusy(false);
    }
  };

  const handleAssignmentComment = async (assignmentId: string) => {
    const comment = (assignmentCommentDrafts[assignmentId] ?? "").trim();
    if (!comment) return;
    setBusy(true);
    setError(null);
    try {
      const updated = await api.updateAssignment(threatModelId, assignmentId, { comment });
      setAssignments((current) => current.map((item) => (item.id === assignmentId ? updated : item)));
      setAssignmentCommentDrafts((current) => ({ ...current, [assignmentId]: "" }));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to comment on assignment");
    } finally {
      setBusy(false);
    }
  };

  const handleNotificationRead = async (notificationId: string) => {
    setBusy(true);
    setError(null);
    try {
      const updated = await api.updateNotification(threatModelId, notificationId, "read");
      setNotifications((current) => current.map((item) => (item.id === notificationId ? updated : item)));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to update notification");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="tm-section tm-governance-panel">
      <div className="tm-section-header">
        <div>
          <h4>Collaboration</h4>
          <p>Manage access, assignments, and the model activity feed without leaving the workspace.</p>
        </div>
        <button type="button" className="tm-secondary-btn" onClick={() => void load()} disabled={busy}>
          Refresh
        </button>
      </div>

      {loading ? <p className="tm-muted">Loading collaboration data…</p> : null}
      {error ? <div className="tm-error-banner">{error}</div> : null}

      <div className="tm-governance-grid">
        <div className="tm-governance-card">
          <h5>Collaborators</h5>
          <div className="tm-field-list">
            <input
              className="tm-text-input"
              placeholder="teammate@example.com"
              value={inviteForm.email}
              onChange={(event) => setInviteForm((current) => ({ ...current, email: event.target.value }))}
            />
            <label className="tm-label">
              Role
              <select
                className="tm-select-input"
                value={inviteForm.role}
                onChange={(event) =>
                  setInviteForm((current) => ({
                    ...current,
                    role: event.target.value as ThreatModelCollaboratorCreate["role"],
                  }))
                }
              >
                <option value="viewer">viewer</option>
                <option value="reviewer">reviewer</option>
                <option value="editor">editor</option>
              </select>
            </label>
            <button type="button" className="tm-primary-btn" onClick={handleInvite} disabled={busy}>
              Add Collaborator
            </button>
          </div>
          <div className="tm-list">
            {collaborators.map((collaborator) => (
              <article key={`${collaborator.email}-${collaborator.id}`} className="tm-list-item">
                <div className="tm-list-item-header">
                  <strong>{collaborator.email}</strong>
                  <span className={`tm-status-pill tm-status-${collaborator.status}`}>{collaborator.role}</span>
                </div>
                <p className="tm-muted">
                  {collaborator.status} · invited by {collaborator.invited_by}
                </p>
                {collaborator.role !== "owner" ? (
                  <div className="tm-inline-columns">
                    <label className="tm-label">
                      Role
                      <select
                        className="tm-select-input"
                        value={collaborator.role}
                        onChange={(event) =>
                          void handleCollaboratorPatch(collaborator.id, {
                            role: event.target.value as ThreatModelCollaboratorResponse["role"],
                          })
                        }
                      >
                        <option value="viewer">viewer</option>
                        <option value="reviewer">reviewer</option>
                        <option value="editor">editor</option>
                      </select>
                    </label>
                    <label className="tm-label">
                      Status
                      <select
                        className="tm-select-input"
                        value={collaborator.status}
                        onChange={(event) =>
                          void handleCollaboratorPatch(collaborator.id, {
                            status: event.target.value as ThreatModelCollaboratorResponse["status"],
                          })
                        }
                      >
                        <option value="active">active</option>
                        <option value="disabled">disabled</option>
                      </select>
                    </label>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </div>

        <div className="tm-governance-card">
          <h5>Assignments</h5>
          <div className="tm-field-list">
            <input
              className="tm-text-input"
              placeholder="Assignment title"
              value={assignmentForm.title}
              onChange={(event) => setAssignmentForm((current) => ({ ...current, title: event.target.value }))}
            />
            <textarea
              className="tm-textarea-input"
              rows={2}
              placeholder="What needs to happen?"
              value={assignmentForm.description}
              onChange={(event) => setAssignmentForm((current) => ({ ...current, description: event.target.value }))}
            />
            <input
              className="tm-text-input"
              placeholder="Assignee email"
              value={assignmentForm.assignee}
              onChange={(event) => setAssignmentForm((current) => ({ ...current, assignee: event.target.value }))}
            />
            <div className="tm-inline-columns">
              <label className="tm-label">
                Priority
                <select
                  className="tm-select-input"
                  value={assignmentForm.priority}
                  onChange={(event) =>
                    setAssignmentForm((current) => ({
                      ...current,
                      priority: event.target.value as ThreatModelAssignmentCreate["priority"],
                    }))
                  }
                >
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                </select>
              </label>
              <label className="tm-label">
                Due date
                <input
                  className="tm-text-input"
                  type="datetime-local"
                  value={assignmentForm.due_date ?? ""}
                  onChange={(event) =>
                    setAssignmentForm((current) => ({
                      ...current,
                      due_date: event.target.value || null,
                    }))
                  }
                />
              </label>
            </div>
            <label className="tm-label">
              Linked threat
              <select
                className="tm-select-input"
                value={assignmentForm.threat_id ?? ""}
                onChange={(event) =>
                  setAssignmentForm((current) => ({
                    ...current,
                    threat_id: event.target.value || null,
                  }))
                }
              >
                <option value="">None</option>
                {threatOptions.map((threat) => (
                  <option key={threat.id} value={threat.id}>
                    {threat.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="tm-label">
              Linked review
              <select
                className="tm-select-input"
                value={assignmentForm.review_id ?? ""}
                onChange={(event) =>
                  setAssignmentForm((current) => ({
                    ...current,
                    review_id: event.target.value || null,
                  }))
                }
              >
                <option value="">None</option>
                {reviews.map((review) => (
                  <option key={review.id} value={review.id}>
                    {review.title}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" className="tm-primary-btn" onClick={handleCreateAssignment} disabled={busy}>
              Create Assignment
            </button>
          </div>
          <div className="tm-list">
            {assignments.length === 0 ? <p className="tm-muted">No shared assignments yet.</p> : null}
            {assignments.map((assignment) => (
              <article key={assignment.id} className="tm-list-item">
                <div className="tm-list-item-header">
                  <strong>{assignment.title}</strong>
                  <span className={`tm-status-pill tm-status-${assignment.status.replace("_", "-")}`}>
                    {assignment.status.replace("_", " ")}
                  </span>
                </div>
                <p>{assignment.description || "No extra detail yet."}</p>
                <p className="tm-muted">
                  {assignment.priority} · {assignment.assignee}
                  {assignment.due_date ? ` · due ${new Date(assignment.due_date).toLocaleString()}` : ""}
                </p>
                <div className="tm-inline-row">
                  {(["open", "in_progress", "blocked", "done"] as const).map((status) => (
                    <button
                      key={status}
                      type="button"
                      className="tm-secondary-btn"
                      disabled={busy || assignment.status === status}
                      onClick={() => void handleAssignmentStatus(assignment.id, status)}
                    >
                      {status.replace("_", " ")}
                    </button>
                  ))}
                </div>
                <textarea
                  className="tm-textarea-input"
                  rows={2}
                  placeholder="Add assignment note"
                  value={assignmentCommentDrafts[assignment.id] ?? ""}
                  onChange={(event) =>
                    setAssignmentCommentDrafts((current) => ({ ...current, [assignment.id]: event.target.value }))
                  }
                />
                <button
                  type="button"
                  className="tm-secondary-btn"
                  disabled={busy || !(assignmentCommentDrafts[assignment.id] ?? "").trim()}
                  onClick={() => void handleAssignmentComment(assignment.id)}
                >
                  Add Comment
                </button>
                {assignment.comments.length > 0 ? (
                  <div className="tm-comment-list">
                    {assignment.comments.map((comment) => (
                      <div key={comment.id} className="tm-comment-item">
                        <strong>{comment.author}</strong>
                        <span>{new Date(comment.created_at).toLocaleString()}</span>
                        <p>{comment.comment}</p>
                      </div>
                    ))}
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </div>
      </div>

      <div className="tm-governance-card">
        <h5>Activity Feed</h5>
        <div className="tm-list">
          {notifications.length === 0 ? <p className="tm-muted">No model notifications yet.</p> : null}
          {notifications.map((notification) => (
            <article key={notification.id} className="tm-list-item">
              <div className="tm-list-item-header">
                <strong>{notification.title}</strong>
                <span className={`tm-status-pill tm-status-${notification.status}`}>{notification.status}</span>
              </div>
              <p>{notification.message}</p>
              <p className="tm-muted">
                {notification.actor} · {new Date(notification.created_at).toLocaleString()}
              </p>
              {notification.status === "unread" ? (
                <button
                  type="button"
                  className="tm-secondary-btn"
                  disabled={busy}
                  onClick={() => void handleNotificationRead(notification.id)}
                >
                  Mark Read
                </button>
              ) : null}
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

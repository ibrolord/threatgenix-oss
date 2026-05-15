import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../api/client";
import type {
  AssumptionAnchorKind,
  AssumptionAnchorTarget,
  DFDResponse,
  ThreatModelAssumptionCreate,
  ThreatModelAssumptionResponse,
  ThreatModelAssumptionUpdate,
} from "../types/api";

interface AssumptionsPanelProps {
  threatModelId: string;
  pendingAnchor: AssumptionAnchorTarget | null;
  onPendingAnchorConsumed: () => void;
  onChanged?: () => void;
}

type AssumptionFormState = {
  id?: string;
  title: string;
  description: string;
  status: ThreatModelAssumptionResponse["status"];
  anchor_kind: AssumptionAnchorKind;
  anchor_id: string;
  anchor_label: string;
};

const STATUS_OPTIONS: { value: ThreatModelAssumptionResponse["status"]; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "validated", label: "Validated" },
  { value: "challenged", label: "Challenged" },
];

function buildAnchorOptions(dfd: DFDResponse | null): Record<AssumptionAnchorKind, AssumptionAnchorTarget[]> {
  if (!dfd) {
    return { node: [], edge: [], boundary: [] };
  }

  const nodeLabelById = new Map(dfd.nodes.map((node) => [node.id, node.name]));
  return {
    node: dfd.nodes.map((node) => ({
      kind: "node",
      id: node.id,
      label: node.name,
    })),
    edge: dfd.edges.map((edge) => ({
      kind: "edge",
      id: edge.id,
      label:
        edge.label?.trim() ||
        `${nodeLabelById.get(edge.source_node_id) ?? "Unknown"} -> ${nodeLabelById.get(edge.target_node_id) ?? "Unknown"}`,
    })),
    boundary: dfd.trust_boundaries.map((boundary) => ({
      kind: "boundary",
      id: boundary.id,
      label: boundary.name,
    })),
  };
}

function formatTimestamp(value: string): string {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

export function AssumptionsPanel({
  threatModelId,
  pendingAnchor,
  onPendingAnchorConsumed,
  onChanged,
}: AssumptionsPanelProps): JSX.Element {
  const [assumptions, setAssumptions] = useState<ThreatModelAssumptionResponse[]>([]);
  const [dfd, setDfd] = useState<DFDResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [showEditor, setShowEditor] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState<AssumptionFormState | null>(null);

  const loadPanelData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nextAssumptions, nextDfd] = await Promise.all([
        api.getAssumptions(threatModelId),
        api.getDFD(threatModelId),
      ]);
      setAssumptions(nextAssumptions);
      setDfd(nextDfd);
    } catch (caughtError) {
      const message =
        caughtError instanceof Error ? caughtError.message : "Failed to load assumptions.";
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [threatModelId]);

  useEffect(() => {
    void loadPanelData();
  }, [loadPanelData]);

  const anchorOptions = useMemo(() => buildAnchorOptions(dfd), [dfd]);

  const openCreateEditor = useCallback(
    (anchor?: AssumptionAnchorTarget | null) => {
      const fallbackAnchor =
        anchor ??
        anchorOptions.node[0] ??
        anchorOptions.edge[0] ??
        anchorOptions.boundary[0] ??
        null;
      if (!fallbackAnchor) {
        setError("Add nodes, flows, or boundaries to the DFD before creating assumptions.");
        return;
      }
      setForm({
        title: "",
        description: "",
        status: "open",
        anchor_kind: fallbackAnchor.kind,
        anchor_id: fallbackAnchor.id,
        anchor_label: fallbackAnchor.label,
      });
      setShowEditor(true);
      setError(null);
    },
    [anchorOptions]
  );

  useEffect(() => {
    if (!pendingAnchor) return;
    openCreateEditor(pendingAnchor);
    onPendingAnchorConsumed();
  }, [pendingAnchor, openCreateEditor, onPendingAnchorConsumed]);

  const handleEdit = useCallback((assumption: ThreatModelAssumptionResponse) => {
    setForm({
      id: assumption.id,
      title: assumption.title,
      description: assumption.description,
      status: assumption.status,
      anchor_kind: assumption.anchor_kind,
      anchor_id: assumption.anchor_id,
      anchor_label: assumption.anchor_label,
    });
    setShowEditor(true);
    setError(null);
  }, []);

  const syncAnchorSelection = useCallback(
    (kind: AssumptionAnchorKind, id: string) => {
      const nextAnchor = anchorOptions[kind].find((candidate) => candidate.id === id);
      setForm((current) =>
        current
          ? {
              ...current,
              anchor_kind: kind,
              anchor_id: id,
              anchor_label: nextAnchor?.label ?? current.anchor_label,
            }
          : current
      );
    },
    [anchorOptions]
  );

  const handleSave = useCallback(async () => {
    if (!form) return;
    if (!form.title.trim()) {
      setError("Assumption title is required.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      if (form.id) {
        const updated = await api.updateAssumption(threatModelId, form.id, {
          title: form.title.trim(),
          description: form.description.trim(),
          status: form.status,
          anchor_kind: form.anchor_kind,
          anchor_id: form.anchor_id,
          anchor_label: form.anchor_label,
        } satisfies ThreatModelAssumptionUpdate);
        setAssumptions((current) =>
          current.map((item) => (item.id === updated.id ? updated : item))
        );
      } else {
        const created = await api.createAssumption(threatModelId, {
          title: form.title.trim(),
          description: form.description.trim(),
          status: form.status,
          anchor_kind: form.anchor_kind,
          anchor_id: form.anchor_id,
          anchor_label: form.anchor_label,
        } satisfies ThreatModelAssumptionCreate);
        setAssumptions((current) => [created, ...current]);
      }
      setShowEditor(false);
      setForm(null);
      onChanged?.();
    } catch (caughtError) {
      const message =
        caughtError instanceof Error ? caughtError.message : "Failed to save assumption.";
      setError(message);
    } finally {
      setSaving(false);
    }
  }, [form, onChanged, threatModelId]);

  const handleDelete = useCallback(
    async (assumption: ThreatModelAssumptionResponse) => {
      if (!window.confirm(`Delete the assumption "${assumption.title}"?`)) {
        return;
      }
      try {
        await api.deleteAssumption(threatModelId, assumption.id);
        setAssumptions((current) => current.filter((item) => item.id !== assumption.id));
        onChanged?.();
      } catch (caughtError) {
        const message =
          caughtError instanceof Error ? caughtError.message : "Failed to delete assumption.";
        setError(message);
      }
    },
    [onChanged, threatModelId]
  );

  const selectedAnchorOptions = form ? anchorOptions[form.anchor_kind] : [];

  return (
    <section className="tm-section">
      <div className="assumptions-header">
        <div>
          <h3>Assumptions Register</h3>
          <p className="assumptions-copy">
            Track explicit modeling assumptions tied to nodes, flows, and trust boundaries.
          </p>
        </div>
        <button className="dfd-toolbar-btn" onClick={() => openCreateEditor(null)} disabled={loading}>
          Add Assumption
        </button>
      </div>

      {error && <div className="dfd-inline-error" role="alert">{error}</div>}

      {loading ? (
        <div className="assumptions-empty">Loading assumptions…</div>
      ) : assumptions.length === 0 ? (
        <div className="assumptions-empty">
          No assumptions yet. Right-click a node, flow, or trust boundary to anchor one directly from the DFD.
        </div>
      ) : (
        <div className="assumptions-list">
          {assumptions.map((assumption) => (
            <article key={assumption.id} className="assumption-card">
              <div className="assumption-card-head">
                <div>
                  <h4>{assumption.title}</h4>
                  <p className="assumption-anchor">
                    {assumption.anchor_kind} · {assumption.anchor_label}
                  </p>
                </div>
                <span className={`assumption-status assumption-status-${assumption.status}`}>
                  {assumption.status}
                </span>
              </div>
              {assumption.description && (
                <p className="assumption-description">{assumption.description}</p>
              )}
              <p className="assumption-meta">
                Updated {formatTimestamp(assumption.updated_at)}
              </p>
              <div className="assumption-actions">
                <button className="dfd-toolbar-btn" onClick={() => handleEdit(assumption)}>
                  Edit
                </button>
                <button
                  className="dfd-toolbar-btn"
                  onClick={() =>
                    void api
                      .updateAssumption(threatModelId, assumption.id, {
                        status:
                          assumption.status === "validated" ? "open" : "validated",
                      })
                      .then((updated) => {
                        setAssumptions((current) =>
                          current.map((item) => (item.id === updated.id ? updated : item))
                        );
                        onChanged?.();
                      })
                      .catch((caughtError) => {
                        const message =
                          caughtError instanceof Error
                            ? caughtError.message
                            : "Failed to update assumption.";
                        setError(message);
                      })
                  }
                >
                  {assumption.status === "validated" ? "Reopen" : "Mark Validated"}
                </button>
                <button className="dfd-toolbar-btn" onClick={() => handleDelete(assumption)}>
                  Delete
                </button>
              </div>
            </article>
          ))}
        </div>
      )}

      {showEditor && form && (
        <div className="dfd-dialog-overlay" onClick={() => setShowEditor(false)}>
          <div className="dfd-dialog dfd-assumption-dialog" onClick={(event) => event.stopPropagation()}>
            <h3 className="dfd-dialog-title">{form.id ? "Edit Assumption" : "Add Assumption"}</h3>
            <p className="dfd-dialog-copy">
              Capture the modeling condition you are relying on and anchor it to the exact object it affects.
            </p>

            <div className="form-field">
              <label htmlFor="assumption-title">Title</label>
              <input
                id="assumption-title"
                type="text"
                value={form.title}
                onChange={(event) =>
                  setForm((current) =>
                    current ? { ...current, title: event.target.value } : current
                  )
                }
                autoFocus
                placeholder="e.g. API Gateway only accepts mTLS traffic"
              />
            </div>

            <div className="dfd-node-editor-grid">
              <div className="form-field">
                <label htmlFor="assumption-anchor-kind">Anchor Type</label>
                <select
                  id="assumption-anchor-kind"
                  value={form.anchor_kind}
                  onChange={(event) => {
                    const nextKind = event.target.value as AssumptionAnchorKind;
                    const fallbackAnchor = anchorOptions[nextKind][0];
                    if (!fallbackAnchor) {
                      return;
                    }
                    setForm((current) =>
                      current
                        ? {
                            ...current,
                            anchor_kind: nextKind,
                            anchor_id: fallbackAnchor.id,
                            anchor_label: fallbackAnchor.label,
                          }
                        : current
                    );
                  }}
                >
                  <option value="node">Node</option>
                  <option value="edge">Flow</option>
                  <option value="boundary">Trust Boundary</option>
                </select>
              </div>

              <div className="form-field">
                <label htmlFor="assumption-anchor-id">Anchored Object</label>
                <select
                  id="assumption-anchor-id"
                  value={form.anchor_id}
                  onChange={(event) => syncAnchorSelection(form.anchor_kind, event.target.value)}
                >
                  {selectedAnchorOptions.map((option) => (
                    <option key={option.id} value={option.id}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-field">
                <label htmlFor="assumption-status">Status</label>
                <select
                  id="assumption-status"
                  value={form.status}
                  onChange={(event) =>
                    setForm((current) =>
                      current
                        ? {
                            ...current,
                            status: event.target.value as ThreatModelAssumptionResponse["status"],
                          }
                        : current
                    )
                  }
                >
                  {STATUS_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="form-field">
              <label htmlFor="assumption-description">Description</label>
              <textarea
                id="assumption-description"
                value={form.description}
                onChange={(event) =>
                  setForm((current) =>
                    current ? { ...current, description: event.target.value } : current
                  )
                }
                rows={4}
                placeholder="Explain why this assumption exists and what would break if it is false."
              />
            </div>

            <div className="dfd-dialog-actions">
              <button
                className="btn-triage btn-triage-cancel"
                onClick={() => {
                  setShowEditor(false);
                  setForm(null);
                }}
                disabled={saving}
              >
                Cancel
              </button>
              <button className="btn-create" onClick={handleSave} disabled={saving}>
                {saving ? "Saving..." : form.id ? "Save Assumption" : "Add Assumption"}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

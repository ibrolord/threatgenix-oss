import { useState } from "react";

interface CreateDFDWorkspaceDialogProps {
  currentViewName: string | null;
  currentViewId: string | null;
  saving: boolean;
  error: string | null;
  onCreate: (payload: { name: string; sourceViewId: string | null }) => Promise<void>;
  onClose: () => void;
}

type SeedMode = "blank" | "duplicate";

export function CreateDFDWorkspaceDialog({
  currentViewName,
  currentViewId,
  saving,
  error,
  onCreate,
  onClose,
}: CreateDFDWorkspaceDialogProps): JSX.Element {
  const [name, setName] = useState("");
  const [seedMode, setSeedMode] = useState<SeedMode>("blank");

  const canDuplicate = Boolean(currentViewId);

  const handleSubmit = () => {
    const trimmedName = name.trim();
    if (!trimmedName) {
      return;
    }
    void onCreate({
      name: trimmedName,
      sourceViewId: seedMode === "duplicate" && currentViewId ? currentViewId : null,
    });
  };

  return (
    <div className="dfd-dialog-overlay" onClick={onClose}>
      <div
        className="dfd-dialog dfd-view-create-dialog"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="create-dfd-workspace-title"
      >
        <h3 className="dfd-dialog-title" id="create-dfd-workspace-title">
          Create New DFD
        </h3>
        <p className="dfd-dialog-copy">
          Add a separate editable DFD tab inside this threat model. New tabs are independent workspaces and do not auto-sync with System View after creation.
        </p>

        <div className="form-field">
          <label htmlFor="create-dfd-workspace-name">DFD Name</label>
          <input
            id="create-dfd-workspace-name"
            type="text"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Payments Settlement Flow"
            autoFocus
          />
        </div>

        <div className="form-field">
          <label>Start From</label>
          <div className="dfd-view-create-options">
            <label className="dfd-view-create-option">
              <input
                type="radio"
                name="dfd-workspace-seed-mode"
                checked={seedMode === "blank"}
                onChange={() => setSeedMode("blank")}
                disabled={saving}
              />
              <span>
                <strong>Blank canvas</strong>
                <small>Start a separate DFD from scratch.</small>
              </span>
            </label>
            <label className="dfd-view-create-option">
              <input
                type="radio"
                name="dfd-workspace-seed-mode"
                checked={seedMode === "duplicate"}
                onChange={() => setSeedMode("duplicate")}
                disabled={saving || !canDuplicate}
              />
              <span>
                <strong>Duplicate current view</strong>
                <small>
                  {canDuplicate
                    ? `Seed this DFD from ${currentViewName ?? "the current view"}.`
                    : "No current view is available to duplicate."}
                </small>
              </span>
            </label>
          </div>
        </div>

        {error ? <p className="form-error">{error}</p> : null}

        <div className="dfd-dialog-actions">
          <button className="btn-triage btn-triage-cancel" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button className="btn-create" onClick={handleSubmit} disabled={saving || !name.trim()}>
            {saving ? "Creating..." : "Create DFD"}
          </button>
        </div>
      </div>
    </div>
  );
}

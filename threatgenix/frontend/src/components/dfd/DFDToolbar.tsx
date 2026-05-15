import {
  getPaletteToggleTooltip,
  getSnapToggleTooltip,
} from "./dfdInteractionUtils";

interface DFDToolbarProps {
  onOpenTemplates: () => void;
  onAddNode: () => void;
  onTogglePalette?: () => void;
  onShowShortcuts?: () => void;
  onUndo?: () => void;
  onRedo?: () => void;
  onAutoLayout: () => void;
  onBulkEdit: () => void;
  onDeleteSelected: () => void;
  onCreateBoundary: () => void;
  onSuggestBoundaries?: () => void;
  onSave: () => void;
  onZoomIn?: () => void;
  onZoomOut?: () => void;
  onFitView?: () => void;
  onToggleSnap?: () => void;
  onToggleFullscreen?: () => void;
  isFullscreen?: boolean;
  snapToGrid?: boolean;
  saveStatus: "idle" | "saving" | "saved" | "error";
  autoSaveStatus?: "idle" | "saving" | "saved";
  hasNodes: boolean;
  hasSelection: boolean;
  canCreateBoundary: boolean;
  canSuggestBoundaries?: boolean;
  canBulkEdit?: boolean;
  readOnly?: boolean;
  disableTemplates?: boolean;
  paletteVisible?: boolean;
  canUndo?: boolean;
  canRedo?: boolean;
}

export function DFDToolbar({
  onOpenTemplates,
  onAddNode,
  onTogglePalette,
  onShowShortcuts,
  onUndo,
  onRedo,
  onAutoLayout,
  onBulkEdit,
  onDeleteSelected,
  onCreateBoundary,
  onSuggestBoundaries,
  onSave,
  onZoomIn,
  onZoomOut,
  onFitView,
  onToggleSnap,
  onToggleFullscreen,
  isFullscreen = false,
  snapToGrid = false,
  saveStatus,
  autoSaveStatus = "idle",
  hasNodes,
  hasSelection,
  canCreateBoundary,
  canSuggestBoundaries = false,
  canBulkEdit = false,
  readOnly = false,
  disableTemplates = false,
  paletteVisible = true,
  canUndo = false,
  canRedo = false,
}: DFDToolbarProps): JSX.Element {
  const saveLabel =
    saveStatus === "saving"
      ? "Saving..."
      : saveStatus === "saved"
        ? "Saved"
        : saveStatus === "error"
          ? "Save Failed"
          : "Save";

  return (
    <div className="dfd-toolbar">
      <div className="dfd-toolbar-group">
        <span className="dfd-toolbar-group-label">Build</span>
        <div className="dfd-toolbar-group-row">
          <button
            className="dfd-toolbar-btn"
            onClick={onOpenTemplates}
            disabled={disableTemplates}
            title="Open a starter DFD template"
          >
            Templates
          </button>
          <button
            className="dfd-toolbar-btn dfd-toolbar-btn-primary"
            onClick={onAddNode}
            disabled={readOnly}
            title="Open the add-component dialog"
          >
            Components
          </button>
          {onTogglePalette && !readOnly ? (
            <button
              className={`dfd-toolbar-btn${paletteVisible ? " dfd-toolbar-btn-active" : ""}`}
              onClick={onTogglePalette}
              title={getPaletteToggleTooltip(paletteVisible)}
            >
              {paletteVisible ? "Hide Palette" : "Show Palette"}
            </button>
          ) : null}
        </div>
      </div>

      <div className="dfd-toolbar-group">
        <span className="dfd-toolbar-group-label">Edit</span>
        <div className="dfd-toolbar-group-row">
          <button
            className="dfd-toolbar-btn"
            onClick={onAutoLayout}
            disabled={!hasNodes || readOnly}
            title="Repack the current DFD automatically"
          >
            Auto Layout
          </button>
          <button
            className="dfd-toolbar-btn"
            onClick={onBulkEdit}
            disabled={!canBulkEdit || readOnly}
            title="Update shared properties across the current selection"
          >
            Bulk Edit
          </button>
          <button
            className="dfd-toolbar-btn"
            onClick={onDeleteSelected}
            disabled={!hasSelection || readOnly}
            title="Delete the current selection"
          >
            Delete Selected
          </button>
          {onUndo ? (
            <button
              className="dfd-toolbar-btn"
              onClick={onUndo}
              disabled={!canUndo || readOnly}
              title="Undo the last canvas change (Cmd/Ctrl+Z)"
            >
              Undo
            </button>
          ) : null}
          {onRedo ? (
            <button
              className="dfd-toolbar-btn"
              onClick={onRedo}
              disabled={!canRedo || readOnly}
              title="Redo the last undone canvas change (Cmd/Ctrl+Shift+Z or Ctrl+Y)"
            >
              Redo
            </button>
          ) : null}
        </div>
      </div>

      <div className="dfd-toolbar-group">
        <span className="dfd-toolbar-group-label">Boundary</span>
        <div className="dfd-toolbar-group-row">
          <button
            className="dfd-toolbar-btn dfd-toolbar-btn-primary"
            onClick={onCreateBoundary}
            disabled={!canCreateBoundary || readOnly}
            title="Wrap selected nodes or create an empty trust boundary"
          >
            Create Boundary
          </button>
          {onSuggestBoundaries && (
            <button
              className="dfd-toolbar-btn"
              onClick={onSuggestBoundaries}
              disabled={!canSuggestBoundaries || readOnly}
              title="Auto-suggest trust boundaries from exposure, privilege, third-party, and sensitive-data signals"
            >
              Suggest Boundaries
            </button>
          )}
        </div>
      </div>

      <div className="dfd-toolbar-group">
        <span className="dfd-toolbar-group-label">View</span>
        <div className="dfd-toolbar-group-row">
          {onZoomIn && (
            <button className="dfd-toolbar-btn" onClick={onZoomIn} title="Zoom In">
              +
            </button>
          )}
          {onZoomOut && (
            <button className="dfd-toolbar-btn" onClick={onZoomOut} title="Zoom Out">
              −
            </button>
          )}
          {onFitView && (
            <button className="dfd-toolbar-btn" onClick={onFitView} title="Fit View">
              Fit
            </button>
          )}
          {onToggleSnap && (
            <button
              className={`dfd-toolbar-btn${snapToGrid ? " dfd-toolbar-btn-active" : ""}`}
              onClick={onToggleSnap}
              title={getSnapToggleTooltip(snapToGrid)}
            >
              Snap
            </button>
          )}
          {onShowShortcuts && (
            <button
              className="dfd-toolbar-btn"
              onClick={onShowShortcuts}
              title="Show keyboard shortcuts and canvas interaction help (?)"
              aria-keyshortcuts="Shift+/"
            >
              Shortcuts
            </button>
          )}
          {onToggleFullscreen && (
            <button
              className={`dfd-toolbar-btn${isFullscreen ? " dfd-toolbar-btn-active" : ""}`}
              onClick={onToggleFullscreen}
              title={isFullscreen ? "Exit Full Screen" : "Open DFD in Full Screen"}
            >
              {isFullscreen ? "Exit Full Screen" : "Full Screen"}
            </button>
          )}
        </div>
      </div>

      <div className="dfd-toolbar-group">
        <span className="dfd-toolbar-group-label">Save</span>
        <div className="dfd-toolbar-group-row">
          <button
            className={`dfd-toolbar-btn dfd-toolbar-btn-save${saveStatus === "error" ? " dfd-toolbar-btn-error" : ""}${saveStatus === "saved" ? " dfd-toolbar-btn-saved" : ""}`}
            onClick={onSave}
            disabled={saveStatus === "saving" || readOnly}
          >
            {saveLabel}
          </button>
          {readOnly && <span className="dfd-toolbar-meta dfd-toolbar-meta-view-only">View only</span>}
          {autoSaveStatus !== "idle" && (
            <span
              className={`dfd-toolbar-meta ${autoSaveStatus === "saving" ? "dfd-toolbar-meta-saving" : "dfd-toolbar-meta-saved"}`}
            >
              {autoSaveStatus === "saving" ? "Saving..." : "Saved"}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

import type { DFDTemplateDefinition } from "./dfdTemplates";

interface DFDTemplateDialogProps {
  templates: DFDTemplateDefinition[];
  applying: boolean;
  onApply: (template: DFDTemplateDefinition) => void;
  onClose: () => void;
}

export function DFDTemplateDialog({
  templates,
  applying,
  onApply,
  onClose,
}: DFDTemplateDialogProps): JSX.Element {
  return (
    <div className="dfd-dialog-overlay" onClick={onClose}>
      <div
        className="dfd-dialog dfd-template-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="dfd-template-dialog-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="dfd-template-dialog-header">
          <div>
            <div className="dfd-dialog-title" id="dfd-template-dialog-title">
              Starter Templates
            </div>
            <p className="dfd-template-dialog-copy">
              Load a realistic benchmark DFD to exercise flows, trust boundaries, layout, and
              threat generation without starting from a blank canvas.
            </p>
          </div>
          <button
            type="button"
            className="dfd-template-dialog-close"
            aria-label="Close template dialog"
            onClick={onClose}
          >
            x
          </button>
        </div>

        <div className="dfd-template-grid">
          {templates.map((template) => (
            <article key={template.id} className="dfd-template-card">
              <div className="dfd-template-card-meta">{template.domain}</div>
              <h4 className="dfd-template-card-title">{template.name}</h4>
              <p className="dfd-template-card-summary">{template.summary}</p>
              <div className="dfd-template-card-stats">
                <span>{template.nodes.length} nodes</span>
                <span>{template.edges.length} flows</span>
                <span>{template.trust_boundaries.length} boundaries</span>
              </div>
              <button
                type="button"
                className="dfd-toolbar-btn dfd-template-card-action"
                onClick={() => onApply(template)}
                disabled={applying}
              >
                {applying ? "Applying..." : "Load Template"}
              </button>
            </article>
          ))}
        </div>
      </div>
    </div>
  );
}

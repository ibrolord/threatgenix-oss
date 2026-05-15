import { useEffect, useMemo } from "react";

import { getShortcutSections } from "./dfdInteractionUtils";

interface DFDShortcutsDialogProps {
  isReadOnlyView: boolean;
  isDecompositionView: boolean;
  onClose: () => void;
}

export function DFDShortcutsDialog({
  isReadOnlyView,
  isDecompositionView,
  onClose,
}: DFDShortcutsDialogProps): JSX.Element {
  const shortcutSections = useMemo(
    () => getShortcutSections({ isReadOnlyView, isDecompositionView }),
    [isDecompositionView, isReadOnlyView]
  );

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  return (
    <div className="dfd-dialog-overlay" onClick={onClose}>
      <div
        className="dfd-dialog dfd-dialog-wide dfd-shortcuts-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="dfd-shortcuts-dialog-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="dfd-shortcuts-dialog-header">
          <div>
            <h3 className="dfd-dialog-title" id="dfd-shortcuts-dialog-title">
              Canvas Shortcuts
            </h3>
            <p className="dfd-dialog-copy">
              Use these gestures to move faster through the DFD editor. Mac uses{" "}
              <strong>Cmd</strong>; Windows and Linux use <strong>Ctrl</strong>.
            </p>
          </div>
          <button
            type="button"
            className="dfd-template-dialog-close"
            aria-label="Close shortcuts dialog"
            onClick={onClose}
          >
            Close
          </button>
        </div>
        <div className="dfd-shortcuts-dialog-grid">
          {shortcutSections.map((section) => (
            <section key={section.title} className="dfd-shortcuts-section">
              <h4>{section.title}</h4>
              <ul className="dfd-shortcuts-list">
                {section.items.map((item) => (
                  <li key={`${section.title}-${item.keys}`}>
                    <span className="dfd-shortcuts-keys">{item.keys}</span>
                    <span className="dfd-shortcuts-description">
                      {item.description}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}

import { useMemo, type CSSProperties } from "react";

import type { DFDComponentTemplateResponse, NodeType } from "../../types/api";
import { humanizeNodeType } from "./componentTemplateUtils";
import { getNodeVisualConfig, getStencilPaletteGroups } from "./dfdVisualRegistry";

interface DFDStencilPaletteProps {
  readOnly?: boolean;
  customTemplates?: DFDComponentTemplateResponse[];
  onHide: () => void;
  onCreateNode: (nodeType: NodeType) => void;
  onCreateTemplate: (template: DFDComponentTemplateResponse) => void;
  onCreateBoundary: () => void;
  onCreateCustom: () => void;
}

export function DFDStencilPalette({
  readOnly = false,
  customTemplates = [],
  onHide,
  onCreateNode,
  onCreateTemplate,
  onCreateBoundary,
  onCreateCustom,
}: DFDStencilPaletteProps): JSX.Element {
  const stencilGroups = getStencilPaletteGroups();
  const customTemplateGroups = useMemo(() => {
    const groups = new Map<string, DFDComponentTemplateResponse[]>();
    for (const template of customTemplates) {
      const groupName = template.group?.trim() || "Custom";
      const groupItems = groups.get(groupName) ?? [];
      groupItems.push(template);
      groups.set(groupName, groupItems);
    }
    return [...groups.entries()].map(([groupName, groupItems]) => [
      groupName,
      [...groupItems].sort((left, right) => left.label.localeCompare(right.label)),
    ] as const);
  }, [customTemplates]);

  return (
    <aside className="dfd-stencil-palette dfd-stencil-palette-open" aria-label="DFD component palette">
      <div className="dfd-stencil-palette-header">
        <div className="dfd-stencil-palette-title-row">
          <p className="dfd-stencil-palette-kicker">Component palette</p>
        </div>
        <div className="dfd-stencil-palette-actions">
          <button
            type="button"
            className="dfd-stencil-palette-create"
            onClick={onCreateCustom}
            disabled={readOnly}
          >
            Create custom
          </button>
          <button
            type="button"
            className="dfd-stencil-palette-toggle"
            onClick={onHide}
            aria-label="Hide component palette"
          >
            Hide
          </button>
        </div>
        <p className="dfd-stencil-palette-copy">
          Click a stencil to place it in the current viewport. Right-click the canvas for exact cursor
          placement, or save a reusable custom component for this threat model.
        </p>
      </div>

      <div className="dfd-stencil-groups">
        <section className="dfd-stencil-group">
          <div className="dfd-stencil-group-heading">
            <h4 className="dfd-stencil-group-title">Your Components</h4>
            {customTemplates.length > 0 ? (
              <span className="dfd-stencil-group-count">{customTemplates.length}</span>
            ) : null}
          </div>

          {customTemplateGroups.length === 0 ? (
            <div className="dfd-stencil-empty-state">
              Save a reusable stencil once and it will appear here for quick placement.
            </div>
          ) : (
            <div className="dfd-stencil-custom-groups">
              {customTemplateGroups.map(([groupName, groupItems]) => (
                <div key={groupName} className="dfd-stencil-subgroup">
                  <div className="dfd-stencil-subgroup-title">{groupName}</div>
                  <div className="dfd-stencil-grid">
                    {groupItems.map((template) => {
                      const visual = getNodeVisualConfig(template.semantic_node_type);
                      return (
                        <button
                          key={template.id}
                          type="button"
                          className="dfd-stencil-card"
                          style={
                            {
                              "--dfd-stencil-accent": visual.accentColor,
                              "--dfd-stencil-tint": visual.tintColor,
                            } as CSSProperties
                          }
                          onClick={() => onCreateTemplate(template)}
                          disabled={readOnly}
                          title={template.description ?? `Custom ${humanizeNodeType(template.semantic_node_type)} stencil`}
                        >
                          <span className="dfd-stencil-card-glyph" aria-hidden="true">
                            <visual.Icon />
                          </span>
                          <span className="dfd-stencil-card-body">
                            <span className="dfd-stencil-card-title">{template.label}</span>
                            <span className="dfd-stencil-card-description">
                              {template.description ?? `Custom ${humanizeNodeType(template.semantic_node_type)} stencil.`}
                            </span>
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {stencilGroups.map((group) => (
          <section key={group.title} className="dfd-stencil-group">
            <h4 className="dfd-stencil-group-title">{group.title}</h4>
            <div className="dfd-stencil-grid">
              {group.items.map((item) => (
                <button
                  key={item.key}
                  type="button"
                  className="dfd-stencil-card"
                  style={
                    {
                      "--dfd-stencil-accent": item.accentColor,
                      "--dfd-stencil-tint": item.tintColor,
                    } as CSSProperties
                  }
                  onClick={() => {
                    if (item.kind === "trust_boundary") {
                      onCreateBoundary();
                    } else {
                      onCreateNode(item.nodeType);
                    }
                  }}
                  disabled={readOnly}
                  title={item.description}
                >
                  <span className="dfd-stencil-card-glyph" aria-hidden="true">
                    <item.Icon />
                  </span>
                  <span className="dfd-stencil-card-body">
                    <span className="dfd-stencil-card-title">{item.label}</span>
                    <span className="dfd-stencil-card-description">{item.description}</span>
                  </span>
                </button>
              ))}
            </div>
          </section>
        ))}
      </div>
    </aside>
  );
}

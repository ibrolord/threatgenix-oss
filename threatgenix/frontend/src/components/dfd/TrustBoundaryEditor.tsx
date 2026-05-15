import { useState } from "react";
import type { BoundaryType } from "../../types/api";
import { MIN_BOUNDARY_HEIGHT, MIN_BOUNDARY_WIDTH } from "./trustBoundaryGeometry";
import { CustomSelectField, type CustomSelectOption } from "./CustomSelectField";

interface TrustBoundaryEditorProps {
  boundaryId: string;
  initialName: string;
  initialBoundaryType?: BoundaryType;
  initialWidth: number;
  initialHeight: number;
  onSaved: (
    boundaryId: string,
    name: string,
    boundaryType: BoundaryType | undefined,
    width: number,
    height: number
  ) => void;
  onClose: () => void;
}

const BOUNDARY_TYPE_OPTIONS: CustomSelectOption[] = [
  { value: "network", label: "Network (firewall/subnet)" },
  { value: "organizational", label: "Organizational (team/department)" },
  { value: "regulatory", label: "Regulatory (PCI CDE, HIPAA scope)" },
  { value: "privilege", label: "Privilege (admin/management plane)" },
  { value: "cloud", label: "Cloud (AWS account/VPC)" },
];

export function TrustBoundaryEditor({
  boundaryId,
  initialName,
  initialBoundaryType,
  initialWidth,
  initialHeight,
  onSaved,
  onClose,
}: TrustBoundaryEditorProps): JSX.Element {
  const [name, setName] = useState(initialName);
  const [boundaryType, setBoundaryType] = useState<BoundaryType | undefined>(initialBoundaryType);
  const [width, setWidth] = useState<number>(Math.max(MIN_BOUNDARY_WIDTH, Math.round(initialWidth)));
  const [height, setHeight] = useState<number>(Math.max(MIN_BOUNDARY_HEIGHT, Math.round(initialHeight)));

  const handleSave = () => {
    if (!name.trim()) return;
    onSaved(
      boundaryId,
      name.trim(),
      boundaryType?.trim() ? boundaryType.trim() : undefined,
      Math.max(MIN_BOUNDARY_WIDTH, width),
      Math.max(MIN_BOUNDARY_HEIGHT, height)
    );
    onClose();
  };

  return (
    <div className="dfd-dialog-overlay" onClick={onClose}>
      <div className="dfd-dialog" onClick={(event) => event.stopPropagation()}>
        <h3 className="dfd-dialog-title">Edit Trust Boundary</h3>
        <p className="dfd-dialog-copy">
          Name the boundary and set its type to drive PCI DSS 4.0 and regulatory scope tagging in the report.
        </p>

        <div className="form-field">
          <label htmlFor="edit-boundary-name">Name</label>
          <input
            id="edit-boundary-name"
            type="text"
            value={name}
            onChange={(event) => setName(event.target.value)}
            autoFocus
            placeholder="e.g. Payment CDE, Public DMZ"
          />
        </div>

        <CustomSelectField
          id="edit-boundary-type"
          label="Boundary Type"
          value={boundaryType}
          options={BOUNDARY_TYPE_OPTIONS}
          onChange={(value) => setBoundaryType(value as BoundaryType | undefined)}
          customPlaceholder="Enter a custom trust boundary type"
        />

        <div className="dfd-boundary-size-grid">
          <div className="form-field">
            <label htmlFor="edit-boundary-width">Width</label>
            <input
              id="edit-boundary-width"
              type="number"
              min={MIN_BOUNDARY_WIDTH}
              step={10}
              value={width}
              onChange={(event) =>
                setWidth(
                  Math.max(
                    MIN_BOUNDARY_WIDTH,
                    Number.parseInt(event.target.value || "0", 10) || MIN_BOUNDARY_WIDTH
                  )
                )
              }
            />
          </div>

          <div className="form-field">
            <label htmlFor="edit-boundary-height">Height</label>
            <input
              id="edit-boundary-height"
              type="number"
              min={MIN_BOUNDARY_HEIGHT}
              step={10}
              value={height}
              onChange={(event) =>
                setHeight(
                  Math.max(
                    MIN_BOUNDARY_HEIGHT,
                    Number.parseInt(event.target.value || "0", 10) || MIN_BOUNDARY_HEIGHT
                  )
                )
              }
            />
          </div>
        </div>

        <div className="dfd-dialog-actions">
          <button className="btn-triage btn-triage-cancel" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-create" onClick={handleSave} disabled={!name.trim()}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

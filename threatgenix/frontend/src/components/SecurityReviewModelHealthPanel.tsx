import type { AssumptionAnchorTarget, DFDQualityGateSummary } from "../types/api";
import { AssumptionsPanel } from "./AssumptionsPanel";
import { DFDQualityPanel } from "./dfd/DFDQualityPanel";

interface SecurityReviewModelHealthPanelProps {
  threatModelId: string;
  qualitySummary: DFDQualityGateSummary | null;
  qualityLoading?: boolean;
  pendingAssumptionAnchor: AssumptionAnchorTarget | null;
  onPendingAnchorConsumed: () => void;
  onAssumptionsChanged?: () => void;
}

export function SecurityReviewModelHealthPanel({
  threatModelId,
  qualitySummary,
  qualityLoading = false,
  pendingAssumptionAnchor,
  onPendingAnchorConsumed,
  onAssumptionsChanged,
}: SecurityReviewModelHealthPanelProps): JSX.Element {
  return (
    <div className="security-review-model-health">
      <section className="security-review-model-health-section">
        <div className="security-review-mode-header">
          <h4>Model Quality</h4>
        </div>
        <DFDQualityPanel summary={qualitySummary} loading={qualityLoading} />
      </section>
      <section className="security-review-model-health-section">
        <div className="security-review-mode-header">
          <h4>Assumptions</h4>
        </div>
        <AssumptionsPanel
          threatModelId={threatModelId}
          pendingAnchor={pendingAssumptionAnchor}
          onPendingAnchorConsumed={onPendingAnchorConsumed}
          onChanged={onAssumptionsChanged}
        />
      </section>
    </div>
  );
}

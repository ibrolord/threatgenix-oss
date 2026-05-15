import { useState } from "react";
import type { ThreatResponse } from "../../types/api";
import { api } from "../../api/client";

interface GenerateThreatsButtonProps {
  threatModelId: string;
  onGenerated: (threats: ThreatResponse[], aiSkippedReason: string | null) => void;
  disabled?: boolean;
  disabledReason?: string | null;
}

export function GenerateThreatsButton({
  threatModelId,
  onGenerated,
  disabled,
  disabledReason,
}: GenerateThreatsButtonProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const effectiveDisabledReason = disabledReason?.trim() || null;
  const isDisabled = Boolean(disabled || loading || effectiveDisabledReason);

  async function handleClick() {
    if (isDisabled) return;
    setLoading(true);
    setError(null);
    try {
      const result = await api.analyze(threatModelId);
      onGenerated(result.threats, result.ai_skipped_reason);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to generate threats";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="generate-threats">
      <button
        className="btn-generate-threats"
        onClick={handleClick}
        disabled={isDisabled}
        title={
          effectiveDisabledReason ??
          "Run threat analysis on the current model and generate STRIDE threats"
        }
      >
        {loading ? (
          <>
            <span className="btn-spinner" />
            Generating...
          </>
        ) : (
          "Generate Threats"
        )}
      </button>
      {effectiveDisabledReason && !loading ? (
        <p className="generate-threats-hint">{effectiveDisabledReason}</p>
      ) : null}
      {error && <p className="generate-threats-error">{error}</p>}
    </div>
  );
}

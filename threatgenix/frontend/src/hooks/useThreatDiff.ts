import { useState, useCallback, useRef } from "react";
import type { ThreatDiffResponse } from "../types/api";
import { api } from "../api/client";

interface UseThreatDiffReturn {
  diff: ThreatDiffResponse | null;
  isLoading: boolean;
  triggerDiff: () => void;
  clearDiff: () => void;
}

export function useThreatDiff(threatModelId: string): UseThreatDiffReturn {
  const [diff, setDiff] = useState<ThreatDiffResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const triggerDiff = useCallback(() => {
    // Cancel any in-flight request
    if (abortRef.current) {
      abortRef.current.abort();
    }
    const controller = new AbortController();
    abortRef.current = controller;

    setIsLoading(true);
    api
      .getThreatDiff(threatModelId, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        // Suppress display when counts are all zero
        const { added, removed } = result.counts;
        if (added === 0 && removed === 0) {
          setDiff(null);
        } else {
          setDiff(result);
        }
      })
      .catch(() => {
        // Diff is non-critical — swallow errors silently
        if (!controller.signal.aborted) {
          setDiff(null);
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setIsLoading(false);
        }
      });
  }, [threatModelId]);

  const clearDiff = useCallback(() => {
    if (abortRef.current) {
      abortRef.current.abort();
    }
    setDiff(null);
    setIsLoading(false);
  }, []);

  return { diff, isLoading, triggerDiff, clearDiff };
}

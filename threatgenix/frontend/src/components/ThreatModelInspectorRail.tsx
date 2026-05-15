import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { api } from "../api/client";
import type {
  AssistantMutationOutcome,
  AssistantActionArtifact,
  AssistantReference,
  AssistantRequest,
  AssumptionAnchorTarget,
  DFDQualityGateSummary,
  ReviewArtifactKind,
  ReviewQueueBucket,
  ReviewStatus,
  SecurityReviewApplicationSummary,
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
  SecurityReviewRiskAcceptanceRequest,
  ThreatModelResponse,
  ThreatResponse,
} from "../types/api";
import { SecurityReviewCompliancePanel } from "./SecurityReviewCompliancePanel";
import { SecurityReviewFindingsPanel } from "./SecurityReviewFindingsPanel";
import { SecurityReviewModelHealthPanel } from "./SecurityReviewModelHealthPanel";
import { SecurityReviewPanel } from "./SecurityReviewPanel";
import { SecurityReviewReportPanel } from "./SecurityReviewReportPanel";
import { ThreatModelAssistantPanel } from "./assistant/ThreatModelAssistantPanel";
import {
  buildThreatTriagePayload,
  isComplianceFinding,
  isFindingsModeFinding,
} from "./securityReviewWorkbenchUtils";

interface AssistantQueuedRequest {
  nonce: number;
  request: AssistantRequest;
}

interface ThreatModelInspectorRailProps {
  threatModelId: string;
  model: ThreatModelResponse;
  threats: ThreatResponse[];
  layout?: "rail" | "page";
  initialTab?: InspectorTab;
  focusedThreatId?: string | null;
  onFocusedThreatCleared?: () => void;
  onHide?: () => void;
  queuedAssistantRequest: AssistantQueuedRequest | null;
  onReferencesChange?: (references: AssistantReference[]) => void;
  onGraphMutated?: () =>
    | Promise<AssistantMutationOutcome | void>
    | AssistantMutationOutcome
    | void;
  onThreatUpdated?: (threat: ThreatResponse) => void;
  onTabChange?: (tab: InspectorTab) => void;
  initialSummary?: SecurityReviewApplicationSummary | null;
  initialFindingsResponse?: SecurityReviewFindingListResponse | null;
  qualitySummary: DFDQualityGateSummary | null;
  qualityLoading?: boolean;
  hasDfdContent?: boolean | null;
  pendingAssumptionAnchor: AssumptionAnchorTarget | null;
  onPendingAnchorConsumed: () => void;
  refreshToken?: number;
}

type InspectorTab =
  | "review"
  | "findings"
  | "compliance"
  | "modelHealth"
  | "report";
type FindingSelectionByTab = Record<InspectorTab, string | null>;

const TAB_COPY: Record<InspectorTab, { label: string; description: string }> = {
  review: {
    label: "What matters now",
    description:
      "Start with the live review queue: what is real, what needs evidence, and what should move next.",
  },
  findings: {
    label: "Investigate findings",
    description:
      "Work through individual findings with rationale, signals, and reusable engineer artifacts.",
  },
  compliance: {
    label: "Readiness and evidence",
    description:
      "Turn framework mapping into concrete evidence work, control follow-through, and readiness blockers.",
  },
  modelHealth: {
    label: "Model quality and assumptions",
    description:
      "Keep the threat model trustworthy by reviewing DFD quality gates, metadata gaps, and assumptions.",
  },
  report: {
    label: "Full picture report",
    description:
      "Read the stakeholder view across all findings, evidence sources, attack paths, deltas, and accepted risk.",
  },
};

const EMPTY_FINDING_SELECTION: FindingSelectionByTab = {
  review: null,
  findings: null,
  compliance: null,
  modelHealth: null,
  report: null,
};
const TERMINAL_REVIEW_STATUSES = new Set<ReviewStatus>([
  "accepted",
  "mitigated",
  "dismissed",
]);

function patchFindingInResponse(
  findingsResponse: SecurityReviewFindingListResponse | null,
  findingId: string,
  patch:
    | Partial<SecurityReviewFinding>
    | ((finding: SecurityReviewFinding) => Partial<SecurityReviewFinding>),
): SecurityReviewFindingListResponse | null {
  if (!findingsResponse) {
    return findingsResponse;
  }

  return {
    ...findingsResponse,
    findings: findingsResponse.findings.map((finding) => {
      if (finding.id !== findingId) {
        return finding;
      }
      const nextPatch = typeof patch === "function" ? patch(finding) : patch;
      return { ...finding, ...nextPatch };
    }),
  };
}

function optimisticStatusPatch(
  finding: SecurityReviewFinding,
  status: ReviewStatus,
): Partial<SecurityReviewFinding> {
  if (TERMINAL_REVIEW_STATUSES.has(status)) {
    return {
      review_status: status,
      queue_bucket: null,
      last_non_terminal_bucket:
        finding.queue_bucket ??
        finding.last_non_terminal_bucket ??
        finding.computed_queue_bucket ??
        "verify",
      risk_acceptance:
        status === "accepted"
          ? {
              finding_title: finding.title,
              status: "active",
              accepted_by: "Current reviewer",
              accepted_at: new Date().toISOString(),
              expires_at: null,
              acceptance_rationale:
                "Accepted through the security review workbench; add reviewer-specific rationale before external sharing.",
              compensating_control: null,
              reopen_triggers: [],
            }
          : finding.risk_acceptance,
    };
  }

  if (TERMINAL_REVIEW_STATUSES.has(finding.review_status)) {
    return {
      review_status: status,
      queue_bucket:
        finding.last_non_terminal_bucket ??
        finding.computed_queue_bucket ??
        "verify",
      risk_acceptance:
        finding.risk_acceptance &&
        finding.risk_acceptance.status !== "reopened"
          ? {
              ...finding.risk_acceptance,
              status: "reopened",
              reopen_triggers: [
                ...new Set([
                  ...finding.risk_acceptance.reopen_triggers,
                  "finding reopened by reviewer",
                ]),
              ],
            }
          : finding.risk_acceptance,
    };
  }

  return { review_status: status };
}

function optimisticRiskAcceptancePatch(
  finding: SecurityReviewFinding,
  payload: SecurityReviewRiskAcceptanceRequest,
): Partial<SecurityReviewFinding> {
  return {
    review_status: "accepted",
    queue_bucket: null,
    last_non_terminal_bucket:
      finding.queue_bucket ??
      finding.last_non_terminal_bucket ??
      finding.computed_queue_bucket ??
      "verify",
    risk_acceptance: {
      finding_title: finding.title,
      status: "active",
      accepted_by: payload.accepted_by ?? null,
      accepted_at: new Date().toISOString(),
      expires_at: payload.expires_at ?? null,
      acceptance_rationale: payload.acceptance_rationale,
      compensating_control: payload.compensating_control ?? null,
      reopen_triggers: [],
    },
  };
}

function findingBelongsToTab(
  finding: SecurityReviewFinding,
  tab: InspectorTab,
): boolean {
  if (tab === "findings") {
    return isFindingsModeFinding(finding);
  }
  if (tab === "compliance") {
    return isComplianceFinding(finding);
  }
  if (tab === "modelHealth" || tab === "report") {
    return false;
  }
  return true;
}

function defaultFindingIdForTab(
  findingsResponse: SecurityReviewFindingListResponse,
  tab: InspectorTab,
): string | null {
  if (tab === "modelHealth" || tab === "report") {
    return null;
  }

  const visibleFindings = findingsResponse.findings.filter((finding) =>
    findingBelongsToTab(finding, tab),
  );
  if (visibleFindings.length === 0) {
    return null;
  }

  const defaultFinding = findingsResponse.findings.find(
    (finding) => finding.id === findingsResponse.default_finding_id,
  );
  if (defaultFinding && findingBelongsToTab(defaultFinding, tab)) {
    return defaultFinding.id;
  }
  return visibleFindings[0]?.id ?? null;
}

function reconcileFindingSelections(
  current: FindingSelectionByTab,
  findingsResponse: SecurityReviewFindingListResponse,
): FindingSelectionByTab {
  const next = { ...EMPTY_FINDING_SELECTION };
  for (const tab of Object.keys(next) as InspectorTab[]) {
    const currentId = current[tab];
    const currentFinding = findingsResponse.findings.find(
      (finding) => finding.id === currentId,
    );
    next[tab] =
      currentFinding && findingBelongsToTab(currentFinding, tab)
        ? currentFinding.id
        : defaultFindingIdForTab(findingsResponse, tab);
  }
  return next;
}

function mapReviewStatusToThreatStatus(
  status: ReviewStatus,
): "Open" | "In Progress" | "Mitigated" | "Accepted" | "Dismissed" {
  switch (status) {
    case "in_progress":
      return "In Progress";
    case "mitigated":
      return "Mitigated";
    case "accepted":
      return "Accepted";
    case "dismissed":
      return "Dismissed";
    default:
      return "Open";
  }
}

function mapThreatStatusToReviewStatus(
  status: ThreatResponse["status"],
): ReviewStatus {
  switch (status) {
    case "In Progress":
      return "in_progress";
    case "Mitigated":
      return "mitigated";
    case "Accepted":
      return "accepted";
    case "Dismissed":
      return "dismissed";
    default:
      return "open";
  }
}

export function ThreatModelInspectorRail({
  threatModelId,
  model,
  threats,
  layout = "rail",
  initialTab = "review",
  focusedThreatId = null,
  onFocusedThreatCleared,
  onHide,
  queuedAssistantRequest,
  onReferencesChange,
  onGraphMutated,
  onThreatUpdated,
  onTabChange,
  initialSummary = null,
  initialFindingsResponse = null,
  qualitySummary,
  qualityLoading = false,
  hasDfdContent,
  pendingAssumptionAnchor,
  onPendingAnchorConsumed,
  refreshToken = 0,
}: ThreatModelInspectorRailProps): JSX.Element {
  const [activeTab, setActiveTab] = useState<InspectorTab>(initialTab);
  const [summary, setSummary] =
    useState<SecurityReviewApplicationSummary | null>(null);
  const [findingsResponse, setFindingsResponse] =
    useState<SecurityReviewFindingListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [selectedFindingIds, setSelectedFindingIds] =
    useState<FindingSelectionByTab>(EMPTY_FINDING_SELECTION);
  const [queueUpdatingId, setQueueUpdatingId] = useState<string | null>(null);
  const [statusUpdatingId, setStatusUpdatingId] = useState<string | null>(null);
  const [artifactCreatingId, setArtifactCreatingId] = useState<string | null>(
    null,
  );
  const [artifactCreatingKind, setArtifactCreatingKind] =
    useState<ReviewArtifactKind | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);
  const mutationVersionRef = useRef(0);

  useEffect(() => {
    setActiveTab(initialTab);
  }, [initialTab]);

  const refreshWorkbench = useCallback(
    async (options: { showLoading?: boolean } = {}) => {
      const refreshVersion = mutationVersionRef.current;
      const showLoading = options.showLoading ?? true;
      if (showLoading) {
        setLoading(true);
      }
      setError(null);
      try {
        const [nextSummary, nextFindings] = await Promise.all([
          api.getThreatModelSecurityReview(threatModelId),
          api.getThreatModelReviewFindings(threatModelId),
        ]);
        if (mutationVersionRef.current !== refreshVersion) {
          return;
        }
        setSummary(nextSummary);
        setFindingsResponse(nextFindings);
        setActionError(null);
        setSelectedFindingIds((current) =>
          reconcileFindingSelections(current, nextFindings),
        );
      } catch (nextError) {
        if (mutationVersionRef.current !== refreshVersion) {
          return;
        }
        const message =
          nextError instanceof Error
            ? nextError.message
            : "Security review refresh failed.";
        setError(message);
        throw nextError;
      } finally {
        if (showLoading) {
          setLoading(false);
        }
      }
    },
    [threatModelId],
  );

  const replaceFinding = useCallback((finding: SecurityReviewFinding) => {
    setFindingsResponse((current) =>
      patchFindingInResponse(current, finding.id, finding),
    );
  }, []);

  const refreshWorkbenchInBackground = useCallback(() => {
    void refreshWorkbench({ showLoading: false }).catch(() => undefined);
  }, [refreshWorkbench]);

  useEffect(() => {
    if (initialSummary && initialFindingsResponse) {
      setSummary(initialSummary);
      setFindingsResponse(initialFindingsResponse);
      setActionError(null);
      setError(null);
      setLoading(false);
      setSelectedFindingIds((current) =>
        reconcileFindingSelections(current, initialFindingsResponse),
      );
    }
  }, [initialSummary, initialFindingsResponse]);

  useEffect(() => {
    if (initialSummary && initialFindingsResponse) {
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    void Promise.all([
      api.getThreatModelSecurityReview(threatModelId),
      api.getThreatModelReviewFindings(threatModelId),
    ])
      .then(([nextSummary, nextFindings]) => {
        if (cancelled) return;
        setSummary(nextSummary);
        setFindingsResponse(nextFindings);
        setActionError(null);
        setSelectedFindingIds((current) =>
          reconcileFindingSelections(current, nextFindings),
        );
      })
      .catch((nextError: Error) => {
        if (cancelled) return;
        setError(nextError.message);
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [threatModelId, refreshToken, initialSummary, initialFindingsResponse]);

  useEffect(() => {
    if (!findingsResponse) return;
    if (pendingAssumptionAnchor) {
      setActiveTab("modelHealth");
      return;
    }
    if (!focusedThreatId) return;
    const matchingFinding = findingsResponse.findings.find(
      (item) => item.threat_id === focusedThreatId,
    );
    if (!matchingFinding) return;
    setSelectedFindingIds((current) => ({
      ...current,
      findings: matchingFinding.id,
    }));
    setActiveTab("findings");
    onTabChange?.("findings");
  }, [findingsResponse, focusedThreatId, onTabChange, pendingAssumptionAnchor]);

  const activeSelectedFindingId = selectedFindingIds[activeTab] ?? null;
  const selectedFinding = useMemo(
    () =>
      findingsResponse?.findings.find(
        (item) =>
          item.id === activeSelectedFindingId &&
          findingBelongsToTab(item, activeTab),
      ) ?? null,
    [activeSelectedFindingId, activeTab, findingsResponse],
  );

  useEffect(() => {
    const panel = panelRef.current;
    if (!panel) return;
    panel.scrollTop = 0;
  }, [activeTab]);

  const handleTabChange = useCallback(
    (nextTab: InspectorTab) => {
      if (nextTab !== "findings" && focusedThreatId) {
        onFocusedThreatCleared?.();
      }
      setActiveTab(nextTab);
      onTabChange?.(nextTab);
    },
    [focusedThreatId, onFocusedThreatCleared, onTabChange],
  );

  const handleOpenWorkspace = useCallback(
    (finding: SecurityReviewFinding) => {
      const targetTab =
        finding.primary_mode === "compliance" ? "compliance" : "findings";
      setSelectedFindingIds((current) => ({
        ...current,
        [targetTab]: finding.id,
      }));
      setActiveTab(targetTab);
      onTabChange?.(targetTab);
    },
    [onTabChange],
  );

  const handleOpenReportFinding = useCallback(
    (finding: SecurityReviewFinding) => {
      const targetTab = isComplianceFinding(finding)
        ? "compliance"
        : "findings";
      setSelectedFindingIds((current) => ({
        ...current,
        [targetTab]: finding.id,
      }));
      setActiveTab(targetTab);
      onTabChange?.(targetTab);
    },
    [onTabChange],
  );

  const handleSelectActiveFinding = useCallback(
    (findingId: string) => {
      setSelectedFindingIds((current) => ({
        ...current,
        [activeTab]: findingId,
      }));
    },
    [activeTab],
  );

  const handleQueueBucketChange = useCallback(
    async (finding: SecurityReviewFinding, bucket: ReviewQueueBucket) => {
      const mutationVersion = mutationVersionRef.current + 1;
      mutationVersionRef.current = mutationVersion;
      setQueueUpdatingId(finding.id);
      setActionError(null);
      setFindingsResponse((current) =>
        patchFindingInResponse(current, finding.id, { queue_bucket: bucket }),
      );
      try {
        const updatedFinding = await api.updateThreatModelReviewFinding(
          threatModelId,
          finding.source_object_type,
          finding.source_object_id,
          { queue_bucket: bucket },
        );
        if (mutationVersionRef.current === mutationVersion) {
          replaceFinding(updatedFinding);
          refreshWorkbenchInBackground();
        }
      } catch (nextError) {
        if (mutationVersionRef.current === mutationVersion) {
          replaceFinding(finding);
          const message =
            nextError instanceof Error
              ? nextError.message
              : "Queue update failed.";
          setActionError(message);
        }
      } finally {
        if (mutationVersionRef.current === mutationVersion) {
          setQueueUpdatingId(null);
        }
      }
    },
    [refreshWorkbenchInBackground, replaceFinding, threatModelId],
  );

  const handleStatusChange = useCallback(
    async (finding: SecurityReviewFinding, status: ReviewStatus) => {
      if (finding.source_object_type !== "threat" && status === "accepted") {
        return;
      }
      const mutationVersion = mutationVersionRef.current + 1;
      mutationVersionRef.current = mutationVersion;
      setStatusUpdatingId(finding.id);
      setActionError(null);
      setFindingsResponse((current) =>
        patchFindingInResponse(current, finding.id, (currentFinding) =>
          optimisticStatusPatch(currentFinding, status),
        ),
      );
      try {
        if (finding.source_object_type === "threat" && finding.threat_id) {
          const threat = threats.find((item) => item.id === finding.threat_id);
          if (!threat) {
            throw new Error("Threat not found for security review action.");
          }
          const updatedThreat = await api.triageThreat(
            threatModelId,
            threat.id,
            buildThreatTriagePayload(
              threat,
              mapReviewStatusToThreatStatus(status),
            ),
          );
          if (mutationVersionRef.current === mutationVersion) {
            onThreatUpdated?.(updatedThreat);
            const serverReviewStatus = mapThreatStatusToReviewStatus(
              updatedThreat.status,
            );
            setFindingsResponse((current) =>
              patchFindingInResponse(current, finding.id, (currentFinding) =>
                optimisticStatusPatch(currentFinding, serverReviewStatus),
              ),
            );
          }
        } else {
          const updatedFinding = await api.updateThreatModelReviewFinding(
            threatModelId,
            finding.source_object_type,
            finding.source_object_id,
            { review_status: status },
          );
          if (mutationVersionRef.current === mutationVersion) {
            replaceFinding(updatedFinding);
          }
        }
        if (mutationVersionRef.current === mutationVersion) {
          refreshWorkbenchInBackground();
        }
      } catch (nextError) {
        if (mutationVersionRef.current === mutationVersion) {
          replaceFinding(finding);
          const message =
            nextError instanceof Error
              ? nextError.message
              : "Status update failed.";
          setActionError(message);
        }
      } finally {
        if (mutationVersionRef.current === mutationVersion) {
          setStatusUpdatingId(null);
        }
      }
    },
    [
      onThreatUpdated,
      refreshWorkbenchInBackground,
      replaceFinding,
      threatModelId,
      threats,
    ],
  );

  const handleRiskAcceptanceSubmit = useCallback(
    async (
      finding: SecurityReviewFinding,
      payload: SecurityReviewRiskAcceptanceRequest,
    ) => {
      const mutationVersion = mutationVersionRef.current + 1;
      mutationVersionRef.current = mutationVersion;
      setStatusUpdatingId(finding.id);
      setActionError(null);
      setFindingsResponse((current) =>
        patchFindingInResponse(current, finding.id, (currentFinding) =>
          optimisticRiskAcceptancePatch(currentFinding, payload),
        ),
      );
      try {
        if (finding.source_object_type === "threat" && finding.threat_id) {
          const threat = threats.find((item) => item.id === finding.threat_id);
          if (!threat) {
            throw new Error("Threat not found for risk acceptance.");
          }
          const updatedThreat = await api.triageThreat(
            threatModelId,
            threat.id,
            buildThreatTriagePayload(threat, "Accepted", payload),
          );
          if (mutationVersionRef.current === mutationVersion) {
            onThreatUpdated?.(updatedThreat);
            refreshWorkbenchInBackground();
          }
        } else {
          const updatedFinding = await api.acceptThreatModelReviewFindingRisk(
            threatModelId,
            finding.source_object_type,
            finding.source_object_id,
            payload,
          );
          if (mutationVersionRef.current === mutationVersion) {
            replaceFinding(updatedFinding);
            refreshWorkbenchInBackground();
          }
        }
      } catch (nextError) {
        if (mutationVersionRef.current === mutationVersion) {
          replaceFinding(finding);
          const message =
            nextError instanceof Error
              ? nextError.message
              : "Risk acceptance failed.";
          setActionError(message);
        }
        throw nextError;
      } finally {
        if (mutationVersionRef.current === mutationVersion) {
          setStatusUpdatingId(null);
        }
      }
    },
    [
      onThreatUpdated,
      refreshWorkbenchInBackground,
      replaceFinding,
      threatModelId,
      threats,
    ],
  );

  const handleCreateArtifact = useCallback(
    async (finding: SecurityReviewFinding, kind: ReviewArtifactKind) => {
      setArtifactCreatingId(finding.id);
      setArtifactCreatingKind(kind);
      setActionError(null);
      try {
        await api.createThreatModelReviewArtifact(
          threatModelId,
          finding.source_object_type,
          finding.source_object_id,
          { kind },
        );
        await refreshWorkbench();
      } catch (nextError) {
        const message =
          nextError instanceof Error
            ? nextError.message
            : "Artifact draft failed.";
        setActionError(message);
      } finally {
        setArtifactCreatingId(null);
        setArtifactCreatingKind(null);
      }
    },
    [refreshWorkbench, threatModelId],
  );

  const handlePersistAssistantArtifacts = useCallback(
    async (artifacts: AssistantActionArtifact[]) => {
      if (artifacts.length === 0) return;
      setActionError(null);
      const firstArtifact = artifacts[0];
      if (!firstArtifact) return;
      setArtifactCreatingId(firstArtifact.review_finding_id);
      setArtifactCreatingKind(firstArtifact.kind);
      try {
        for (const artifact of artifacts) {
          await api.createThreatModelReviewArtifact(
            threatModelId,
            artifact.source_object_type,
            artifact.source_object_id,
            { kind: artifact.kind },
          );
        }
        await refreshWorkbench();
      } catch (nextError) {
        const message =
          nextError instanceof Error
            ? nextError.message
            : "Assistant artifact save failed.";
        setActionError(message);
      } finally {
        setArtifactCreatingId(null);
        setArtifactCreatingKind(null);
      }
    },
    [refreshWorkbench, threatModelId],
  );

  const qualityBadge =
    (qualitySummary?.blocking_count ?? 0) > 0
      ? `${qualitySummary?.blocking_count ?? 0} blocking`
      : (qualitySummary?.warning_count ?? 0) > 0
        ? `${qualitySummary?.warning_count ?? 0} warnings`
        : "Clear";

  const copilotScopeLabel = selectedFinding
    ? selectedFinding.display_id
      ? `Focused · ${selectedFinding.display_id}`
      : "Focused finding"
    : "Queue-wide";
  const fullReviewHref = `/threat-models/${threatModelId}/review?tab=${activeTab}`;
  const shellClassName =
    layout === "page"
      ? "tm-review-page-workbench"
      : "tm-inspector-rail tm-inspector-rail-workbench";
  const activeTabCopy = TAB_COPY[activeTab];
  const p0BlockerCount =
    summary?.priority_counts.find((item) => item.key === "p0_blocker")?.count ??
    0;

  const panelMarkup = (
    <div
      ref={panelRef}
      className="tm-inspector-tab-panel tm-inspector-workbench-panel"
      role="tabpanel"
    >
      {error ? (
        <div className="application-review-panel-state">
          <strong>Security review unavailable.</strong>
          <p>{error}</p>
        </div>
      ) : null}

      {!error && actionError ? (
        <div className="application-review-inline-error" role="alert">
          <strong>Action blocked.</strong>
          <p>{actionError}</p>
        </div>
      ) : null}

      {!error && hasDfdContent === false ? (
        <div className="tm-review-readiness-banner" role="status">
          <strong>DFD required before semantic threat generation.</strong>
          <p>
            This review can still show model-health and evidence-gap blockers,
            but generated semantic threats require components, data flows, or
            trust boundaries first.
          </p>
        </div>
      ) : null}

      {!error && activeTab === "review" ? (
        <SecurityReviewPanel
          model={model}
          threats={threats}
          summary={summary}
          findingsResponse={findingsResponse}
          selectedFindingId={activeSelectedFindingId}
          onSelectFinding={handleSelectActiveFinding}
          onOpenWorkspace={handleOpenWorkspace}
          onQueueBucketChange={handleQueueBucketChange}
          onStatusChange={handleStatusChange}
          onRiskAcceptanceSubmit={handleRiskAcceptanceSubmit}
          onCreateArtifact={handleCreateArtifact}
          queueUpdatingId={queueUpdatingId}
          statusUpdatingId={statusUpdatingId}
          artifactCreatingId={artifactCreatingId}
          artifactCreatingKind={artifactCreatingKind}
          hasDfdContent={hasDfdContent}
        />
      ) : null}

      {!error && activeTab === "findings" ? (
        <SecurityReviewFindingsPanel
          threatModelId={threatModelId}
          model={model}
          threats={threats}
          findingsResponse={findingsResponse}
          selectedFindingId={activeSelectedFindingId}
          onSelectFinding={handleSelectActiveFinding}
          onQueueBucketChange={handleQueueBucketChange}
          onStatusChange={handleStatusChange}
          onRiskAcceptanceSubmit={handleRiskAcceptanceSubmit}
          onCreateArtifact={handleCreateArtifact}
          queueUpdatingId={queueUpdatingId}
          statusUpdatingId={statusUpdatingId}
          artifactCreatingId={artifactCreatingId}
          artifactCreatingKind={artifactCreatingKind}
        />
      ) : null}

      {!error && activeTab === "compliance" ? (
        <SecurityReviewCompliancePanel
          findingsResponse={findingsResponse}
          threats={threats}
          selectedFindingId={activeSelectedFindingId}
          onSelectFinding={handleSelectActiveFinding}
          onQueueBucketChange={handleQueueBucketChange}
          onStatusChange={handleStatusChange}
          onRiskAcceptanceSubmit={handleRiskAcceptanceSubmit}
          queueUpdatingId={queueUpdatingId}
          statusUpdatingId={statusUpdatingId}
        />
      ) : null}

      {!error && activeTab === "modelHealth" ? (
        <SecurityReviewModelHealthPanel
          threatModelId={threatModelId}
          qualitySummary={qualitySummary}
          qualityLoading={qualityLoading || loading}
          pendingAssumptionAnchor={pendingAssumptionAnchor}
          onPendingAnchorConsumed={onPendingAnchorConsumed}
        />
      ) : null}

      {!error && activeTab === "report" ? (
        <SecurityReviewReportPanel
          model={model}
          threats={threats}
          summary={summary}
          findingsResponse={findingsResponse}
          onOpenFinding={handleOpenReportFinding}
        />
      ) : null}
    </div>
  );

  const copilotMarkup = (
    <div className="tm-inspector-copilot">
      <div className="tm-inspector-copilot-header">
        <h4>Copilot</h4>
        <span title={selectedFinding?.title ?? "Queue-wide scope"}>
          {copilotScopeLabel}
        </span>
      </div>
      <ThreatModelAssistantPanel
        threatModelId={threatModelId}
        queuedRequest={queuedAssistantRequest}
        onReferencesChange={onReferencesChange}
        onGraphMutated={onGraphMutated}
        onThreatUpdated={onThreatUpdated}
        embedded
        selectedReviewFinding={selectedFinding}
        onPersistActionArtifacts={handlePersistAssistantArtifacts}
      />
    </div>
  );

  return (
    <section className={shellClassName}>
      <div className="tm-inspector-rail-header">
        <div>
          <h3>{layout === "page" ? "Choose a mode" : "Security Review"}</h3>
          <p>
            {layout === "page"
              ? "Move between the live queue, individual findings, readiness work, and model quality without losing shared context."
              : "Review one application, separate real work from missing evidence, and keep the next action grounded in the model."}
          </p>
        </div>
        {layout === "rail" ? (
          <div className="tm-inspector-rail-actions">
            <a className="tm-open-review-link" href={fullReviewHref}>
              Open Full Review
            </a>
            {onHide ? (
              <button
                type="button"
                className="tm-inspector-visibility-btn"
                onClick={onHide}
                aria-label="Hide inspector"
              >
                Hide
              </button>
            ) : null}
          </div>
        ) : onHide ? (
          <button
            type="button"
            className="tm-inspector-visibility-btn"
            onClick={onHide}
            aria-label="Hide inspector"
          >
            Hide
          </button>
        ) : null}
      </div>

      <div
        className="tm-inspector-tabs"
        role="tablist"
        aria-label="Security review"
      >
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "review"}
          className={`tm-inspector-tab${activeTab === "review" ? " tm-inspector-tab-active" : ""}`}
          onClick={() => handleTabChange("review")}
        >
          Review
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "findings"}
          className={`tm-inspector-tab${activeTab === "findings" ? " tm-inspector-tab-active" : ""}`}
          onClick={() => handleTabChange("findings")}
        >
          Findings
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "compliance"}
          className={`tm-inspector-tab${activeTab === "compliance" ? " tm-inspector-tab-active" : ""}`}
          onClick={() => handleTabChange("compliance")}
        >
          Compliance
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "modelHealth"}
          className={`tm-inspector-tab${activeTab === "modelHealth" ? " tm-inspector-tab-active" : ""}`}
          onClick={() => handleTabChange("modelHealth")}
        >
          Model Health
          <span className="tm-inspector-tab-badge">
            {qualityLoading ? "..." : qualityBadge}
          </span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "report"}
          className={`tm-inspector-tab${activeTab === "report" ? " tm-inspector-tab-active" : ""}`}
          onClick={() => handleTabChange("report")}
        >
          Report
          {p0BlockerCount > 0 ? (
            <span className="tm-inspector-tab-badge">
              {p0BlockerCount} blocker{p0BlockerCount === 1 ? "" : "s"}
            </span>
          ) : null}
        </button>
      </div>

      {layout === "page" ? (
        <>
          <div className="tm-review-page-mode-summary">
            <strong>{activeTabCopy.label}</strong>
            <p>{activeTabCopy.description}</p>
          </div>
          <div
            className={`tm-review-page-body${activeTab === "report" ? " tm-review-page-body-report" : ""}`}
          >
            <div className="tm-review-page-main">{panelMarkup}</div>
            {activeTab === "report" ? null : (
              <aside className="tm-review-page-copilot-column">
                {copilotMarkup}
              </aside>
            )}
          </div>
        </>
      ) : (
        <>
          {panelMarkup}
          {activeTab === "report" ? null : copilotMarkup}
        </>
      )}
    </section>
  );
}

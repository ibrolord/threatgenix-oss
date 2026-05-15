import { useEffect, useState, useCallback, useMemo, useRef } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { toPng } from "html-to-image";
import type {
  AnalyzeResponse,
  AssistantMutationOutcome,
  DFDIacImportResponse,
  DFDQualityGateSummary,
  DFDRepositorySeedApplyResponse,
  EvidenceStatusResponse,
  ReportTemplateDefinition,
  TMACImportResponse,
  ThreatModelResponse,
  ThreatResponse,
} from "../types/api";
import { api } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { DFDCanvas } from "../components/dfd/DFDCanvas";
import { DocumentUpload } from "../components/DocumentUpload";
import { EnvironmentEvidencePanel } from "../components/EnvironmentEvidencePanel";
import { ThreatTable } from "../components/threats/ThreatTable";
import {
  ThreatFilterBar,
  type ThreatFilters,
} from "../components/threats/ThreatFilterBar";
import { GenerateThreatsButton } from "../components/threats/GenerateThreatsButton";
import { ThreatTriageModal } from "../components/threats/ThreatTriageModal";
import { ThreatDashboard } from "../components/threats/ThreatDashboard";
import { ThreatDiffBanner } from "../components/threats/ThreatDiffBanner";
import { ThreatSearchPanel } from "../components/threats/ThreatSearchPanel";
import { ScanPanel } from "../components/scan/ScanPanel";
import { ThreatModelInspectorRail } from "../components/ThreatModelInspectorRail";
import { ThreatModelCodeModal } from "../components/ThreatModelCodeModal";
import { useThreatDiff } from "../hooks/useThreatDiff";
import { ReportExportModal } from "../components/ReportExportModal";
import type { ArchDiagram } from "../components/ReportExportModal";
import type { AssistantReference, AssistantRequest, AssumptionAnchorTarget } from "../types/api";
import { classificationColor } from "../utils/classification";
import { QualificationQueuePanel } from "../components/threats/QualificationQueuePanel";
import { ThreatPriorityStrip } from "../components/threats/ThreatPriorityStrip";

const EMPTY_THREAT_FILTERS: ThreatFilters = {
  stride: null,
  severity: null,
  status: null,
  source: null,
  scanStatus: null,
  notes: null,
  search: null,
};
const INSPECTOR_VISIBLE_STORAGE_KEY = "tg_tm_inspector_visible";
type ReportExportStage = "idle" | "capturing_dfd" | "saving_config" | "generating_pdf" | "failed";
const REPORT_EXPORT_TIMEOUT_MS = 90_000;

const THREAT_SEVERITY_ORDER: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

function evidenceStatusLabel(status: EvidenceStatusResponse | null): string {
  if (!status) return "Not checked";
  if (status.projection_status === "not_built") return "Not built";
  if (status.projection_status === "error") return "Needs attention";
  if (status.projection_status === "stale") return "Stale";
  if (status.coverage_gaps.some((gap) => gap.severity === "blocking")) {
    return "Blocked";
  }
  if (status.coverage_gaps.some((gap) => gap.severity === "warning")) {
    return "Partial";
  }
  return "Current";
}

function evidenceStatusTone(status: EvidenceStatusResponse | null): string {
  if (!status) return "unknown";
  if (status.projection_status === "error") return "error";
  if (
    status.projection_status === "not_built" ||
    status.projection_status === "stale"
  ) return "warning";
  if (status.coverage_gaps.some((gap) => gap.severity === "blocking")) {
    return "error";
  }
  if (status.coverage_gaps.some((gap) => gap.severity === "warning")) {
    return "warning";
  }
  return "ready";
}

function mergeReferences(references: AssistantReference[]): AssistantReference[] {
  const unique = new Map<string, AssistantReference>();
  for (const reference of references) {
    unique.set(`${reference.kind}:${reference.id}`, reference);
  }
  return Array.from(unique.values());
}

function buildThreatFocusReferences(threat: ThreatResponse): AssistantReference[] {
  return mergeReferences([
    {
      kind: "threat",
      id: threat.id,
      label: threat.display_id,
    },
    ...threat.affected_node_ids.map((nodeId) => ({
      kind: "node" as const,
      id: nodeId,
      label: threat.display_id,
    })),
    ...threat.affected_edge_ids.map((edgeId) => ({
      kind: "edge" as const,
      id: edgeId,
      label: threat.display_id,
    })),
  ]);
}

function diffThreats(
  previousThreats: ThreatResponse[],
  nextThreats: ThreatResponse[],
): Pick<AssistantMutationOutcome, "addedThreats" | "removedThreats"> {
  const previousIds = new Set(previousThreats.map((threat) => threat.id));
  const nextIds = new Set(nextThreats.map((threat) => threat.id));
  return {
    addedThreats: nextThreats.filter((threat) => !previousIds.has(threat.id)),
    removedThreats: previousThreats.filter((threat) => !nextIds.has(threat.id)),
  };
}
function ThreatModelPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { user, updateReportTemplateLibrary } = useAuth();
  const [model, setModel] = useState<ThreatModelResponse | null>(null);
  const [dashboardKey, setDashboardKey] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dfdKey, setDfdKey] = useState(0);
  const [threats, setThreats] = useState<ThreatResponse[]>([]);
  const [threatsLoading, setThreatsLoading] = useState(false);
  const [threatsLoadError, setThreatsLoadError] = useState<string | null>(null);
  const [threatFilters, setThreatFilters] = useState<ThreatFilters>(EMPTY_THREAT_FILTERS);
  const [selectedThreat, setSelectedThreat] = useState<ThreatResponse | null>(null);
  const [inspectorThreatId, setInspectorThreatId] = useState<string | null>(null);
  const [aiSkippedReason, setAiSkippedReason] = useState<string | null>(null);
  const [exportingPdf, setExportingPdf] = useState(false);
  const [reportExportStage, setReportExportStage] = useState<ReportExportStage>("idle");
  const [reportExportError, setReportExportError] = useState<string | null>(null);
  const [showReportModal, setShowReportModal] = useState(false);
  const [showThreatModelCodeModal, setShowThreatModelCodeModal] = useState(false);
  const [showQualificationQueue, setShowQualificationQueue] = useState(false);
  const [qualitySummary, setQualitySummary] = useState<DFDQualityGateSummary | null>(null);
  const [qualityLoading, setQualityLoading] = useState(false);
  const [evidenceStatus, setEvidenceStatus] = useState<EvidenceStatusResponse | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [evidenceRebuilding, setEvidenceRebuilding] = useState(false);
  const [hasDfdContent, setHasDfdContent] = useState<boolean | null>(null);
  const [setupExpanded, setSetupExpanded] = useState(false);
  const [operationsExpanded, setOperationsExpanded] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkTriaging, setBulkTriaging] = useState(false);
  const [showBulkDismissInput, setShowBulkDismissInput] = useState(false);
  const [bulkDismissReason, setBulkDismissReason] = useState("");
  const [exportingCsv, setExportingCsv] = useState(false);
  const [exportingDfd, setExportingDfd] = useState(false);
  const [reanalyzing, setReanalyzing] = useState(false);
  const [reanalyzeError, setReanalyzeError] = useState<string | null>(null);
  const [assistantHighlights, setAssistantHighlights] = useState<AssistantReference[]>([]);
  const [threatFocusState, setThreatFocusState] = useState<{
    nonce: number;
    references: AssistantReference[];
  } | null>(null);
  const [graphThreatFilter, setGraphThreatFilter] = useState<{
    kind: "node" | "edge";
    id: string;
    label: string;
  } | null>(null);
  const [pendingAssumptionAnchor, setPendingAssumptionAnchor] = useState<AssumptionAnchorTarget | null>(null);
  const [queuedAssistantRequest, setQueuedAssistantRequest] = useState<{
    nonce: number;
    request: AssistantRequest;
  } | null>(null);
  const [showInspector, setShowInspector] = useState<boolean>(() => {
    if (typeof window === "undefined") return true;
    return window.localStorage.getItem(INSPECTOR_VISIBLE_STORAGE_KEY) !== "false";
  });
  const { diff, isLoading: diffLoading, triggerDiff, clearDiff } = useThreatDiff(id ?? "");
  const autoAnalyzeRef = useRef<AbortController | null>(null);
  const dfdSectionRef = useRef<HTMLElement | null>(null);
  const threatSectionRef = useRef<HTMLElement | null>(null);
  const setupExpansionInitializedRef = useRef(false);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(
      INSPECTOR_VISIBLE_STORAGE_KEY,
      showInspector ? "true" : "false"
    );
  }, [showInspector]);

  const refreshModel = useCallback(async () => {
    if (!id) return;
    const latest = await api.getThreatModel(id);
    setModel(latest);
  }, [id]);

  const refreshQualityGates = useCallback(async () => {
    if (!id) return;
    setQualityLoading(true);
    try {
      const summary = await api.getDFDQualityGates(id);
      setQualitySummary(summary);
    } catch {
      setQualitySummary(null);
    } finally {
      setQualityLoading(false);
    }
  }, [id]);

  const refreshEvidenceStatus = useCallback(async () => {
    if (!id) return;
    setEvidenceLoading(true);
    setEvidenceError(null);
    try {
      const status = await api.getEvidenceStatus(id);
      setEvidenceStatus(status);
    } catch (err) {
      setEvidenceStatus(null);
      setEvidenceError(err instanceof Error ? err.message : "Could not load data status.");
    } finally {
      setEvidenceLoading(false);
    }
  }, [id]);

  useEffect(() => {
    if (!id) return;
    refreshModel()
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [id, refreshModel]);

  useEffect(() => {
    if (!id) return;
    void refreshQualityGates();
  }, [id, refreshQualityGates, dfdKey]);

  useEffect(() => {
    if (!id) return;
    void refreshEvidenceStatus();
  }, [id, refreshEvidenceStatus, dfdKey, dashboardKey]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    api.getDFD(id)
      .then((dfd) => {
        if (cancelled) return;
        setHasDfdContent(
          dfd.nodes.length > 0 || dfd.edges.length > 0 || dfd.trust_boundaries.length > 0
        );
      })
      .catch(() => {
        if (cancelled) return;
        setHasDfdContent(false);
      });

    return () => {
      cancelled = true;
    };
  }, [id, dfdKey]);

  useEffect(() => {
    if (hasDfdContent === null) return;
    if (!setupExpansionInitializedRef.current) {
      setSetupExpanded(!hasDfdContent);
      setupExpansionInitializedRef.current = true;
      return;
    }
    if (!hasDfdContent) {
      setSetupExpanded(true);
    }
  }, [hasDfdContent]);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    setThreatsLoading(true);
    setThreatsLoadError(null);
    api.getThreats(id)
      .then((data) => { if (!cancelled) { setThreats(data); setThreatsLoadError(null); } })
      .catch(() => { if (!cancelled) setThreatsLoadError("Could not load threats — try refreshing the page."); })
      .finally(() => { if (!cancelled) setThreatsLoading(false); });
    return () => { cancelled = true; };
  }, [id, dfdKey]); // refetch when DFD changes

  // Copilot Mode: auto-run rules engine after every DFD save
  const handleAutoAnalyze = useCallback(async (): Promise<AnalyzeResponse | null> => {
    if (!id) return null;
    // Cancel any in-flight auto-analysis
    autoAnalyzeRef.current?.abort();
    const controller = new AbortController();
    autoAnalyzeRef.current = controller;

    // Also trigger diff for the banner
    triggerDiff();

    try {
      const result = await api.analyze(id, true); // rules_only=true
      if (controller.signal.aborted) return null;
      setThreats(result.threats);
      setDashboardKey((k) => k + 1);
      await refreshQualityGates();
      return result;
    } catch {
      // Silent — auto-analysis is best-effort
      return null;
    }
  }, [id, triggerDiff, refreshQualityGates]);

  const handleReanalyze = useCallback(async () => {
    if (!id) return;
    setReanalyzing(true);
    setReanalyzeError(null);
    clearDiff();
    try {
      const result = await api.analyze(id); // full analysis with AI
      setThreats(result.threats);
      setAiSkippedReason(result.ai_skipped_reason);
      setDashboardKey((k) => k + 1);
      void refreshEvidenceStatus();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Analysis failed — please try again.";
      setReanalyzeError(msg);
    } finally {
      setReanalyzing(false);
    }
  }, [id, clearDiff, refreshEvidenceStatus]);

  const handleRebuildEvidenceGraph = useCallback(async () => {
    if (!id) return;
    setEvidenceRebuilding(true);
    setEvidenceError(null);
    try {
      const status = await api.rebuildEvidenceGraph(id);
      setEvidenceStatus(status);
    } catch (err) {
      setEvidenceError(err instanceof Error ? err.message : "Could not rebuild data status.");
    } finally {
      setEvidenceRebuilding(false);
    }
  }, [id]);

  const handleUploadComplete = useCallback(() => {
    // Force DFDCanvas to remount and refetch by changing key
    setDfdKey((k) => k + 1);
    void refreshModel();
    void refreshEvidenceStatus();
  }, [refreshModel, refreshEvidenceStatus]);

  const handleEnvironmentEvidenceUpdated = useCallback(
    (evidence: {
      repository_evidence: ThreatModelResponse["repository_evidence"];
      cloud_scan_evidence: ThreatModelResponse["cloud_scan_evidence"];
      iac_evidence: ThreatModelResponse["iac_evidence"];
      environment_context_summary: ThreatModelResponse["environment_context_summary"];
    }) => {
      setModel((current) => (current ? { ...current, ...evidence } : current));
      void refreshEvidenceStatus();
    },
    [refreshEvidenceStatus]
  );

  const handleIacImported = useCallback(
    async (_result: DFDIacImportResponse | DFDRepositorySeedApplyResponse) => {
      setDfdKey((k) => k + 1);
      await refreshModel();
      await refreshQualityGates();
      await refreshEvidenceStatus();
      await handleAutoAnalyze();
    },
    [refreshModel, refreshQualityGates, refreshEvidenceStatus, handleAutoAnalyze]
  );

  const handleGenerated = useCallback((newThreats: ThreatResponse[], skipReason: string | null) => {
    setThreats(newThreats);
    setAiSkippedReason(skipReason);
    setDashboardKey((k) => k + 1);
    void refreshEvidenceStatus();
  }, [refreshEvidenceStatus]);

  const generateThreatsDisabledReason = useMemo(() => {
    if (hasDfdContent === null) {
      return "Checking DFD readiness before threat generation.";
    }
    if (!hasDfdContent) {
      return "Build or upload a DFD before generating threats. ThreatGenix needs components, data flows, or trust boundaries to run STRIDE analysis.";
    }
    return null;
  }, [hasDfdContent]);

  const handleManualThreatAdded = useCallback((threat: ThreatResponse) => {
    setThreats((prev) => [...prev, threat]);
    setDashboardKey((k) => k + 1);
  }, []);

  const handleThreatQuickTriage = useCallback((threat: ThreatResponse) => {
    setInspectorThreatId(threat.id);
    setShowInspector(true);
    setSelectedThreat(threat);
  }, []);

  const handleInspectorThreatCleared = useCallback(() => {
    setInspectorThreatId(null);
  }, []);

  const queueAssistantRequest = useCallback((request: AssistantRequest) => {
    setShowInspector(true);
    setQueuedAssistantRequest({
      nonce: Date.now(),
      request,
    });
  }, []);

  const handleAskAboutGraphObject = useCallback(
    (target: { kind: "node" | "edge" | "boundary"; id: string }) => {
      queueAssistantRequest({
        message: "/ask explain this and tell me what I should do next",
        anchor: {
          kind: target.kind,
          id: target.id,
        },
      });
    },
    [queueAssistantRequest]
  );

  const handleAskAboutThreat = useCallback(
    (threat: ThreatResponse) => {
      setInspectorThreatId(threat.id);
      queueAssistantRequest({
        message: "/explain explain this threat and tell me what I should do next",
        anchor: {
          kind: "threat",
          id: threat.id,
        },
      });
    },
    [queueAssistantRequest]
  );

  const handleFocusThreat = useCallback((threat: ThreatResponse) => {
    setInspectorThreatId(threat.id);
    setShowInspector(true);
    setThreatFocusState({
      nonce: Date.now(),
      references: buildThreatFocusReferences(threat),
    });
    dfdSectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  const handleFocusThreatsForGraphObject = useCallback(
    (target: { kind: "node" | "edge"; id: string; label: string }) => {
      setGraphThreatFilter(target);
      threatSectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    },
    []
  );

  const handleCreateAssumptionAnchor = useCallback((anchor: AssumptionAnchorTarget) => {
    setPendingAssumptionAnchor(anchor);
  }, []);

  const handleAssistantGraphMutation = useCallback(async (): Promise<AssistantMutationOutcome> => {
    const previousThreats = threats;
    setDfdKey((k) => k + 1);
    await refreshModel();
    const analysis = await handleAutoAnalyze();
    const nextThreats = analysis?.threats ?? previousThreats;
    const delta = diffThreats(previousThreats, nextThreats);
    return {
      threats: nextThreats,
      addedThreats: delta.addedThreats,
      removedThreats: delta.removedThreats,
      aiSkippedReason: analysis?.ai_skipped_reason ?? null,
    };
  }, [refreshModel, handleAutoAnalyze, threats]);

  const handleTriaged = useCallback((updated: ThreatResponse) => {
    setThreats((prev) => prev.map((t) => (t.id === updated.id ? updated : t)));
    setSelectedThreat(null);
    setDashboardKey((k) => k + 1);
  }, []);

  const handleAssistantThreatUpdated = useCallback((updated: ThreatResponse) => {
    setThreats((prev) => {
      const exists = prev.some((threat) => threat.id === updated.id);
      if (!exists) {
        return [...prev, updated];
      }
      return prev.map((threat) => (threat.id === updated.id ? updated : threat));
    });
    setSelectedThreat((current) => (current?.id === updated.id ? updated : current));
    setDashboardKey((k) => k + 1);
  }, []);

  const handleBulkTriage = useCallback(
    async (status: "Accepted" | "Dismissed", dismissReason?: string) => {
      if (!id || selectedIds.size === 0) return;
      setBulkTriaging(true);
      try {
        const updated = await api.bulkTriageThreats(id, {
          threat_ids: Array.from(selectedIds),
          status,
          dismiss_reason: dismissReason ?? null,
        });
        setThreats((prev) => {
          const updatedMap = new Map(updated.map((t) => [t.id, t]));
          return prev.map((t) => updatedMap.get(t.id) ?? t);
        });
        setSelectedIds(new Set());
        setDashboardKey((k) => k + 1);
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Bulk triage failed";
        alert(msg);
      } finally {
        setBulkTriaging(false);
      }
    },
    [id, selectedIds]
  );

  const handleExportPdf = useCallback(async (
    sections: string[],
    archDiagrams: ArchDiagram[],
    reportTemplateId: string,
    reportTemplates: ReportTemplateDefinition[],
  ) => {
    if (!id) return;
    setExportingPdf(true);
    setReportExportError(null);
    setReportExportStage("capturing_dfd");
    try {
      // Capture DFD canvas as PNG base64 for PDF embedding
      let dfdImageBase64 = "";
      const viewport = document
        .querySelector(`#dfd-canvas-${id} .react-flow__viewport`) as HTMLElement | null;
      if (viewport) {
        try {
          const dataUrl = await toPng(viewport, { backgroundColor: "#ffffff" });
          dfdImageBase64 = dataUrl.split(",")[1] ?? "";
        } catch {
          // Canvas capture failed — proceed without DFD image
        }
      }

      setReportExportStage("saving_config");
      await api.updateReportConfig(id, {
        report_template: reportTemplateId,
        report_templates: reportTemplates,
        arch_diagrams: archDiagrams,
      });
      await refreshModel();

      setReportExportStage("generating_pdf");
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), REPORT_EXPORT_TIMEOUT_MS);
      let blob: Blob;
      try {
        blob = await api.generateReport(id, dfdImageBase64, sections, controller.signal);
      } finally {
        window.clearTimeout(timeout);
      }
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `threatmodel-${id}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setShowReportModal(false);
      setReportExportStage("idle");
    } catch (e) {
      const msg =
        e instanceof DOMException && e.name === "AbortError"
          ? "PDF generation exceeded the 90 second safety limit. Try again after narrowing report scope."
          : e instanceof Error
            ? e.message
            : "Unknown error";
      setReportExportStage("failed");
      setReportExportError(msg);
    } finally {
      setExportingPdf(false);
    }
  }, [id, refreshModel]);

  const openReportModal = useCallback(() => {
    setReportExportError(null);
    setReportExportStage("idle");
    setShowReportModal(true);
  }, []);

  const closeReportModal = useCallback(() => {
    if (exportingPdf) return;
    setShowReportModal(false);
    setReportExportError(null);
    setReportExportStage("idle");
  }, [exportingPdf]);

  const handleExportDfd = useCallback(async () => {
    if (!id) return;
    setExportingDfd(true);
    try {
      const viewport = document
        .querySelector(`#dfd-canvas-${id} .react-flow__viewport`) as HTMLElement | null;
      if (!viewport) {
        alert("No DFD canvas found to export.");
        return;
      }
      const dataUrl = await toPng(viewport, { backgroundColor: "#ffffff" });
      const a = document.createElement("a");
      a.href = dataUrl;
      a.download = `dfd-${id}.png`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      alert(`DFD export failed: ${msg}`);
    } finally {
      setExportingDfd(false);
    }
  }, [id]);

  const handleExportCsv = useCallback(async () => {
    if (!id) return;
    setExportingCsv(true);
    try {
      const blob = await api.exportThreatsCSV(id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `threats-${id}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      alert(`CSV export failed: ${msg}`);
    } finally {
      setExportingCsv(false);
    }
  }, [id]);

  const handleTMACImported = useCallback(
    (response: TMACImportResponse) => {
      setShowThreatModelCodeModal(false);
      const warningText =
        response.warnings.length > 0
          ? `\n\nWarnings:\n- ${response.warnings.join("\n- ")}`
          : "";
      if (response.threat_model_id && response.threat_model_id !== id) {
        alert(`Created new threat model "${response.system_name}".${warningText}`);
        navigate(`/threat-models/${response.threat_model_id}`);
        return;
      }
      alert(`Imported TMAC into "${response.system_name}".${warningText}`);
      window.location.reload();
    },
    [id, navigate]
  );

  const diagramHighlights = useMemo(
    () =>
      mergeReferences([
        ...assistantHighlights,
        ...(threatFocusState?.references ?? []),
      ]),
    [assistantHighlights, threatFocusState]
  );

  const threatSignalsByNodeId = useMemo(() => {
    const next: Record<string, { count: number; highestSeverity: string | null }> = {};

    for (const threat of threats) {
      if (threat.status === "Dismissed") continue;
      const nodeIds = Array.from(new Set(threat.affected_node_ids));
      for (const nodeId of nodeIds) {
        const current = next[nodeId] ?? { count: 0, highestSeverity: null };
        const currentRank =
          current.highestSeverity != null
            ? THREAT_SEVERITY_ORDER[current.highestSeverity] ?? Number.POSITIVE_INFINITY
            : Number.POSITIVE_INFINITY;
        const threatRank =
          THREAT_SEVERITY_ORDER[threat.severity] ?? Number.POSITIVE_INFINITY;
        next[nodeId] = {
          count: current.count + 1,
          highestSeverity:
            threatRank < currentRank ? threat.severity : current.highestSeverity,
        };
      }
    }

    return next;
  }, [threats]);

  const filteredThreats = useMemo(() => {
    let nextThreats = threats;
    if (threatFilters.stride) {
      nextThreats = nextThreats.filter(
        (threat) => threat.stride_category === threatFilters.stride
      );
    }
    if (threatFilters.severity) {
      nextThreats = nextThreats.filter((threat) => threat.severity === threatFilters.severity);
    }
    if (threatFilters.status) {
      nextThreats = nextThreats.filter((threat) => threat.status === threatFilters.status);
    }
    if (threatFilters.source) {
      nextThreats = nextThreats.filter((threat) => threat.source === threatFilters.source);
    }
    if (threatFilters.scanStatus) {
      nextThreats = nextThreats.filter(
        (threat) => (threat.scan_status ?? "unscanned") === threatFilters.scanStatus
      );
    }
    if (threatFilters.notes === "with_notes") {
      nextThreats = nextThreats.filter(
        (threat) =>
          Boolean(
            threat.mitigation_notes?.trim() ||
            threat.mitigation_plan?.trim() ||
            threat.dismiss_reason?.trim()
          )
      );
    }
    if (threatFilters.search) {
      const q = threatFilters.search.toLowerCase();
      nextThreats = nextThreats.filter((threat) => {
        const haystack = [
          threat.display_id,
          threat.description,
          threat.rule_id ?? "",
          threat.stride_category,
          threat.threat_subtype ?? "",
        ]
          .join(" ")
          .toLowerCase();
        return haystack.includes(q);
      });
    }
    if (graphThreatFilter) {
      nextThreats = nextThreats.filter((threat) =>
        graphThreatFilter.kind === "node"
          ? threat.affected_node_ids.includes(graphThreatFilter.id)
          : threat.affected_edge_ids.includes(graphThreatFilter.id)
      );
    }
    return nextThreats;
  }, [graphThreatFilter, threatFilters, threats]);

  useEffect(() => {
    setSelectedIds((current) => {
      const visibleThreatIds = new Set(filteredThreats.map((threat) => threat.id));
      let changed = false;
      const next = new Set<string>();
      for (const threatId of current) {
        if (visibleThreatIds.has(threatId)) {
          next.add(threatId);
        } else {
          changed = true;
        }
      }
      return changed ? next : current;
    });
  }, [filteredThreats]);

  if (loading) return <div className="page-loading"><div className="dfd-spinner" /><span>Loading...</span></div>;
  if (error) {
    const is404 = error.includes("404");
    return (
      <div className="not-found-page">
        <div className="not-found-card">
          <h2 className="not-found-code">{is404 ? "404" : "Error"}</h2>
          <h3 className="not-found-title">
            {is404 ? "Threat model not found" : "Something went wrong"}
          </h3>
          <p className="not-found-copy">
            {is404
              ? "This threat model may have been deleted or you may not have access to it."
              : "We could not load this threat model. Please try again or return to the dashboard."}
          </p>
          <Link to="/dashboard" className="btn-create not-found-link">
            Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }
  if (!model || !id) return <p>Threat model not found.</p>;

  const evidenceTone = evidenceStatusTone(evidenceStatus);
  const blockingGapCount = evidenceStatus?.coverage_gaps.filter((gap) => gap.severity === "blocking").length ?? 0;
  const warningGapCount = evidenceStatus?.coverage_gaps.filter((gap) => gap.severity === "warning").length ?? 0;
  const topEvidenceGap = evidenceStatus?.coverage_gaps[0] ?? null;

  return (
    <div className={`tm-page-layout${showInspector ? "" : " tm-page-layout-wide"}`}>
      <div className="tm-main-column">
        <section className="tm-model-header">
          <div className="tm-model-header-top">
            <div className="tm-model-header-main">
              <Link to="/dashboard" className="tm-model-back">
                &larr; Back to Dashboard
              </Link>
              <div className="tm-model-title-row">
                <h2 className="tm-model-title">{model.system_name}</h2>
                <span
                  className="tm-model-classification-badge"
                  style={{ background: classificationColor(model.data_classification) }}
                >
                  {model.data_classification}
                </span>
              </div>
              <p className="tm-model-description">{model.description}</p>
              <div className="tm-model-saas-context" aria-label="SaaS workspace context">
                <span>{user?.organization_name || "Personal pilot workspace"}</span>
                <span>{user?.role || "User"}</span>
                <span>{user?.email_verified === false ? "Email verification pending" : "Email trusted"}</span>
                <span>Runner: SaaS-safe by default</span>
              </div>
            </div>

            <div className="tm-page-actions tm-model-actions">
              <div className="tm-model-document-action">
                <button
                  className="btn-export btn-document"
                  onClick={openReportModal}
                  disabled={exportingPdf || qualityLoading || (qualitySummary?.blocking_count ?? 0) > 0}
                  title={
                    (qualitySummary?.blocking_count ?? 0) > 0
                      ? "Resolve the blocking DFD quality gates before generating the formal threat model document."
                      : qualityLoading
                        ? "Checking DFD quality gates..."
                        : undefined
                  }
                >
                  {exportingPdf ? "Generating Document..." : "Generate Threat Model Document"}
                </button>
                {(qualitySummary?.blocking_count ?? 0) > 0 && (
                  <p className="tm-model-document-hint tm-model-document-hint-blocked">
                    {qualitySummary!.blocking_count} blocking quality gate{qualitySummary!.blocking_count > 1 ? "s" : ""} must be resolved before exporting.
                  </p>
                )}
                {!(qualitySummary?.blocking_count ?? 0) && (
                  <p className="tm-model-document-hint">
                    Formal PDF with engineer actions, compliance evidence, the DFD, and the supporting review record.
                  </p>
                )}
              </div>

              <div className="tm-model-utility-cluster" role="group" aria-label="Threat model utilities">
                <span className="tm-model-utility-label">Utilities</span>
                <div className="tm-model-secondary-actions" role="group" aria-label="Threat model utilities">
                  <Link className="btn-export" to={`/threat-models/${id}/review`}>
                    Security Review
                  </Link>
                  <Link className="btn-export" to={`/threat-models/${id}/validation-lab`}>
                    Validation Lab
                  </Link>
                  <button className="btn-export" onClick={handleExportDfd} disabled={exportingDfd}>
                    {exportingDfd ? "Exporting..." : "Export DFD"}
                  </button>
                  <button className="btn-export" onClick={handleExportCsv} disabled={exportingCsv}>
                    {exportingCsv ? "Exporting..." : "Export CSV"}
                  </button>
                  <button
                    className="btn-export"
                    type="button"
                    onClick={() => setShowThreatModelCodeModal(true)}
                  >
                    TMAC
                  </button>
                </div>
              </div>
              {!showInspector ? (
                <button
                  className="btn-export tm-model-inspector-restore"
                  type="button"
                  onClick={() => setShowInspector(true)}
                >
                  Show Inspector
                </button>
              ) : null}
            </div>
          </div>

          <div className="tm-review-loop" aria-label="Engineer review workflow">
            <div className="tm-review-loop-card">
              <span className="tm-review-loop-step">1</span>
              <div>
                <strong>Model the system</strong>
                <p>Keep the DFD current so the review starts from the real architecture.</p>
              </div>
            </div>
            <div className="tm-review-loop-card">
              <span className="tm-review-loop-step">2</span>
              <div>
                <strong>Ground with evidence</strong>
                <p>Attach repository, cloud, IaC, and source evidence to reduce assumption-driven noise.</p>
              </div>
            </div>
            <div className="tm-review-loop-card">
              <span className="tm-review-loop-step">3</span>
              <div>
                <strong>Review what matters</strong>
                <p>Generate threats, then use the queue to separate fix-now work from missing evidence.</p>
              </div>
            </div>
            <div className="tm-review-loop-card">
              <span className="tm-review-loop-step">4</span>
              <div>
                <strong>Export action-ready output</strong>
                <p>Generate the formal document once the review and evidence posture are clear.</p>
              </div>
            </div>
          </div>

          <div className={`tm-data-status-strip tm-data-status-${evidenceTone}`}>
            <div className="tm-data-status-main">
              <span className="tm-data-status-kicker">Data layer</span>
              <strong>{evidenceStatusLabel(evidenceStatus)}</strong>
              <p>
                {evidenceLoading
                  ? "Checking evidence graph status."
                  : evidenceError
                    ? evidenceError
                    : topEvidenceGap
                      ? topEvidenceGap.detail
                      : "Evidence graph is built from the current model, documents, environment evidence, threats, and validation output."}
              </p>
            </div>
            <div className="tm-data-status-metrics" aria-label="Evidence graph counts">
              <span><strong>{evidenceStatus?.source_count ?? 0}</strong> sources</span>
              <span><strong>{evidenceStatus?.entity_count ?? 0}</strong> entities</span>
              <span><strong>{evidenceStatus?.relationship_count ?? 0}</strong> links</span>
              <span><strong>{evidenceStatus?.finding_count ?? 0}</strong> findings</span>
              <span><strong>{blockingGapCount}</strong> blocking</span>
              <span><strong>{warningGapCount}</strong> warnings</span>
            </div>
            <button
              type="button"
              className="tm-data-status-action"
              onClick={handleRebuildEvidenceGraph}
              disabled={evidenceRebuilding}
            >
              {evidenceRebuilding ? "Rebuilding..." : "Rebuild Graph"}
            </button>
          </div>
        </section>

      <section className="tm-section tm-section-primary tm-section-workspace" ref={dfdSectionRef}>
        <div className="tm-page-section-intro">
          <span className="tm-page-section-step">Step 1 · Model the system</span>
          <h3 className="tm-page-section-heading">Data Flow Diagram</h3>
          <p className="tm-page-section-copy">
            Review and edit your architecture first so the security review queue starts from the right trust boundaries, data paths, and control surfaces.
          </p>
        </div>
        <DFDCanvas
          key={dfdKey}
          threatModelId={id}
          onAutoSaveComplete={handleAutoAnalyze}
          onAskAboutGraphObject={handleAskAboutGraphObject}
          onFocusThreatsForGraphObject={handleFocusThreatsForGraphObject}
          onCreateAssumptionAnchor={handleCreateAssumptionAnchor}
          highlightedReferences={diagramHighlights}
          threatSignalsByNodeId={threatSignalsByNodeId}
          focusRequest={threatFocusState}
        />
      </section>

      <details
        className="tm-secondary-panel tm-setup-panel"
        open={setupExpanded}
        onToggle={(event) => setSetupExpanded(event.currentTarget.open)}
      >
        <summary className="tm-secondary-toggle tm-setup-toggle">
          <span className="tm-secondary-summary">
            <span className="tm-secondary-kicker">Step 2</span>
            <span className="tm-secondary-title">Upload and Environment Setup</span>
            <span className="tm-secondary-copy">
              Ground the review with repository evidence, cloud context, IaC import, and source documents.
            </span>
          </span>
        </summary>
        <div className="tm-setup-content">
          <section className="tm-section">
            <DocumentUpload
              threatModelId={id}
              onUploadComplete={handleUploadComplete}
            />
          </section>

          <EnvironmentEvidencePanel
            threatModelId={id}
            model={model}
            onUpdated={handleEnvironmentEvidenceUpdated}
            onImportedToDfd={handleIacImported}
          />
        </div>
      </details>

      <ThreatDiffBanner
        diff={diff}
        isLoading={diffLoading}
        onReanalyze={handleReanalyze}
        reanalyzing={reanalyzing}
      />

      {reanalyzeError && (
        <div className="tm-analyze-error-banner" role="alert">
          <span>Analysis failed: {reanalyzeError}</span>
          <button onClick={() => setReanalyzeError(null)} aria-label="Dismiss">&#x2715;</button>
        </div>
      )}

      <section className="tm-section tm-section-primary tm-section-analysis" ref={threatSectionRef}>
        <div className="tm-page-section-intro">
          <span className="tm-page-section-step">Step 3 · Review what matters</span>
          <h3 className="tm-page-section-heading">Review Findings</h3>
          <p className="tm-page-section-copy">
            Generate or refresh threats, then use the review queue and detail views to decide what is real, what is urgent, and what still needs evidence.
          </p>
        </div>
        <div className="qual-toolbar">
          <GenerateThreatsButton
            threatModelId={id}
            onGenerated={handleGenerated}
            disabled={threatsLoading}
            disabledReason={generateThreatsDisabledReason}
          />
          {threats.length > 0 && (
            <button
              className="btn-qualify-threats"
              onClick={() => setShowQualificationQueue(true)}
              disabled={threatsLoading}
            >
              Qualify Threats
            </button>
          )}
        </div>
        <ThreatSearchPanel
          threatModelId={id}
          onThreatAdded={handleManualThreatAdded}
        />
        {aiSkippedReason && (
          <div className="ai-skipped-warning" role="alert">
            {aiSkippedReason}
          </div>
        )}
        <ThreatFilterBar
          threats={threats}
          filters={threatFilters}
          visibleCount={filteredThreats.length}
          onChange={setThreatFilters}
        />
        {graphThreatFilter && (
          <div className="bulk-triage-bar">
            <span>
              Focused on {graphThreatFilter.kind === "node" ? "node" : "flow"}: {graphThreatFilter.label}
            </span>
            <button
              onClick={() => setGraphThreatFilter(null)}
              disabled={bulkTriaging}
              title="Clear the current node or flow focus and show all threats again"
            >
              Clear Focus
            </button>
          </div>
        )}
        {selectedIds.size > 0 && (
          <div className="bulk-triage-bar">
            <span>{selectedIds.size} threat{selectedIds.size > 1 ? "s" : ""} selected</span>
            <button
              className="btn-create"
              onClick={() => { setShowBulkDismissInput(false); setBulkDismissReason(""); handleBulkTriage("Accepted"); }}
              disabled={bulkTriaging}
              title="Mark all selected threats as accepted risk"
            >
              Accept Selected
            </button>
            {!showBulkDismissInput ? (
              <button
                className="btn-triage btn-triage-cancel"
                onClick={() => setShowBulkDismissInput(true)}
                disabled={bulkTriaging}
                title="Dismiss all selected threats after providing a reason"
              >
                Dismiss Selected
              </button>
            ) : (
              <>
                <input
                  type="text"
                  className="bulk-dismiss-reason-input"
                  placeholder="Dismiss reason (required)"
                  value={bulkDismissReason}
                  onChange={(e) => setBulkDismissReason(e.target.value)}
                  autoFocus
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && bulkDismissReason.trim()) {
                      void handleBulkTriage("Dismissed", bulkDismissReason.trim());
                      setShowBulkDismissInput(false);
                      setBulkDismissReason("");
                    }
                    if (e.key === "Escape") {
                      setShowBulkDismissInput(false);
                      setBulkDismissReason("");
                    }
                  }}
                />
                <button
                  className="btn-triage btn-triage-cancel"
                  onClick={() => {
                    if (bulkDismissReason.trim()) {
                      void handleBulkTriage("Dismissed", bulkDismissReason.trim());
                      setShowBulkDismissInput(false);
                      setBulkDismissReason("");
                    }
                  }}
                  disabled={bulkTriaging || !bulkDismissReason.trim()}
                >
                  Confirm
                </button>
                <button
                  onClick={() => { setShowBulkDismissInput(false); setBulkDismissReason(""); }}
                  disabled={bulkTriaging}
                >
                  Cancel
                </button>
              </>
            )}
            <button
              onClick={() => { setSelectedIds(new Set()); setShowBulkDismissInput(false); setBulkDismissReason(""); }}
              disabled={bulkTriaging}
              title="Clear the current bulk selection"
            >
              Clear
            </button>
          </div>
        )}
        {threatsLoadError && (
          <div className="tm-threats-load-error">
            {threatsLoadError}
          </div>
        )}
        <ThreatPriorityStrip
          threats={filteredThreats}
          onThreatClick={handleThreatQuickTriage}
        />
        <ThreatTable
          threats={filteredThreats}
          loading={threatsLoading}
          threatModelId={id}
          onThreatQuickTriage={handleThreatQuickTriage}
          selectedIds={selectedIds}
          onSelectionChange={setSelectedIds}
          onAskAboutThreat={handleAskAboutThreat}
          onFocusThreat={handleFocusThreat}
          highlightedReferences={diagramHighlights}
        />
      </section>

      <details
        className="tm-secondary-panel tm-operations-panel"
        open={operationsExpanded}
        onToggle={(event) => setOperationsExpanded(event.currentTarget.open)}
      >
        <summary className="tm-secondary-toggle">
          <span className="tm-secondary-summary">
            <span className="tm-secondary-kicker">Step 4</span>
            <span className="tm-secondary-title">Signals, Validation, and Reporting</span>
            <span className="tm-secondary-copy">
              Keep scorecards and scan validation available without crowding the main review loop.
            </span>
          </span>
        </summary>
        <div className="tm-operations-content">
          <ThreatDashboard threatModelId={id} refreshKey={dashboardKey} />
          <div className="tm-operations-actions">
            <Link className="tm-primary-btn" to={`/threat-models/${id}/validation-lab`}>
              Open Validation Lab
            </Link>
            <Link className="tm-secondary-btn" to={`/threat-models/${id}/review?tab=report`}>
              Open Report
            </Link>
          </div>
          <section className="tm-section tm-section-secondary">
            <ScanPanel threatModelId={id} onScanComplete={() => setDashboardKey(k => k + 1)} />
          </section>
        </div>
      </details>

      {selectedThreat && id && (
        <ThreatTriageModal
          threat={selectedThreat}
          threatModelId={id}
          onClose={() => setSelectedThreat(null)}
          onTriaged={handleTriaged}
          onAskAboutThreat={handleAskAboutThreat}
        />
      )}
      {showQualificationQueue && id && (
        <div className="qualification-panel-overlay">
          <QualificationQueuePanel
            threatModelId={id}
            onClose={() => setShowQualificationQueue(false)}
            onThreatUpdated={handleTriaged}
          />
        </div>
      )}
      {showReportModal && (
        <ReportExportModal
          onClose={closeReportModal}
          onExport={handleExportPdf}
          exporting={exportingPdf}
          exportStage={reportExportStage}
          exportError={reportExportError}
          existingArchDiagrams={(model?.arch_diagrams as ArchDiagram[] | undefined) ?? []}
          existingReportTemplates={model?.report_templates ?? []}
          sharedReportTemplates={user?.report_template_library ?? []}
          onUpdateSharedReportTemplates={updateReportTemplateLibrary}
          initialTemplateId={model?.report_template ?? "default"}
        />
      )}
      {showThreatModelCodeModal && id && (
        <ThreatModelCodeModal
          threatModelId={id}
          onClose={() => setShowThreatModelCodeModal(false)}
          onImported={handleTMACImported}
        />
      )}
      </div>

      {showInspector ? (
        <ThreatModelInspectorRail
          threatModelId={id}
          model={model}
          threats={threats}
          focusedThreatId={inspectorThreatId}
          onFocusedThreatCleared={handleInspectorThreatCleared}
          onHide={() => setShowInspector(false)}
          queuedAssistantRequest={queuedAssistantRequest}
          onReferencesChange={setAssistantHighlights}
          onGraphMutated={handleAssistantGraphMutation}
          onThreatUpdated={handleAssistantThreatUpdated}
          qualitySummary={qualitySummary}
          qualityLoading={qualityLoading}
          pendingAssumptionAnchor={pendingAssumptionAnchor}
          onPendingAnchorConsumed={() => setPendingAssumptionAnchor(null)}
          refreshToken={dfdKey + dashboardKey}
          hasDfdContent={hasDfdContent}
        />
      ) : null}
    </div>
  );
}

export default ThreatModelPage;

import { useEffect, useState, useCallback } from "react";
import { useParams, Link, useSearchParams } from "react-router-dom";

import type {
  AssistantResponse,
  DFDNodeResponse,
  DFDEdgeResponse,
  ThreatAuditEntry,
  ThreatCatalogEntry,
  ThreatIntelResponse,
  ThreatRemediationRun,
  ThreatResponse,
  ThreatScanCorrelationResponse,
  ThreatValidationRun,
  FixAgentType,
  DomainAgentTargetRequest,
  DomainAgentToolMode,
  DomainValidationAgentType,
  ValidationTargetType,
} from "../types/api";
import { api } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { ThreatIntelPanel } from "../components/threats/ThreatIntelPanel";
import { ThreatTriageModal } from "../components/threats/ThreatTriageModal";

const CONTROL_EFFECTIVENESS_LABELS: Record<string, string> = {
  none: "None",
  partial: "Partial",
  substantial: "Substantial",
  full: "Full",
};

function severityTone(severity: string | null | undefined): string {
  switch (severity) {
    case "Critical":
      return "critical";
    case "High":
      return "high";
    case "Medium":
      return "medium";
    case "Low":
      return "low";
    default:
      return "muted";
  }
}

function statusTone(status: string | null | undefined): string {
  switch (status) {
    case "Open":
    case "In Progress":
      return "info";
    case "Mitigated":
    case "Accepted":
      return "success";
    case "Dismissed":
      return "muted";
    default:
      return "muted";
  }
}

function residualRiskTone(level: string | null | undefined): string {
  switch (level) {
    case "Critical":
      return "critical";
    case "High":
      return "high";
    case "Medium":
      return "medium";
    case "Low":
      return "info";
    case "Negligible":
      return "success";
    default:
      return "muted";
  }
}

function scanStatusTone(status: string | null | undefined): string {
  switch (status) {
    case "confirmed":
      return "critical";
    case "mitigated":
      return "success";
    case "not_found":
      return "muted";
    default:
      return "info";
  }
}

function scanStatusLabel(status: string | null | undefined): string {
  switch (status) {
    case "confirmed":
      return "Scan Confirmed";
    case "mitigated":
      return "Scan Validated as Mitigated";
    case "not_found":
      return "Not Found in Scan";
    default:
      return "Scan Unverifiable";
  }
}

function scanStatusCopy(status: string | null | undefined): string {
  switch (status) {
    case "confirmed":
      return "The latest attached scan found evidence that maps directly to this threat path.";
    case "mitigated":
      return "The target was checked and current controls prevented the vulnerable condition from being observed.";
    case "not_found":
      return "The target was scanned, but no matching evidence was found for this threat category.";
    default:
      return "Scan telemetry exists, but the current result cannot strongly confirm or disprove this threat.";
  }
}

function validationConclusionLabel(conclusion: string | null | undefined): string {
  switch (conclusion) {
    case "confirmed":
      return "Confirmed";
    case "not_supported":
      return "Not Supported";
    case "needs_human_review":
      return "Needs Review";
    case "more_evidence_required":
      return "More Evidence Required";
    case "failed":
      return "Failed";
    default:
      return "Not Validated";
  }
}

function validationTone(conclusion: string | null | undefined): string {
  switch (conclusion) {
    case "confirmed":
      return "critical";
    case "not_supported":
      return "success";
    case "needs_human_review":
      return "info";
    case "more_evidence_required":
      return "muted";
    case "failed":
      return "high";
    default:
      return "muted";
  }
}

function exploitabilityLabel(status: string | null | undefined): string {
  switch (status) {
    case "exploitable":
      return "Exploitable";
    case "not_exploitable":
      return "Not Exploitable";
    case "theoretical":
      return "Theoretical";
    case "blocked_by_control":
      return "Blocked by Control";
    case "conflicting_evidence":
      return "Conflicting Evidence";
    case "needs_more_evidence":
      return "Needs More Evidence";
    default:
      return "Not Assessed";
  }
}

function exploitabilityTone(status: string | null | undefined): string {
  switch (status) {
    case "exploitable":
      return "critical";
    case "blocked_by_control":
    case "not_exploitable":
      return "success";
    case "conflicting_evidence":
      return "info";
    case "theoretical":
    case "needs_more_evidence":
      return "muted";
    default:
      return "muted";
  }
}

const FIX_AGENT_LABELS: Record<FixAgentType, string> = {
  code_fix: "Code Fix",
  iac_fix: "IaC Fix",
  configuration_fix: "Configuration Fix",
};

const DOMAIN_AGENT_OPTIONS: Array<{
  id: DomainValidationAgentType;
  label: string;
  tools: string[];
  warning?: string;
}> = [
  { id: "sast", label: "SAST Agent", tools: ["semgrep"] },
  {
    id: "dast",
    label: "DAST Agent",
    tools: ["nuclei"],
    warning: "DAST requires an allowlisted target and isolated runner before execution.",
  },
  { id: "llm_security", label: "LLM Security Agent", tools: ["ai-red-team", "external-report", "pentest-report"] },
  { id: "iac", label: "IaC Agent", tools: ["checkov", "trivy"] },
  { id: "dependency", label: "Dependency Agent", tools: ["osv-scanner", "trivy"] },
  { id: "secrets", label: "Secrets Agent", tools: ["trufflehog"] },
  { id: "configuration", label: "Configuration Agent", tools: ["trivy", "external-report", "pentest-report"] },
];

function formatValidationToolName(toolName: string | null | undefined): string {
  if (!toolName) return "Unknown tool";
  const normalized = toolName.toLowerCase();
  if (normalized === "semgrep") return "Semgrep";
  if (normalized === "nuclei") return "Nuclei";
  if (normalized === "ai-red-team") return "AI Red Team";
  if (normalized === "checkov") return "Checkov";
  if (normalized === "trivy") return "Trivy";
  if (normalized === "osv-scanner") return "OSV Scanner";
  if (normalized === "trufflehog") return "TruffleHog";
  if (normalized === "external-report") return "External Report";
  if (normalized === "pentest-report") return "Pentest Report";
  return toolName;
}

function validationEvidenceSourceLabel(
  evidence: ThreatScanCorrelationResponse["evidence"][number]
): string {
  const toolName = formatValidationToolName(evidence.tool_name);
  return evidence.deterministic ? `${toolName} - deterministic` : toolName;
}

function toneClass(prefix: string, tone: string): string {
  return `${prefix} ${prefix}--${tone}`;
}

function formatDisplayDate(value: string): string {
  return new Date(value).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatDisplayDateTime(value: string): string {
  return new Date(value).toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

/** Strip unresolved {placeholder} tokens left when catalog threats have no DFD context. */
function cleanDescription(text: string): string {
  const cleaned = text.replace(/\s*\{[a-z_]+\}\s*/g, " ").replace(/\s{2,}/g, " ").trim();
  return cleaned || "No description available.";
}

function ThreatDetailPage() {
  const { user } = useAuth();
  const { threatModelId, threatId } = useParams<{
    threatModelId: string;
    threatId: string;
  }>();
  const [searchParams, setSearchParams] = useSearchParams();

  const [threat, setThreat] = useState<ThreatResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [showTriageModal, setShowTriageModal] = useState(false);
  const [assistantPrompt, setAssistantPrompt] = useState(
    "Explain this threat, how it would likely be exploited, and what I should do next."
  );
  const [assistantLoading, setAssistantLoading] = useState(false);
  const [assistantError, setAssistantError] = useState<string | null>(null);
  const [assistantResponse, setAssistantResponse] = useState<AssistantResponse | null>(null);
  const [auditHistory, setAuditHistory] = useState<ThreatAuditEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelResponse | null>(null);
  const [threatIntelLoading, setThreatIntelLoading] = useState(false);
  const [threatIntelError, setThreatIntelError] = useState<string | null>(null);
  const [scanCorrelation, setScanCorrelation] =
    useState<ThreatScanCorrelationResponse | null>(null);
  const [dfdNodes, setDfdNodes] = useState<DFDNodeResponse[]>([]);
  const [dfdEdges, setDfdEdges] = useState<DFDEdgeResponse[]>([]);
  const [ruleDetail, setRuleDetail] = useState<ThreatCatalogEntry | null>(null);
  const [validationRuns, setValidationRuns] = useState<ThreatValidationRun[]>([]);
  const [validationLoading, setValidationLoading] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [selectedValidationRunId, setSelectedValidationRunId] = useState<string | null>(null);
  const [selectedDomainAgents, setSelectedDomainAgents] = useState<DomainValidationAgentType[]>([
    "sast",
  ]);
  const [domainAgentTools, setDomainAgentTools] = useState<
    Partial<Record<DomainValidationAgentType, string[]>>
  >({ sast: ["semgrep"] });
  const [domainAgentToolMode, setDomainAgentToolMode] = useState<
    Partial<Record<DomainValidationAgentType, DomainAgentToolMode>>
  >({ sast: "recommended" });
  const [domainAgentInstructions, setDomainAgentInstructions] = useState<
    Partial<Record<DomainValidationAgentType, string>>
  >({});
  const [runnerTargetType, setRunnerTargetType] = useState<ValidationTargetType>("repository_path");
  const [runnerTarget, setRunnerTarget] = useState("");
  const [runnerAuthorization, setRunnerAuthorization] = useState(false);
  const [remediationRuns, setRemediationRuns] = useState<ThreatRemediationRun[]>([]);
  const [remediationLoading, setRemediationLoading] = useState<FixAgentType | null>(null);
  const [remediationError, setRemediationError] = useState<string | null>(null);
  const [handoffRunId, setHandoffRunId] = useState<string | null>(null);
  const [handoffProvider, setHandoffProvider] = useState<"manual" | "github_issue">("manual");
  const [githubRepository, setGithubRepository] = useState("");
  const [githubToken, setGithubToken] = useState("");

  const fetchThreat = useCallback(async () => {
    if (!threatModelId || !threatId) return;
    try {
      const data = await api.getThreat(threatModelId, threatId);
      setThreat(data);
      setNotFound(false);
      setError(null);
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "Failed to load threat";
      if (message.includes("404")) {
        setNotFound(true);
      } else {
        setError(message);
      }
    } finally {
      setLoading(false);
    }
  }, [threatId, threatModelId]);

  const fetchHistory = useCallback(async () => {
    if (!threatModelId || !threatId) return;
    setHistoryLoading(true);
    try {
      const entries = await api.getThreatHistory(threatModelId, threatId);
      setAuditHistory(entries);
    } catch {
      setAuditHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }, [threatId, threatModelId]);

  useEffect(() => {
    void fetchThreat();
  }, [fetchThreat]);

  useEffect(() => {
    void fetchHistory();
  }, [fetchHistory]);

  const fetchValidationRuns = useCallback(async () => {
    if (!threatModelId || !threatId) return;
    try {
      const runs = await api.listThreatValidationRuns(threatModelId, threatId);
      setValidationRuns(runs);
      setSelectedValidationRunId((current) => current ?? runs[0]?.id ?? null);
    } catch (caught) {
      setValidationError(
        caught instanceof Error ? caught.message : "Failed to load validation runs"
      );
    }
  }, [threatId, threatModelId]);

  useEffect(() => {
    void fetchValidationRuns();
  }, [fetchValidationRuns]);

  useEffect(() => {
    if (!threatModelId) return;
    let cancelled = false;
    api.getDFD(threatModelId)
      .then((dfd) => {
        if (!cancelled) {
          setDfdNodes(dfd.nodes);
          setDfdEdges(dfd.edges);
        }
      })
      .catch(() => {
        // non-critical — UUID fallback is fine
      });
    return () => { cancelled = true; };
  }, [threatModelId]);

  useEffect(() => {
    if (!threat?.rule_id) {
      setRuleDetail(null);
      return;
    }
    let cancelled = false;
    api.getThreatCatalog(undefined, undefined).then((catalog) => {
      if (!cancelled) {
        const match = catalog.find((e) => e.rule_id === threat.rule_id);
        setRuleDetail(match ?? null);
      }
    }).catch(() => { /* non-critical */ });
    return () => { cancelled = true; };
  }, [threat?.rule_id]);

  useEffect(() => {
    // Deferred: only fetch intel after the primary threat data has loaded.
    // The /intel endpoint does a 4.6s pgvector search — loading it on mount
    // would block a visible section of the page before the threat content renders.
    if (!threatModelId || !threatId || !threat?.id) return;
    let cancelled = false;

    const fetchThreatIntel = async () => {
      setThreatIntelLoading(true);
      setThreatIntelError(null);
      try {
        const intel = await api.getThreatIntel(threatModelId, threatId);
        if (!cancelled) {
          setThreatIntel(intel);
        }
      } catch (caught) {
        if (!cancelled) {
          setThreatIntel(null);
          setThreatIntelError(
            caught instanceof Error ? caught.message : "Failed to load threat intelligence"
          );
        }
      } finally {
        if (!cancelled) {
          setThreatIntelLoading(false);
        }
      }
    };

    void fetchThreatIntel();

    return () => {
      cancelled = true;
    };
  }, [threatId, threatModelId, threat?.id]);

  useEffect(() => {
    if (!threat || !threatModelId) return;
    const fetchScanCorrelation = async () => {
      try {
        const result = await api.getLatestThreatScanCorrelation(threatModelId, threat.id);
        setScanCorrelation(result);
      } catch {
        setScanCorrelation(null);
      }
    };
    void fetchScanCorrelation();
  }, [threat, threatModelId]);

  const handleTriaged = useCallback(
    (updated: ThreatResponse) => {
      setThreat(updated);
      setThreatIntel((current) =>
        current ? { ...current, local_severity: updated.severity } : current
      );
      setShowTriageModal(false);
      void fetchHistory();
    },
    [fetchHistory]
  );

  const handleAskAboutThreat = useCallback(async () => {
    if (!threatModelId || !threat) return;
    setAssistantLoading(true);
    setAssistantError(null);
    try {
      const prompt = assistantPrompt.trim();
      const response = await api.assistantRespond(threatModelId, {
        message: prompt.startsWith("/") ? prompt : `/explain ${prompt}`,
        anchor: {
          kind: "threat",
          id: threat.id,
        },
        mode_hint: "explain",
      });
      setAssistantResponse(response);
    } catch (caught) {
      setAssistantError(
        caught instanceof Error ? caught.message : "Assistant request failed"
      );
    } finally {
      setAssistantLoading(false);
    }
  }, [assistantPrompt, threat, threatModelId]);

  const toggleDomainAgent = useCallback((agent: DomainValidationAgentType) => {
    const option = DOMAIN_AGENT_OPTIONS.find((item) => item.id === agent);
    setSelectedDomainAgents((current) =>
      current.includes(agent)
        ? current.filter((item) => item !== agent)
        : [...current, agent]
    );
    setDomainAgentTools((current) => ({
      ...current,
      [agent]: current[agent]?.length ? current[agent] : option?.tools ?? [],
    }));
    setDomainAgentToolMode((current) => ({
      ...current,
      [agent]: current[agent] ?? "recommended",
    }));
  }, []);

  const toggleDomainTool = useCallback(
    (agent: DomainValidationAgentType, tool: string) => {
      setDomainAgentToolMode((current) => ({
        ...current,
        [agent]: "manual",
      }));
      setDomainAgentTools((current) => {
        const currentTools =
          current[agent] ??
          DOMAIN_AGENT_OPTIONS.find((item) => item.id === agent)?.tools ??
          [];
        const nextTools = currentTools.includes(tool)
          ? currentTools.filter((item) => item !== tool)
          : [...currentTools, tool];
        return { ...current, [agent]: nextTools };
      });
    },
    []
  );

  const buildValidationRequest = useCallback(() => {
    const selectedToolsByAgent = Object.fromEntries(
        selectedDomainAgents.map((agent) => {
          const option = DOMAIN_AGENT_OPTIONS.find((item) => item.id === agent);
          return [agent, domainAgentTools[agent] ?? option?.tools ?? []];
        })
      ) as Partial<Record<DomainValidationAgentType, string[]>>;
    const requestedTools = Array.from(
        new Set(Object.values(selectedToolsByAgent).flatMap((tools) => tools ?? []))
      );
    const instructions = Object.fromEntries(
        selectedDomainAgents
          .map((agent) => [agent, domainAgentInstructions[agent]?.trim() ?? ""] as const)
          .filter(([, value]) => value.length > 0)
      ) as Partial<Record<DomainValidationAgentType, string>>;
    const toolMode = Object.fromEntries(
      selectedDomainAgents.map((agent) => [
        agent,
        domainAgentToolMode[agent] ?? "recommended",
      ])
    ) as Partial<Record<DomainValidationAgentType, DomainAgentToolMode>>;
    return {
      selectedToolsByAgent,
      requestedTools,
      instructions,
      toolMode,
    };
  }, [domainAgentInstructions, domainAgentToolMode, domainAgentTools, selectedDomainAgents]);

  const buildDomainAgentTargets = useCallback(
    (tools: string[]) => {
      const trimmedTarget = runnerTarget.trim();
      if (!trimmedTarget) return undefined;
      return Object.fromEntries(
        tools.map((tool) => [
          tool,
          {
            tool_name: tool,
            target_type: runnerTargetType,
            target: trimmedTarget,
            scope: "internal",
            authorization_acknowledged: runnerAuthorization,
          } satisfies DomainAgentTargetRequest,
        ])
      );
    },
    [runnerAuthorization, runnerTarget, runnerTargetType]
  );

  const handleValidateThreat = useCallback(async () => {
    if (!threatModelId || !threat) return;
    setValidationLoading(true);
    setValidationError(null);
    try {
      const { selectedToolsByAgent, requestedTools, instructions, toolMode } =
        buildValidationRequest();
      const domainAgentTargets = buildDomainAgentTargets(requestedTools);
      const run = await api.startThreatValidationRun(threatModelId, threat.id, {
        domain_agents: selectedDomainAgents,
        domain_agent_tools: selectedToolsByAgent,
        domain_agent_tool_mode: toolMode,
        domain_agent_instructions: instructions,
        ...(domainAgentTargets ? { domain_agent_targets: domainAgentTargets } : {}),
        requested_tools: requestedTools,
      });
      setValidationRuns((current) => [run, ...current.filter((item) => item.id !== run.id)]);
      setSelectedValidationRunId(run.id);
    } catch (caught) {
      setValidationError(caught instanceof Error ? caught.message : "Validation failed");
    } finally {
      setValidationLoading(false);
    }
  }, [
    buildDomainAgentTargets,
    buildValidationRequest,
    selectedDomainAgents,
    threat,
    threatModelId,
  ]);

  const handleProposeScanPlan = useCallback(async () => {
    if (!threatModelId || !threat) return;
    setValidationLoading(true);
    setValidationError(null);
    try {
      const { selectedToolsByAgent, requestedTools, instructions, toolMode } =
        buildValidationRequest();
      const run = await api.proposeThreatScanPlan(threatModelId, threat.id, {
        domain_agents: selectedDomainAgents,
        domain_agent_tools: selectedToolsByAgent,
        domain_agent_tool_mode: toolMode,
        domain_agent_instructions: instructions,
        requested_tools: requestedTools,
      });
      setValidationRuns((current) => [run, ...current.filter((item) => item.id !== run.id)]);
      setSelectedValidationRunId(run.id);
    } catch (caught) {
      setValidationError(caught instanceof Error ? caught.message : "Scan plan failed");
    } finally {
      setValidationLoading(false);
    }
  }, [buildValidationRequest, selectedDomainAgents, threat, threatModelId]);

  const handleApproveScanPlan = useCallback(async () => {
    const selected = validationRuns.find((item) => item.id === selectedValidationRunId);
    if (!selected) return;
    setValidationLoading(true);
    setValidationError(null);
    try {
      const requestedTools =
        selected.requested_tools.length > 0
          ? selected.requested_tools
          : selected.domain_agent_plan.flatMap((item) => item.tools);
      const domainAgentTargets = buildDomainAgentTargets(Array.from(new Set(requestedTools)));
      const run = await api.approveThreatScanPlan(selected.id, {
        ...(domainAgentTargets ? { domain_agent_targets: domainAgentTargets } : {}),
        approval_note: runnerAuthorization
          ? "Reviewer authorized controlled domain-agent tool execution."
          : "Reviewer approved the scan plan without a controlled runner target.",
      });
      setValidationRuns((current) => [run, ...current.filter((item) => item.id !== run.id)]);
      setSelectedValidationRunId(run.id);
    } catch (caught) {
      setValidationError(caught instanceof Error ? caught.message : "Scan plan approval failed");
    } finally {
      setValidationLoading(false);
    }
  }, [
    buildDomainAgentTargets,
    runnerAuthorization,
    selectedValidationRunId,
    validationRuns,
  ]);

  useEffect(() => {
    if (searchParams.get("validate") !== "1" || !threat) return;
    void handleValidateThreat();
    const next = new URLSearchParams(searchParams);
    next.delete("validate");
    setSearchParams(next, { replace: true });
  }, [handleValidateThreat, searchParams, setSearchParams, threat]);

  const handleRerunValidation = useCallback(async () => {
    const selected = validationRuns.find((item) => item.id === selectedValidationRunId);
    if (!selected) return;
    setValidationLoading(true);
    setValidationError(null);
    try {
      const run = await api.rerunThreatValidationRun(selected.id);
      setValidationRuns((current) => [run, ...current]);
      setSelectedValidationRunId(run.id);
    } catch (caught) {
      setValidationError(caught instanceof Error ? caught.message : "Validation rerun failed");
    } finally {
      setValidationLoading(false);
    }
  }, [selectedValidationRunId, validationRuns]);

  const handleGenerateFix = useCallback(
    async (agentType: FixAgentType) => {
      const selected = validationRuns.find((item) => item.id === selectedValidationRunId);
      if (!selected) return;
      setRemediationLoading(agentType);
      setRemediationError(null);
      try {
        const run = await api.startThreatRemediationRun(selected.id, agentType);
        setRemediationRuns((current) => [run, ...current.filter((item) => item.id !== run.id)]);
      } catch (caught) {
        setRemediationError(caught instanceof Error ? caught.message : "Fix generation failed");
      } finally {
        setRemediationLoading(null);
      }
    },
    [selectedValidationRunId, validationRuns]
  );

  const handleOpenHandoffModal = useCallback((run: ThreatRemediationRun) => {
    setRemediationError(null);
    setHandoffRunId(run.id);
    setHandoffProvider("manual");
    setGithubRepository("");
    setGithubToken("");
  }, []);

  const handleSubmitHandoff = useCallback(async () => {
    const run = remediationRuns.find((item) => item.id === handoffRunId);
    if (!run) return;
    setRemediationError(null);
    try {
      const updated = await api.confirmThreatRemediationHandoff(run.id, {
        confirmed: true,
        provider: handoffProvider,
        github_repository: handoffProvider === "github_issue" ? githubRepository : null,
        access_token: handoffProvider === "github_issue" ? githubToken : null,
        confirmed_by: user?.email ?? "reviewer",
      });
      setRemediationRuns((current) =>
        current.map((item) => (item.id === updated.id ? updated : item))
      );
      setHandoffRunId(null);
      setGithubToken("");
    } catch (caught) {
      setRemediationError(caught instanceof Error ? caught.message : "Handoff failed");
    }
  }, [githubRepository, githubToken, handoffProvider, handoffRunId, remediationRuns, user?.email]);

  const handleAttachRemediationEvidence = useCallback(async (run: ThreatRemediationRun) => {
    setRemediationError(null);
    try {
      const updated = await api.attachThreatRemediationEvidence(run.id, {
        provider: run.agent_type === "configuration_fix" ? "manual" : "github_issue",
        evidence_summary: "Confirmed handoff evidence attached for rerun validation.",
        external_ticket_id: run.external_ticket_id,
        external_ticket_url: run.external_ticket_url,
        external_pr_url: run.external_pr_url,
      });
      setRemediationRuns((current) =>
        current.map((item) => (item.id === updated.id ? updated : item))
      );
    } catch (caught) {
      setRemediationError(
        caught instanceof Error ? caught.message : "Evidence attachment failed"
      );
    }
  }, []);

  if (loading) {
    return (
      <div className="page-loading">
        <div className="dfd-spinner" />
        <span>Loading threat...</span>
      </div>
    );
  }

  if (!threatModelId) {
    return null;
  }

  if (error) {
    return (
      <div className="td-page">
        <div className="td-shell td-shell-empty">
          <Link to={`/threat-models/${threatModelId}`} className="td-back">
            &larr; Back to Threat Model
          </Link>
          <section className="td-section td-section-empty">
            <p className="td-section-kicker">Load Error</p>
            <h1 className="td-section-title">Threat detail is unavailable.</h1>
            <p className="td-copy td-copy-muted">Failed to load threat: {error}</p>
          </section>
        </div>
      </div>
    );
  }

  if (notFound) {
    return (
      <div className="td-page">
        <div className="td-shell td-shell-empty">
          <Link to={`/threat-models/${threatModelId}`} className="td-back">
            &larr; Back to Threat Model
          </Link>
          <section className="td-section td-section-empty">
            <p className="td-section-kicker">Not Found</p>
            <h1 className="td-section-title">Threat record not found.</h1>
            <p className="td-copy td-copy-muted">
              The threat you are looking for does not exist or has been removed.
            </p>
          </section>
        </div>
      </div>
    );
  }

  if (!threat) return null;

  const controlsByFramework = threat.compliance_controls.reduce<
    Record<string, typeof threat.compliance_controls>
  >((groups, control) => {
    const framework = control.framework;
    if (!groups[framework]) groups[framework] = [];
    groups[framework].push(control);
    return groups;
  }, {});
  const selectedValidationRun =
    validationRuns.find((item) => item.id === selectedValidationRunId) ?? validationRuns[0] ?? null;
  const canGenerateFix =
    selectedValidationRun?.conclusion === "confirmed" ||
    selectedValidationRun?.conclusion === "needs_human_review";
  const canApproveScanPlan = selectedValidationRun?.status === "created";

  return (
    <div className="td-page">
      <div className="td-shell">
        <Link to={`/threat-models/${threatModelId}`} className="td-back">
          &larr; Back to Threat Model
        </Link>

        <header className="td-header">
          <div className="td-header-main">
            <p className="td-kicker">Threat Record</p>
            <h1 className="td-title">{threat.display_id}</h1>
            {threat.threat_subtype ? (
              <p className="td-subtitle">{threat.threat_subtype}</p>
            ) : null}
          </div>
          <div className="td-badge-row">
            <span className={toneClass("td-badge", severityTone(threat.severity))}>
              {threat.severity}
            </span>
            <span className={toneClass("td-badge", statusTone(threat.status))}>
              {threat.status}
            </span>
            {threat.residual_risk_level ? (
              <span className={toneClass("td-badge", residualRiskTone(threat.residual_risk_level))}>
                Residual {threat.residual_risk_level}
              </span>
            ) : null}
            <span className="td-badge td-badge--stride">{threat.stride_category}</span>
          </div>
        </header>

        <section className="td-saas-context" aria-label="SaaS workspace and validation context">
          <div>
            <span className="td-meta-label">Workspace</span>
            <strong>{user?.organization_name || "Personal pilot workspace"}</strong>
          </div>
          <div>
            <span className="td-meta-label">Reviewer Role</span>
            <strong>{user?.role || "User"}</strong>
          </div>
          <div>
            <span className="td-meta-label">Validation Boundary</span>
            <strong>Imported evidence and Try Sandbox are SaaS-safe; live tools require an isolated runner.</strong>
          </div>
        </section>

        <div className={`td-story-grid${threat.relevance_rationale ? "" : " td-story-grid-single"}`}>
          <section className="td-section">
            <p className="td-section-kicker">Threat Narrative</p>
            <h2 className="td-section-title">Description</h2>
            <p className="td-copy">{cleanDescription(threat.description)}</p>
          </section>

          {threat.relevance_rationale ? (
            <section className="td-section">
              <p className="td-section-kicker">Applicability</p>
              <h2 className="td-section-title">Why This Matters</h2>
              <p className="td-copy">{threat.relevance_rationale}</p>
            </section>
          ) : null}
        </div>

        <section className="td-section">
          <p className="td-section-kicker">Snapshot</p>
          <h2 className="td-section-title">Metadata</h2>
          <div className="td-meta-grid">
            <div className="td-meta-item">
              <span className="td-meta-label">Source</span>
              <span className="td-meta-value">{threat.source}</span>
            </div>
            {threat.threat_subtype ? (
              <div className="td-meta-item">
                <span className="td-meta-label">Threat Title</span>
                <span className="td-meta-value">{threat.threat_subtype}</span>
              </div>
            ) : null}
            {threat.rule_id ? (
              <div className="td-meta-item">
                <span className="td-meta-label">Rule ID</span>
                <span className="td-meta-value td-meta-value-mono">{threat.rule_id}</span>
              </div>
            ) : null}
            {ruleDetail ? (
              <div className="td-meta-item" style={{ gridColumn: "1 / -1" }}>
                <span className="td-meta-label">Rule Logic</span>
                <span className="td-meta-value" style={{ fontSize: "0.82rem", lineHeight: 1.5 }}>
                  <strong>{ruleDetail.threat_subtype}</strong>
                  <span className="td-copy-muted" style={{ display: "block", marginTop: 4 }}>
                    Condition: {ruleDetail.condition_type === "tuple"
                      ? "Fires when a matching source-edge-target tuple crosses a trust boundary"
                      : ruleDetail.condition_type === "standalone"
                        ? "Fires on individual nodes matching specific properties"
                        : ruleDetail.condition_type}
                  </span>
                  <span className="td-copy-muted" style={{ display: "block", marginTop: 2 }}>
                    Template: {ruleDetail.description_template.slice(0, 200)}{ruleDetail.description_template.length > 200 ? "..." : ""}
                  </span>
                </span>
              </div>
            ) : null}
            <div className="td-meta-item">
              <span className="td-meta-label">Created</span>
              <span className="td-meta-value">{formatDisplayDate(threat.created_at)}</span>
            </div>
            <div className="td-meta-item">
              <span className="td-meta-label">AI Enhanced</span>
              <span className="td-meta-value">{threat.ai_enhanced ? "Yes" : "No"}</span>
            </div>
            {threat.provider_managed ? (
              <div className="td-meta-item">
                <span className="td-meta-label">Responsibility</span>
                <span className="td-pill td-pill--info">Provider-managed</span>
              </div>
            ) : null}
          </div>
        </section>

        <section className="td-section">
          <p className="td-section-kicker">Signals</p>
          <h2 className="td-section-title">Threat Intel</h2>
          <ThreatIntelPanel
            intel={threatIntel}
            loading={threatIntelLoading}
            error={threatIntelError}
          />
        </section>

        {(threat.affected_node_ids.length > 0 ||
          threat.affected_edge_ids.length > 0 ||
          threat.compliance_controls.length > 0) && (
          <div className="td-support-grid">
            {(threat.affected_node_ids.length > 0 || threat.affected_edge_ids.length > 0) && (
              <section className="td-section">
                <p className="td-section-kicker">Blast Radius</p>
                <h2 className="td-section-title">Affected Components</h2>
                {threat.affected_node_ids.length > 0 ? (
                  <div className="td-stack">
                    <span className="td-meta-label">Nodes</span>
                    <ul className="td-mono-list">
                      {threat.affected_node_ids.map((nodeId) => {
                        const node = dfdNodes.find((n) => n.id === nodeId);
                        return (
                          <li key={nodeId}>
                            {node ? (
                              <><strong>{node.name}</strong> <span className="td-copy-muted">({node.node_type})</span></>
                            ) : (
                              nodeId
                            )}
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ) : null}
                {threat.affected_edge_ids.length > 0 ? (
                  <div className="td-stack">
                    <span className="td-meta-label">Data Flows</span>
                    <ul className="td-mono-list">
                      {threat.affected_edge_ids.map((edgeId) => {
                        const edge = dfdEdges.find((e) => e.id === edgeId);
                        if (edge) {
                          const srcNode = dfdNodes.find((n) => n.id === edge.source_node_id);
                          const tgtNode = dfdNodes.find((n) => n.id === edge.target_node_id);
                          const srcName = srcNode?.name ?? edge.source_node_id;
                          const tgtName = tgtNode?.name ?? edge.target_node_id;
                          return (
                            <li key={edgeId}>
                              <strong>{srcName}</strong> &rarr; <strong>{tgtName}</strong>
                              {edge.label ? <span className="td-copy-muted"> ({edge.label})</span> : null}
                            </li>
                          );
                        }
                        return <li key={edgeId}>{edgeId}</li>;
                      })}
                    </ul>
                  </div>
                ) : null}
              </section>
            )}

            {threat.compliance_controls.length > 0 ? (
              <section className="td-section">
                <p className="td-section-kicker">Control Mapping</p>
                <h2 className="td-section-title">Compliance Controls</h2>
                <div className="td-stack">
                  {Object.entries(controlsByFramework).map(([framework, controls]) => (
                    <div key={framework} className="td-control-group">
                      <span className="td-control-framework">{framework}</span>
                      <ul className="td-control-list">
                        {controls.map((control) => (
                          <li key={`${control.framework}-${control.control_id}`}>
                            <strong>{control.control_id}</strong> {control.control_name}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </section>
            ) : null}
          </div>
        )}

        {(threat.mitigation_plan ||
          threat.mitigation_owner ||
          threat.due_date ||
          threat.mitigation_notes ||
          threat.dismiss_reason ||
          threat.closed_at ||
          threat.status !== "Open") && (
          <section className="td-section">
            <p className="td-section-kicker">Disposition</p>
            <h2 className="td-section-title">Mitigation and Workflow</h2>
            <div className="td-meta-grid">
              <div className="td-meta-item">
                <span className="td-meta-label">Workflow Status</span>
                <span className="td-meta-value">{threat.status}</span>
              </div>
              <div className="td-meta-item">
                <span className="td-meta-label">Control Effectiveness</span>
                <span className="td-meta-value">
                  {CONTROL_EFFECTIVENESS_LABELS[threat.control_effectiveness] ??
                    threat.control_effectiveness}
                </span>
              </div>
              {threat.residual_risk_level ? (
                <div className="td-meta-item">
                  <span className="td-meta-label">Residual Risk</span>
                  <span className="td-meta-value">{threat.residual_risk_level}</span>
                </div>
              ) : null}
              {threat.mitigation_owner ? (
                <div className="td-meta-item">
                  <span className="td-meta-label">Owner</span>
                  <span className="td-meta-value">{threat.mitigation_owner}</span>
                </div>
              ) : null}
              {threat.due_date ? (
                <div className="td-meta-item">
                  <span className="td-meta-label">Due Date</span>
                  <span className="td-meta-value">{threat.due_date}</span>
                </div>
              ) : null}
              {threat.closed_at ? (
                <div className="td-meta-item">
                  <span className="td-meta-label">Closed</span>
                  <span className="td-meta-value">{formatDisplayDate(threat.closed_at)}</span>
                </div>
              ) : null}
            </div>

            {threat.mitigation_plan ? (
              <div className="td-note-block">
                <span className="td-meta-label">Mitigation Plan</span>
                <p className="td-copy">{threat.mitigation_plan}</p>
              </div>
            ) : null}

            {threat.mitigation_notes ? (
              <div className="td-note-block">
                <span className="td-meta-label">Mitigation Notes</span>
                <p className="td-copy">{threat.mitigation_notes}</p>
              </div>
            ) : null}

            {threat.dismiss_reason ? (
              <div className="td-note-block">
                <span className="td-meta-label">Dismiss Reason</span>
                <p className="td-copy">{threat.dismiss_reason}</p>
              </div>
            ) : null}
          </section>
        )}

        <section className="td-section">
          <p className="td-section-kicker">Workflow</p>
          <h2 className="td-section-title">Triage Actions</h2>
          <div className="td-action-row">
            <button
              type="button"
              className="td-btn td-btn--primary"
              onClick={() => setShowTriageModal(true)}
              title="Open the triage workflow for this threat"
            >
              Update Status and Mitigation
            </button>
            <button
              type="button"
              className="td-btn td-btn--secondary"
              onClick={handleAskAboutThreat}
              disabled={assistantLoading}
              title="Ask the assistant to explain this threat and recommend next steps"
            >
              {assistantLoading ? "Asking AI..." : "Ask AI About This Threat"}
            </button>
          </div>
          <p className="td-copy td-copy-muted">
            Move the threat through triage, keep mitigation ownership current, and capture
            the rationale behind accepted or dismissed risk.
          </p>
        </section>

        <section className="td-section">
          <p className="td-section-kicker">Agent Orchestration</p>
          <h2 className="td-section-title">Threat Validation and Fix Handoff</h2>
          <div className="td-note-block">
            <span className="td-meta-label">Validation Setup</span>
            <div className="td-stack">
              {DOMAIN_AGENT_OPTIONS.map((agent) => {
                const selected = selectedDomainAgents.includes(agent.id);
                const selectedTools = domainAgentTools[agent.id] ?? agent.tools;
                return (
                  <div key={agent.id} className="td-stack">
                    <label className="td-copy">
                      <input
                        type="checkbox"
                        checked={selected}
                        onChange={() => toggleDomainAgent(agent.id)}
                      />{" "}
                      <strong>{agent.label}</strong>
                    </label>
                    <div className="td-chip-group">
                      {agent.tools.map((tool) => (
                        <label key={`${agent.id}-${tool}`} className="td-chip">
                          <input
                            type="checkbox"
                            checked={selectedTools.includes(tool)}
                            disabled={!selected}
                            onChange={() => toggleDomainTool(agent.id, tool)}
                          />{" "}
                          {formatValidationToolName(tool)}
                        </label>
                      ))}
                    </div>
                    <label className="td-field">
                      <span>Tool Selection</span>
                      <select
                        className="td-input"
                        value={domainAgentToolMode[agent.id] ?? "recommended"}
                        disabled={!selected}
                        onChange={(event) =>
                          setDomainAgentToolMode((current) => ({
                            ...current,
                            [agent.id]: event.target.value as DomainAgentToolMode,
                          }))
                        }
                        title={`Choose how ${agent.label} selects validation tools`}
                      >
                        <option value="recommended">Best available</option>
                        <option value="all">Run all allowed tools</option>
                        <option value="manual">Manual tool selection</option>
                      </select>
                    </label>
                    <textarea
                      className="td-textarea"
                      rows={2}
                      value={domainAgentInstructions[agent.id] ?? ""}
                      disabled={!selected}
                      onChange={(event) =>
                        setDomainAgentInstructions((current) => ({
                          ...current,
                          [agent.id]: event.target.value,
                        }))
                      }
                      placeholder={`Special instructions for ${agent.label}`}
                      title={`Special instructions for ${agent.label}`}
                    />
                    {agent.warning && selected ? (
                      <p className="td-copy td-copy-muted">{agent.warning}</p>
                    ) : null}
                  </div>
                );
              })}
              <div className="td-stack">
                <span className="td-meta-label">Controlled Runner Target</span>
                <div className="td-form-grid">
                  <label className="td-field">
                    <span>Target Type</span>
                    <select
                      className="td-input"
                      value={runnerTargetType}
                      onChange={(event) => setRunnerTargetType(event.target.value as ValidationTargetType)}
                      title="Select the target type for controlled validation runners"
                    >
                      <option value="repository_path">Repository Path</option>
                      <option value="iac_directory">IaC Directory</option>
                      <option value="lockfile">Lockfile</option>
                      <option value="container_image">Container Image</option>
                      <option value="ai_system">AI System Evidence</option>
                      <option value="url">URL</option>
                    </select>
                  </label>
                  <label className="td-field">
                    <span>Target</span>
                    <input
                      className="td-input"
                      value={runnerTarget}
                      onChange={(event) => setRunnerTarget(event.target.value)}
                      placeholder="tgx-target://bundle-id or approved local target"
                      title="Controlled runner target reference"
                    />
                  </label>
                </div>
                <label className="td-copy">
                  <input
                    type="checkbox"
                    checked={runnerAuthorization}
                    onChange={(event) => setRunnerAuthorization(event.target.checked)}
                  />{" "}
                  I am authorized to validate this target.
                </label>
              </div>
            </div>
          </div>
          <div className="td-action-row">
            <button
              type="button"
              className="td-btn td-btn--primary"
              onClick={handleValidateThreat}
              disabled={validationLoading}
              title="Run the model-agnostic Threat Validation Agent for this threat"
            >
              {validationLoading ? "Validating..." : "Validate Threat"}
            </button>
            <button
              type="button"
              className="td-btn td-btn--secondary"
              onClick={handleProposeScanPlan}
              disabled={validationLoading}
              title="Propose a human-approved domain-agent scan plan before running tools"
            >
              Propose Scan Plan
            </button>
            <button
              type="button"
              className="td-btn td-btn--secondary"
              onClick={handleApproveScanPlan}
              disabled={validationLoading || !canApproveScanPlan}
              title="Approve the selected scan plan and authorize controlled tool execution"
            >
              Approve Scan Plan
            </button>
            <button
              type="button"
              className="td-btn td-btn--secondary"
              onClick={handleRerunValidation}
              disabled={validationLoading || !selectedValidationRun}
              title="Rerun validation using the same evidence scope"
            >
              Rerun Validation
            </button>
          </div>

          {validationError ? <p className="td-inline-error">{validationError}</p> : null}

          {selectedValidationRun ? (
            <div className="td-note-block">
              <div className="td-badge-row">
                <span
                  className={toneClass(
                    "td-badge",
                    validationTone(selectedValidationRun.conclusion)
                  )}
                >
                  {validationConclusionLabel(selectedValidationRun.conclusion)}
                </span>
                {selectedValidationRun.metadata.deterministic_fallback_used ? (
                  <span className="td-badge td-badge--info">Deterministic fallback</span>
                ) : null}
                {selectedValidationRun.metadata.model_provider ? (
                  <span className="td-badge td-badge--stride">
                    {selectedValidationRun.metadata.model_provider} /{" "}
                    {selectedValidationRun.metadata.model_name ?? "model"}
                  </span>
                ) : null}
              </div>
              <p className="td-copy">{selectedValidationRun.summary}</p>
              <div className="td-stack">
                <span className="td-meta-label">Exploitability</span>
                <div className="td-badge-row">
                  <span
                    className={toneClass(
                      "td-badge",
                      exploitabilityTone(selectedValidationRun.exploitability.status)
                    )}
                  >
                    {exploitabilityLabel(selectedValidationRun.exploitability.status)}
                  </span>
                  <span className="td-badge td-badge--muted">
                    Confidence {selectedValidationRun.exploitability.confidence}
                  </span>
                </div>
                {selectedValidationRun.exploitability.attacker_profile ? (
                  <p className="td-copy">
                    <strong>Attacker:</strong>{" "}
                    {selectedValidationRun.exploitability.attacker_profile}
                  </p>
                ) : null}
                {selectedValidationRun.exploitability.rationale ? (
                  <p className="td-copy td-copy-muted">
                    {selectedValidationRun.exploitability.rationale}
                  </p>
                ) : null}
                {selectedValidationRun.exploitability.attack_path.length > 0 ? (
                  <ol className="td-control-list">
                    {selectedValidationRun.exploitability.attack_path.map((step, index) => (
                      <li key={`${index}-${step}`}>{step}</li>
                    ))}
                  </ol>
                ) : null}
                {selectedValidationRun.exploitability.preconditions.length > 0 ? (
                  <div>
                    <span className="td-meta-label">Required Preconditions</span>
                    <ul className="td-control-list">
                      {selectedValidationRun.exploitability.preconditions.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                {selectedValidationRun.exploitability.blocking_controls.length > 0 ? (
                  <div>
                    <span className="td-meta-label">Blocking Controls</span>
                    <ul className="td-control-list">
                      {selectedValidationRun.exploitability.blocking_controls.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </div>
              <div className="td-meta-grid">
                <div className="td-meta-item">
                  <span className="td-meta-label">Agent Contract</span>
                  <span className="td-meta-value">
                    {selectedValidationRun.metadata.agent_version}
                  </span>
                </div>
                <div className="td-meta-item">
                  <span className="td-meta-label">Evidence Refs</span>
                  <span className="td-meta-value">
                    {selectedValidationRun.evidence_refs.length}
                  </span>
                </div>
                <div className="td-meta-item">
                  <span className="td-meta-label">Tools</span>
                  <span className="td-meta-value">
                    {selectedValidationRun.requested_tools.join(", ") || "none"}
                  </span>
                </div>
              </div>

              {(selectedValidationRun.domain_agent_plan ?? []).length > 0 ? (
                <div className="td-stack">
                  <span className="td-meta-label">Domain Agent Plan</span>
                  <ul className="td-control-list">
                    {(selectedValidationRun.domain_agent_plan ?? []).map((item) => (
                      <li key={item.domain_agent}>
                        <strong>{item.label}</strong>
                        <span className="td-copy-muted">
                          {" "}
                          {item.tools.length > 0
                            ? `Tools: ${item.tools.map(formatValidationToolName).join(", ")}`
                            : "No tools requested"}
                        </span>
                        {item.instructions ? (
                          <span className="td-copy-muted"> · {item.instructions}</span>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}

              {(selectedValidationRun.domain_agent_results ?? []).length > 0 ? (
                <div className="td-stack">
                  <span className="td-meta-label">Domain Execution</span>
                  <ul className="td-control-list">
                    {selectedValidationRun.domain_agent_results.map((result) => (
                      <li key={result.domain_agent}>
                        <strong>{result.label}</strong>{" "}
                        <span className="td-copy-muted">{result.status}</span>
                        {result.skipped_reason ? (
                          <span className="td-copy-muted"> · {result.skipped_reason}</span>
                        ) : null}
                        {result.tools.length > 0 ? (
                          <ul className="td-control-list">
                            {result.tools.map((tool) => (
                              <li key={`${result.domain_agent}-${tool.tool}`}>
                                {formatValidationToolName(tool.tool)}: {tool.status}
                                {tool.evidence_refs.length > 0
                                  ? ` · ${tool.evidence_refs.length} evidence ref(s)`
                                  : ""}
                                {tool.scan_job_id ? ` · scan ${tool.scan_job_id.slice(0, 8)}` : ""}
                                {tool.skipped_reason ? ` · ${tool.skipped_reason}` : ""}
                              </li>
                            ))}
                          </ul>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}

              {selectedValidationRun.evidence_refs.length > 0 ? (
                <div className="td-stack">
                  <span className="td-meta-label">Evidence Chain</span>
                  <ul className="td-control-list">
                    {selectedValidationRun.evidence_refs.slice(0, 6).map((ref, index) => (
                      <li key={`${String(ref.id ?? index)}`}>
                        <strong>{String(ref.title ?? "Evidence")}</strong>
                        <span className="td-copy-muted">
                          {" "}
                          {String(ref.item_type ?? ref.source_type ?? "evidence")}
                          {ref.content_hash ? ` · ${String(ref.content_hash).slice(0, 12)}` : ""}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}

              {selectedValidationRun.trace.events.length > 0 ? (
                <div className="td-stack">
                  <span className="td-meta-label">Agent Trace</span>
                  <ul className="td-control-list">
                    {selectedValidationRun.trace.events.slice(0, 8).map((event) => (
                      <li key={event.id}>
                        <strong>{String(event.payload.agent_event ?? event.event_type)}</strong>{" "}
                        {event.message}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : (
            <p className="td-copy td-copy-muted">
              No validation run exists yet. Validation uses controlled tool harnesses and
              deterministic evidence rules before any fix agent can create a handoff.
            </p>
          )}

          <div className="td-action-row">
            {(Object.keys(FIX_AGENT_LABELS) as FixAgentType[]).map((agentType) => (
              <button
                key={agentType}
                type="button"
                className="td-btn td-btn--secondary"
                onClick={() => void handleGenerateFix(agentType)}
                disabled={!canGenerateFix || remediationLoading !== null}
                title={`Draft a ${FIX_AGENT_LABELS[agentType]} remediation handoff`}
              >
                {remediationLoading === agentType
                  ? "Drafting..."
                  : `Generate ${FIX_AGENT_LABELS[agentType]}`}
              </button>
            ))}
          </div>

          {remediationError ? <p className="td-inline-error">{remediationError}</p> : null}

          {remediationRuns.length > 0 ? (
            <div className="td-stack">
              {remediationRuns.map((run) => (
                <div key={run.id} className="td-note-block">
                  <div className="td-badge-row">
                    <span className="td-badge td-badge--info">
                      {FIX_AGENT_LABELS[run.agent_type]}
                    </span>
                    <span className="td-badge td-badge--muted">{run.status}</span>
                    <span className="td-badge td-badge--muted">
                      {run.handoff_delivery_status}
                    </span>
                    {run.metadata.deterministic_fallback_used ? (
                      <span className="td-badge td-badge--info">Fallback draft</span>
                    ) : null}
                  </div>
                  <p className="td-copy">{run.fix_summary}</p>
                  {run.patch_preview ? (
                    <pre className="td-copy td-copy-prewrap">{run.patch_preview}</pre>
                  ) : null}
                  <div className="td-action-row">
                    <button
                      type="button"
                      className="td-btn td-btn--primary"
                      disabled={run.status === "handoff_created"}
                      onClick={() => handleOpenHandoffModal(run)}
                      title="Create the confirmed remediation PR/ticket handoff"
                    >
                      {run.status === "handoff_created" ? "Handoff Created" : "Confirm Handoff"}
                    </button>
                    {run.external_ticket_url ? (
                      <a className="td-btn td-btn--ghost" href={run.external_ticket_url}>
                        Open Ticket
                      </a>
                    ) : null}
                    {run.external_pr_url ? (
                      <a className="td-btn td-btn--ghost" href={run.external_pr_url}>
                        Open PR
                      </a>
                    ) : null}
                    {run.status === "handoff_created" ? (
                      <button
                        type="button"
                        className="td-btn td-btn--secondary"
                        onClick={() => void handleAttachRemediationEvidence(run)}
                        title="Attach handoff evidence for the next validation rerun"
                      >
                        Attach Evidence
                      </button>
                    ) : null}
                  </div>
                  {run.handoff_error ? (
                    <p className="td-inline-error">{run.handoff_error}</p>
                  ) : null}
                  {run.evidence_refs.length > 0 ? (
                    <div className="td-stack">
                      <span className="td-meta-label">Remediation Evidence</span>
                      <ul className="td-control-list">
                        {run.evidence_refs.slice(0, 4).map((ref, index) => (
                          <li key={`${String(ref.id ?? index)}`}>
                            {String(ref.title ?? ref.evidence_summary ?? "Evidence attached")}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          ) : null}
          {handoffRunId ? (
            <div className="td-note-block" role="dialog" aria-label="Confirm remediation handoff">
              <span className="td-meta-label">Confirm Handoff</span>
              <div className="td-stack">
                <label className="td-copy">
                  Provider
                  <select
                    className="td-input"
                    value={handoffProvider}
                    onChange={(event) =>
                      setHandoffProvider(event.target.value as "manual" | "github_issue")
                    }
                    title="Choose remediation handoff provider"
                  >
                    <option value="manual">Manual record</option>
                    <option value="github_issue">GitHub Issue</option>
                  </select>
                </label>
                {handoffProvider === "github_issue" ? (
                  <>
                    <label className="td-copy">
                      GitHub repository
                      <input
                        className="td-input"
                        value={githubRepository}
                        onChange={(event) => setGithubRepository(event.target.value)}
                        placeholder="owner/repository"
                        title="GitHub repository for the issue"
                      />
                    </label>
                    <label className="td-copy">
                      GitHub token
                      <input
                        className="td-input"
                        type="password"
                        value={githubToken}
                        onChange={(event) => setGithubToken(event.target.value)}
                        title="Customer-owned GitHub token used only for this request"
                      />
                    </label>
                  </>
                ) : null}
                <div className="td-action-row">
                  <button
                    type="button"
                    className="td-btn td-btn--primary"
                    onClick={() => void handleSubmitHandoff()}
                    disabled={
                      handoffProvider === "github_issue" &&
                      (!githubRepository.trim() || !githubToken.trim())
                    }
                  >
                    Create Handoff
                  </button>
                  <button
                    type="button"
                    className="td-btn td-btn--ghost"
                    onClick={() => {
                      setHandoffRunId(null);
                      setGithubToken("");
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          ) : null}
        </section>

        <section className="td-section">
          <p className="td-section-kicker">Analysis</p>
          <h2 className="td-section-title">AI Guidance</h2>
          <div className="td-stack">
            <textarea
              className="td-textarea"
              value={assistantPrompt}
              onChange={(event) => setAssistantPrompt(event.target.value)}
              placeholder="Ask a focused question about this threat..."
              rows={4}
              title="Write a focused question for the assistant about this threat"
            />
            <div className="td-action-row">
              <button
                type="button"
                className="td-btn td-btn--secondary"
                onClick={handleAskAboutThreat}
                disabled={assistantLoading}
                title="Send the current question to the assistant"
              >
                {assistantLoading ? "Thinking..." : "Ask AI"}
              </button>
              {assistantResponse ? (
                <button
                  type="button"
                  className="td-btn td-btn--ghost"
                  onClick={() => {
                    setAssistantResponse(null);
                    setAssistantError(null);
                  }}
                  title="Clear the current assistant answer"
                >
                  Clear Answer
                </button>
              ) : null}
            </div>

            {assistantError ? <p className="td-inline-error">{assistantError}</p> : null}

            {assistantResponse ? (
              <div className="td-note-block">
                <span className="td-meta-label">AI Answer</span>
                <p className="td-copy td-copy-prewrap">{assistantResponse.answer}</p>
                {assistantResponse.degraded_reason ? (
                  <p className="td-copy td-copy-muted">{assistantResponse.degraded_reason}</p>
                ) : null}
                {assistantResponse.findings.length > 0 ? (
                  <div className="td-stack">
                    <span className="td-meta-label">Key Findings</span>
                    <ul className="td-control-list">
                      {assistantResponse.findings.map((finding, index) => (
                        <li key={`${finding.title}-${index}`}>
                          <strong>{finding.title}</strong> {finding.description}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        </section>

        <section className="td-section">
          <p className="td-section-kicker">History</p>
          <h2 className="td-section-title">Audit Trail</h2>
          {historyLoading ? (
            <p className="td-copy td-copy-muted">Loading history...</p>
          ) : auditHistory.length === 0 ? (
            <p className="td-copy td-copy-muted">No history yet.</p>
          ) : (
            <ul className="td-timeline">
              {auditHistory.map((entry) => (
                <li key={entry.id} className="td-timeline-entry">
                  <span className="td-timeline-date">
                    {formatDisplayDateTime(entry.changed_at)} - {entry.changed_by}
                  </span>
                  <p className="td-copy td-copy-prewrap">
                    {entry.action}
                    {entry.old_status && entry.new_status
                      ? `: ${entry.old_status} -> ${entry.new_status}`
                      : entry.new_status
                        ? `: -> ${entry.new_status}`
                        : ""}
                  </p>
                  {entry.reason ? (
                    <p className="td-copy td-copy-muted">Reason: {entry.reason}</p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>

        {scanCorrelation ? (
          <section className={`td-section td-section-scan td-section-scan--${scanStatusTone(scanCorrelation.scan_status)}`}>
            <div className="td-section-header">
              <div>
                <p className="td-section-kicker">Validation</p>
                <h2 className="td-section-title">{scanStatusLabel(scanCorrelation.scan_status)}</h2>
              </div>
              <span className={toneClass("td-pill", scanStatusTone(scanCorrelation.scan_status))}>
                {scanCorrelation.scan_status.replace(/_/g, " ")}
              </span>
            </div>

            <p className="td-copy td-copy-muted">{scanStatusCopy(scanCorrelation.scan_status)}</p>

            <div className="td-scan-meta">
              <div className="td-scan-meta-item">
                <span className="td-meta-label">Latest completed scan</span>
                <span className="td-meta-value">
                  {scanCorrelation.scan_completed_at
                    ? formatDisplayDateTime(scanCorrelation.scan_completed_at)
                    : "Unknown"}
                </span>
              </div>
              {scanCorrelation.matched_targets.length > 0 ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Matched targets</span>
                  <span className="td-copy">{scanCorrelation.matched_targets.join(", ")}</span>
                </div>
              ) : null}
              {scanCorrelation.templates.length > 0 ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Templates</span>
                  <span className="td-copy">{scanCorrelation.templates.join(", ")}</span>
                </div>
              ) : null}
              {scanCorrelation.matched_node_labels.length > 0 ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Mapped DFD nodes</span>
                  <span className="td-copy">{scanCorrelation.matched_node_labels.join(", ")}</span>
                </div>
              ) : null}
              {scanCorrelation.finding_titles.length > 0 ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Finding trail</span>
                  <span className="td-copy">
                    {scanCorrelation.finding_titles.slice(0, 3).join(" | ")}
                  </span>
                </div>
              ) : null}
              {scanCorrelation.validation_tools?.length ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Evidence sources</span>
                  <span className="td-copy">
                    {scanCorrelation.validation_tools.map(formatValidationToolName).join(", ")}
                  </span>
                </div>
              ) : null}
              {(scanCorrelation.deterministic_evidence_count ?? 0) > 0 ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Deterministic evidence</span>
                  <span className="td-meta-value">
                    {scanCorrelation.deterministic_evidence_count} finding
                    {scanCorrelation.deterministic_evidence_count === 1 ? "" : "s"}
                  </span>
                </div>
              ) : null}
            </div>

            {scanCorrelation.cve_ids.length > 0 ? (
              <div className="td-chip-group">
                {scanCorrelation.cve_ids.map((cveId) => (
                  <span key={cveId} className="td-chip">
                    {cveId}
                  </span>
                ))}
              </div>
            ) : null}

            {scanCorrelation.evidence.length > 0 ? (
              <div className="td-table-wrap">
                <table className="td-table">
                  <thead>
                    <tr>
                      <th>Template</th>
                      <th>Severity</th>
                      <th>Matched At</th>
                      <th>Evidence Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanCorrelation.evidence.map((evidence) => (
                      <tr key={evidence.finding_id}>
                        <td>{evidence.template_name}</td>
                        <td>
                          <span
                            className={toneClass(
                              "td-pill",
                              evidence.severity === "critical" || evidence.severity === "high"
                                ? "critical"
                                : evidence.severity === "medium"
                                  ? "medium"
                                  : "muted"
                            )}
                          >
                            {evidence.severity}
                          </span>
                        </td>
                        <td className="td-table-mono">
                          {evidence.matched_at.length > 60
                            ? `${evidence.matched_at.slice(0, 60)}...`
                            : evidence.matched_at}
                        </td>
                        <td>
                          {evidence.tool_name ? (
                            <span className="td-chip">
                              {validationEvidenceSourceLabel(evidence)}
                            </span>
                          ) : (
                            <span className="td-copy td-copy-muted">Legacy scan evidence</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : scanCorrelation.scan_status !== "unverifiable" ? (
              <p className="td-copy td-copy-muted">
                {scanCorrelation.scan_status === "mitigated"
                  ? "Security controls were verified during the scan and no vulnerable condition was found."
                  : "The target was scanned, but no matching findings were returned for this threat category."}
              </p>
            ) : null}
          </section>
        ) : null}

        {showTriageModal ? (
          <ThreatTriageModal
            threat={threat}
            threatModelId={threatModelId}
            onClose={() => setShowTriageModal(false)}
            onTriaged={handleTriaged}
            onAskAboutThreat={() => {
              setShowTriageModal(false);
              void handleAskAboutThreat();
            }}
          />
        ) : null}
      </div>
    </div>
  );
}

export default ThreatDetailPage;

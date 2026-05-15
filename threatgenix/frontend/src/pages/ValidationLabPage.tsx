import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, FlaskConical, Play, Save, ShieldCheck, Trash2, Upload } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
import type {
  DFDNodeResponse,
  OrchestrationJob,
  ProductSecurityValidationCase,
  ValidationCaseWorkflowPriority,
  ValidationCaseWorkflowStatus,
  ValidationCadence,
  ValidationLabSummary,
  ValidationSchedule,
  ValidationTargetType,
  ValidationToolInventoryItem,
} from "../types/api";

const DEFAULT_TARGET_TYPE: ValidationTargetType = "repository_path";
const HOSTED_TARGET_TYPES: ValidationTargetType[] = ["repository_path", "lockfile", "iac_directory", "ai_system"];
const ALL_IMPORT_TARGET_TYPES: ValidationTargetType[] = [
  "url",
  "repository_path",
  "lockfile",
  "container_image",
  "iac_directory",
  "ai_system",
];
const IMPORT_ONLY_SOURCES = [
  {
    name: "external-report",
    label: "External Tool Report",
    supported_targets: ALL_IMPORT_TARGET_TYPES,
    description: "Third-party scanner, BAS, security platform, or vendor assessment output.",
  },
  {
    name: "pentest-report",
    label: "Pentest Report",
    supported_targets: ALL_IMPORT_TARGET_TYPES,
    description: "Human pentest findings, exploit notes, or consultant assessment evidence.",
  },
] as const;

const CASE_WORKFLOW_STATUSES: ValidationCaseWorkflowStatus[] = [
  "open",
  "investigating",
  "mitigated",
  "accepted",
  "dismissed",
  "refuted",
];

const CASE_WORKFLOW_PRIORITIES: ValidationCaseWorkflowPriority[] = ["P1", "P2", "P3"];
type ArtifactImportMode = "single_file" | "manifest_bundle";
const VALIDATION_MANIFEST_FILENAME = "threatgenix-validation-manifest.json";

interface ScheduleDraft {
  name: string;
  tool_name: string;
  target_type: ValidationTargetType;
  target: string;
  target_node_id: string;
  cadence: ValidationCadence;
  enabled: boolean;
  authorization_acknowledged: boolean;
}

interface ImportDraft {
  tool_name: string;
  target_type: ValidationTargetType;
  target: string;
  target_node_id: string;
  raw_output: string;
}

interface CaseWorkflowDraft {
  workflow_status: ValidationCaseWorkflowStatus;
  workflow_priority: "" | ValidationCaseWorkflowPriority;
  owner_label: string;
  due_date: string;
  analyst_note: string;
  last_decision: string;
}

const emptyDraft: ScheduleDraft = {
  name: "",
  tool_name: "semgrep",
  target_type: DEFAULT_TARGET_TYPE,
  target: "",
  target_node_id: "",
  cadence: "manual",
  enabled: false,
  authorization_acknowledged: false,
};

const emptyImportDraft: ImportDraft = {
  tool_name: "semgrep",
  target_type: DEFAULT_TARGET_TYPE,
  target: "",
  target_node_id: "",
  raw_output: "",
};

const emptyCaseWorkflowDraft: CaseWorkflowDraft = {
  workflow_status: "open",
  workflow_priority: "",
  owner_label: "",
  due_date: "",
  analyst_note: "",
  last_decision: "",
};

function validationLabLoadErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : "Failed to load validation lab";
  if (raw.includes("403") || /access denied/i.test(raw)) {
    return "This validation workspace may have been deleted or you may not have access to it.";
  }
  if (raw.includes("404")) {
    return "Validation workspace not found.";
  }
  return raw;
}

const fallbackRuntime: ValidationLabSummary["runtime"] = {
  mode: "try_sandbox",
  run_submission_enabled: false,
  live_execution_enabled: false,
  inline_execution_enabled: false,
  worker_execution_enabled: false,
  managed_runner_enabled: false,
  try_sandbox_enabled: false,
  title: "Validation runner unavailable",
  detail: "Validation runner status is not available yet.",
};

const fallbackPosture: ValidationLabSummary["posture"] = {
  schedule_count: 0,
  enabled_schedule_count: 0,
  recent_scan_count: 0,
  ready_tool_count: 0,
  deterministic_tool_count: 0,
  ai_assisted_tool_count: 0,
  validated_threat_count: 0,
  indicated_threat_count: 0,
  untested_threat_count: 0,
  validated_risk_score: 0,
  indicated_risk_score: 0,
  ai_assisted_risk_score: 0,
};

const fallbackRunnerStatus: ValidationLabSummary["runner_status"] = {
  status: "unavailable",
  detail: "Runner queue status is not available yet.",
  pending_count: 0,
  running_count: 0,
  failed_count: 0,
  oldest_pending_age_seconds: null,
  oldest_running_age_seconds: null,
  stale_running_count: 0,
  active_worker_count: 0,
  last_heartbeat_at: null,
};

function toolLabel(toolName: string): string {
  if (toolName === "osv-scanner") return "OSV Scanner";
  if (toolName === "ai-red-team") return "AI Red Team";
  if (toolName === "external-report") return "External Tool Report";
  if (toolName === "pentest-report") return "Pentest Report";
  return toolName
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function statusLabel(tool: ValidationToolInventoryItem): string {
  if (tool.readiness_status === "ready") return "Ready";
  if (tool.readiness_status === "needs_configuration") return "Needs setup";
  if (!tool.execution_enabled) return "Policy disabled";
  if (!tool.available) return "CLI missing";
  return "Ready";
}

function runnerLabel(tool: ValidationToolInventoryItem): string {
  if (tool.runtime_strategy === "container_image") return "container-hosted";
  if (tool.runs_in_sandbox_required) {
    return `${tool.sandbox_mode === "container" ? "container" : "process"} sandbox`;
  }
  if (tool.runtime_strategy === "host_cli") return "host CLI";
  return "runner unavailable";
}

function formatDate(value: string | null): string {
  if (!value) return "Not scheduled";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function targetTypesForTool(tool?: ValidationToolInventoryItem): ValidationTargetType[] {
  if (!tool) return [DEFAULT_TARGET_TYPE];
  return tool.supported_targets as ValidationTargetType[];
}

function targetTypesForImportSource(source?: { supported_targets: readonly ValidationTargetType[] }): ValidationTargetType[] {
  return [...(source?.supported_targets ?? [DEFAULT_TARGET_TYPE])];
}

function hostedTargetTypeForTool(tool?: ValidationToolInventoryItem): ValidationTargetType {
  return targetTypesForTool(tool).find((targetType) => HOSTED_TARGET_TYPES.includes(targetType)) ?? DEFAULT_TARGET_TYPE;
}

function formatBinding(value: string): string {
  return value.replace(/_/g, " ");
}

function caseStatusLabel(status: ProductSecurityValidationCase["status"]): string {
  if (status === "needs_evidence") return "Needs Evidence";
  if (status === "needs_binding") return "Needs Binding";
  return status.charAt(0).toUpperCase() + status.slice(1);
}

function proofLevelLabel(value: ProductSecurityValidationCase["proof_level"]): string {
  if (value === "human_attested") return "Human Attested";
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function workflowStatusLabel(status: ValidationCaseWorkflowStatus): string {
  return status
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export default function ValidationLabPage(): JSX.Element {
  const { id } = useParams<{ id: string }>();
  const [lab, setLab] = useState<ValidationLabSummary | null>(null);
  const [orchestrationJobs, setOrchestrationJobs] = useState<OrchestrationJob[]>([]);
  const [nodes, setNodes] = useState<DFDNodeResponse[]>([]);
  const [draft, setDraft] = useState<ScheduleDraft>(emptyDraft);
  const [importDraft, setImportDraft] = useState<ImportDraft>(emptyImportDraft);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [caseDraft, setCaseDraft] = useState<CaseWorkflowDraft>(emptyCaseWorkflowDraft);
  const [runAcknowledgements, setRunAcknowledgements] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [uploadingArtifact, setUploadingArtifact] = useState(false);
  const [artifactFile, setArtifactFile] = useState<File | null>(null);
  const [artifactImportMode, setArtifactImportMode] = useState<ArtifactImportMode>("single_file");
  const [uploadingTargetBundle, setUploadingTargetBundle] = useState(false);
  const [targetBundleFile, setTargetBundleFile] = useState<File | null>(null);
  const [savingCase, setSavingCase] = useState(false);
  const [bindingTargetNodeId, setBindingTargetNodeId] = useState("");
  const [bindingSubmitting, setBindingSubmitting] = useState(false);
  const [runningOrchestrationJobId, setRunningOrchestrationJobId] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const [labResponse, dfdResponse, orchestrationResponse] = await Promise.all([
        api.getValidationLab(id),
        api.getDFD(id),
        api.getOrchestrationJobs(id),
      ]);
      setLab(labResponse);
      setNodes(dfdResponse.nodes);
      setOrchestrationJobs(orchestrationResponse);
    } catch (err) {
      setError(validationLabLoadErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  const runtime = lab?.runtime ?? fallbackRuntime;
  const runnerStatus = lab?.runner_status ?? fallbackRunnerStatus;
  const posture = lab?.posture ?? fallbackPosture;
  const tools = useMemo(() => lab?.tools ?? [], [lab?.tools]);
  const setupLanes = lab?.setup_lanes ?? [];
  const toolSetupProfiles = lab?.tool_setup_profiles ?? [];
  const targetBundles = lab?.target_bundles ?? [];
  const schedules = lab?.schedules ?? [];
  const safetyControls = lab?.safety_controls ?? [];
  const recommendedNextRuns = lab?.recommended_next_runs ?? [];
  const agenticToolBench = lab?.agentic_tool_bench ?? null;
  const latestRunbook = lab?.latest_runbook ?? null;
  const selectedTool = useMemo(
    () => tools.find((tool) => tool.name === draft.tool_name),
    [draft.tool_name, tools],
  );
  const availableTargetTypes = targetTypesForTool(selectedTool);
  const importSources = useMemo(
    () => [
      ...tools.map((tool) => ({
        name: tool.name,
        label: toolLabel(tool.name),
        supported_targets: tool.supported_targets as ValidationTargetType[],
        description: tool.proof_mode,
      })),
      ...IMPORT_ONLY_SOURCES,
    ],
    [tools],
  );
  const selectedImportSource = useMemo(
    () => importSources.find((source) => source.name === importDraft.tool_name),
    [importDraft.tool_name, importSources],
  );
  const availableImportTargetTypes = targetTypesForImportSource(selectedImportSource);
  const gaps = lab?.gaps ?? [];
  const evidenceLedger = useMemo(() => lab?.evidence_ledger ?? [], [lab?.evidence_ledger]);
  const productSecurityCases = useMemo(
    () => lab?.product_security_cases ?? [],
    [lab?.product_security_cases],
  );
  const demoScenario = lab?.demo_scenario ?? null;
  const liveExecutionEnabled = Boolean(runtime.live_execution_enabled);
  const runSubmissionEnabled = Boolean(runtime.run_submission_enabled ?? runtime.live_execution_enabled);
  const managedRunnerEnabled = Boolean(runtime.managed_runner_enabled);
  const selectedCase = useMemo(
    () => productSecurityCases.find((item) => item.case_id === selectedCaseId) ?? null,
    [productSecurityCases, selectedCaseId],
  );
  const caseCounts = useMemo(() => ({
    validated: productSecurityCases.filter((item) => item.status === "validated").length,
    relevant: productSecurityCases.filter((item) => item.status === "relevant").length,
    needsEvidence: productSecurityCases.filter((item) => item.status === "needs_evidence").length,
    needsBinding: productSecurityCases.filter((item) => item.status === "needs_binding").length,
  }), [productSecurityCases]);
  const workspaceSummary = useMemo(() => {
    const totalFindings = evidenceLedger.reduce((count, entry) => count + entry.finding_count, 0);
    const unboundFindings = evidenceLedger.reduce((count, entry) => count + entry.unbound_finding_count, 0);
    const boundRuns = evidenceLedger.filter((entry) => entry.target_binding === "node_bound").length;
    const runnableTools = tools.filter((tool) => statusLabel(tool) === "Ready").length;
    const blockedTools = Math.max(tools.length - runnableTools, 0);
    const bindingState = boundRuns > 0
      ? "Node-bound"
      : nodes.length === 0
        ? "DFD needed"
        : productSecurityCases.length === 0
          ? "No cases yet"
          : "Unbound";
    const bindingDetail = boundRuns > 0
      ? "Evidence is mapped to modeled components and semantic threat cases."
      : nodes.length === 0
        ? "Add DFD components or bind imported evidence so tool output can confirm semantic threats."
        : productSecurityCases.length === 0
          ? "Run or import evidence against modeled components to generate product security cases."
          : unboundFindings > 0
            ? `${unboundFindings} findings need DFD/component binding before they can validate threats.`
            : "Evidence is captured but still needs a modeled target relationship.";

    return {
      blockedTools,
      boundRuns,
      runnableTools,
      totalFindings,
      unboundFindings,
      bindingState,
      bindingDetail,
    };
  }, [evidenceLedger, nodes.length, productSecurityCases.length, tools]);

  useEffect(() => {
    if (!selectedCase) {
      setCaseDraft(emptyCaseWorkflowDraft);
      setBindingTargetNodeId("");
      return;
    }
    setCaseDraft({
      workflow_status: selectedCase.workflow_status ?? "open",
      workflow_priority: selectedCase.workflow_priority ?? "",
      owner_label: selectedCase.owner_label ?? "",
      due_date: selectedCase.due_date ?? "",
      analyst_note: selectedCase.analyst_note ?? "",
      last_decision: selectedCase.last_decision ?? "",
    });
    setBindingTargetNodeId(selectedCase.case_type === "unbound_finding" ? (nodes[0]?.id ?? "") : "");
  }, [
    nodes,
    selectedCase,
  ]);

  const createSchedule = async (event: FormEvent) => {
    event.preventDefault();
    if (!id) return;
    setSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      await api.createValidationSchedule(id, {
        name: draft.name || `${toolLabel(draft.tool_name)} validation`,
        tool_name: draft.tool_name,
        target_type: draft.target_type,
        target: draft.target,
        target_node_id: draft.target_node_id || null,
        cadence: draft.cadence,
        enabled: draft.enabled,
        authorization_acknowledged: draft.authorization_acknowledged,
      });
      setDraft(emptyDraft);
      setMessage("Validation schedule saved.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save validation schedule");
    } finally {
      setSubmitting(false);
    }
  };

  const runSchedule = async (schedule: ValidationSchedule) => {
    if (!id) return;
    setSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      await api.runValidationSchedule(id, schedule.id, Boolean(runAcknowledgements[schedule.id]));
      setRunAcknowledgements((current) => ({ ...current, [schedule.id]: false }));
      setMessage(`${schedule.name} queued.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run validation schedule");
    } finally {
      setSubmitting(false);
    }
  };

  const deleteSchedule = async (schedule: ValidationSchedule) => {
    if (!id) return;
    setSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      await api.deleteValidationSchedule(id, schedule.id);
      setMessage(`${schedule.name} deleted.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete validation schedule");
    } finally {
      setSubmitting(false);
    }
  };

  const runOrchestration = async (job: OrchestrationJob) => {
    if (!id) return;
    setRunningOrchestrationJobId(job.id);
    setError(null);
    setMessage(null);
    try {
      const updated = await api.runOrchestrationJob(id, job.id);
      setOrchestrationJobs((current) =>
        current.map((item) => (item.id === updated.id ? updated : item)),
      );
      setMessage(`Orchestration ${formatBinding(updated.status)}.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run orchestration job");
    } finally {
      setRunningOrchestrationJobId(null);
    }
  };

  const importEvidence = async (event: FormEvent) => {
    event.preventDefault();
    if (!id) return;
    setImporting(true);
    setError(null);
    setMessage(null);
    try {
      const detail = await api.ingestScanEvidence(id, {
        tool_name: importDraft.tool_name,
        target_type: importDraft.target_type,
        target: importDraft.target,
        target_node_id: importDraft.target_node_id || null,
        raw_output: importDraft.raw_output,
      });
      setImportDraft(emptyImportDraft);
      setMessage(`${toolLabel(detail.tool_name)} evidence imported and mapped.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to import validation evidence");
    } finally {
      setImporting(false);
    }
  };

  const uploadEvidenceArtifact = async () => {
    if (!id || !artifactFile) return;
    setUploadingArtifact(true);
    setError(null);
    setMessage(null);
    try {
      const response = await api.uploadValidationArtifactBundle(id, {
        file: artifactFile,
        ...(artifactImportMode === "single_file"
          ? {
              tool_name: importDraft.tool_name,
              target_type: importDraft.target_type,
              target: importDraft.target,
              target_node_id: importDraft.target_node_id || null,
            }
          : {}),
      });
      setArtifactFile(null);
      setImportDraft((current) => ({ ...current, raw_output: "" }));
      const scanCount = response.created_scans.length;
      setMessage(`${response.bundle.filename} imported as ${scanCount} validation artifact${scanCount === 1 ? "" : "s"}.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to upload validation artifact");
    } finally {
      setUploadingArtifact(false);
    }
  };

  const uploadTargetBundle = async () => {
    if (!id || !targetBundleFile) return;
    setUploadingTargetBundle(true);
    setError(null);
    setMessage(null);
    try {
      const bundle = await api.uploadValidationTargetBundle(id, {
        file: targetBundleFile,
        name: draft.name || undefined,
        authorization_acknowledged: draft.authorization_acknowledged,
      });
      const nextTargetType = hostedTargetTypeForTool(selectedTool);
      setTargetBundleFile(null);
      setDraft((current) => ({
        ...current,
        name: current.name || bundle.name,
        target_type: nextTargetType,
        target: bundle.target_ref,
      }));
      setMessage(`${bundle.name} uploaded as a hosted validation target.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to upload validation target");
    } finally {
      setUploadingTargetBundle(false);
    }
  };

  const applyTargetBundle = (targetRef: string, name: string) => {
    setDraft((current) => ({
      ...current,
      name: current.name || name,
      target_type: hostedTargetTypeForTool(selectedTool),
      target: targetRef,
    }));
  };

  const runOnce = async () => {
    if (!id) return;
    setSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      const scan = await api.runValidationTool(id, {
        tool_name: draft.tool_name,
        target_type: draft.target_type,
        target: draft.target,
        target_node_id: draft.target_node_id || null,
        scope: "external",
        authorization_acknowledged: draft.authorization_acknowledged,
      });
      setMessage(`${toolLabel(scan.tool_name)} validation queued.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run validation target");
    } finally {
      setSubmitting(false);
    }
  };

  const runTrySandbox = async () => {
    if (!id) return;
    setSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      const scan = await api.runValidationTrySandbox(id);
      setMessage(`${toolLabel(scan.tool_name)} try sandbox completed.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run try sandbox");
    } finally {
      setSubmitting(false);
    }
  };

  const saveCaseState = async (event: FormEvent) => {
    event.preventDefault();
    if (!id || !selectedCase) return;
    setSavingCase(true);
    setError(null);
    setMessage(null);
    try {
      const updatedCase = await api.updateValidationCaseState(id, selectedCase.case_id, {
        workflow_status: caseDraft.workflow_status,
        workflow_priority: caseDraft.workflow_priority || null,
        clear_priority: !caseDraft.workflow_priority,
        owner_label: caseDraft.owner_label || null,
        clear_owner: !caseDraft.owner_label,
        due_date: caseDraft.due_date || null,
        clear_due_date: !caseDraft.due_date,
        analyst_note: caseDraft.analyst_note || null,
        last_decision: caseDraft.last_decision || null,
      });
      setLab((current) => current
        ? {
            ...current,
            product_security_cases: (current.product_security_cases ?? []).map((item) =>
              item.case_id === updatedCase.case_id ? updatedCase : item,
            ),
          }
        : current);
      setSelectedCaseId(updatedCase.case_id);
      setMessage(`${updatedCase.title} workflow saved.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save validation case");
    } finally {
      setSavingCase(false);
    }
  };

  const bindSelectedEvidence = async () => {
    if (!id || !selectedCase || !bindingTargetNodeId) return;
    setBindingSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      const response = await api.bindValidationEvidence(id, selectedCase.case_id, {
        target_node_id: bindingTargetNodeId,
      });
      setMessage(response.message);
      setSelectedCaseId(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to bind validation evidence");
    } finally {
      setBindingSubmitting(false);
    }
  };

  const loadDemoScenario = () => {
    if (!demoScenario) return;
    setImportDraft({
      tool_name: demoScenario.tool_name,
      target_type: demoScenario.target_type,
      target: demoScenario.target,
      target_node_id: "",
      raw_output: demoScenario.raw_output,
    });
    setMessage(`${demoScenario.title} loaded into the import form.`);
  };

  const draftBlockedReason = !runSubmissionEnabled
    ? "Live validation runner is not enabled. Use Try Sandbox or import captured evidence."
    : !draft.target.trim()
      ? "Target is required."
      : !draft.authorization_acknowledged
        ? "Authorization acknowledgement is required."
        : selectedTool?.blocker_reasons?.[0] ?? null;

  if (!id) {
    return <div className="validation-lab-page">Threat model id is required.</div>;
  }

  return (
    <div className="validation-lab-page">
      <div className="validation-lab-header">
        <div>
          <p className="validation-lab-kicker">Validation Lab</p>
          <h1>Deterministic Evidence Workspace</h1>
        </div>
        <div className="validation-lab-header-actions">
          <Link className="tm-secondary-btn" to={`/threat-models/${id}`}>Model</Link>
          <Link className="tm-primary-btn" to={`/threat-models/${id}/review?tab=report`}>Report</Link>
        </div>
      </div>

      {error && lab ? <div className="validation-lab-alert validation-lab-alert-error">{error}</div> : null}
      {message ? <div className="validation-lab-alert validation-lab-alert-success">{message}</div> : null}

      {loading ? (
        <div className="validation-lab-loading">
          <div className="dfd-spinner" />
          Loading validation lab...
        </div>
      ) : !lab ? (
        <div className="validation-lab-empty" role="alert">
          <strong>Validation lab unavailable.</strong>
          <p>{error ?? "ThreatGenix could not load validation evidence for this model."}</p>
          <Link className="tm-secondary-btn" to={`/threat-models/${id}`}>
            Back to model
          </Link>
        </div>
      ) : (
        <>
          <section className="validation-lab-command-strip" aria-label="Validation workspace status">
            <article>
              <span>Runner</span>
              <strong>{formatBinding(runnerStatus.status)}</strong>
              <p>
                {liveExecutionEnabled
                  ? "Live execution enabled"
                  : managedRunnerEnabled
                    ? `${runnerStatus.active_worker_count} worker${runnerStatus.active_worker_count === 1 ? "" : "s"} connected`
                    : "Hosted import and sandbox only"}
              </p>
            </article>
            <article>
              <span>Tools</span>
              <strong>{workspaceSummary.runnableTools}/{tools.length} ready</strong>
              <p>{workspaceSummary.blockedTools} need setup or policy enablement</p>
            </article>
            <article>
              <span>Evidence</span>
              <strong>{workspaceSummary.totalFindings} findings</strong>
              <p>{evidenceLedger.length} runs or imports captured</p>
            </article>
            <article>
              <span>Semantic binding</span>
              <strong>{workspaceSummary.bindingState}</strong>
              <p>{workspaceSummary.boundRuns} node-bound runs</p>
            </article>
          </section>

          <section className="validation-lab-runner-strip" aria-label="Managed runner queue">
            <div>
              <span>Queue</span>
              <strong>{runnerStatus.pending_count} pending · {runnerStatus.running_count} running</strong>
            </div>
            <div>
              <span>Workers</span>
              <strong>{runnerStatus.active_worker_count} active</strong>
            </div>
            <div>
              <span>Lease health</span>
              <strong>{runnerStatus.stale_running_count} stale</strong>
            </div>
            <div>
              <span>Last heartbeat</span>
              <strong>{formatDate(runnerStatus.last_heartbeat_at)}</strong>
            </div>
            <p>{runnerStatus.detail}</p>
          </section>

          {workspaceSummary.bindingState !== "Node-bound" ? (
            <section className="validation-lab-binding-callout" aria-label="Semantic binding guidance">
              <div>
                <strong>{workspaceSummary.bindingState}</strong>
                <p>{workspaceSummary.bindingDetail}</p>
              </div>
              <Link className="tm-secondary-btn" to={`/threat-models/${id}`}>
                Review DFD
              </Link>
            </section>
          ) : null}

          <section className="validation-lab-panel validation-lab-panel-full validation-lab-runtime-panel">
            <div className="validation-lab-panel-header">
              <div>
                <p className="validation-lab-kicker">{runtime.mode.replace(/_/g, " ")}</p>
                <h2>{runtime.title}</h2>
                <p>{runtime.detail}</p>
              </div>
              {runtime.try_sandbox_enabled ? (
                <button
                  className="tm-primary-btn"
                  type="button"
                  disabled={submitting}
                  onClick={() => void runTrySandbox()}
                >
                  <Play size={16} aria-hidden="true" />
                  Try Sandbox
                </button>
              ) : null}
            </div>
            <div className={`validation-lab-saas-guardrail${runSubmissionEnabled ? " validation-lab-saas-guardrail-live" : ""}`}>
              <strong>
                {liveExecutionEnabled
                  ? "Self-hosted execution boundary"
                  : managedRunnerEnabled
                    ? "Managed runner execution boundary"
                    : "Hosted SaaS execution boundary"}
              </strong>
              <p>
                {liveExecutionEnabled
                  ? "This deployment can run approved tools because the operator owns the runner, paths, credentials, and network policy."
                  : managedRunnerEnabled
                    ? "ThreatGenix queues live scanners to the isolated validation worker. The API server remains a control plane and does not execute scanner processes."
                    : "ThreatGenix will not run live scanners against tenant targets from hosted SaaS until the managed isolated runner is connected. Use Try Sandbox for demo proof, or import scanner and pentest evidence for semantic validation."}
              </p>
            </div>
          </section>

          {agenticToolBench ? (
            <section className="validation-lab-panel validation-lab-panel-full validation-lab-agentic-panel">
              <div className="validation-lab-panel-header">
                <div>
                  <p className="validation-lab-kicker">Tool intelligence</p>
                  <h2>Agentic Tool Bench</h2>
                  <p>{agenticToolBench.summary}</p>
                </div>
                <ShieldCheck size={20} aria-hidden="true" />
              </div>
              <div className="validation-lab-chip-row">
                <span>{formatBinding(agenticToolBench.status)}</span>
                {agenticToolBench.planning_inputs.map((input) => (
                  <span key={input}>{input}</span>
                ))}
              </div>
              <div className="validation-lab-agentic-grid">
                <div>
                  <strong>Planner Queue</strong>
                  <div className="validation-lab-agentic-list">
                    {agenticToolBench.recommendations.slice(0, 4).map((item) => (
                      <article key={item.recommendation_id} className="validation-lab-agentic-item">
                        <div>
                          <strong>{item.priority} · {toolLabel(item.tool_name)}</strong>
                          <span>{formatBinding(item.target_type)}</span>
                        </div>
                        <p>{item.objective}</p>
                        <em>{item.evidence_gap}</em>
                        <div className="validation-lab-chip-row">
                          <span>{item.expected_evidence}</span>
                          <span>{item.saved_target_id ? "saved target" : "target needed"}</span>
                        </div>
                        {item.blocked_reason ? (
                          <p className="validation-lab-blocked">{item.blocked_reason}</p>
                        ) : null}
                      </article>
                    ))}
                    {agenticToolBench.recommendations.length === 0 ? (
                      <div className="validation-lab-empty">No tool plan is ready yet.</div>
                    ) : null}
                  </div>
                </div>
                <div>
                  <strong>Execution Contract</strong>
                  <div className="validation-lab-agentic-list">
                    {agenticToolBench.execution_contract.map((step) => (
                      <article key={step.step} className="validation-lab-agentic-step">
                        <span>{formatBinding(step.step)}</span>
                        <strong>{step.owner}</strong>
                        <p>{step.detail}</p>
                      </article>
                    ))}
                  </div>
                </div>
                <div>
                  <strong>Critic Rules</strong>
                  <ul className="validation-lab-sublist validation-lab-agentic-rules">
                    {agenticToolBench.global_critic_rules.map((rule) => (
                      <li key={rule}>{rule}</li>
                    ))}
                  </ul>
                  <strong>Capability Cards</strong>
                  <div className="validation-lab-agentic-capabilities">
                    {agenticToolBench.capabilities.slice(0, 6).map((capability) => (
                      <article key={capability.tool_name}>
                        <strong>{capability.label}</strong>
                        <p>{capability.proves.slice(0, 2).join("; ")}</p>
                        <span>{capability.target_types.map(formatBinding).join(", ")}</span>
                      </article>
                    ))}
                  </div>
                </div>
              </div>
            </section>
          ) : null}

          <section className="validation-lab-panel validation-lab-panel-full">
            <div className="validation-lab-panel-header">
              <div>
                <p className="validation-lab-kicker">Orchestration</p>
                <h2>Agent and Tool Timeline</h2>
                <p>Track durable jobs, task status, tool outputs, blocked reasons, and worker audit events.</p>
              </div>
              <Play size={20} aria-hidden="true" />
            </div>
            <div className="validation-lab-schedule-list">
              {orchestrationJobs.slice(0, 5).map((job) => (
                <article key={job.id} className="validation-lab-schedule-card">
                  <div className="validation-lab-schedule-main">
                    <div>
                      <strong>{formatBinding(job.job_kind)} · {formatBinding(job.status)}</strong>
                      <p>{job.objective}</p>
                    </div>
                    <button
                      className="tm-secondary-btn"
                      type="button"
                      disabled={
                        runningOrchestrationJobId === job.id
                        || job.status === "running"
                        || job.status === "completed"
                        || job.status === "failed"
                        || job.status === "blocked"
                        || job.status === "cancelled"
                      }
                      onClick={() => void runOrchestration(job)}
                    >
                      {runningOrchestrationJobId === job.id ? "Running" : "Run"}
                    </button>
                  </div>
                  <div className="validation-lab-chip-row">
                    <span>{job.tasks.length} tasks</span>
                    <span>{job.requested_tools.length ? job.requested_tools.join(", ") : "custom workflow"}</span>
                    <span>{formatDate(job.created_at)}</span>
                  </div>
                  {job.error_message ? <p className="validation-lab-blocked">{job.error_message}</p> : null}
                  <div className="validation-lab-threat-list">
                    {job.tasks.slice(0, 6).map((task) => (
                      <article key={task.id}>
                        <strong>
                          {formatBinding(task.task_kind)} · {formatBinding(task.status)}
                        </strong>
                        <p>{task.tool_name || task.agent_name || "workflow task"}</p>
                        <span>attempt {task.attempt_count}/{task.max_attempts}</span>
                        {task.error_message ? <em>{task.error_message}</em> : null}
                      </article>
                    ))}
                  </div>
                  {job.events.length > 0 ? (
                    <div className="validation-lab-runbook-gaps">
                      {job.events.slice(-4).map((event) => (
                        <span key={event.id}>{event.event_type}: {event.message}</span>
                      ))}
                    </div>
                  ) : null}
                </article>
              ))}
              {orchestrationJobs.length === 0 ? (
                <div className="validation-lab-empty">No orchestration jobs have been created yet.</div>
              ) : null}
            </div>
          </section>

          <section className="validation-lab-panel validation-lab-panel-full validation-lab-setup-panel">
            <div className="validation-lab-panel-header">
              <div>
                <p className="validation-lab-kicker">Tool setup</p>
                <h2>Runner Architecture</h2>
                <p>Choose the execution lane first, then configure tools inside that boundary.</p>
              </div>
              <ShieldCheck size={20} aria-hidden="true" />
            </div>
            <div className="validation-lab-setup-lanes">
              {setupLanes.map((lane) => (
                <article key={lane.name} className={`validation-lab-setup-lane validation-lab-setup-lane-${lane.status}`}>
                  <div>
                    <strong>{lane.name}</strong>
                    <span>{lane.status.replace(/_/g, " ")}</span>
                  </div>
                  <p>{lane.summary}</p>
                  <ul className="validation-lab-sublist">
                    {(lane.controls ?? []).map((control) => (
                      <li key={control}>{control}</li>
                    ))}
                  </ul>
                </article>
              ))}
            </div>
            <details className="validation-lab-setup-details">
              <summary>
                <span>Per-tool runner requirements</span>
                <strong>{toolSetupProfiles.length} profiles</strong>
              </summary>
              <div className="validation-lab-setup-profiles">
                {toolSetupProfiles.map((profile) => (
                  <article key={profile.tool_name} className="validation-lab-setup-profile">
                    <div>
                      <strong>{profile.label}</strong>
                      <span>{profile.setup_mode}</span>
                    </div>
                    <p>{profile.runner_profile}</p>
                    <div className="validation-lab-setup-profile-columns">
                      <div>
                        <strong>Prerequisites</strong>
                        <ul className="validation-lab-sublist">
                          {(profile.prerequisites ?? []).map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <strong>Configuration</strong>
                        <ul className="validation-lab-sublist">
                          {(profile.configuration ?? []).map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <strong>Safety gates</strong>
                        <ul className="validation-lab-sublist">
                          {(profile.safety_gates ?? []).map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            </details>
          </section>

          <section className="validation-lab-posture">
            <article>
              <strong>{posture.ready_tool_count}</strong>
              <span>Ready tools</span>
            </article>
            <article>
              <strong>{posture.validated_threat_count}</strong>
              <span>Validated threats</span>
            </article>
            <article>
              <strong>{posture.indicated_risk_score}</strong>
              <span>Indicated risk score</span>
            </article>
            <article>
              <strong>{posture.enabled_schedule_count}</strong>
              <span>Enabled schedules</span>
            </article>
          </section>

          <section className="validation-lab-panel validation-lab-panel-full validation-lab-cases-panel">
            <div className="validation-lab-panel-header">
              <div>
                <p className="validation-lab-kicker">Product Security</p>
                <h2>Validation Cases</h2>
                <p>Threat hypotheses, proof state, recommended checks, and remediation decisions.</p>
              </div>
              <div className="validation-lab-case-summary" aria-label="Validation case summary">
                <span>{caseCounts.validated} validated</span>
                <span>{caseCounts.relevant} relevant</span>
                <span>{caseCounts.needsEvidence} need evidence</span>
                <span>{caseCounts.needsBinding} need binding</span>
              </div>
            </div>
            {selectedCase ? (
              <form className="validation-lab-case-detail" onSubmit={saveCaseState}>
                <div className="validation-lab-case-detail-header">
                  <div>
                    <p className="validation-lab-kicker">Case Detail</p>
                    <h3>{selectedCase.title}</h3>
                    <p>{selectedCase.hypothesis}</p>
                  </div>
                  <button className="tm-secondary-btn" type="button" onClick={() => setSelectedCaseId(null)}>
                    Close
                  </button>
                </div>
                <div className="validation-lab-case-detail-grid">
                  <label>
                    <span>Workflow Status</span>
                    <select
                      value={caseDraft.workflow_status}
                      onChange={(event) => setCaseDraft((current) => ({
                        ...current,
                        workflow_status: event.target.value as ValidationCaseWorkflowStatus,
                      }))}
                    >
                      {CASE_WORKFLOW_STATUSES.map((status) => (
                        <option key={status} value={status}>{workflowStatusLabel(status)}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>Priority</span>
                    <select
                      value={caseDraft.workflow_priority}
                      onChange={(event) => setCaseDraft((current) => ({
                        ...current,
                        workflow_priority: event.target.value as CaseWorkflowDraft["workflow_priority"],
                      }))}
                    >
                      <option value="">No priority</option>
                      {CASE_WORKFLOW_PRIORITIES.map((priority) => (
                        <option key={priority} value={priority}>{priority}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>Owner</span>
                    <input
                      value={caseDraft.owner_label}
                      onChange={(event) => setCaseDraft((current) => ({ ...current, owner_label: event.target.value }))}
                      placeholder="Product Security owner"
                    />
                  </label>
                  <label>
                    <span>Due Date</span>
                    <input
                      type="date"
                      value={caseDraft.due_date}
                      onChange={(event) => setCaseDraft((current) => ({ ...current, due_date: event.target.value }))}
                    />
                  </label>
                </div>
                <div className="validation-lab-case-detail-columns">
                  <div>
                    <strong>Evidence and Next Action</strong>
                    <p>{selectedCase.remediation_action}</p>
                    <div className="validation-lab-chip-row">
                      <span>{caseStatusLabel(selectedCase.status)}</span>
                      <span>{proofLevelLabel(selectedCase.proof_level)}</span>
                      <span>{selectedCase.evidence_quality} evidence</span>
                      <span>{selectedCase.risk_score} risk</span>
                    </div>
                    {(selectedCase.recommended_checks ?? []).length > 0 ? (
                      <div className="validation-lab-case-checks">
                        {(selectedCase.recommended_checks ?? []).map((check) => (
                          <span key={`${selectedCase.case_id}-${check.tool_name}-${check.target_type}`}>
                            {check.priority} {toolLabel(check.tool_name)} · {check.target_type.replace(/_/g, " ")}
                          </span>
                        ))}
                      </div>
                    ) : null}
                    {selectedCase.case_type === "unbound_finding" ? (
                      <div className="validation-lab-binding-panel">
                        <strong>Bind Evidence To DFD Component</strong>
                        {nodes.length > 0 ? (
                          <>
                            <label>
                              <span>Bind To DFD Node</span>
                              <select
                                aria-label="Bind To DFD Node"
                                value={bindingTargetNodeId}
                                onChange={(event) => setBindingTargetNodeId(event.target.value)}
                              >
                                {nodes.map((node) => (
                                  <option key={node.id} value={node.id}>
                                    {node.name} ({node.node_type})
                                  </option>
                                ))}
                              </select>
                            </label>
                            <button
                              className="tm-primary-btn"
                              type="button"
                              onClick={() => void bindSelectedEvidence()}
                              disabled={bindingSubmitting || !bindingTargetNodeId}
                            >
                              {bindingSubmitting ? "Binding..." : "Bind Evidence"}
                            </button>
                          </>
                        ) : (
                          <Link className="tm-secondary-btn" to={`/threat-models/${id}?tab=dfd`}>
                            Review DFD
                          </Link>
                        )}
                      </div>
                    ) : null}
                  </div>
                  <div>
                    <strong>Audit Trail</strong>
                    {(selectedCase.audit_events ?? []).length > 0 ? (
                      <div className="validation-lab-case-audit-list">
                        {(selectedCase.audit_events ?? []).map((event) => (
                          <article key={event.id}>
                            <span>{event.action === "created" ? "Created" : "Updated"} · {formatDate(event.created_at)}</span>
                            <p>{event.note || Object.keys(event.changes ?? {}).join(", ") || "Case state recorded."}</p>
                          </article>
                        ))}
                      </div>
                    ) : (
                      <p>No analyst changes recorded yet.</p>
                    )}
                  </div>
                </div>
                <label>
                  <span>Analyst Notes</span>
                  <textarea
                    value={caseDraft.analyst_note}
                    onChange={(event) => setCaseDraft((current) => ({ ...current, analyst_note: event.target.value }))}
                    rows={4}
                    placeholder="What did Product Security verify, assume, or need next?"
                  />
                </label>
                <label>
                  <span>Decision / Rationale</span>
                  <textarea
                    value={caseDraft.last_decision}
                    onChange={(event) => setCaseDraft((current) => ({ ...current, last_decision: event.target.value }))}
                    rows={3}
                    placeholder="Why this status is correct right now"
                  />
                </label>
                <button className="tm-primary-btn" type="submit" disabled={savingCase}>
                  {savingCase ? "Saving..." : "Save Case State"}
                </button>
              </form>
            ) : null}
            {productSecurityCases.length > 0 ? (
              <div className="validation-lab-case-grid">
                {productSecurityCases.slice(0, 8).map((item) => (
                  <article key={item.case_id} className={`validation-lab-case-card validation-lab-case-${item.status}`}>
                    <div className="validation-lab-case-card-header">
                      <div>
                        <strong>{item.title}</strong>
                        <p>{item.hypothesis}</p>
                      </div>
                      <span className={`validation-lab-pill validation-lab-case-pill-${item.status}`}>
                        {caseStatusLabel(item.status)}
                      </span>
                    </div>
                    <div className="validation-lab-case-meter">
                      <span style={{ width: `${item.confidence_score}%` }} />
                    </div>
                    <div className="validation-lab-chip-row">
                      <span>{workflowStatusLabel(item.workflow_status ?? "open")}</span>
                      {item.workflow_priority ? <span>{item.workflow_priority}</span> : null}
                      <span>{item.confidence_label} confidence</span>
                      <span>{proofLevelLabel(item.proof_level)}</span>
                      <span>{item.evidence_count} evidence</span>
                      <span>risk {item.risk_score}</span>
                    </div>
                    {(item.evidence_sources ?? []).length > 0 ? (
                      <div className="validation-lab-case-sources">
                        {(item.evidence_sources ?? []).map((source) => (
                          <span key={source}>{toolLabel(source)}</span>
                        ))}
                      </div>
                    ) : null}
                    <div className="validation-lab-case-section">
                      <strong>Product Security Checks</strong>
                      <ul className="validation-lab-sublist">
                        {(item.product_questions ?? []).slice(0, 2).map((question) => (
                          <li key={question}>{question}</li>
                        ))}
                      </ul>
                    </div>
                    {(item.recommended_checks ?? []).length > 0 ? (
                      <div className="validation-lab-case-section">
                        <strong>Recommended Validation</strong>
                        <div className="validation-lab-case-checks">
                          {(item.recommended_checks ?? []).map((check) => (
                            <span key={`${item.case_id}-${check.tool_name}-${check.target_type}`}>
                              {check.priority} {toolLabel(check.tool_name)} · {check.target_type.replace(/_/g, " ")}
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : null}
                    <em>{item.remediation_action}</em>
                    <button
                      className="tm-secondary-btn"
                      type="button"
                      onClick={() => setSelectedCaseId(item.case_id)}
                    >
                      Open Case
                    </button>
                  </article>
                ))}
              </div>
            ) : (
              <div className="validation-lab-empty">Run or import validation evidence to generate Product Security cases.</div>
            )}
          </section>

          {gaps.length > 0 ? (
            <section className="validation-lab-panel validation-lab-panel-full validation-lab-gap-panel">
              <div className="validation-lab-panel-header">
                <div>
                  <h2>Gap Closure Plan</h2>
                  <p>What blocks this lab from producing stronger validation confidence.</p>
                </div>
                <AlertTriangle size={20} aria-hidden="true" />
              </div>
              <div className="validation-lab-gap-list">
                {gaps.map((gap) => (
                  <article key={gap.title} className={`validation-lab-gap-card validation-lab-gap-${gap.severity}`}>
                    <div>
                      <strong>{gap.title}</strong>
                      <span>{gap.severity}</span>
                    </div>
                    <p>{gap.detail}</p>
                    <em>{gap.next_action}</em>
                  </article>
                ))}
              </div>
            </section>
          ) : null}

          <section className="validation-lab-grid">
            <div className="validation-lab-panel validation-lab-panel-wide">
              <div className="validation-lab-panel-header">
                <div>
                  <h2>Tool Readiness</h2>
                  <p>Execution state, proof mode, and safety boundary.</p>
                </div>
                <FlaskConical size={20} aria-hidden="true" />
              </div>
              <div className="validation-lab-tool-grid">
                {tools.map((tool) => (
                  <article key={tool.name} className="validation-lab-tool-card">
                    <div>
                      <strong>{toolLabel(tool.name)}</strong>
                      <span className={`validation-lab-pill validation-lab-pill-${statusLabel(tool).toLowerCase().replace(/\s+/g, "-")}`}>
                        {statusLabel(tool)}
                      </span>
                    </div>
                    <p>{tool.proof_mode}</p>
                    <div className="validation-lab-chip-row">
                      <span>{tool.network_mode.replace(/_/g, " ")}</span>
                      <span>{tool.max_runtime_seconds}s</span>
                      <span>{runnerLabel(tool)}</span>
                      {tool.container_image && tool.runtime_strategy === "container_image" ? (
                        <span>{tool.container_image}</span>
                      ) : null}
                      {tool.runtime_strategy === "container_image" ? (
                        <span>
                          {tool.container_image_present ? "image local" : `pull ${tool.container_pull_policy}`}
                        </span>
                      ) : null}
                    </div>
                    {tool.runtime_detail ? <p>{tool.runtime_detail}</p> : null}
                    {(tool.blocker_reasons ?? []).length > 0 ? (
                      <ul className="validation-lab-sublist validation-lab-blocker-list">
                        {(tool.blocker_reasons ?? []).map((reason) => (
                          <li key={reason}>{reason}</li>
                        ))}
                      </ul>
                    ) : null}
                    {(tool.setup_actions ?? []).length > 0 ? (
                      <div className="validation-lab-next-actions">
                        <strong>Next step</strong>
                        <ul className="validation-lab-sublist">
                          {(tool.setup_actions ?? []).slice(0, 3).map((action) => (
                            <li key={action}>{action}</li>
                          ))}
                        </ul>
                      </div>
                    ) : null}
                  </article>
                ))}
              </div>
            </div>

            <div className="validation-lab-panel">
              <div className="validation-lab-panel-header">
                <div>
                  <h2>Safety Controls</h2>
                  <p>Current enforcement before any live validation.</p>
                </div>
                <ShieldCheck size={20} aria-hidden="true" />
              </div>
              <div className="validation-lab-control-list">
                {safetyControls.map((control) => (
                  <article key={control.name}>
                    {control.status === "missing" ? (
                      <AlertTriangle size={18} aria-hidden="true" />
                    ) : (
                      <CheckCircle2 size={18} aria-hidden="true" />
                    )}
                    <div>
                      <strong>{control.name}</strong>
                      <span>{control.status}</span>
                      <p>{control.detail}</p>
                    </div>
                  </article>
                ))}
              </div>
            </div>
          </section>

          <section className="validation-lab-grid validation-lab-grid-bottom">
            <form className="validation-lab-panel validation-lab-form" onSubmit={createSchedule}>
              <div className="validation-lab-panel-header">
                <div>
                  <h2>Saved Validation Target</h2>
                  <p>
                    {liveExecutionEnabled
                      ? "One authorized target for manual or scheduled runs."
                      : managedRunnerEnabled
                        ? "One authorized target queued to the managed validation runner."
                        : "Unavailable in hosted SaaS mode until the managed isolated runner is connected."}
                  </p>
                </div>
                <Save size={20} aria-hidden="true" />
              </div>
              <label>
                <span>Name</span>
                <input
                  value={draft.name}
                  onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))}
                  placeholder="Repository SAST baseline"
                />
              </label>
              <div className="validation-lab-form-row">
                <label>
                  <span>Tool</span>
                  <select
                    value={draft.tool_name}
                    onChange={(event) => {
                      const nextTool = tools.find((tool) => tool.name === event.target.value);
                      const nextTargetType = targetTypesForTool(nextTool)[0] ?? DEFAULT_TARGET_TYPE;
                      setDraft((current) => ({
                        ...current,
                        tool_name: event.target.value,
                        target_type: nextTargetType,
                      }));
                    }}
                  >
                    {tools.map((tool) => (
                      <option key={tool.name} value={tool.name}>{toolLabel(tool.name)}</option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>Target Type</span>
                  <select
                    value={draft.target_type}
                    onChange={(event) => setDraft((current) => ({
                      ...current,
                      target_type: event.target.value as ValidationTargetType,
                    }))}
                  >
                    {availableTargetTypes.map((targetType) => (
                      <option key={targetType} value={targetType}>{targetType.replace(/_/g, " ")}</option>
                    ))}
                  </select>
                </label>
              </div>
              <label>
                <span>Target</span>
                <input
                  value={draft.target}
                  onChange={(event) => setDraft((current) => ({ ...current, target: event.target.value }))}
                  placeholder={draft.target_type === "url" ? "https://api.example.com" : draft.target_type === "ai_system" ? "/allowed/ai-system/redteam.json" : "/allowed/repository/path"}
                  required
                />
              </label>
              <div className="validation-lab-artifact-upload">
                <div>
                  <strong>Hosted target bundle</strong>
                  <p>Upload source, lockfile, or IaC content for the managed runner.</p>
                </div>
                <input
                  aria-label="Target Bundle File"
                  type="file"
                  accept=".zip,.tar,.tgz,.gz,.json,.lock,.txt,.tf,.yaml,.yml"
                  onChange={(event) => setTargetBundleFile(event.target.files?.[0] ?? null)}
                  disabled={uploadingTargetBundle || !runSubmissionEnabled}
                />
                <button
                  className="tm-secondary-btn"
                  type="button"
                  disabled={
                    uploadingTargetBundle
                    || !runSubmissionEnabled
                    || !targetBundleFile
                    || !draft.authorization_acknowledged
                  }
                  onClick={() => void uploadTargetBundle()}
                >
                  <Upload size={16} aria-hidden="true" />
                  {uploadingTargetBundle ? "Uploading..." : "Upload Target Bundle"}
                </button>
                {targetBundles.length > 0 ? (
                  <div className="validation-lab-target-bundle-list">
                    {targetBundles.map((bundle) => (
                      <div key={bundle.id} className="validation-lab-target-bundle-row">
                        <span>
                          {bundle.filename} · {(bundle.byte_size / 1024).toFixed(1)} KB · {((bundle.manifest["file_count"] as number | undefined) ?? 1)} files
                        </span>
                        <button
                          className="tm-secondary-btn"
                          type="button"
                          onClick={() => applyTargetBundle(bundle.target_ref, bundle.name)}
                        >
                          Use
                        </button>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
              <div className="validation-lab-form-row">
                <label>
                  <span>DFD Node</span>
                  <select
                    value={draft.target_node_id}
                    onChange={(event) => {
                      const node = nodes.find((item) => item.id === event.target.value);
                      setDraft((current) => ({
                        ...current,
                        target_node_id: event.target.value,
                        target: current.target || node?.scan_target_url || "",
                      }));
                    }}
                  >
                    <option value="">No node binding</option>
                    {nodes.map((node) => (
                      <option key={node.id} value={node.id}>{node.name}</option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>Cadence</span>
                  <select
                    value={draft.cadence}
                    onChange={(event) => setDraft((current) => ({
                      ...current,
                      cadence: event.target.value as ValidationCadence,
                    }))}
                  >
                    <option value="manual">Manual</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </label>
              </div>
              <label className="validation-lab-checkbox">
                <input
                  type="checkbox"
                  checked={draft.enabled}
                  onChange={(event) => setDraft((current) => ({ ...current, enabled: event.target.checked }))}
                />
                <span>Enable schedule</span>
              </label>
              <label className="validation-lab-checkbox validation-lab-consent">
                <input
                  type="checkbox"
                  checked={draft.authorization_acknowledged}
                  onChange={(event) => setDraft((current) => ({
                    ...current,
                    authorization_acknowledged: event.target.checked,
                  }))}
                />
                <span>I am authorized to test this target and accept responsibility for the configured scope.</span>
              </label>
              <button
                className="tm-primary-btn"
                type="submit"
                disabled={submitting || !runSubmissionEnabled || !draft.authorization_acknowledged || !draft.target.trim()}
              >
                Save Target
              </button>
              <button
                className="tm-secondary-btn"
                type="button"
                disabled={submitting || !runSubmissionEnabled || Boolean(draftBlockedReason)}
                onClick={() => void runOnce()}
              >
                Run Once
              </button>
              {draftBlockedReason ? <p className="validation-lab-blocked">{draftBlockedReason}</p> : null}
            </form>

            <form className="validation-lab-panel validation-lab-form" onSubmit={importEvidence}>
              <div className="validation-lab-panel-header">
                <div>
                  <h2>Import Captured Evidence</h2>
                  <p>Parse scanner, platform, or pentest output and map it to semantic threats without executing tools.</p>
                </div>
                <div className="validation-lab-header-actions">
                  {demoScenario ? (
                    <button className="tm-primary-btn" type="button" disabled={submitting} onClick={() => void runTrySandbox()}>
                      <Play size={16} aria-hidden="true" />
                      Try Sandbox
                    </button>
                  ) : null}
                  {demoScenario ? (
                    <button className="tm-secondary-btn" type="button" onClick={loadDemoScenario}>
                      Load Safe Sample
                    </button>
                  ) : null}
                  <Upload size={20} aria-hidden="true" />
                </div>
              </div>
              {demoScenario ? (
                <div className="validation-lab-demo-card">
                  <strong>{demoScenario.title}</strong>
                  <p>{demoScenario.summary}</p>
                  <span>{demoScenario.expected_signal}</span>
                </div>
              ) : null}
              <div className="validation-lab-form-row">
                <label>
                  <span>Tool or Source</span>
                  <select
                    value={importDraft.tool_name}
                    onChange={(event) => {
                      const nextSource = importSources.find((source) => source.name === event.target.value);
                      const nextTargetType = targetTypesForImportSource(nextSource)[0] ?? DEFAULT_TARGET_TYPE;
                      setImportDraft((current) => ({
                        ...current,
                        tool_name: event.target.value,
                        target_type: nextTargetType,
                      }));
                    }}
                  >
                    {importSources.map((source) => (
                      <option key={source.name} value={source.name}>{source.label}</option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>Target Type</span>
                  <select
                    value={importDraft.target_type}
                    onChange={(event) => setImportDraft((current) => ({
                      ...current,
                      target_type: event.target.value as ValidationTargetType,
                    }))}
                  >
                    {availableImportTargetTypes.map((targetType) => (
                      <option key={targetType} value={targetType}>{targetType.replace(/_/g, " ")}</option>
                    ))}
                  </select>
                </label>
              </div>
              {selectedImportSource ? (
                <div className="validation-lab-demo-card">
                  <strong>{selectedImportSource.label}</strong>
                  <p>{selectedImportSource.description}</p>
                  <span>Imported findings become evidence in semantic threat mapping and the validation runbook.</span>
                </div>
              ) : null}
              <label>
                <span>Target</span>
                <input
                  value={importDraft.target}
                  onChange={(event) => setImportDraft((current) => ({ ...current, target: event.target.value }))}
                  placeholder={importDraft.target_type === "url" ? "https://api.example.com" : importDraft.target_type === "ai_system" ? "AI system, agent, or promptfoo evidence target" : "repository, lockfile, IaC path, or container image"}
                  required
                />
              </label>
              <label>
                <span>DFD Node Binding</span>
                <select
                  value={importDraft.target_node_id}
                  onChange={(event) => {
                    const node = nodes.find((item) => item.id === event.target.value);
                    setImportDraft((current) => ({
                      ...current,
                      target_node_id: event.target.value,
                      target: current.target || node?.scan_target_url || "",
                    }));
                  }}
                >
                  <option value="">Infer from evidence and node metadata</option>
                  {nodes.map((node) => (
                    <option key={node.id} value={node.id}>{node.name}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Evidence Output</span>
                <textarea
                  value={importDraft.raw_output}
                  onChange={(event) => setImportDraft((current) => ({ ...current, raw_output: event.target.value }))}
                  placeholder="Paste JSON, JSONL, or text findings from a scanner, security platform, or pentest report"
                  rows={10}
                  maxLength={10_000_000}
                  required
                />
              </label>
              <div className="validation-lab-artifact-upload">
                <label>
                  <span>File Mode</span>
                  <select
                    value={artifactImportMode}
                    onChange={(event) => setArtifactImportMode(event.target.value as ArtifactImportMode)}
                    aria-label="Evidence file mode"
                  >
                    <option value="single_file">Single evidence file</option>
                    <option value="manifest_bundle">ThreatGenix manifest bundle</option>
                  </select>
                </label>
                <label>
                  <span>Evidence File</span>
                  <input
                    type="file"
                    accept=".json,.jsonl,.sarif,.txt,.zip,.tar,.tgz,.gz"
                    onChange={(event) => setArtifactFile(event.target.files?.[0] ?? null)}
                    aria-describedby="validation-artifact-upload-status"
                  />
                </label>
                <button
                  className="tm-secondary-btn"
                  type="button"
                  disabled={
                    uploadingArtifact
                    || !artifactFile
                    || (artifactImportMode === "single_file" && !importDraft.target.trim())
                  }
                  onClick={() => void uploadEvidenceArtifact()}
                >
                  {uploadingArtifact ? "Uploading..." : "Import File"}
                </button>
                <p id="validation-artifact-upload-status" role="status">
                  {artifactFile
                    ? `${artifactFile.name} selected`
                    : artifactImportMode === "manifest_bundle"
                      ? `${VALIDATION_MANIFEST_FILENAME} supplies tool, target, and evidence item metadata`
                      : "Single evidence file uses the selected tool and target metadata"}
                </p>
              </div>
              <button
                className="tm-primary-btn"
                type="submit"
                disabled={importing || !importDraft.target.trim() || !importDraft.raw_output.trim()}
              >
                {importing ? "Importing..." : "Import Evidence"}
              </button>
            </form>
          </section>

          <section className="validation-lab-grid validation-lab-grid-bottom">
            <div className="validation-lab-panel validation-lab-panel-wide validation-lab-panel-full">
              <div className="validation-lab-panel-header">
                <div>
                  <h2>Schedules and Run Queue</h2>
                  <p>Manual execution remains gated by per-run consent.</p>
                </div>
                <Play size={20} aria-hidden="true" />
              </div>
              <div className="validation-lab-schedule-list">
                {schedules.map((schedule) => (
                  <article key={schedule.id} className="validation-lab-schedule-card">
                    <div className="validation-lab-schedule-main">
                      <div>
                        <strong>{schedule.name}</strong>
                        <p>{toolLabel(schedule.tool_name)} · {schedule.target_type.replace(/_/g, " ")} · {schedule.target}</p>
                      </div>
                      <span className={`validation-lab-pill ${schedule.runnable ? "validation-lab-pill-ready" : "validation-lab-pill-blocked"}`}>
                        {schedule.runnable ? "Runnable" : "Blocked"}
                      </span>
                    </div>
                    <div className="validation-lab-chip-row">
                      <span>{schedule.cadence}</span>
                      <span>{schedule.enabled ? "enabled" : "manual only"}</span>
                      <span>next {formatDate(schedule.next_run_at)}</span>
                    </div>
                    {schedule.blocked_reason ? (
                      <p className="validation-lab-blocked">{schedule.blocked_reason}</p>
                    ) : null}
                    <div className="validation-lab-schedule-actions">
                      <label className="validation-lab-checkbox">
                        <input
                          type="checkbox"
                          checked={Boolean(runAcknowledgements[schedule.id])}
                          onChange={(event) => setRunAcknowledgements((current) => ({
                            ...current,
                            [schedule.id]: event.target.checked,
                          }))}
                        />
                        <span>Authorized run</span>
                      </label>
                      <button
                        className="tm-primary-btn"
                        type="button"
                        disabled={submitting || !schedule.runnable || !runAcknowledgements[schedule.id]}
                        onClick={() => void runSchedule(schedule)}
                      >
                        Run
                      </button>
                      <button
                        className="tm-secondary-btn validation-lab-icon-btn"
                        type="button"
                        title="Delete schedule"
                        disabled={submitting}
                        onClick={() => void deleteSchedule(schedule)}
                      >
                        <Trash2 size={16} aria-hidden="true" />
                      </button>
                    </div>
                  </article>
                ))}
                {schedules.length === 0 ? (
                  <div className="validation-lab-empty">No saved validation targets yet.</div>
                ) : null}
              </div>
            </div>

            <div className="validation-lab-panel">
              <div className="validation-lab-panel-header">
                <div>
                  <h2>Recommended Next Runs</h2>
                  <p>Prioritized from current tool and evidence posture.</p>
                </div>
              </div>
              <div className="validation-lab-recommendation-list">
                {recommendedNextRuns.map((item) => (
                  <article key={`${item.tool_name}-${item.target_type}`}>
                    <strong>{item.priority} · {toolLabel(item.tool_name)}</strong>
                    <p>{item.reason}</p>
                    {item.blocked_reason ? <span>{item.blocked_reason}</span> : <span>Ready when target is set.</span>}
                  </article>
                ))}
              </div>
            </div>

            <div className="validation-lab-panel">
              <div className="validation-lab-panel-header">
                <div>
                  <h2>Evidence Ledger</h2>
                  <p>Recent runs, imported evidence, artifacts, and semantic mapping state.</p>
                </div>
              </div>
              <div className="validation-lab-ledger-list">
                {evidenceLedger.map((entry) => (
                  <article key={entry.scan_id} className="validation-lab-ledger-card">
                    <div>
                      <strong>{toolLabel(entry.tool_name)} · {entry.status}</strong>
                      <span>{formatBinding(entry.target_binding)}</span>
                    </div>
                    <div className="validation-lab-chip-row">
                      <span>{entry.finding_count} findings</span>
                      <span>{entry.validated_threat_count} validated</span>
                      <span>{entry.indicated_threat_count} indicated</span>
                      <span>{entry.unbound_finding_count} unbound</span>
                      <span>{entry.artifact_count} artifacts</span>
                    </div>
                    {entry.output_sha256 ? (
                      <p>Output hash {entry.output_sha256.slice(0, 12)}</p>
                    ) : null}
                    {entry.error_message ? <p className="validation-lab-blocked">{entry.error_message}</p> : null}
                  </article>
                ))}
                {evidenceLedger.length === 0 ? (
                  <div className="validation-lab-empty">No validation evidence has been captured yet.</div>
                ) : null}
              </div>
            </div>

            <div className="validation-lab-panel validation-lab-panel-wide">
              <div className="validation-lab-panel-header">
                <div>
                  <h2>Latest Evidence Picture</h2>
                  <p>Validated, indicated, and untested risk from the current tool set.</p>
                </div>
              </div>
              {latestRunbook ? (
                <div className="validation-lab-runbook">
                  <p>{latestRunbook.executive_summary}</p>
                  <div className="validation-lab-risk-grid">
                    <span>Validated risk <strong>{latestRunbook.coverage.validated_risk_score}</strong></span>
                    <span>Indicated risk <strong>{latestRunbook.coverage.indicated_risk_score}</strong></span>
                  </div>
                  <div className="validation-lab-threat-list">
                    {(latestRunbook.mapped_threats ?? []).slice(0, 6).map((threat) => (
                      <article key={threat.threat_id}>
                        <strong>{threat.threat_display_id} · {threat.confidence_label}</strong>
                        <p>{threat.threat_description}</p>
                        <span>{threat.proof_class} · {threat.evidence_quality} · risk {threat.risk_score}</span>
                        <em>{threat.next_action}</em>
                      </article>
                    ))}
                  </div>
                  {(latestRunbook.unbound_findings ?? []).length > 0 ? (
                    <div className="validation-lab-unbound-section">
                      <h3>Unbound Findings</h3>
                      <div className="validation-lab-threat-list">
                        {(latestRunbook.unbound_findings ?? []).slice(0, 4).map((finding) => (
                          <article key={finding.finding_id}>
                            <strong>{finding.title}</strong>
                            <p>{finding.explanation}</p>
                            <span>{finding.tool_name ?? "validation"} · {finding.severity} · risk {finding.risk_score}</span>
                            <em>{finding.next_action}</em>
                          </article>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {(latestRunbook.gaps ?? []).length > 0 ? (
                    <div className="validation-lab-runbook-gaps">
                      {(latestRunbook.gaps ?? []).map((gap) => (
                        <span key={gap}>{gap}</span>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="validation-lab-empty">No completed validation runbook is available.</div>
              )}
            </div>
          </section>
        </>
      )}
    </div>
  );
}

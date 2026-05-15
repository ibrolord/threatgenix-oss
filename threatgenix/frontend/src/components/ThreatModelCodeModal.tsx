import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent, MouseEvent as ReactMouseEvent } from "react";

import { api } from "../api/client";
import type {
  AssistantRequest,
  AssistantResponse,
  TMACDiffResponse,
  TMACFormat,
  TMACImportMode,
  TMACImportResponse,
  TMACSummary,
  TMACValidationResponse,
} from "../types/api";

interface ThreatModelCodeModalProps {
  threatModelId: string;
  onClose: () => void;
  onImported: (response: TMACImportResponse) => void;
}

type TMACAIAction = "review" | "rewrite" | "explain";

type EditorSelection = {
  start: number;
  end: number;
  text: string;
};

const TMAC_DOCS_ROUTE = "/docs/tmac";
const MAX_ASSISTANT_MESSAGE_LENGTH = 20_000;
const MAX_ASSISTANT_ANSWER_LENGTH = 20_000;
const LARGE_DOCUMENT_AI_THRESHOLD = 12_000;
const AI_CODE_FENCE_OVERHEAD = 64;
const TMAC_REFERENCE_POINTS = [
  "Node position_x / position_y fields are optional on import. ThreatGenix auto-generates initial layout coordinates when they are missing.",
  "Use stable ids when you are editing an existing model so threat, control, and assumption references stay valid.",
  "Built-in view snapshots can stay empty until you customize layout. Use Load Scaffold if you want a recommended starting structure.",
] as const;

const SUMMARY_ROWS: Array<{ key: keyof TMACSummary; label: string }> = [
  { key: "node_count", label: "Nodes" },
  { key: "edge_count", label: "Flows" },
  { key: "boundary_count", label: "Trust Boundaries" },
  { key: "built_in_view_count", label: "Built-In Views" },
  { key: "custom_view_count", label: "Custom Views" },
  { key: "threat_count", label: "Threats" },
  { key: "assumption_count", label: "Assumptions" },
  { key: "control_count", label: "Controls" },
  { key: "component_template_count", label: "Templates" },
  { key: "property_option_count", label: "Property Options" },
  { key: "snapshot_count", label: "Snapshots" },
  { key: "review_count", label: "Reviews" },
  { key: "collaborator_count", label: "Collaborators" },
  { key: "assignment_count", label: "Assignments" },
  { key: "notification_count", label: "Notifications" },
];

const EMPTY_SELECTION: EditorSelection = {
  start: 0,
  end: 0,
  text: "",
};

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

function normalizeFormat(format: string | null | undefined, fallback: TMACFormat): TMACFormat {
  if (format === "json") {
    return "json";
  }
  if (format === "yaml" || format === "yml") {
    return "yaml";
  }
  return fallback;
}

function summarizeSummary(summary: TMACSummary) {
  return `${summary.node_count} nodes, ${summary.edge_count} flows, ${summary.boundary_count} trust boundaries, ${summary.threat_count} threats`;
}

function summarizeWarnings(warnings: string[]) {
  if (warnings.length === 0) {
    return "No warnings.";
  }
  if (warnings.length === 1) {
    return warnings[0];
  }
  return `${warnings.length} warnings detected.`;
}

function formatAnalysisTime(value: string | null) {
  if (!value) {
    return "Waiting for analysis.";
  }
  return `Last analyzed ${new Date(value).toLocaleTimeString([], {
    hour: "numeric",
    minute: "2-digit",
  })}`;
}

function selectionSummary(text: string) {
  const lineCount = text.trim().length === 0 ? 0 : text.split(/\r?\n/).length;
  return `${lineCount} line${lineCount === 1 ? "" : "s"}, ${text.length} chars`;
}

function extractCodeBlock(
  answer: string,
  fallbackFormat: TMACFormat,
): { content: string | null; format: TMACFormat } {
  const matches = Array.from(answer.matchAll(/```([a-zA-Z0-9_-]+)?\n([\s\S]*?)```/g));
  if (matches.length === 0) {
    return { content: null, format: fallbackFormat };
  }

  const preferred = matches.find((match) => normalizeFormat(match[1], fallbackFormat) === fallbackFormat);
  const picked = preferred ?? matches[0];
  if (!picked) {
    return { content: null, format: fallbackFormat };
  }
  return {
    content: (picked[2] ?? "").trim(),
    format: normalizeFormat(picked[1], fallbackFormat),
  };
}

function buildValidationContext(
  validation: TMACValidationResponse | null,
  diff: TMACDiffResponse | null,
) {
  const details: string[] = [];
  if (validation) {
    details.push(
      `Validation: ${validation.format.toUpperCase()} draft with ${summarizeSummary(validation.summary)}.`,
    );
    if (validation.warnings.length > 0) {
      details.push(`Validation warnings: ${validation.warnings.join(" | ")}`);
    }
  } else {
    details.push("Validation state is not available yet.");
  }

  if (diff) {
    const changed = diff.changed_sections.length > 0 ? diff.changed_sections.join(", ") : "none";
    details.push(`Changed sections versus the live model: ${changed}.`);
    if (diff.warnings.length > 0) {
      details.push(`Diff warnings: ${diff.warnings.join(" | ")}`);
    }
  }
  return details.join("\n");
}

function buildAIPrompt({
  action,
  format,
  content,
  selection,
  customPrompt,
  validation,
  diff,
}: {
  action: TMACAIAction;
  format: TMACFormat;
  content: string;
  selection: EditorSelection;
  customPrompt: string;
  validation: TMACValidationResponse | null;
  diff: TMACDiffResponse | null;
}) {
  const selectionBlock =
    selection.text.trim().length > 0
      ? `Focused excerpt:\n\`\`\`${format}\n${selection.text.trim()}\n\`\`\``
      : "Focused excerpt: none.";
  const analysisContext = buildValidationContext(validation, diff);
  const instruction = customPrompt.trim();

  if (action === "rewrite") {
    return [
      "You are editing a ThreatGenix Threat Model as Code (TMAC) document.",
      "Return the full updated TMAC document in exactly one fenced code block using the same format as the current draft.",
      "Preserve unchanged sections unless the requested change or validation issues require edits.",
      instruction
        ? `Requested change: ${instruction}`
        : "Requested change: improve the draft while keeping it valid, explicit, and operationally useful.",
      analysisContext,
      selectionBlock,
      `Current TMAC draft:\n\`\`\`${format}\n${content}\n\`\`\``,
    ].join("\n\n");
  }

  if (action === "explain") {
    return [
      "Explain this ThreatGenix TMAC content for an engineer reviewing the live threat model.",
      "Focus on what the code means, what it changes in the model, and what to verify next.",
      instruction ? `Additional instruction: ${instruction}` : "",
      selection.text.trim().length > 0
        ? `Selected TMAC excerpt:\n\`\`\`${format}\n${selection.text.trim()}\n\`\`\``
        : `TMAC draft:\n\`\`\`${format}\n${content}\n\`\`\``,
    ]
      .filter(Boolean)
      .join("\n\n");
  }

  return [
    "Review this ThreatGenix TMAC draft for correctness, schema issues, threat-model gaps, and risky inconsistencies.",
    "Prioritize concrete findings and the smallest edits that would improve the draft.",
    instruction ? `Additional instruction: ${instruction}` : "",
    analysisContext,
    selectionBlock,
    `Current TMAC draft:\n\`\`\`${format}\n${content}\n\`\`\``,
  ]
    .filter(Boolean)
    .join("\n\n");
}

function SummaryGrid({ summary }: { summary: TMACSummary }) {
  return (
    <div className="tmac-summary-grid">
      {SUMMARY_ROWS.map((item) => (
        <div className="tmac-summary-card" key={item.key}>
          <span className="tmac-summary-label">{item.label}</span>
          <strong className="tmac-summary-value">{summary[item.key]}</strong>
        </div>
      ))}
    </div>
  );
}

export function ThreatModelCodeModal({
  threatModelId,
  onClose,
  onImported,
}: ThreatModelCodeModalProps) {
  const [editorFormat, setEditorFormat] = useState<TMACFormat>("yaml");
  const [includeOperationalState, setIncludeOperationalState] = useState(false);
  const [includeBinaryAssets, setIncludeBinaryAssets] = useState(false);
  const [content, setContent] = useState("");
  const [baselineContent, setBaselineContent] = useState("");
  const [validation, setValidation] = useState<TMACValidationResponse | null>(null);
  const [diff, setDiff] = useState<TMACDiffResponse | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [operationError, setOperationError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [loadingLive, setLoadingLive] = useState(false);
  const [loadingScaffold, setLoadingScaffold] = useState(false);
  const [validating, setValidating] = useState(false);
  const [importingMode, setImportingMode] = useState<TMACImportMode | null>(null);
  const [aiPrompt, setAiPrompt] = useState("");
  const [aiResponse, setAiResponse] = useState<AssistantResponse | null>(null);
  const [aiAction, setAiAction] = useState<TMACAIAction | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [selection, setSelection] = useState<EditorSelection>(EMPTY_SELECTION);
  const [lastAnalysisAt, setLastAnalysisAt] = useState<string | null>(null);
  const [copyNotice, setCopyNotice] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const editorRef = useRef<HTMLTextAreaElement | null>(null);
  const analysisNonce = useRef(0);
  const tmacExportOptionsRef = useRef({
    editorFormat,
    includeBinaryAssets,
    includeOperationalState,
  });

  const hasContent = content.trim().length > 0;
  const dirty = hasContent && content !== baselineContent;
  const selectedText = selection.text.trim();

  const changedSectionsCopy = useMemo(() => {
    if (!diff?.changed_sections.length) {
      return "No structural differences detected.";
    }
    return `Changed sections: ${diff.changed_sections.join(", ")}.`;
  }, [diff]);

  const liveDraftStatus = useMemo(() => {
    if (loadingLive) {
      return "Loading live TMAC…";
    }
    if (!hasContent) {
      return "Editor is empty.";
    }
    if (dirty) {
      return "Local code differs from the live model.";
    }
    return "Editor matches the latest loaded live model.";
  }, [dirty, hasContent, loadingLive]);

  const aiDraft = useMemo(
    () => extractCodeBlock(aiResponse?.answer ?? "", editorFormat),
    [aiResponse, editorFormat],
  );

  useEffect(() => {
    tmacExportOptionsRef.current = {
      editorFormat,
      includeBinaryAssets,
      includeOperationalState,
    };
  }, [editorFormat, includeBinaryAssets, includeOperationalState]);

  function readEditorSelection(): EditorSelection {
    const nextSelection = editorRef.current;
    if (!nextSelection) {
      return EMPTY_SELECTION;
    }
    const start = nextSelection.selectionStart ?? 0;
    const end = nextSelection.selectionEnd ?? start;
    return {
      start,
      end,
      text: content.slice(start, end),
    };
  }

  const loadEditorContent = useCallback(async (source: "live" | "scaffold") => {
    if (source === "live") {
      setLoadingLive(true);
    } else {
      setLoadingScaffold(true);
    }
    setOperationError(null);
    setAiError(null);
    setAiResponse(null);
    try {
      const exportOptions = tmacExportOptionsRef.current;
      const blob =
        source === "live"
          ? await api.exportTMAC(threatModelId, exportOptions.editorFormat, {
              include_operational_state: exportOptions.includeOperationalState,
              include_binary_assets: exportOptions.includeBinaryAssets,
            })
          : await api.getTMACScaffold();
      const nextContent = await blob.text();
      setContent(nextContent);
      if (source === "live") {
        setBaselineContent(nextContent);
      }
      setValidation(null);
      setDiff(null);
      setAnalysisError(null);
      setSelection(EMPTY_SELECTION);
    } catch (unknownError) {
      setOperationError(
        unknownError instanceof Error
          ? unknownError.message
          : source === "live"
            ? "Failed to load the live TMAC document."
            : "Failed to load the TMAC scaffold.",
      );
    } finally {
      setLoadingLive(false);
      setLoadingScaffold(false);
    }
  }, [threatModelId]);

  useEffect(() => {
    void loadEditorContent("live");
  }, [loadEditorContent]);

  useEffect(() => {
    if (!copyNotice) {
      return undefined;
    }
    const timeout = window.setTimeout(() => setCopyNotice(null), 1800);
    return () => window.clearTimeout(timeout);
  }, [copyNotice]);

  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, []);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  const runAnalysis = useCallback(async (draft: string) => {
    if (!draft.trim()) {
      setValidation(null);
      setDiff(null);
      setAnalysisError(null);
      setLastAnalysisAt(null);
      return;
    }

    const requestId = analysisNonce.current + 1;
    analysisNonce.current = requestId;
    setValidating(true);
    setAnalysisError(null);

    try {
      const [validationResponse, diffResponse] = await Promise.all([
        api.validateTMAC(draft),
        api.diffTMAC(threatModelId, draft),
      ]);

      if (requestId !== analysisNonce.current) {
        return;
      }

      setValidation(validationResponse);
      setDiff(diffResponse);
      setEditorFormat(validationResponse.format);
      setLastAnalysisAt(new Date().toISOString());
    } catch (unknownError) {
      if (requestId !== analysisNonce.current) {
        return;
      }
      setValidation(null);
      setDiff(null);
      setAnalysisError(
        unknownError instanceof Error ? unknownError.message : "TMAC validation failed.",
      );
      setLastAnalysisAt(null);
    } finally {
      if (requestId === analysisNonce.current) {
        setValidating(false);
      }
    }
  }, [threatModelId]);

  useEffect(() => {
    if (!hasContent) {
      setValidation(null);
      setDiff(null);
      setAnalysisError(null);
      setLastAnalysisAt(null);
      return undefined;
    }

    const timeout = window.setTimeout(() => {
      void runAnalysis(content);
    }, 650);

    return () => window.clearTimeout(timeout);
  }, [content, hasContent, runAnalysis]);

  const handleDownloadExport = async () => {
    setExporting(true);
    setOperationError(null);
    try {
      const blob = await api.exportTMAC(threatModelId, editorFormat, {
        include_operational_state: includeOperationalState,
        include_binary_assets: includeBinaryAssets,
      });
      downloadBlob(blob, `threat-model-${threatModelId}.tmac.${editorFormat}`);
    } catch (unknownError) {
      setOperationError(
        unknownError instanceof Error ? unknownError.message : "TMAC export failed.",
      );
    } finally {
      setExporting(false);
    }
  };

  const handleLoadFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    setOperationError(null);
    setAiError(null);
    setAiResponse(null);
    try {
      const text = await file.text();
      setContent(text);
      setValidation(null);
      setDiff(null);
      setAnalysisError(null);
      setSelection(EMPTY_SELECTION);
    } catch (unknownError) {
      setOperationError(
        unknownError instanceof Error
          ? unknownError.message
          : "Failed to read the selected file.",
      );
    } finally {
      if (fileRef.current) {
        fileRef.current.value = "";
      }
    }
  };

  const handleEditorSelection = () => {
    setSelection(readEditorSelection());
  };

  const handleCopy = async () => {
    if (!hasContent) {
      return;
    }
    setOperationError(null);
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(content);
      } else {
        throw new Error("Clipboard access is not available in this browser.");
      }
      setCopyNotice("Copied TMAC.");
    } catch (unknownError) {
      setOperationError(
        unknownError instanceof Error ? unknownError.message : "Failed to copy TMAC.",
      );
    }
  };

  const handleValidateNow = async () => {
    setOperationError(null);
    await runAnalysis(content);
  };

  const handleImport = async (mode: Extract<TMACImportMode, "replace" | "create_new">) => {
    if (!hasContent) {
      return;
    }
    setImportingMode(mode);
    setOperationError(null);
    try {
      const response = await api.importTMAC({
        content,
        mode,
        target_threat_model_id: mode === "replace" ? threatModelId : null,
        apply_operational_state: includeOperationalState,
        apply_binary_assets: includeBinaryAssets,
      });
      onImported(response);
    } catch (unknownError) {
      setOperationError(
        unknownError instanceof Error ? unknownError.message : "TMAC import failed.",
      );
    } finally {
      setImportingMode(null);
    }
  };

  const handleRunAI = async (action: TMACAIAction) => {
    if (!hasContent || aiAction) {
      return;
    }
    const currentSelection = readEditorSelection();
    const currentSelectedText = currentSelection.text.trim();
    setSelection(currentSelection);
    if (action === "explain" && !currentSelectedText) {
      setAiError("Select a TMAC section in the editor before asking AI to explain it.");
      return;
    }
    if (content.length > LARGE_DOCUMENT_AI_THRESHOLD && action !== "explain" && !currentSelectedText) {
      setAiError(
        "This TMAC draft is large for a whole-document AI pass. Select a smaller section or shorten the draft before sending it to AI.",
      );
      return;
    }

    if (action === "rewrite" && content.length > MAX_ASSISTANT_ANSWER_LENGTH - AI_CODE_FENCE_OVERHEAD) {
      setAiError(
        "This TMAC draft is too large for a single AI rewrite response. Select a smaller section or shorten the draft before generating a full draft.",
      );
      return;
    }

    const prompt = buildAIPrompt({
      action,
      format: editorFormat,
      content,
      selection: currentSelection,
      customPrompt: aiPrompt,
      validation,
      diff,
    });
    if (prompt.length > MAX_ASSISTANT_MESSAGE_LENGTH) {
      setAiError(
        "This AI request is too large for the assistant endpoint. Select a smaller section or shorten the draft before sending it.",
      );
      return;
    }

    setAiAction(action);
    setAiError(null);
    setAiResponse(null);
    setOperationError(null);

    const request: AssistantRequest = {
      message: prompt,
      mode_hint:
        action === "rewrite" ? "build" : action === "review" ? "review" : "explain",
    };

    try {
      const response = await api.assistantRespond(threatModelId, request);
      setAiResponse(response);
    } catch (unknownError) {
      setAiError(
        unknownError instanceof Error ? unknownError.message : "AI request failed.",
      );
    } finally {
      setAiAction(null);
    }
  };

  const handleApplyAIDraft = () => {
    if (!aiDraft.content) {
      return;
    }
    setContent(aiDraft.content);
    setEditorFormat(aiDraft.format);
    setSelection(EMPTY_SELECTION);
    setAiError(null);
  };

  const handleBackdropClick = (event: ReactMouseEvent<HTMLDivElement>) => {
    if (event.target === event.currentTarget) {
      onClose();
    }
  };

  return (
    <div className="dfd-dialog-overlay tmac-overlay" onClick={handleBackdropClick}>
      <div
        className="dfd-dialog dfd-dialog-wide tmac-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="tmac-dialog-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="tmac-dialog-header">
          <div>
            <h3 className="dfd-dialog-title" id="tmac-dialog-title">
              TMAC Editor
            </h3>
            <p className="dfd-dialog-copy">
              Edit the live threat model as code, keep validation and structural diff in view while
              you type, and use AI to review or rewrite the draft before you apply it back to the
              model.
            </p>
          </div>
          <div className="tmac-dialog-header-actions">
            <a
              className="btn-export btn-export-accent tmac-guide-link"
              href={TMAC_DOCS_ROUTE}
              target="_blank"
              rel="noreferrer"
            >
              Open TMAC Guide
            </a>
            <button
              type="button"
              className="tmac-close-button"
              aria-label="Close TMAC editor"
              onClick={onClose}
              title="Close the TMAC editor"
            >
              ×
            </button>
          </div>
        </div>

        <div className="tmac-dialog-body">
          <section className="tmac-section">
            <div className="tmac-reference-card">
              <div className="tmac-section-head">
                <div>
                  <h4>Authoring Notes</h4>
                  <p>
                    Treat TMAC as the portable graph and threat contract. ThreatGenix now fills in
                    missing layout coordinates for DFD nodes during validation/import, so you can
                    author structure first and refine layout later.
                  </p>
                </div>
                <a
                  className="btn-export btn-export-accent tmac-file-button tmac-reference-link"
                  href={TMAC_DOCS_ROUTE}
                  target="_blank"
                  rel="noreferrer"
                >
                  Reference
                </a>
              </div>
              <ul className="tmac-reference-list">
                {TMAC_REFERENCE_POINTS.map((point) => (
                  <li key={point}>{point}</li>
                ))}
              </ul>
            </div>
          </section>

          <section className="tmac-section">
            <div className="tmac-section-head">
              <div>
                <h4>Workspace</h4>
                <p>
                  Editor format controls the live load, export, and AI code-fence format. Reload the
                  live model after changing it.
                </p>
              </div>
              <div className="tmac-export-actions">
                <select
                  aria-label="TMAC format"
                  className="tmac-select"
                  value={editorFormat}
                  onChange={(event) => setEditorFormat(event.target.value as TMACFormat)}
                  disabled={loadingLive || exporting}
                >
                  <option value="yaml">YAML</option>
                  <option value="json">JSON</option>
                </select>
                <button
                  type="button"
                  className="btn-export btn-export-accent"
                  onClick={() => void loadEditorContent("live")}
                  disabled={loadingLive}
                  title="Load the current live model into the editor"
                >
                  {loadingLive ? "Loading..." : "Load Live Model"}
                </button>
                <button
                  type="button"
                  className="btn-export"
                  onClick={() => void loadEditorContent("scaffold")}
                  disabled={loadingScaffold}
                  title="Load a starter TMAC scaffold with recommended sections"
                >
                  {loadingScaffold ? "Loading..." : "Load Scaffold"}
                </button>
                <button
                  type="button"
                  className="btn-export"
                  onClick={handleDownloadExport}
                  disabled={exporting}
                  title="Download the current editor draft as a TMAC file"
                >
                  {exporting ? "Exporting..." : "Download TMAC"}
                </button>
                <label className="btn-export btn-export-accent tmac-file-button" title="Load a TMAC file from disk into the editor">
                  Load File
                  <input
                    ref={fileRef}
                    type="file"
                    accept=".yaml,.yml,.json,.tmac,.txt"
                    onChange={handleLoadFile}
                    hidden
                  />
                </label>
              </div>
            </div>
            <div className="tmac-options-grid">
              <label className="tmac-option">
                <input
                  type="checkbox"
                  aria-label="Include governance and collaboration state"
                  checked={includeOperationalState}
                  onChange={(event) => setIncludeOperationalState(event.target.checked)}
                />
                <span>
                  <strong>Include governance and collaboration state</strong>
                  <small>Snapshots, reviews, collaborators, assignments, and notifications.</small>
                </span>
              </label>
              <label className="tmac-option">
                <input
                  type="checkbox"
                  aria-label="Include embedded reporting assets"
                  checked={includeBinaryAssets}
                  onChange={(event) => setIncludeBinaryAssets(event.target.checked)}
                />
                <span>
                  <strong>Include embedded reporting assets</strong>
                  <small>Report logo and architecture diagram binaries for full rendering parity.</small>
                </span>
              </label>
            </div>
          </section>

          <section className="tmac-section">
            <div className="tmac-live-status">
              <span className={`tmac-status-pill ${dirty ? "tmac-status-pill-warning" : "tmac-status-pill-neutral"}`}>
                {liveDraftStatus}
              </span>
              <span className={`tmac-status-pill ${validating ? "tmac-status-pill-progress" : validation ? "tmac-status-pill-valid" : "tmac-status-pill-neutral"}`}>
                {validating
                  ? "Analyzing draft…"
                  : validation
                    ? `Valid ${validation.format.toUpperCase()}`
                    : "No validated draft yet"}
              </span>
              {selectedText && (
                <span className="tmac-status-pill tmac-status-pill-neutral">
                  Selection: {selectionSummary(selectedText)}
                </span>
              )}
            </div>

            <div className="tmac-workspace">
              <div className="tmac-editor-column">
                <div className="tmac-section-head">
                  <div>
                    <h4>Code</h4>
                    <p>
                      Type directly, paste external TMAC, or replace the editor with an AI-generated
                      draft before you apply it back to the live model.
                    </p>
                  </div>
                  <div className="tmac-export-actions">
                    <button
                      type="button"
                      className="btn-export btn-export-quiet"
                      onClick={handleCopy}
                      disabled={!hasContent}
                      title="Copy the current TMAC draft to the clipboard"
                    >
                      Copy
                    </button>
                    <button
                      type="button"
                      className="btn-export btn-export-quiet"
                      onClick={() => setContent(baselineContent)}
                      disabled={!baselineContent || !dirty}
                      title="Reset the editor back to the last live model you loaded"
                    >
                      Reset to Loaded Live
                    </button>
                    <button
                      type="button"
                      className="btn-export btn-export-accent"
                      onClick={handleValidateNow}
                      disabled={!hasContent || validating}
                      title="Run validation and structural diff on the current draft"
                    >
                      {validating ? "Analyzing..." : "Validate Now"}
                    </button>
                  </div>
                </div>

                <textarea
                  ref={editorRef}
                  className="tmac-editor"
                  value={content}
                  onChange={(event) => {
                    setContent(event.target.value);
                    setOperationError(null);
                    setAiError(null);
                  }}
                  onSelect={handleEditorSelection}
                  onKeyUp={handleEditorSelection}
                  onMouseUp={handleEditorSelection}
                  placeholder="The live TMAC document loads here. You can also paste YAML or JSON."
                  spellCheck={false}
                />

                <div className="tmac-actions-row">
                  <button
                    type="button"
                    className="btn-create"
                    onClick={() => void handleImport("replace")}
                    disabled={!hasContent || importingMode !== null}
                    title="Replace the current live model with this TMAC draft"
                  >
                    {importingMode === "replace" ? "Applying..." : "Apply to Live Model"}
                  </button>
                  <button
                    type="button"
                    className="btn-export"
                    onClick={() => void handleImport("create_new")}
                    disabled={!hasContent || importingMode !== null}
                    title="Create a new review workspace from this TMAC draft"
                  >
                    {importingMode === "create_new" ? "Creating..." : "Import as New Review"}
                  </button>
                </div>

                <p className="tmac-import-note">
                  Replace mode keeps the current model id. Operational workflow state and binary
                  assets are only applied when the options above are enabled.
                </p>
                <p className="tmac-import-note">{formatAnalysisTime(lastAnalysisAt)}</p>
                {copyNotice && <p className="tmac-import-note">{copyNotice}</p>}
              </div>

              <aside className="tmac-side-column">
                <div className="tmac-side-card">
                  <div className="tmac-section-head">
                    <div>
                      <h4>AI</h4>
                      <p>
                        Review the draft, explain a selected section, or ask AI to generate a full
                        updated TMAC draft that you can load into the editor.
                      </p>
                    </div>
                  </div>

                  <textarea
                    className="tmac-ai-prompt"
                    value={aiPrompt}
                    onChange={(event) => setAiPrompt(event.target.value)}
                    placeholder="Tell AI what to review, explain, or change. For example: Add a secrets vault and update the related threats."
                  />

                  <div className="tmac-ai-actions">
                    <button
                      type="button"
                      className="btn-export"
                      onClick={() => void handleRunAI("review")}
                      disabled={!hasContent || aiAction !== null}
                      title="Ask AI to review the current draft for issues and gaps"
                    >
                      {aiAction === "review" ? "Reviewing..." : "AI Review"}
                    </button>
                    <button
                      type="button"
                      className="btn-export"
                      onClick={() => void handleRunAI("explain")}
                      disabled={!hasContent || aiAction !== null}
                      title="Explain the selected TMAC block or current draft context"
                    >
                      {aiAction === "explain" ? "Explaining..." : "Explain Selection"}
                    </button>
                    <button
                      type="button"
                      className="btn-create"
                      onClick={() => void handleRunAI("rewrite")}
                      disabled={!hasContent || aiAction !== null}
                      title="Generate a full updated TMAC draft with AI"
                    >
                      {aiAction === "rewrite" ? "Drafting..." : "Generate Draft"}
                    </button>
                  </div>

                  {aiResponse && (
                    <div className="tmac-ai-response">
                      <div className="tmac-ai-response-head">
                        <span className="tmac-status-pill tmac-status-pill-neutral">
                          AI mode: {aiResponse.mode}
                        </span>
                        {aiDraft.content && (
                          <button type="button" className="btn-export" onClick={handleApplyAIDraft}>
                            Load AI Draft into Editor
                          </button>
                        )}
                      </div>
                      <pre>{aiResponse.answer}</pre>
                    </div>
                  )}

                  {!aiResponse && (
                    <p className="tmac-import-note">
                      {selectedText
                        ? `AI will use the current selection (${selectionSummary(selectedText)}) when it helps.`
                        : "Select a TMAC block in the editor if you want focused explanation instead of a full-draft pass."}
                    </p>
                  )}

                  {aiResponse?.references.length ? (
                    <p className="tmac-import-note">
                      Referenced graph objects:{" "}
                      {aiResponse.references.map((reference) => reference.label).join(", ")}
                    </p>
                  ) : null}
                </div>

                <div className="tmac-side-card">
                  <div className="tmac-section-head">
                    <div>
                      <h4>Validation</h4>
                      <p>
                        {validation
                          ? `Detected as ${validation.format.toUpperCase()} and structurally valid.`
                          : "Analysis updates as you edit."}
                      </p>
                    </div>
                  </div>
                  {validation ? (
                    <>
                      <SummaryGrid summary={validation.summary} />
                      <p className="tmac-import-note">{summarizeWarnings(validation.warnings)}</p>
                      {validation.warnings.length > 0 && (
                        <ul className="tmac-warning-list">
                          {validation.warnings.map((warning) => (
                            <li key={warning}>{warning}</li>
                          ))}
                        </ul>
                      )}
                    </>
                  ) : (
                    <p className="tmac-import-note">
                      {hasContent
                        ? validating
                          ? "Running validation and live diff…"
                          : "Validation results will appear here."
                        : "Load or paste TMAC to start live validation."}
                    </p>
                  )}
                </div>

                <div className="tmac-side-card">
                  <div className="tmac-section-head">
                    <div>
                      <h4>Live Diff</h4>
                      <p>{diff ? changedSectionsCopy : "Compare the draft against the current live model."}</p>
                    </div>
                  </div>
                  {diff ? (
                    <>
                      <div className="tmac-diff-grid">
                        <div>
                          <span className="tmac-diff-label">Current Model</span>
                          <SummaryGrid summary={diff.current_summary} />
                        </div>
                        <div>
                          <span className="tmac-diff-label">Editor Draft</span>
                          <SummaryGrid summary={diff.incoming_summary} />
                        </div>
                      </div>
                      <p className="tmac-import-note">{summarizeWarnings(diff.warnings)}</p>
                      {diff.warnings.length > 0 && (
                        <ul className="tmac-warning-list">
                          {diff.warnings.map((warning) => (
                            <li key={warning}>{warning}</li>
                          ))}
                        </ul>
                      )}
                    </>
                  ) : (
                    <p className="tmac-import-note">
                      {hasContent
                        ? validating
                          ? "Waiting for live diff…"
                          : "Diff results will appear here after validation."
                        : "Load or paste TMAC to compare it against the live model."}
                    </p>
                  )}
                </div>
              </aside>
            </div>
          </section>

          {analysisError && <p className="tmac-error">Analysis failed: {analysisError}</p>}
          {operationError && <p className="tmac-error">{operationError}</p>}
          {aiError && <p className="tmac-error">AI: {aiError}</p>}

          <div className="tmac-dialog-footer">
            <a
              className="btn-export btn-export-accent tmac-guide-link"
              href={TMAC_DOCS_ROUTE}
              target="_blank"
              rel="noreferrer"
              title="Open the TMAC reference guide in a new tab"
            >
              Open TMAC Guide
            </a>
            <button type="button" className="btn-export btn-export-quiet" onClick={onClose} title="Close the TMAC editor">
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

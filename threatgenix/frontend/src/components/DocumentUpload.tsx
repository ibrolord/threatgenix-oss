import { useRef, useState } from "react";

import { api } from "../api/client";
import type { DocumentUploadResponse } from "../types/api";

interface DocumentUploadProps {
  threatModelId: string;
  onUploadComplete: () => void;
}

type UploadState = "idle" | "uploading" | "success" | "error";

const UPLOAD_PHASES = [
  "Uploading document...",
  "Extracting text and diagrams...",
  "Identifying system components...",
  "Building data flow relationships...",
  "Finalizing component extraction...",
];

function formatDocumentType(value: string | null): string | null {
  if (!value) return null;
  return value
    .split("_")
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(" ");
}

function formatExtractionSource(value: string): string {
  if (value.toLowerCase() === "llm") {
    return "LLM";
  }
  return value
    .split("_")
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(" ");
}

export function DocumentUpload({ threatModelId, onUploadComplete }: DocumentUploadProps) {
  const [state, setState] = useState<UploadState>("idle");
  const [errorMsg, setErrorMsg] = useState<string>("");
  const [result, setResult] = useState<DocumentUploadResponse | null>(null);
  const [uploadPhase, setUploadPhase] = useState(0);
  const phaseTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleUpload() {
    const file = fileRef.current?.files?.[0];
    if (!file) return;

    setState("uploading");
    setErrorMsg("");
    setResult(null);
    setUploadPhase(0);

    // Advance through progress phases every 4 seconds
    phaseTimerRef.current = setInterval(() => {
      setUploadPhase((prev) => Math.min(prev + 1, UPLOAD_PHASES.length - 1));
    }, 4000);

    try {
      const response = await api.uploadDocument(threatModelId, file);
      setResult(response);
      setState("success");
      if (fileRef.current) fileRef.current.value = "";
      onUploadComplete();
    } catch (e: unknown) {
      setState("error");
      setErrorMsg(e instanceof Error ? e.message : "Upload failed");
    } finally {
      if (phaseTimerRef.current) {
        clearInterval(phaseTimerRef.current);
        phaseTimerRef.current = null;
      }
    }
  }

  const evidence = result?.evidence;

  if (state === "success" && result && evidence) {
    const formattedDocType = formatDocumentType(evidence.detected_doc_type);

    return (
      <div className="document-upload document-upload-success-card">
        <div className="document-upload-success-header">
          <div>
            <h3>Document analyzed</h3>
            <p className="document-upload-subcopy">
              The DFD has been refreshed from the uploaded design evidence, and the extracted
              document context is now available for later threat analysis.
            </p>
          </div>
          <button
            className="btn-export"
            onClick={() => {
              setResult(null);
              setState("idle");
            }}
          >
            Upload Another
          </button>
        </div>

        <div className="document-upload-stats" aria-label="Document extraction summary">
          <div className="document-upload-stat">
            <span className="document-upload-stat-value">{evidence.component_count}</span>
            <span className="document-upload-stat-label">Components</span>
          </div>
          <div className="document-upload-stat">
            <span className="document-upload-stat-value">{evidence.flow_count}</span>
            <span className="document-upload-stat-label">Flows</span>
          </div>
          <div className="document-upload-stat">
            <span className="document-upload-stat-value">{evidence.boundary_count}</span>
            <span className="document-upload-stat-label">Trust Boundaries</span>
          </div>
        </div>

        <div className="document-upload-meta">
          {formattedDocType && (
            <span className="document-upload-pill">Detected doc type: {formattedDocType}</span>
          )}
          {evidence.diagram_pages.length > 0 && (
            <span className="document-upload-pill">
              Diagram pages: {evidence.diagram_pages.join(", ")}
            </span>
          )}
          {evidence.diagram_artifacts.length > 0 && (
            <span className="document-upload-pill">
              Diagram sources: {evidence.diagram_artifacts.join(", ")}
            </span>
          )}
          {evidence.extraction_sources.length > 0 && (
            <span className="document-upload-pill">
              Sources: {evidence.extraction_sources.map(formatExtractionSource).join(", ")}
            </span>
          )}
        </div>

        {(result.warnings.length > 0 || evidence.low_confidence_areas.length > 0) && (
          <div className="document-upload-review">
            <strong>Review before relying on the generated model:</strong>
            <ul>
              {[...result.warnings, ...evidence.low_confidence_areas].map((warning, index) => (
                <li key={`${warning}-${index}`}>{warning}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="document-upload">
      <div className="document-upload-header">
        <div>
          <h3>Upload Threat-Modeling Documents</h3>
          <p className="document-upload-subcopy">
            Upload the design evidence that best describes the real system so ThreatGenix can
            build a DFD and ground later threat analysis in actual architecture context.
          </p>
        </div>
      </div>

      <div className="document-upload-guidance">
        <p className="document-upload-guidance-title">Best inputs</p>
        <ul>
          <li>System design docs and technical specs</li>
          <li>Architecture, deployment, or sequence diagrams in PDF, DOCX, or image form</li>
          <li>Authentication, authorization, trust-boundary, and data-flow details</li>
          <li>Service, database, queue, external integration, and network topology descriptions</li>
        </ul>
        <p className="document-upload-guidance-note">
          Supported uploads: PDF, DOCX, PNG, JPG, JPEG, and WEBP. ThreatGenix extracts text,
          embedded diagrams, and direct diagram images deterministically first, then uses model
          inference only to fill structured gaps.
        </p>
      </div>

      <div className="document-upload-row">
        <input
          ref={fileRef}
          type="file"
          accept=".pdf,.docx,.png,.jpg,.jpeg,.webp,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,image/png,image/jpeg,image/webp"
          disabled={state === "uploading"}
          aria-label="Select threat modeling document"
        />
        <button
          className="btn-upload"
          onClick={handleUpload}
          disabled={state === "uploading"}
        >
          {state === "uploading" ? "Processing..." : "Upload and Extract"}
        </button>
      </div>
      {state === "uploading" && (
        <div className="document-upload-progress">
          <div className="dfd-spinner" style={{ width: 16, height: 16 }} />
          <span className="document-upload-progress-text">{UPLOAD_PHASES[uploadPhase]}</span>
          <div className="document-upload-progress-bar">
            <div
              className="document-upload-progress-fill"
              style={{ width: `${Math.min(((uploadPhase + 1) / UPLOAD_PHASES.length) * 100, 95)}%` }}
            />
          </div>
        </div>
      )}
      {state === "error" && (
        <p className="upload-error">Upload failed: {errorMsg}</p>
      )}
    </div>
  );
}

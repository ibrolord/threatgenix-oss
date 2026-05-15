import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type {
  DFDIacImportResponse,
  DFDRepositorySeedApplyResponse,
  DFDRepositorySeedPreviewResponse,
  EnvironmentEvidenceResponse,
  RouteAuthEntry,
  ThreatModelResponse,
} from "../types/api";

interface EnvironmentEvidencePanelProps {
  threatModelId: string;
  model: ThreatModelResponse;
  onUpdated: (evidence: EnvironmentEvidenceResponse) => void;
  onImportedToDfd: (result: DFDIacImportResponse | DFDRepositorySeedApplyResponse) => void;
}

type UploadState = "idle" | "uploading" | "success" | "error";

function PillList({ items }: { items?: string[] | null }) {
  const safeItems = items ?? [];
  if (safeItems.length === 0) return <span style={{ color: "#64748b" }}>None parsed yet</span>;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
      {safeItems.map((item) => (
        <span
          key={item}
          style={{
            background: "#e2e8f0",
            color: "#0f172a",
            borderRadius: "999px",
            padding: "4px 10px",
            fontSize: "0.8rem",
          }}
        >
          {item}
        </span>
      ))}
    </div>
  );
}

function RouteAuthList({ entries }: { entries?: RouteAuthEntry[] | null }) {
  const safeEntries = entries ?? [];
  if (safeEntries.length === 0) return <span style={{ color: "#64748b" }}>No route guard mapping parsed yet</span>;
  return (
    <div style={{ display: "grid", gap: "8px" }}>
      {safeEntries.map((entry) => {
        const authGuards = entry.auth_guards ?? [];
        const sensitiveSignals = entry.sensitive_data_signals ?? [];
        const validationSignals = entry.validation_signals ?? [];
        const outboundSignals = entry.outbound_call_signals ?? [];
        const riskFlags = entry.risk_flags ?? [];
        return (
        <div
          key={`${entry.method}-${entry.path}-${entry.source_file}-${entry.line_number ?? "na"}`}
          style={{
            background: "#f8fafc",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "10px",
          }}
        >
          <div style={{ fontWeight: 700 }}>
            {entry.method} {entry.path}
          </div>
          <div style={{ color: "#475569", fontSize: "0.82rem", marginTop: "4px" }}>
            {entry.source_file}
            {entry.line_number ? `:${entry.line_number}` : ""}
          </div>
          <div style={{ marginTop: "6px", fontSize: "0.9rem" }}>
            {authGuards.length > 0 ? (
              <>Auth guards: {authGuards.join(", ")}</>
            ) : (
              <span style={{ color: "#92400e" }}>No detected auth guard</span>
            )}
          </div>
          {sensitiveSignals.length > 0 && (
            <div style={{ marginTop: "6px", fontSize: "0.9rem", color: "#7c2d12" }}>
              Sensitive data touched: {sensitiveSignals.join(", ")}
            </div>
          )}
          {validationSignals.length > 0 && (
            <div style={{ marginTop: "6px", fontSize: "0.9rem", color: "#1d4ed8" }}>
              Validation signals: {validationSignals.join(", ")}
            </div>
          )}
          {outboundSignals.length > 0 && (
            <div style={{ marginTop: "6px", fontSize: "0.9rem", color: "#0f766e" }}>
              Outbound call signals: {outboundSignals.join(", ")}
            </div>
          )}
          {riskFlags.length > 0 && (
            <div style={{ marginTop: "6px", fontSize: "0.9rem", color: "#b91c1c" }}>
              Risk flags: {riskFlags.join(", ")}
            </div>
          )}
        </div>
      )})}
    </div>
  );
}

function GuidanceBlock({ title, body, command }: { title: string; body: string; command: string }) {
  return (
    <div
      style={{
        background: "#0f172a",
        color: "#e2e8f0",
        borderRadius: "10px",
        padding: "12px 14px",
        marginTop: "10px",
      }}
    >
      <div style={{ fontWeight: 700, marginBottom: "6px" }}>{title}</div>
      <div style={{ fontSize: "0.9rem", color: "#cbd5e1", marginBottom: "8px" }}>{body}</div>
      <pre
        style={{
          margin: 0,
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
          fontSize: "0.8rem",
          fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        }}
      >
        {command}
      </pre>
    </div>
  );
}

function impactCount(items?: string[] | null): number {
  return (items ?? []).length;
}

function formatSyncTime(value?: string | null): string {
  if (!value) return "Not synced yet";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

export function EnvironmentEvidencePanel({
  threatModelId,
  model,
  onUpdated,
  onImportedToDfd,
}: EnvironmentEvidencePanelProps) {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    if (typeof window === "undefined") {
      return false;
    }
    return window.localStorage.getItem("tg_environment_evidence_collapsed") === "true";
  });
  const repoRef = useRef<HTMLInputElement>(null);
  const scanRef = useRef<HTMLInputElement>(null);
  const [githubRepository, setGithubRepository] = useState("");
  const [githubTransport, setGithubTransport] = useState<"https" | "ssh">("https");
  const [githubRef, setGithubRef] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [githubSshPrivateKey, setGithubSshPrivateKey] = useState("");
  const iacRef = useRef<HTMLInputElement>(null);
  const [repoReference, setRepoReference] = useState("");
  const [iacReference, setIacReference] = useState("");
  const [repoState, setRepoState] = useState<UploadState>("idle");
  const [scanState, setScanState] = useState<UploadState>("idle");
  const [iacState, setIacState] = useState<UploadState>("idle");
  const [importState, setImportState] = useState<UploadState>("idle");
  const [seedState, setSeedState] = useState<UploadState>("idle");
  const [repoError, setRepoError] = useState("");
  const [scanError, setScanError] = useState("");
  const [iacError, setIacError] = useState("");
  const [importError, setImportError] = useState("");
  const [lastImport, setLastImport] = useState<DFDIacImportResponse | null>(null);
  const [seedError, setSeedError] = useState("");
  const [seedPreview, setSeedPreview] =
    useState<DFDRepositorySeedPreviewResponse | null>(null);
  const [selectedSeedIds, setSelectedSeedIds] = useState<string[]>([]);
  const [lastSeedApply, setLastSeedApply] =
    useState<DFDRepositorySeedApplyResponse | null>(null);

  const repository = model.repository_evidence;
  const repositoryConnection = repository?.connection;
  const cloudScan = model.cloud_scan_evidence;
  const iacEvidence = model.iac_evidence;
  const evidenceSummary = [
    repository ? "Repository loaded" : "No repository evidence",
    cloudScan ? "Cloud posture loaded" : "No cloud scan evidence",
    iacEvidence ? "IaC loaded" : "No IaC evidence",
  ].join(" • ");
  const cloudImpactRows = cloudScan
    ? [
        `${cloudScan.finding_count} cloud finding${cloudScan.finding_count === 1 ? "" : "s"} now inform review rationale.`,
        `${impactCount(cloudScan.exposed_services)} exposed service signal${impactCount(cloudScan.exposed_services) === 1 ? "" : "s"} can move findings out of design-only assumptions.`,
        `${impactCount(cloudScan.identity_risks)} identity risk${impactCount(cloudScan.identity_risks) === 1 ? "" : "s"} and ${impactCount(cloudScan.encryption_gaps)} encryption gap${impactCount(cloudScan.encryption_gaps) === 1 ? "" : "s"} now influence queue priority.`,
        "Logging and control-coverage gaps can now show up as Verify or Fix Now work instead of staying only in Gather Evidence.",
      ]
    : [
        "Internet exposure, IAM, encryption, and logging remain evidence gaps until a cloud scan is attached.",
        "The review can still rank modeled attack paths, but cloud-backed control coverage remains unproven.",
        "Cloud-specific findings will stay grounded in architecture assumptions instead of real account evidence.",
        "Uploading a supported cloud posture export is the fastest way to reduce Gather Evidence noise for cloud workloads.",
      ];

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(
      "tg_environment_evidence_collapsed",
      collapsed ? "true" : "false"
    );
  }, [collapsed]);

  useEffect(() => {
    const connection = repositoryConnection;
    if (!connection || connection.provider !== "github") {
      return;
    }
    setGithubRepository(connection.repository);
    setGithubTransport(connection.transport);
    setGithubRef(connection.ref ?? "");
    setRepoReference(connection.reference ?? "");
  }, [
    repositoryConnection,
  ]);

  async function handleRepositoryUpload() {
    const file = repoRef.current?.files?.[0];
    if (!file) return;
    setRepoState("uploading");
    setRepoError("");
    try {
      const evidence = await api.uploadRepositoryEvidence(threatModelId, file, repoReference);
      setRepoState("success");
      onUpdated(evidence);
      if (repoRef.current) repoRef.current.value = "";
    } catch (error) {
      setRepoState("error");
      setRepoError(error instanceof Error ? error.message : "Repository upload failed");
    }
  }

  async function handleGitHubImport() {
    if (!githubRepository.trim()) {
      setRepoState("error");
      setRepoError("Enter a GitHub repo URL or owner/repo slug.");
      return;
    }
    setRepoState("uploading");
    setRepoError("");
    try {
      const evidence = await api.importRepositoryEvidenceFromGitHub(
        threatModelId,
        {
          repository: githubRepository.trim(),
          transport: githubTransport,
          ref: githubRef.trim() || undefined,
          reference: repoReference.trim() || undefined,
          ssh_private_key:
            githubTransport === "ssh" ? githubSshPrivateKey.trim() || undefined : undefined,
        },
        githubTransport === "https" ? githubToken.trim() || undefined : undefined
      );
      setRepoState("success");
      setGithubToken("");
      setGithubSshPrivateKey("");
      onUpdated(evidence);
    } catch (error) {
      setRepoState("error");
      setRepoError(error instanceof Error ? error.message : "GitHub repository import failed");
    }
  }

  async function handleGitHubRefresh() {
    const connection = repository?.connection;
    if (!connection || connection.provider !== "github") {
      setRepoState("error");
      setRepoError("No saved GitHub repository connection is available to refresh.");
      return;
    }
    setRepoState("uploading");
    setRepoError("");
    try {
      const evidence = await api.refreshRepositoryEvidenceFromGitHub(
        threatModelId,
        {
          ssh_private_key:
            connection.transport === "ssh" ? githubSshPrivateKey.trim() || undefined : undefined,
        },
        connection.transport === "https" ? githubToken.trim() || undefined : undefined
      );
      setRepoState("success");
      setGithubToken("");
      setGithubSshPrivateKey("");
      onUpdated(evidence);
    } catch (error) {
      setRepoState("error");
      setRepoError(error instanceof Error ? error.message : "GitHub repository refresh failed");
    }
  }

  async function handleCloudScanUpload() {
    const file = scanRef.current?.files?.[0];
    if (!file) return;
    setScanState("uploading");
    setScanError("");
    try {
      const evidence = await api.uploadCloudScanEvidence(threatModelId, file);
      setScanState("success");
      onUpdated(evidence);
      if (scanRef.current) scanRef.current.value = "";
    } catch (error) {
      setScanState("error");
      setScanError(error instanceof Error ? error.message : "Cloud scan upload failed");
    }
  }

  async function handleIacUpload() {
    const file = iacRef.current?.files?.[0];
    if (!file) return;
    setIacState("uploading");
    setIacError("");
    try {
      const evidence = await api.uploadIacEvidence(threatModelId, file, iacReference);
      setIacState("success");
      onUpdated(evidence);
      if (iacRef.current) iacRef.current.value = "";
    } catch (error) {
      setIacState("error");
      setIacError(error instanceof Error ? error.message : "IaC upload failed");
    }
  }

  async function handleRepositoryClear() {
    const evidence = await api.clearRepositoryEvidence(threatModelId);
    onUpdated(evidence);
    setRepoReference("");
    setRepoState("idle");
    setRepoError("");
    if (repoRef.current) repoRef.current.value = "";
  }

  async function handleCloudScanClear() {
    const evidence = await api.clearCloudScanEvidence(threatModelId);
    onUpdated(evidence);
    setScanState("idle");
    setScanError("");
    if (scanRef.current) scanRef.current.value = "";
  }

  async function handleIacClear() {
    const evidence = await api.clearIacEvidence(threatModelId);
    onUpdated(evidence);
    setIacReference("");
    setIacState("idle");
    setIacError("");
    if (iacRef.current) iacRef.current.value = "";
  }

  async function handleApplyIacToDfd() {
    setImportState("uploading");
    setImportError("");
    try {
      const result = await api.importIacIntoDfd(threatModelId, { mode: "merge" });
      setImportState("success");
      setLastImport(result);
      onImportedToDfd(result);
    } catch (error) {
      setImportState("error");
      setImportError(error instanceof Error ? error.message : "IaC import failed");
    }
  }

  async function handlePreviewRepositorySeeds() {
    setSeedState("uploading");
    setSeedError("");
    try {
      const preview = await api.previewRepositoryDfdSeeds(threatModelId);
      setSeedPreview(preview);
      setSelectedSeedIds(
        preview.suggestions
          .filter((suggestion) => suggestion.match_status === "new")
          .map((suggestion) => suggestion.suggestion_id)
      );
      setSeedState("success");
    } catch (error) {
      setSeedState("error");
      setSeedError(error instanceof Error ? error.message : "Could not preview repository DFD seeds");
    }
  }

  function toggleSeedSelection(suggestionId: string) {
    setSelectedSeedIds((current) =>
      current.includes(suggestionId)
        ? current.filter((id) => id !== suggestionId)
        : [...current, suggestionId]
    );
  }

  async function handleApplyRepositorySeeds() {
    if (selectedSeedIds.length === 0) {
      setSeedState("error");
      setSeedError("Select at least one new DFD seed to apply.");
      return;
    }
    setSeedState("uploading");
    setSeedError("");
    try {
      const result = await api.applyRepositoryDfdSeeds(threatModelId, {
        suggestion_ids: selectedSeedIds,
      });
      setLastSeedApply(result);
      setSeedState("success");
      setSeedPreview(null);
      setSelectedSeedIds([]);
      onImportedToDfd(result);
    } catch (error) {
      setSeedState("error");
      setSeedError(error instanceof Error ? error.message : "Could not apply repository DFD seeds");
    }
  }

  return (
    <section className="tm-section">
      <div className="tm-section-header">
        <div>
          <h3 style={{ margin: 0 }}>Environment Evidence</h3>
          <p>
            {collapsed
              ? evidenceSummary
              : "Optional repository, cloud posture, and IaC evidence improves semantic analysis without changing the DFD directly."}
          </p>
        </div>
        <button
          type="button"
          className="btn-export"
          onClick={() => setCollapsed((current) => !current)}
          aria-expanded={!collapsed}
          title={collapsed ? "Show environment evidence inputs and imported context" : "Hide environment evidence inputs and imported context"}
        >
          {collapsed ? "Expand" : "Collapse"}
        </button>
      </div>

      {collapsed ? null : (
        <>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: "16px",
        }}
      >
        <div
          style={{
            border: "1px solid #cbd5e1",
            borderRadius: "12px",
            padding: "16px",
            background: "#ffffff",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h4 style={{ margin: 0 }}>Repository / Codebase</h4>
            {repository && (
              <button className="btn-export" onClick={handleRepositoryClear} title="Remove the currently loaded repository evidence">
                Clear
              </button>
            )}
          </div>
          <p style={{ color: "#475569", fontSize: "0.92rem" }}>
            Pull a repository directly from GitHub, or upload a private-repo-safe archive or
            manifest bundle when you want to curate the scope manually.
          </p>
          <div style={{ marginTop: "12px", display: "grid", gap: "8px" }}>
            <label style={{ display: "grid", gap: "4px", fontSize: "0.9rem", color: "#334155" }}>
              GitHub auth mode
              <select
                value={githubTransport}
                onChange={(event) => setGithubTransport(event.target.value as "https" | "ssh")}
                disabled={repoState === "uploading"}
                title="Choose whether to fetch the repository using a GitHub token or an SSH key"
              >
                <option value="https">HTTPS token</option>
                <option value="ssh">SSH key</option>
              </select>
            </label>
            <input
              type="text"
              placeholder="GitHub repo URL, PR URL, or owner/repo"
              value={githubRepository}
              onChange={(event) => setGithubRepository(event.target.value)}
              disabled={repoState === "uploading"}
              title="Enter a GitHub repository URL, pull request URL, or owner/repo identifier"
            />
            <input
              type="text"
              placeholder="Branch, tag, or commit (optional)"
              value={githubRef}
              onChange={(event) => setGithubRef(event.target.value)}
              disabled={repoState === "uploading"}
              title="Optional branch, tag, or commit to pull instead of the default branch"
            />
            <input
              type="text"
              placeholder="Optional scope note or service path"
              value={repoReference}
              onChange={(event) => setRepoReference(event.target.value)}
              disabled={repoState === "uploading"}
              title="Optional note to record the service path, scope, or slice you imported"
            />
            {githubTransport === "https" ? (
              <input
                type="password"
                placeholder="GitHub token for private repos (used once, not stored)"
                value={githubToken}
                autoComplete="new-password"
                onChange={(event) => setGithubToken(event.target.value)}
                disabled={repoState === "uploading"}
                title="Optional GitHub token used one time for private repository access"
              />
            ) : (
              <textarea
                placeholder="SSH private key (optional if the server already has a GitHub SSH agent/deploy key)"
                value={githubSshPrivateKey}
                onChange={(event) => setGithubSshPrivateKey(event.target.value)}
                disabled={repoState === "uploading"}
                rows={7}
                style={{ resize: "vertical", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" }}
                title="Optional SSH private key used one time for private repository access"
              />
            )}
            <button
              className="btn-upload"
              onClick={handleGitHubImport}
              disabled={repoState === "uploading"}
              title="Fetch repository evidence directly from GitHub"
            >
              {repoState === "uploading" ? "Pulling repository..." : "Pull from GitHub"}
            </button>
            {repository?.connection?.provider === "github" && (
              <button
                className="btn-export"
                onClick={handleGitHubRefresh}
                disabled={repoState === "uploading"}
                title="Refresh repository evidence from the saved GitHub repo and ref"
              >
                {repoState === "uploading" ? "Refreshing repository..." : "Refresh saved GitHub connection"}
              </button>
            )}
            <p style={{ color: "#475569", fontSize: "0.85rem", margin: 0 }}>
              {githubTransport === "https"
                ? "Use a GitHub token with read access for private repos. ThreatGenix uses the token only for this fetch and does not store it."
                : "Use an SSH private key with read access to the repository, or leave the field blank to rely on the server's SSH agent/deploy key. ThreatGenix uses the key only for this fetch and does not store it."}
            </p>
          </div>
          <GuidanceBlock
            title="Private repo archive"
            body="Create a filtered archive locally and upload the zip or tarball."
            command={`git archive --format=zip --output threat-model-code-evidence.zip HEAD\n# monorepo slice\n# git archive --format=zip --output threat-model-code-evidence.zip HEAD backend frontend infra`}
          />
          <GuidanceBlock
            title="Manifest bundle"
            body="If the repo is too large, upload just the high-signal manifests and entrypoints."
            command={`zip threat-model-manifests.zip package.json pyproject.toml requirements.txt Dockerfile docker-compose.yml vercel.json app.py main.py`}
          />
          <div style={{ marginTop: "12px", display: "grid", gap: "8px" }}>
            <input
              ref={repoRef}
              type="file"
              accept=".zip,.tar,.gz,.tgz,.json,.toml,.txt,.md,.py,.js,.ts,.tsx,.yml,.yaml,.xml"
              disabled={repoState === "uploading"}
            />
            <button
              className="btn-upload"
              onClick={handleRepositoryUpload}
              disabled={repoState === "uploading"}
              title="Upload a repository archive or manifest bundle for code evidence"
            >
              {repoState === "uploading" ? "Parsing repository..." : "Upload repository evidence"}
            </button>
            {repoError && <p className="upload-error">Repository upload failed: {repoError}</p>}
          </div>
          {repository && (
            <div style={{ marginTop: "16px", display: "grid", gap: "10px" }}>
              <div><strong>Source:</strong> {repository.filename} ({repository.source_type})</div>
              {repository.connection?.provider === "github" && (
                <div
                  style={{
                    background: "#f8fafc",
                    border: "1px solid #dbe5f0",
                    borderRadius: "8px",
                    color: "#334155",
                    display: "grid",
                    gap: "4px",
                    padding: "10px",
                  }}
                >
                  <div>
                    <strong>GitHub connection:</strong> {repository.connection.repository}
                    {repository.connection.ref ? `@${repository.connection.ref}` : " default branch"}
                  </div>
                  <div><strong>Auth mode:</strong> {repository.connection.transport.toUpperCase()}</div>
                  <div><strong>Last synced:</strong> {formatSyncTime(repository.connection.last_synced_at)}</div>
                </div>
              )}
              {repository.reference && <div><strong>Reference:</strong> {repository.reference}</div>}
              <div><strong>Files parsed:</strong> {repository.file_count}</div>
              <div><strong>Languages</strong><PillList items={repository.languages} /></div>
              <div><strong>Frameworks</strong><PillList items={repository.frameworks} /></div>
              <div><strong>Entrypoints</strong><PillList items={repository.entrypoints} /></div>
              <div><strong>API routes</strong><PillList items={repository.api_routes} /></div>
              <div><strong>Webhook endpoints</strong><PillList items={repository.webhook_endpoints} /></div>
              <div><strong>Route auth guard map</strong><RouteAuthList entries={repository.route_auth_map} /></div>
              <div><strong>No detected auth guard</strong><PillList items={repository.unprotected_routes} /></div>
              <div><strong>Sensitive-data routes</strong><PillList items={repository.sensitive_routes} /></div>
              <div><strong>Routes with raw input access</strong><PillList items={repository.routes_with_raw_input} /></div>
              <div><strong>Correlated risky routes</strong><PillList items={repository.risky_routes} /></div>
              <div><strong>Auth surfaces</strong><PillList items={repository.auth_surfaces} /></div>
              <div><strong>Auth mechanisms</strong><PillList items={repository.auth_mechanisms} /></div>
              <div><strong>Data stores</strong><PillList items={repository.data_stores} /></div>
              <div><strong>Queues</strong><PillList items={repository.queues} /></div>
              <div><strong>Integrations</strong><PillList items={repository.external_integrations} /></div>
              <div><strong>Outbound calls</strong><PillList items={repository.outbound_calls} /></div>
              <div><strong>Deployment clues</strong><PillList items={repository.deployment_clues} /></div>
              <div><strong>Infrastructure resources</strong><PillList items={repository.infrastructure_resources} /></div>
              <div><strong>Sensitive paths</strong><PillList items={repository.security_sensitive_paths} /></div>
              {repository.warnings.length > 0 && (
                <div style={{ color: "#92400e" }}>
                  <strong>Warnings:</strong> {repository.warnings.join(" ")}
                </div>
              )}
              {(repository.dfd_seed_suggestions?.length ?? 0) > 0 && (
                <div
                  style={{
                    border: "1px solid #bfdbfe",
                    borderRadius: "10px",
                    background: "#eff6ff",
                    padding: "12px",
                    display: "grid",
                    gap: "10px",
                  }}
                >
                  <div>
                    <strong>Repository DFD seeds</strong>
                    <p style={{ margin: "4px 0 0", color: "#475569", fontSize: "0.88rem" }}>
                      Preview repository-derived components before adding them to the diagram.
                    </p>
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                    <button
                      type="button"
                      className="btn-upload"
                      onClick={handlePreviewRepositorySeeds}
                      disabled={seedState === "uploading"}
                      title="Preview repository-derived DFD components without changing the diagram"
                    >
                      {seedState === "uploading" ? "Previewing DFD seeds..." : "Preview DFD seeds"}
                    </button>
                    {seedPreview && seedPreview.unmatched_suggestion_count > 0 && (
                      <button
                        type="button"
                        className="btn-upload"
                        onClick={handleApplyRepositorySeeds}
                        disabled={seedState === "uploading" || selectedSeedIds.length === 0}
                        title="Apply selected repository-derived DFD components to the diagram"
                      >
                        Apply selected
                      </button>
                    )}
                  </div>
                  {seedError && <p className="upload-error">DFD seed action failed: {seedError}</p>}
                  {seedPreview && (
                    <div style={{ display: "grid", gap: "8px" }}>
                      <div style={{ color: "#334155", fontSize: "0.88rem" }}>
                        {seedPreview.unmatched_suggestion_count} new suggestion
                        {seedPreview.unmatched_suggestion_count === 1 ? "" : "s"} from{" "}
                        {seedPreview.suggestions.length} repo-derived seed
                        {seedPreview.suggestions.length === 1 ? "" : "s"} with{" "}
                        {seedPreview.inferred_flow_count} inferred flow
                        {seedPreview.inferred_flow_count === 1 ? "" : "s"} and{" "}
                        {seedPreview.inferred_boundary_count} boundary candidate
                        {seedPreview.inferred_boundary_count === 1 ? "" : "s"}.
                      </div>
                      {seedPreview.suggestions.map((suggestion) => {
                        const isMatched = suggestion.match_status === "matched_existing";
                        const checked = selectedSeedIds.includes(suggestion.suggestion_id);
                        return (
                          <label
                            key={suggestion.suggestion_id}
                            style={{
                              alignItems: "flex-start",
                              background: "#ffffff",
                              border: "1px solid #dbeafe",
                              borderRadius: "8px",
                              display: "grid",
                              gap: "6px",
                              gridTemplateColumns: "auto 1fr",
                              padding: "10px",
                            }}
                          >
                            <input
                              type="checkbox"
                              checked={checked}
                              disabled={isMatched}
                              onChange={() => toggleSeedSelection(suggestion.suggestion_id)}
                              title={isMatched ? "Already represented in the DFD" : "Select DFD seed to apply"}
                            />
                            <span style={{ display: "grid", gap: "4px" }}>
                              <span style={{ fontWeight: 700, color: "#0f172a" }}>
                                {suggestion.label} · {suggestion.node_type.replace("_", " ")}
                              </span>
                              <span style={{ color: "#475569", fontSize: "0.86rem" }}>
                                {isMatched
                                  ? `Already matched to ${suggestion.matched_node_name}.`
                                  : suggestion.rationale}
                              </span>
                              {suggestion.source_refs.length > 0 && (
                                <span style={{ color: "#64748b", fontSize: "0.82rem" }}>
                                  {suggestion.source_refs.slice(0, 2).join(" · ")}
                                </span>
                              )}
                            </span>
                          </label>
                        );
                      })}
                    </div>
                  )}
                  {lastSeedApply && (
                    <div
                      style={{
                        background: "#f8fafc",
                        border: "1px solid #cbd5e1",
                        borderRadius: "8px",
                        color: "#334155",
                        fontSize: "0.9rem",
                        padding: "10px",
                      }}
                    >
                      Applied {lastSeedApply.summary.created_nodes} repository DFD seed
                      {lastSeedApply.summary.created_nodes === 1 ? "" : "s"} and created{" "}
                      {lastSeedApply.summary.created_edges} flow
                      {lastSeedApply.summary.created_edges === 1 ? "" : "s"} and{" "}
                      {lastSeedApply.summary.created_boundaries} trust boundary
                      {lastSeedApply.summary.created_boundaries === 1 ? "" : "s"}.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        <div
          style={{
            border: "1px solid #cbd5e1",
            borderRadius: "12px",
            padding: "16px",
            background: "#ffffff",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h4 style={{ margin: 0 }}>Cloud Posture</h4>
            {cloudScan && (
              <button className="btn-export" onClick={handleCloudScanClear} title="Remove the currently loaded cloud posture evidence">
                Clear
              </button>
            )}
          </div>
          <p style={{ color: "#475569", fontSize: "0.92rem" }}>
            Upload a supported cloud posture scanner export so the model can reason about real exposure,
            IAM, logging, and encryption issues.
          </p>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
              gap: "12px",
              marginTop: "12px",
              marginBottom: "12px",
            }}
          >
            <div
              style={{
                border: "1px solid #dbe5f0",
                borderRadius: "10px",
                padding: "12px",
                background: "#f8fafc",
              }}
            >
              <div style={{ fontWeight: 700, color: "#0f172a", marginBottom: "6px" }}>
                Without cloud evidence
              </div>
              <div style={{ color: "#475569", fontSize: "0.88rem", lineHeight: 1.5 }}>
                The review can model internet-facing paths and privileged assets, but it cannot prove whether deployed cloud controls match the design.
              </div>
            </div>
            <div
              style={{
                border: "1px solid #bfdbfe",
                borderRadius: "10px",
                padding: "12px",
                background: cloudScan ? "#eff6ff" : "#ffffff",
              }}
            >
              <div style={{ fontWeight: 700, color: "#0f172a", marginBottom: "6px" }}>
                How cloud evidence changes the review
              </div>
              <ul style={{ margin: 0, paddingLeft: "18px", color: "#475569", fontSize: "0.88rem", lineHeight: 1.5 }}>
                {cloudImpactRows.map((row) => (
                  <li key={row}>{row}</li>
                ))}
              </ul>
            </div>
          </div>
          <GuidanceBlock
            title="Cloud posture JSON"
            body="Upload the approved scanner export for the applicable cloud account. Prowler OCSF JSON is supported as an import format."
            command={`prowler aws --output-formats json-ocsf --output-directory ./prowler-output\n# upload the resulting JSON file from prowler-output`}
          />
          <GuidanceBlock
            title="ScoutSuite results archive"
            body="ScoutSuite results.js or zipped results directories are also supported as import formats."
            command={`scout aws --report-dir ./scoutsuite-output\n# upload scoutsuite_results.js or zip -r scoutsuite-output.zip ./scoutsuite-output`}
          />
          <div style={{ marginTop: "12px", display: "grid", gap: "8px" }}>
            <input
              ref={scanRef}
              type="file"
              accept=".json,.js,.zip"
              disabled={scanState === "uploading"}
            />
            <button
              className="btn-upload"
              onClick={handleCloudScanUpload}
              disabled={scanState === "uploading"}
              title="Upload supported cloud posture scan evidence"
            >
              {scanState === "uploading" ? "Parsing cloud scan..." : "Upload cloud scan evidence"}
            </button>
            {scanError && <p className="upload-error">Cloud scan upload failed: {scanError}</p>}
          </div>
          {cloudScan && (
            <div style={{ marginTop: "16px", display: "grid", gap: "10px" }}>
              <div><strong>Source:</strong> {cloudScan.filename} ({cloudScan.provider})</div>
              <div><strong>Findings parsed:</strong> {cloudScan.finding_count}</div>
              <div><strong>Internet exposure</strong><PillList items={cloudScan.exposed_services} /></div>
              <div><strong>Identity risks</strong><PillList items={cloudScan.identity_risks} /></div>
              <div><strong>Encryption gaps</strong><PillList items={cloudScan.encryption_gaps} /></div>
              <div><strong>Logging gaps</strong><PillList items={cloudScan.logging_gaps} /></div>
              {cloudScan.high_signal_findings.length > 0 && (
                <div>
                  <strong>Top findings</strong>
                  <div style={{ marginTop: "8px", display: "grid", gap: "8px" }}>
                    {cloudScan.high_signal_findings.slice(0, 5).map((finding, index) => (
                      <div
                        key={`${finding.category}-${index}`}
                        style={{
                          background: "#f8fafc",
                          border: "1px solid #e2e8f0",
                          borderRadius: "8px",
                          padding: "10px",
                        }}
                      >
                        <div style={{ fontWeight: 700 }}>
                          {finding.severity} {finding.category}
                        </div>
                        <div style={{ color: "#475569", fontSize: "0.85rem", marginTop: "4px" }}>
                          {[finding.service, finding.resource, finding.source_finding_id]
                            .filter(Boolean)
                            .join(" / ")}
                        </div>
                        <div style={{ marginTop: "6px", fontSize: "0.9rem" }}>{finding.detail}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {cloudScan.warnings.length > 0 && (
                <div style={{ color: "#92400e" }}>
                  <strong>Warnings:</strong> {cloudScan.warnings.join(" ")}
                </div>
              )}
            </div>
          )}
        </div>

        <div
          style={{
            border: "1px solid #cbd5e1",
            borderRadius: "12px",
            padding: "16px",
            background: "#ffffff",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h4 style={{ margin: 0 }}>Infrastructure as Code</h4>
            {iacEvidence && (
              <button className="btn-export" onClick={handleIacClear} title="Remove the currently loaded infrastructure-as-code evidence">
                Clear
              </button>
            )}
          </div>
          <p style={{ color: "#475569", fontSize: "0.92rem" }}>
            Upload Terraform, CloudFormation, Kubernetes manifests, or a zipped infra bundle so
            ThreatGenix can validate the DFD against declared runtime resources and trust edges.
          </p>
          <GuidanceBlock
            title="Terraform / mixed infra bundle"
            body="Zip the infrastructure folder when you want ThreatGenix to parse multiple files together."
            command={`zip -r threat-model-iac.zip infra terraform kubernetes cloudformation\n# or upload a single main.tf / template.yaml / k8s manifest directly`}
          />
          <GuidanceBlock
            title="Reference"
            body="Use the optional reference to preserve the branch, stack, or environment being validated."
            command={`main\nproduction/networking\npayments-service@terraform/ca-central-1`}
          />
          <div style={{ marginTop: "12px", display: "grid", gap: "8px" }}>
            <input
              type="text"
              placeholder="Optional IaC reference (stack, branch, environment)"
              value={iacReference}
              onChange={(event) => setIacReference(event.target.value)}
              title="Optional stack, branch, or environment label to keep with this IaC evidence"
            />
            <input
              ref={iacRef}
              type="file"
              accept=".zip,.tar,.gz,.tgz,.tf,.tfvars,.json,.yaml,.yml,.template"
              disabled={iacState === "uploading"}
            />
            <button
              className="btn-upload"
              onClick={handleIacUpload}
              disabled={iacState === "uploading"}
              title="Upload Terraform, CloudFormation, Kubernetes, or mixed infrastructure evidence"
            >
              {iacState === "uploading" ? "Parsing IaC..." : "Upload IaC evidence"}
            </button>
            {iacError && <p className="upload-error">IaC upload failed: {iacError}</p>}
          </div>
          {iacEvidence && (
            <div style={{ marginTop: "16px", display: "grid", gap: "10px" }}>
              <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                <button
                  className="btn-upload"
                  onClick={handleApplyIacToDfd}
                  disabled={importState === "uploading"}
                  title="Merge discovered infrastructure resources into the current DFD"
                >
                  {importState === "uploading" ? "Applying to DFD..." : "Apply IaC to DFD"}
                </button>
              </div>
              {importError && <p className="upload-error">IaC import failed: {importError}</p>}
              {lastImport && (
                <div
                  style={{
                    background: "#f8fafc",
                    border: "1px solid #cbd5e1",
                    borderRadius: "8px",
                    padding: "10px",
                    fontSize: "0.9rem",
                    color: "#334155",
                  }}
                >
                  Imported {lastImport.summary.semantic_resource_count} semantic resources from{" "}
                  {lastImport.summary.imported_resource_count} discovered resources. Created{" "}
                  {lastImport.summary.created_nodes} nodes, updated {lastImport.summary.updated_nodes} nodes,
                  created {lastImport.summary.created_edges} flows, and created{" "}
                  {lastImport.summary.created_boundaries} boundaries.
                </div>
              )}
              <div><strong>Source:</strong> {iacEvidence.filename} ({iacEvidence.source_type})</div>
              {iacEvidence.reference && <div><strong>Reference:</strong> {iacEvidence.reference}</div>}
              <div><strong>Resources parsed:</strong> {iacEvidence.resource_count}</div>
              <div><strong>Resource types</strong><PillList items={iacEvidence.resource_types} /></div>
              <div><strong>Named resources</strong><PillList items={iacEvidence.resource_names} /></div>
              <div><strong>Public exposure signals</strong><PillList items={iacEvidence.public_exposure} /></div>
              <div><strong>IAM & trust bindings</strong><PillList items={iacEvidence.iam_bindings} /></div>
              <div><strong>Network paths</strong><PillList items={iacEvidence.network_paths} /></div>
              <div><strong>Secret references</strong><PillList items={iacEvidence.secret_refs} /></div>
              {iacEvidence.warnings.length > 0 && (
                <div style={{ color: "#92400e" }}>
                  <strong>Warnings:</strong> {iacEvidence.warnings.join(" ")}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {model.environment_context_summary && (
        <div
          style={{
            marginTop: "16px",
            background: "#f8fafc",
            border: "1px solid #cbd5e1",
            borderRadius: "12px",
            padding: "16px",
          }}
        >
          <h4 style={{ marginTop: 0 }}>Context Sent To AI Analysis</h4>
          <pre
            style={{
              margin: 0,
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              fontSize: "0.86rem",
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
            }}
          >
            {model.environment_context_summary}
          </pre>
        </div>
      )}
        </>
      )}
    </section>
  );
}

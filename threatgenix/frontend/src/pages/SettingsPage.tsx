import { useEffect, useState, useCallback } from "react";
import { api } from "../api/client";
import type { BYOKKeyResponse, LLMProviderHealth } from "../types/api";
import { useAuth } from "../auth/useAuth";
import ModelSelector from "../components/ModelSelector";

const BYOK_PROVIDERS = [
  { name: "anthropic", display_name: "Anthropic" },
  { name: "openai", display_name: "OpenAI" },
  { name: "openrouter", display_name: "OpenRouter" },
  { name: "gemini", display_name: "Google Gemini" },
  { name: "xai", display_name: "xAI (Grok)" },
  { name: "zai", display_name: "Z.ai" },
  { name: "perplexity", display_name: "Perplexity" },
] as const;

type TestStatus = "idle" | "testing" | "ok" | "error";

interface ProviderRowState {
  editing: boolean;
  keyInput: string;
  modelOverride: string;
  saving: boolean;
  testStatus: TestStatus;
  testDetail: string;
  deleting: boolean;
  actionError: string;
}

function initialRowState(): ProviderRowState {
  return {
    editing: false,
    keyInput: "",
    modelOverride: "",
    saving: false,
    testStatus: "idle",
    testDetail: "",
    deleting: false,
    actionError: "",
  };
}

export default function SettingsPage() {
  const { user, verifyEmail } = useAuth();
  const [storedKeys, setStoredKeys] = useState<BYOKKeyResponse[]>([]);
  const [providerHealth, setProviderHealth] = useState<LLMProviderHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [rowStates, setRowStates] = useState<Record<string, ProviderRowState>>({});
  const [verificationCode, setVerificationCode] = useState("");
  const [verificationStatus, setVerificationStatus] = useState<string | null>(null);
  const [verificationError, setVerificationError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  const loadKeys = useCallback(async () => {
    try {
      const [keysResult, healthResult] = await Promise.allSettled([
        api.getBYOKKeys(),
        api.getLLMProviderHealth(),
      ]);
      if (keysResult.status === "fulfilled") {
        setStoredKeys(keysResult.value);
      }
      if (healthResult.status === "fulfilled") {
        setProviderHealth(healthResult.value);
      }
    } catch {
      // best-effort
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadKeys();
  }, [loadKeys]);

  function getRowState(provider: string): ProviderRowState {
    return rowStates[provider] || initialRowState();
  }

  function updateRow(provider: string, updates: Partial<ProviderRowState>) {
    setRowStates((prev) => ({
      ...prev,
      [provider]: { ...(prev[provider] || initialRowState()), ...updates },
    }));
  }

  function getStoredKey(provider: string): BYOKKeyResponse | undefined {
    return storedKeys.find((k) => k.provider === provider);
  }

  async function handleSave(provider: string) {
    const row = getRowState(provider);
    if (!row.keyInput.trim()) return;

    updateRow(provider, { saving: true, actionError: "" });
    try {
      await api.upsertBYOKKey(provider, {
        api_key: row.keyInput.trim(),
        model_override: row.modelOverride.trim() || undefined,
      });
      updateRow(provider, {
        saving: false,
        editing: false,
        keyInput: "",
        modelOverride: "",
        testStatus: "idle",
        actionError: "",
      });
      await loadKeys();
    } catch (caught) {
      updateRow(provider, {
        saving: false,
        actionError: caught instanceof Error ? caught.message : "Failed to save provider key.",
      });
    }
  }

  async function handleDelete(provider: string) {
    if (!confirm(`Remove your stored key for ${provider}?`)) return;
    updateRow(provider, { deleting: true, actionError: "" });
    try {
      await api.deleteBYOKKey(provider);
      updateRow(provider, { deleting: false, testStatus: "idle", testDetail: "", actionError: "" });
      await loadKeys();
    } catch (caught) {
      updateRow(provider, {
        deleting: false,
        actionError: caught instanceof Error ? caught.message : "Failed to delete provider key.",
      });
    }
  }

  async function handleTest(provider: string) {
    updateRow(provider, { testStatus: "testing", testDetail: "", actionError: "" });
    try {
      const result = await api.testBYOKKey(provider);
      updateRow(provider, {
        testStatus: result.status === "ok" ? "ok" : "error",
        testDetail: result.detail || "",
      });
    } catch (caught) {
      updateRow(provider, {
        testStatus: "error",
        testDetail: caught instanceof Error ? caught.message : "Request failed",
      });
    }
  }

  async function handleVerifyEmail() {
    if (!user?.email || !verificationCode.trim()) return;
    setVerifying(true);
    setVerificationStatus(null);
    setVerificationError(null);
    try {
      const result = await verifyEmail(user.email, verificationCode.trim());
      setVerificationCode("");
      setVerificationStatus(result.detail);
    } catch (caught) {
      setVerificationError(caught instanceof Error ? caught.message : "Email verification failed");
    } finally {
      setVerifying(false);
    }
  }

  if (loading) {
    return (
      <div style={{ padding: "2rem", maxWidth: 800, margin: "0 auto" }}>
        <h1 style={{ fontSize: "1.5rem", marginBottom: "1rem" }}>Settings</h1>
        <p style={{ color: "var(--c-text-muted, #94a3b8)" }}>Loading...</p>
      </div>
    );
  }

  return (
    <div style={{ padding: "2rem", maxWidth: 960, margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.5rem", marginBottom: "0.25rem" }}>Settings</h1>
      <p style={{ color: "var(--c-text-muted, #94a3b8)", marginBottom: "1.5rem", fontSize: "0.875rem" }}>
        Manage account trust, organization context, SaaS entitlements, and AI provider keys.
      </p>

      <section className="settings-saas-grid" aria-label="SaaS account context">
        <article className="settings-saas-card">
          <span>Workspace</span>
          <strong>{user?.organization_name || "Personal pilot workspace"}</strong>
          <p>
            {user?.organization_id
              ? "Models, evidence, and report templates are scoped to this organization."
              : "Join or create an organization before relying on shared governance, billing, and team audit workflows."}
          </p>
        </article>
        <article className="settings-saas-card">
          <span>Plan and Entitlements</span>
          <strong>{user?.organization_id ? "Pilot organization" : "Personal pilot"}</strong>
          <p>
            Upgrade-gated actions now explain the missing entitlement. Hosted live validation remains disabled until the managed isolated runner is available.
          </p>
        </article>
        <article className="settings-saas-card">
          <span>Email Trust</span>
          <strong>{user?.email_verified === false ? "Verification pending" : "Verified"}</strong>
          {user?.email_verified === false ? (
            <div className="settings-verify-form">
              <p>Enter the six-character code sent during registration.</p>
              <div>
                <input
                  value={verificationCode}
                  onChange={(event) => setVerificationCode(event.target.value.toUpperCase())}
                  placeholder="ABC123"
                  maxLength={6}
                  aria-label="Verification code"
                />
                <button
                  type="button"
                  className="btn-create"
                  onClick={() => void handleVerifyEmail()}
                  disabled={verifying || verificationCode.trim().length !== 6}
                >
                  {verifying ? "Verifying..." : "Verify"}
                </button>
              </div>
              {verificationStatus ? <p className="settings-status-success">{verificationStatus}</p> : null}
              {verificationError ? <p className="settings-status-error">{verificationError}</p> : null}
            </div>
          ) : (
            <p>{user?.email || "Account email"} is ready for recovery and audit notifications.</p>
          )}
        </article>
      </section>

      {providerHealth ? (
        <section className="settings-provider-health" aria-label="AI runtime health">
          <div>
            <span>AI Runtime Health</span>
            <strong>{providerHealth.status.charAt(0).toUpperCase() + providerHealth.status.slice(1)}</strong>
            <p>
              Active: {providerHealth.active_provider} / {providerHealth.active_model}
            </p>
          </div>
          <div>
            <span>AI Residency</span>
            <strong>
              {providerHealth.external_ai_providers_enabled
                ? "External Opt-In"
                : providerHealth.canada_residency_enforced
                  ? "Canada Enforced"
                  : "Needs Review"}
            </strong>
            <p>
              {providerHealth.bedrock_region} / {providerHealth.bedrock_model_id}
            </p>
          </div>
          <div>
            <span>Configured Providers</span>
            <strong>{providerHealth.configured_provider_count}</strong>
            <p>{providerHealth.server_provider} server default</p>
          </div>
          {providerHealth.warnings.length ? (
            <ul>
              {providerHealth.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          ) : (
            <p className="settings-status-success">Provider posture is ready for pilot QA.</p>
          )}
        </section>
      ) : null}

      <section className="settings-provider-switch" aria-label="Active AI provider controls">
        <div>
          <span>Active AI Provider</span>
          <strong>Provider and model selection</strong>
          <p>
            Choose the runtime used for AI-assisted generation, review, and explanation workflows.
          </p>
        </div>
        <ModelSelector idPrefix="settings-llm" label="Active AI Provider" />
      </section>

      <h2 style={{ fontSize: "1.125rem", marginBottom: "1rem" }}>AI Provider Keys</h2>

      <div style={{ border: "1px solid var(--c-border, #334155)", borderRadius: 8, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.875rem" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid var(--c-border, #334155)", background: "var(--c-bg-subtle, #1e293b)" }}>
              <th style={{ textAlign: "left", padding: "0.75rem 1rem", fontWeight: 600 }}>Provider</th>
              <th style={{ textAlign: "left", padding: "0.75rem 1rem", fontWeight: 600 }}>Status</th>
              <th style={{ textAlign: "left", padding: "0.75rem 1rem", fontWeight: 600 }}>Key</th>
              <th style={{ textAlign: "right", padding: "0.75rem 1rem", fontWeight: 600 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {BYOK_PROVIDERS.map((p) => {
              const stored = getStoredKey(p.name);
              const row = getRowState(p.name);

              return (
                <tr key={p.name} style={{ borderBottom: "1px solid var(--c-border, #334155)" }}>
                  <td style={{ padding: "0.75rem 1rem", fontWeight: 500 }}>{p.display_name}</td>
                  <td style={{ padding: "0.75rem 1rem" }}>
                    {stored ? (
                      <span style={{ color: "var(--c-success, #22c55e)", fontWeight: 500 }}>Key stored</span>
                    ) : (
                      <span style={{ color: "var(--c-text-muted, #94a3b8)" }}>Not set</span>
                    )}
                  </td>
                  <td style={{ padding: "0.75rem 1rem" }}>
                    {row.editing ? (
                      <div style={{ display: "flex", flexDirection: "column", gap: "0.375rem" }}>
                        <input
                          type="password"
                          placeholder="API key"
                          value={row.keyInput}
                          onChange={(e) => updateRow(p.name, { keyInput: e.target.value })}
                          style={{
                            padding: "0.375rem 0.5rem",
                            border: "1px solid var(--c-border, #334155)",
                            borderRadius: 4,
                            background: "var(--c-bg, #0f172a)",
                            color: "var(--c-text, #e2e8f0)",
                            fontSize: "0.8125rem",
                            width: "100%",
                            minWidth: 200,
                          }}
                        />
                        <input
                          type="text"
                          placeholder="Model override (optional)"
                          value={row.modelOverride}
                          onChange={(e) => updateRow(p.name, { modelOverride: e.target.value })}
                          style={{
                            padding: "0.375rem 0.5rem",
                            border: "1px solid var(--c-border, #334155)",
                            borderRadius: 4,
                            background: "var(--c-bg, #0f172a)",
                            color: "var(--c-text, #e2e8f0)",
                            fontSize: "0.8125rem",
                            width: "100%",
                          }}
                        />
                      </div>
                    ) : stored ? (
                      <code style={{ fontSize: "0.8125rem", color: "var(--c-text-muted, #94a3b8)" }}>
                        {stored.masked_key}
                      </code>
                    ) : (
                      <span style={{ color: "var(--c-text-muted, #94a3b8)" }}>--</span>
                    )}
                  </td>
                  <td style={{ padding: "0.75rem 1rem", textAlign: "right", whiteSpace: "nowrap" }}>
                    {row.editing ? (
                      <div style={{ display: "flex", gap: "0.375rem", justifyContent: "flex-end" }}>
                        <button
                          onClick={() => handleSave(p.name)}
                          disabled={row.saving || !row.keyInput.trim()}
                          style={{
                            padding: "0.375rem 0.75rem",
                            borderRadius: 4,
                            border: "none",
                            background: "var(--c-primary, #3b82f6)",
                            color: "#fff",
                            cursor: "pointer",
                            fontSize: "0.8125rem",
                            opacity: row.saving || !row.keyInput.trim() ? 0.5 : 1,
                          }}
                        >
                          {row.saving ? "Saving..." : "Save"}
                        </button>
                        <button
                          onClick={() => updateRow(p.name, { editing: false, keyInput: "", modelOverride: "" })}
                          style={{
                            padding: "0.375rem 0.75rem",
                            borderRadius: 4,
                            border: "1px solid var(--c-border, #334155)",
                            background: "transparent",
                            color: "var(--c-text, #e2e8f0)",
                            cursor: "pointer",
                            fontSize: "0.8125rem",
                          }}
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <div style={{ display: "flex", gap: "0.375rem", justifyContent: "flex-end", alignItems: "center" }}>
                        {stored && (
                          <>
                            <button
                              onClick={() => handleTest(p.name)}
                              disabled={row.testStatus === "testing"}
                              title="Test this key"
                              style={{
                                padding: "0.375rem 0.75rem",
                                borderRadius: 4,
                                border: "1px solid var(--c-border, #334155)",
                                background: "transparent",
                                color: "var(--c-text, #e2e8f0)",
                                cursor: "pointer",
                                fontSize: "0.8125rem",
                                opacity: row.testStatus === "testing" ? 0.5 : 1,
                              }}
                            >
                              {row.testStatus === "testing"
                                ? "Testing..."
                                : row.testStatus === "ok"
                                  ? "Passed"
                                  : row.testStatus === "error"
                                    ? "Failed"
                                    : "Test"}
                            </button>
                            {row.testStatus === "ok" && (
                              <span style={{ color: "var(--c-success, #22c55e)", fontWeight: 700, fontSize: "1rem" }} title="Key is valid">
                                &#10003;
                              </span>
                            )}
                            {row.testStatus === "error" && (
                              <span
                                style={{ color: "var(--c-danger, #ef4444)", fontWeight: 700, fontSize: "1rem", cursor: "help" }}
                                title={row.testDetail || "Test failed"}
                              >
                                &#10007;
                              </span>
                            )}
                            <button
                              onClick={() => handleDelete(p.name)}
                              disabled={row.deleting}
                              title="Remove this key"
                              style={{
                                padding: "0.375rem 0.75rem",
                                borderRadius: 4,
                                border: "1px solid var(--c-danger, #ef4444)",
                                background: "transparent",
                                color: "var(--c-danger, #ef4444)",
                                cursor: "pointer",
                                fontSize: "0.8125rem",
                                opacity: row.deleting ? 0.5 : 1,
                              }}
                            >
                              {row.deleting ? "..." : "Delete"}
                            </button>
                          </>
                        )}
                        <button
                          onClick={() =>
                            updateRow(p.name, {
                              editing: true,
                              modelOverride: stored?.model_override || "",
                            })
                          }
                          style={{
                            padding: "0.375rem 0.75rem",
                            borderRadius: 4,
                            border: "none",
                            background: stored ? "var(--c-bg-subtle, #1e293b)" : "var(--c-primary, #3b82f6)",
                            color: stored ? "var(--c-text, #e2e8f0)" : "#fff",
                            cursor: "pointer",
                            fontSize: "0.8125rem",
                          }}
                        >
                          {stored ? "Update" : "Add Key"}
                        </button>
                      </div>
                    )}
                    {row.actionError ? (
                      <p className="settings-status-error" style={{ margin: "0.5rem 0 0" }}>
                        {row.actionError}
                      </p>
                    ) : null}
                    {row.testStatus === "error" && row.testDetail ? (
                      <p className="settings-status-error" style={{ margin: "0.5rem 0 0" }}>
                        {row.testDetail}
                      </p>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p style={{ marginTop: "1rem", fontSize: "0.8125rem", color: "var(--c-text-muted, #94a3b8)" }}>
        Keys are encrypted at rest. AWS Bedrock uses IAM credentials and is not configurable here.
      </p>
    </div>
  );
}

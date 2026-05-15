import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "./client";

describe("api.getThreatIntel", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("normalizes degraded threat-intel payloads from older or unavailable backends", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        local_severity: "Critical",
        unavailable_reason: "pgvector type unavailable",
        semantic_matches_inferred: false,
        scan_cve_ids: [],
        severity_signals: [],
        attack_techniques: [],
        attack_patterns: [],
        weaknesses: [],
        advisories: [],
        kev_entries: [],
        cri_controls: [],
      }),
    });

    vi.stubGlobal("fetch", fetchMock);

    const intel = await api.getThreatIntel("tm-1", "th-1");

    expect(fetchMock).toHaveBeenCalledWith("/api/threat-models/tm-1/threats/th-1/intel", {
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer test-token",
      },
    });
    expect(intel.epss_entries).toEqual([]);
    expect(intel.dependency_matches).toEqual([]);
    expect(intel.contextual_assessment).toEqual({
      threat_classes: [],
      confidence: "Low",
      ssvc_decision: "Track",
      why_applicable: [],
      what_to_verify: [],
      decision_rationale: [],
    });
  });
});

describe("api.importRepositoryEvidenceFromGitHub", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("keeps the auth header when no one-time GitHub token is provided", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        repository_evidence: null,
        cloud_scan_evidence: null,
        iac_evidence: null,
        environment_context_summary: null,
      }),
    });

    vi.stubGlobal("fetch", fetchMock);

    await api.importRepositoryEvidenceFromGitHub("tm-1", {
      repository: "octocat/Hello-World",
      transport: "https",
      ref: "refs/pull/123/head",
      reference: "Pull request #123",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/threat-models/tm-1/environment/repository/github",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer test-token",
        },
        body: JSON.stringify({
          repository: "octocat/Hello-World",
          transport: "https",
          ref: "refs/pull/123/head",
          reference: "Pull request #123",
        }),
      }
    );
  });

  it("adds the one-time GitHub token header without changing the request body", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        repository_evidence: null,
        cloud_scan_evidence: null,
        iac_evidence: null,
        environment_context_summary: null,
      }),
    });

    vi.stubGlobal("fetch", fetchMock);

    await api.importRepositoryEvidenceFromGitHub(
      "tm-private",
      {
        repository: "example-org/private-app",
        transport: "https",
        ref: "main",
        reference: "Repo/Application Review",
      },
      "github_pat_private",
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/threat-models/tm-private/environment/repository/github",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer test-token",
          "X-GitHub-Token": "github_pat_private",
        },
        body: JSON.stringify({
          repository: "example-org/private-app",
          transport: "https",
          ref: "main",
          reference: "Repo/Application Review",
        }),
      },
    );
    expect(fetchMock.mock.calls[0]?.[1]?.body).not.toContain("github_pat_private");
  });
});

describe("api.acceptThreatModelReviewFindingRisk", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts governed risk-acceptance metadata to the finding endpoint", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ id: "finding-1", review_status: "accepted" }),
    });

    vi.stubGlobal("fetch", fetchMock);

    await api.acceptThreatModelReviewFindingRisk(
      "tm-1",
      "application_review_finding",
      "model:repository-evidence",
      {
        accepted_by: "Priya Reviewer",
        expires_at: "2026-06-01T00:00:00Z",
        acceptance_rationale: "Accepted until repository access is approved.",
        compensating_control: "Manual reviewer attestation.",
      },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/threat-models/tm-1/review-findings/application_review_finding/model%3Arepository-evidence/risk-acceptance",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer test-token",
        },
        body: JSON.stringify({
          accepted_by: "Priya Reviewer",
          expires_at: "2026-06-01T00:00:00Z",
          acceptance_rationale: "Accepted until repository access is approved.",
          compensating_control: "Manual reviewer attestation.",
        }),
      },
    );
  });
});

describe("api.createThreatModelAgentRemediationConnectorTicket", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts connector ticket requests to the confirmed provider endpoint", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        generated_at: "2026-05-01T12:00:00Z",
        system_name: "Payments Platform",
        provider: "github_issue",
        created_ticket_count: 1,
        updated_finding_ids: ["finding-1"],
        external_ticket_id: "#42",
        external_ticket_url: "https://github.com/acme/app/issues/42",
        callback_url: "https://threatgenix.vercel.app/api/callback",
        callback_payload_template: {},
        callback_security_scheme: "hmac_sha256_v1",
        callback_required_headers: {
          "X-SSR-Webhook-Signature": "sha256=<hmac>",
        },
        callback_signature_base_string: "timestamp + '.' + nonce + '.' + raw_request_body",
        plan: {
          generated_at: "2026-05-01T12:00:00Z",
          system_name: "Payments Platform",
          current_decision: "fix_now",
          loop_status: "ready",
          summary: "ready",
          actions: [],
          action_history: [],
          rerun_instructions: [],
          plan_markdown: "",
        },
      }),
    });

    vi.stubGlobal("fetch", fetchMock);

    await api.createThreatModelAgentRemediationConnectorTicket("tm-1", {
      action_id: "finding:remediation_note",
      provider: "github_issue",
      confirmed: true,
      access_token: "ghp_customer_owned",
      github_repository: "acme/app",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/threat-models/tm-1/agent/remediation-plan/tickets/connectors",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer test-token",
        },
        body: JSON.stringify({
          action_id: "finding:remediation_note",
          provider: "github_issue",
          confirmed: true,
          access_token: "ghp_customer_owned",
          github_repository: "acme/app",
        }),
      },
    );
  });

  it("posts signed provider callback tests to the dry-run endpoint", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        generated_at: "2026-05-01T12:00:00Z",
        system_name: "Payments Platform",
        provider: "github",
        callback_security_status: "verified",
        nonce_status: "accepted",
        normalized_provider_event: "issue_evidence",
        action_id: "finding:remediation_note",
        finding_id: "finding",
        action_title: "Fix finding",
        source_object_type: "threat",
        source_object_id: "threat-1",
        external_ticket_id: "acme/app#42",
        pull_request_url: null,
        commit_sha: null,
        evidence_url: "https://github.com/acme/app/issues/42",
        evidence_summary: "GitHub issue closed: Fix finding",
        next_step: "verified",
        plan: {
          generated_at: "2026-05-01T12:00:00Z",
          system_name: "Payments Platform",
          current_decision: "fix_now",
          loop_status: "ready",
          summary: "ready",
          actions: [],
          action_history: [],
          rerun_instructions: [],
          plan_markdown: "",
        },
      }),
    });

    vi.stubGlobal("fetch", fetchMock);

    await api.testThreatModelAgentRemediationProviderWebhook("tm-1", "github", {
      provider: "github",
      payload_text: "{\"issue\":{\"body\":\"action_id: finding:remediation_note\"}}",
      headers: {
        "X-SSR-Webhook-Timestamp": "1700000000",
        "X-SSR-Webhook-Nonce": "nonce-1",
        "X-SSR-Webhook-Signature": "sha256=abc123",
      },
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/threat-models/tm-1/agent/remediation-plan/webhooks/providers/github/test",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer test-token",
        },
        body: JSON.stringify({
          provider: "github",
          payload_text:
            "{\"issue\":{\"body\":\"action_id: finding:remediation_note\"}}",
          headers: {
            "X-SSR-Webhook-Timestamp": "1700000000",
            "X-SSR-Webhook-Nonce": "nonce-1",
            "X-SSR-Webhook-Signature": "sha256=abc123",
          },
        }),
      },
    );
  });
});

describe("SaaS entitlement errors", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("turns plan-gated API failures into upgrade-oriented copy", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      text: async () => JSON.stringify({ detail: "Your plan does not include this feature" }),
    }));

    await expect(api.generateReport("tm-1")).rejects.toThrow(
      "Upgrade required: Your plan does not include this feature."
    );
  });
});

describe("API validation errors", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("surfaces Pydantic validation messages without raw JSON", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      text: async () => JSON.stringify({
        detail: [
          {
            type: "string_too_long",
            loc: ["body", "description"],
            msg: "String should have at most 500 characters",
          },
        ],
      }),
    }));

    await expect(api.createThreatModel({
      system_name: "Large design",
      description: "x".repeat(600),
      data_classification: "Restricted",
    })).rejects.toThrow("422: String should have at most 500 characters");
  });
});

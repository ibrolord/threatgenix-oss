import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const hash = "d".repeat(64);

const review = {
  id: "review-1",
  tenant_key: "user:browser@example.com",
  owner_id: "owner-1",
  organization_id: null,
  threat_model_id: "tm-1",
  parent_review_id: null,
  review_lineage_id: "review-1",
  app_name: "ExampleApp",
  invocation_surface: "cli",
  input_kind: "diff",
  status: "completed",
  decision: "verify",
  commit_sha: "abc123",
  bundle_hash: null,
  scope_fingerprint: "a".repeat(64),
  idempotency_key: "review-key",
  requested_tools: ["semgrep"],
  scope: {},
  context: {},
  policy: {},
  result_summary: "High-severity scanner evidence needs supporting context.",
  error_message: null,
  created_at: "2026-05-01T00:00:00Z",
  updated_at: "2026-05-01T00:00:00Z",
};

const contextEntry = {
  id: "entry-1",
  review_id: "review-1",
  source_type: "scan_finding",
  source_object_id: "finding-1",
  item_type: "scanner_finding",
  title: "Sensitive export route is missing authorization",
  body: "severity=high missing authorization sensitive customer export",
  keywords: ["severity=high", "authorization"],
  facets: { severity: "high" },
  retrieval_text: "severity=high missing authorization sensitive customer export",
  source_refs: [{ type: "path", path: "apps/api/users.py:42" }],
  content_hash: hash,
  status: "active",
  stale_reason: null,
  created_at: "2026-05-01T00:00:00Z",
  updated_at: "2026-05-01T00:00:00Z",
};

const packet = {
  version: "threatgenix_context_packet_v1",
  review_id: "review-1",
  app_name: "ExampleApp",
  commit_sha: "abc123",
  deterministic_decision: "verify",
  policy: {},
  evidence_snapshot_hash: "f".repeat(64),
  entries: [
    {
      entry_id: "entry-1",
      item_type: "scanner_finding",
      title: contextEntry.title,
      untrusted_text:
        "[UNTRUSTED_REVIEW_CONTEXT_BEGIN]\nseverity=high\n[UNTRUSTED_REVIEW_CONTEXT_END]",
      source_refs: contextEntry.source_refs,
      content_hash: hash,
    },
  ],
  missing_evidence: ["No cloud exposure evidence was indexed."],
};

async function mockApplicationReviewApis(page: Page) {
  await page.addInitScript(() => {
    window.localStorage.setItem("tg_token", "mock-token");
  });
  await page.route("**/api/auth/me", async (route) => {
    await route.fulfill({
      json: {
        id: "user-1",
        email: "browser@example.com",
        full_name: "Browser QA",
        role: "analyst",
        is_active: true,
        report_template_library: [],
      },
    });
  });
  await page.route("**/api/reviews/review-1/artifact", async (route) => {
    await route.fulfill({
      json: {
        review,
        web_url: "http://127.0.0.1:5173/reviews/review-1",
        decision_record: {
          decision: "verify",
          reason: review.result_summary,
          evidence_snapshot_hash: "e".repeat(64),
          decision_engine_version: "appsec-decision-v1.0.0",
          decision_trace: ["engine:appsec-decision-v1.0.0"],
        },
        raw_evidence: [contextEntry],
        raw_evidence_count: 1,
        has_stale_evidence: false,
        missing_evidence: [],
        source_ref_count: 1,
        evidence_chains: [
          {
            chain_id: "chain:dddddddddddddddd",
            title: contextEntry.title,
            item_type: "scanner_finding",
            status: "active",
            stale_reason: null,
            content_hash: hash,
            source_refs: contextEntry.source_refs,
            steps: [
              {
                step_type: "context_entry",
                label: `scanner_finding: ${contextEntry.title}`,
                source_ref: null,
                content_hash: hash,
              },
              {
                step_type: "source_ref",
                label: "path: apps/api/users.py:42",
                source_ref: contextEntry.source_refs[0],
                content_hash: hash,
              },
            ],
          },
        ],
        graph_slice: {
          nodes: [
            {
              id: "review:review-1",
              label: "ExampleApp",
              node_type: "review",
              evidence_hashes: [],
              status: "completed",
            },
            {
              id: "evidence:dddddddddddddddd",
              label: contextEntry.title,
              node_type: "scanner_finding",
              evidence_hashes: [hash],
              status: "active",
            },
          ],
          edges: [
            {
              source: "review:review-1",
              target: "evidence:dddddddddddddddd",
              relationship: "contains_evidence",
              evidence_hashes: [hash],
            },
          ],
          missing_context: [],
        },
        fix_plan: [
          {
            title: "Resolve cited scanner finding",
            action: "Patch the affected code or attach proof that the scanner signal is not exploitable.",
            verification: "Rerun the review and confirm the decision changes.",
            cited_content_hashes: [hash],
            source_refs: contextEntry.source_refs,
          },
        ],
        accepted_risks: [],
        rerun_history: [
          {
            review_id: "review-1",
            parent_review_id: null,
            status: "completed",
            decision: "verify",
            commit_sha: "abc123",
            evidence_snapshot_hash: "e".repeat(64),
            updated_at: "2026-05-01T00:00:00Z",
          },
        ],
        redacted: true,
      },
    });
  });
  await page.route("**/api/reviews/review-1/context-index/search?**", async (route) => {
    await route.fulfill({
      json: { review_id: "review-1", query: "", results: [contextEntry] },
    });
  });
  await page.route("**/api/reviews/review-1/context-packet?**", async (route) => {
    await route.fulfill({ json: packet });
  });
  await page.route("**/api/reviews/review-1/ai-explanation?**", async (route) => {
    await route.fulfill({
      json: {
        review_id: "review-1",
        packet,
        output: {
          summary: "Deterministic decision is verify. Grounded evidence includes export route evidence.",
          proposed_decision: "verify",
          cited_content_hashes: [hash],
          fix_plan: [],
        },
        validation: { valid: true, errors: [] },
        explanation_status: "ready",
        prompt_contract: ["Do not change deterministic decision."],
      },
    });
  });
  await page.route("**/api/agent/reviews/review-1/status", async (route) => {
    await route.fulfill({
      json: {
        review,
        web_url: "http://127.0.0.1:5173/reviews/review-1",
        api_status_url: "http://127.0.0.1:5173/api/agent/reviews/review-1/status",
        terminal_commands: [],
        agent_tools: [],
      },
    });
  });
  await page.route("**/api/reviews/review-1", async (route) => {
    await route.fulfill({ json: review });
  });
  await page.route((url) => url.pathname.startsWith("/api/"), async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/api/auth/me") {
      await route.fulfill({
        json: {
          id: "user-1",
          email: "browser@example.com",
          full_name: "Browser QA",
          role: "analyst",
          is_active: true,
          report_template_library: [],
        },
      });
      return;
    }
    if (url.pathname === "/api/reviews/review-1") {
      await route.fulfill({ json: review });
      return;
    }
    if (url.pathname === "/api/reviews/review-1/artifact") {
      await route.fulfill({
        json: {
          review,
          web_url: "http://127.0.0.1:5173/reviews/review-1",
          decision_record: {
            decision: "verify",
            reason: review.result_summary,
            evidence_snapshot_hash: "e".repeat(64),
            decision_engine_version: "appsec-decision-v1.0.0",
            decision_trace: ["engine:appsec-decision-v1.0.0"],
          },
          raw_evidence: [contextEntry],
          raw_evidence_count: 1,
          has_stale_evidence: false,
          missing_evidence: [],
          source_ref_count: 1,
          evidence_chains: [
            {
              chain_id: "chain:dddddddddddddddd",
              title: contextEntry.title,
              item_type: "scanner_finding",
              status: "active",
              stale_reason: null,
              content_hash: hash,
              source_refs: contextEntry.source_refs,
              steps: [
                {
                  step_type: "context_entry",
                  label: `scanner_finding: ${contextEntry.title}`,
                  source_ref: null,
                  content_hash: hash,
                },
                {
                  step_type: "source_ref",
                  label: "path: apps/api/users.py:42",
                  source_ref: contextEntry.source_refs[0],
                  content_hash: hash,
                },
              ],
            },
          ],
          graph_slice: {
            nodes: [
              {
                id: "review:review-1",
                label: "ExampleApp",
                node_type: "review",
                evidence_hashes: [],
                status: "completed",
              },
              {
                id: "evidence:dddddddddddddddd",
                label: contextEntry.title,
                node_type: "scanner_finding",
                evidence_hashes: [hash],
                status: "active",
              },
            ],
            edges: [
              {
                source: "review:review-1",
                target: "evidence:dddddddddddddddd",
                relationship: "contains_evidence",
                evidence_hashes: [hash],
              },
            ],
            missing_context: [],
          },
          fix_plan: [
            {
              title: "Resolve cited scanner finding",
              action:
                "Patch the affected code or attach proof that the scanner signal is not exploitable.",
              verification: "Rerun the review and confirm the decision changes.",
              cited_content_hashes: [hash],
              source_refs: contextEntry.source_refs,
            },
          ],
          accepted_risks: [],
          rerun_history: [
            {
              review_id: "review-1",
              parent_review_id: null,
              status: "completed",
              decision: "verify",
              commit_sha: "abc123",
              evidence_snapshot_hash: "e".repeat(64),
              updated_at: "2026-05-01T00:00:00Z",
            },
          ],
          redacted: true,
        },
      });
      return;
    }
    if (url.pathname === "/api/reviews/review-1/context-index/search") {
      await route.fulfill({
        json: { review_id: "review-1", query: "", results: [contextEntry] },
      });
      return;
    }
    if (url.pathname === "/api/reviews/review-1/context-packet") {
      await route.fulfill({ json: packet });
      return;
    }
    if (url.pathname === "/api/reviews/review-1/ai-explanation") {
      await route.fulfill({
        json: {
          review_id: "review-1",
          packet,
          output: {
            summary:
              "Deterministic decision is verify. Grounded evidence includes export route evidence.",
            proposed_decision: "verify",
            cited_content_hashes: [hash],
            fix_plan: [],
          },
          validation: { valid: true, errors: [] },
          explanation_status: "ready",
          prompt_contract: ["Do not change deterministic decision."],
        },
      });
      return;
    }
    if (url.pathname === "/api/agent/reviews/review-1/status") {
      await route.fulfill({
        json: {
          review,
          web_url: "http://127.0.0.1:5173/reviews/review-1",
          api_status_url: "http://127.0.0.1:5173/api/agent/reviews/review-1/status",
          terminal_commands: [],
          agent_tools: [],
        },
      });
      return;
    }
    await route.fulfill({
      status: 404,
      json: { detail: `Unmocked API route: ${url.pathname}` },
    });
  });
}

test("renders rich application review artifact sections in desktop and mobile browsers", async ({
  page,
}, testInfo) => {
  const runtimeFailures: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      runtimeFailures.push(`console error: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => {
    runtimeFailures.push(`page error: ${error.message}`);
  });
  page.on("response", (response) => {
    if (response.status() >= 400) {
      runtimeFailures.push(`http ${response.status()}: ${response.url()}`);
    }
  });
  await mockApplicationReviewApis(page);

  await page.goto("/reviews/review-1");

  try {
    await expect(page.getByRole("heading", { name: "ExampleApp" })).toBeVisible({
      timeout: 15000,
    });
  } catch (error) {
    const bodyText = await page.locator("body").innerText().catch(() => "");
    throw new Error(`${String(error)}\nBody:\n${bodyText}\nRuntime:\n${runtimeFailures.join("\n")}`);
  }
  await expect(page.getByRole("heading", { name: "Evidence Chains" })).toBeVisible();
  await expect(page.getByText("1 chains")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Graph Slice" })).toBeVisible();
  await expect(page.getByText("2 nodes / 1 edges")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Artifact Fix Plan" })).toBeVisible();
  await expect(page.getByText("Resolve cited scanner finding").first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Rerun History" })).toBeVisible();
  await expect(page.getByText("abc123").first()).toBeVisible();

  await testInfo.attach("application-review-artifact-desktop", {
    body: await page.screenshot({ fullPage: true }),
    contentType: "image/png",
  });

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("heading", { name: "Evidence Chains" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Graph Slice" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Artifact Fix Plan" })).toBeVisible();

  await testInfo.attach("application-review-artifact-mobile", {
    body: await page.screenshot({ fullPage: true }),
    contentType: "image/png",
  });
});

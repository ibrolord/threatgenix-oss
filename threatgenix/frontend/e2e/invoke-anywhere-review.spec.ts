import { randomUUID } from "node:crypto";

import { expect, test } from "@playwright/test";
import type { APIRequestContext, Page } from "@playwright/test";

import {
  API_BASE_URL,
  E2E_PASSWORD,
  buildAuthHeaders,
  seedAuthenticatedSession,
} from "./helpers/auth";

const JOURNEY_TIMEOUT_MS = 45000;

interface SyntheticUser {
  email: string;
  token: string;
}

function baseUrlOrigin(page: Page): string {
  return new URL(page.url()).origin;
}

function forwardedPublicHeaders(page: Page): Record<string, string> {
  const url = new URL(page.url());
  return {
    "x-forwarded-host": url.host,
    "x-forwarded-proto": url.protocol.replace(":", ""),
  };
}

function attachRuntimeFailureGuards(page: Page): string[] {
  const failures: string[] = [];

  page.on("console", (message) => {
    if (message.type() === "error") {
      failures.push(`console error: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => {
    failures.push(`page error: ${error.message}`);
  });
  page.on("response", (response) => {
    if (response.url().includes("/api/") && response.status() >= 500) {
      failures.push(`api ${response.status()}: ${response.url()}`);
    }
  });

  return failures;
}

async function expectApiOk(response: Awaited<ReturnType<APIRequestContext["post"]>>) {
  if (!response.ok()) {
    throw new Error(`API request failed (${response.status()}): ${await response.text()}`);
  }
}

async function registerSyntheticBrowserUser(request: APIRequestContext): Promise<SyntheticUser> {
  const unique = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const email = `codex-prod-smoke-browser-${unique}@example.com`;
  const registerResponse = await request.post(`${API_BASE_URL}/auth/register`, {
    data: {
      email,
      password: E2E_PASSWORD,
      full_name: "ThreatGenix Browser Journey Smoke",
    },
  });
  await expectApiOk(registerResponse);

  const verificationCode = registerResponse.headers()["x-dev-email-verification-code"];
  if (verificationCode) {
    const verifyResponse = await request.post(`${API_BASE_URL}/auth/verify-email`, {
      data: { email, code: verificationCode },
    });
    await expectApiOk(verifyResponse);
  }

  const loginResponse = await request.post(`${API_BASE_URL}/auth/login`, {
    data: { email, password: E2E_PASSWORD },
  });
  await expectApiOk(loginResponse);
  const payload = (await loginResponse.json()) as { access_token?: string };
  expect(payload.access_token).toBeTruthy();

  return { email, token: payload.access_token! };
}

async function cleanupSyntheticBrowserUser(request: APIRequestContext, token: string | null) {
  if (!token) return;
  const cleanupResponse = await request.delete(`${API_BASE_URL}/auth/synthetic-smoke-account`, {
    headers: buildAuthHeaders(token),
  });
  expect(cleanupResponse.status()).toBe(204);
}

async function createInvokeAnywhereReview(
  request: APIRequestContext,
  page: Page,
  token: string,
) {
  const unique = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const response = await request.post(`${API_BASE_URL}/agent/reviews/orchestrations`, {
    headers: {
      ...buildAuthHeaders(token),
      ...forwardedPublicHeaders(page),
    },
    data: {
      threat_model: {
        system_name: `Browser Invoke Anywhere ${unique}`,
        description: "Disposable browser journey model for invoke-anywhere review QA.",
        data_classification: "Restricted",
        regulatory_scope: ["SOC2", "PCI DSS"],
        deployment_model: "cloud",
      },
      review: {
        app_name: `Browser Invoke Anywhere ${unique}`,
        invocation_surface: "cli",
        input_kind: "diff",
        commit_sha: `browser-${unique}`,
        requested_tools: ["semgrep"],
        intake_answers: {
          business_purpose: "Validate a PR that adds a sensitive customer export route.",
          data_classification: "restricted",
          sensitive_data_types: ["pii", "financial"],
          changed_security_surface: ["authz", "sensitive_data", "public_api"],
          scanner_permissions: ["static_code"],
          out_of_scope: ["production data access"],
        },
      },
      bundle: {
        bundle_kind: "diff",
        source: "cli",
        manifest: [
          {
            path: "apps/api/users.py",
            file_kind: "source",
            sha256: "a".repeat(64),
            byte_size: 412,
            source: "cli",
          },
          {
            path: "docs/security/user-export.md",
            file_kind: "doc",
            sha256: "b".repeat(64),
            byte_size: 820,
            source: "cli",
          },
          {
            path: "infra/alb.tf",
            file_kind: "iac",
            sha256: "c".repeat(64),
            byte_size: 538,
            source: "cli",
          },
          {
            path: "requirements.lock",
            file_kind: "dependency_lock",
            sha256: "d".repeat(64),
            byte_size: 1200,
            source: "cli",
          },
          {
            path: "config/routes.yml",
            file_kind: "config",
            sha256: "e".repeat(64),
            byte_size: 260,
            source: "cli",
          },
        ],
      },
      scanner_tools: ["semgrep"],
      rebuild_context: true,
      evaluate_decision: true,
    },
  });
  await expectApiOk(response);
  const body = (await response.json()) as {
    contract_version?: string;
    orchestration?: {
      status?: string;
      web_url?: string;
      review?: { id?: string; app_name?: string };
      decision?: { decision?: string };
      scanner_jobs?: unknown[];
    };
  };

  expect(body.contract_version).toBe("threatgenix.agent.v1");
  expect(body.orchestration?.status).toBe("completed");
  expect(body.orchestration?.review?.id).toBeTruthy();
  expect(body.orchestration?.web_url).toBeTruthy();
  expect(body.orchestration?.web_url).toContain("/reviews/");
  expect(body.orchestration?.web_url).not.toContain("fly.dev");
  expect(body.orchestration?.web_url).not.toContain("127.0.0.1:8000");
  expect(body.orchestration?.decision?.decision).toBeTruthy();
  expect(body.orchestration?.scanner_jobs?.length).toBe(1);

  return body.orchestration!;
}

test.describe("invoke-anywhere review browser journey", () => {
  test.skip(!E2E_PASSWORD, "Set TG_E2E_PASSWORD to run invoke-anywhere browser coverage.");
  test.setTimeout(180000);

  test("opens the durable review report from agent orchestration without leaking internal hosts", async ({
    context,
    page,
    request,
  }, testInfo) => {
    page.setDefaultTimeout(JOURNEY_TIMEOUT_MS);

    await page.goto("/");
    await page.goto(`/reviews/${randomUUID()}`);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await expect(page.getByText("Access your organization threat-model workspace.")).toBeVisible();

    const syntheticUser = await registerSyntheticBrowserUser(request);
    const runtimeFailures = attachRuntimeFailureGuards(page);

    try {
      await seedAuthenticatedSession(syntheticUser.token, page);
      await page.goto("/");
      await context.grantPermissions(["clipboard-read", "clipboard-write"], {
        origin: baseUrlOrigin(page),
      });

      const orchestration = await createInvokeAnywhereReview(request, page, syntheticUser.token);
      const reviewId = orchestration.review!.id!;
      const appName = orchestration.review!.app_name!;
      const reviewPath = new URL(orchestration.web_url!).pathname;

      await page.goto(reviewPath);
      await expect(page).toHaveURL(new RegExp(`/reviews/${reviewId}$`));
      await expect(page.getByRole("heading", { name: appName })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Invoke Anywhere", exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Customer-Ready Report", exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Evidence Snapshot", exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Missing Evidence", exact: true })).toBeVisible();
      await expect(page.getByText("Check review status")).toBeVisible();

      const openWebReview = page.getByRole("link", { name: "Open Web Review" });
      await expect(openWebReview).toBeVisible();
      const href = await openWebReview.getAttribute("href");
      expect(href).toContain(`/reviews/${reviewId}`);
      expect(href).not.toContain("fly.dev");
      expect(href).not.toContain("127.0.0.1:8000");

      const rebuildResponse = page.waitForResponse((response) =>
        response.url().includes(`/api/reviews/${reviewId}/context-index/rebuild`) &&
        response.ok(),
      );
      await page.getByRole("button", { name: "Rebuild Context" }).click();
      await rebuildResponse;

      const evaluateResponse = page.waitForResponse((response) =>
        response.url().includes(`/api/reviews/${reviewId}/decision/evaluate`) &&
        response.ok(),
      );
      await page.getByRole("button", { name: "Evaluate Decision" }).click();
      const evaluated = (await (await evaluateResponse).json()) as { decision?: string };
      expect(evaluated.decision).toBeTruthy();
      await expect(page.getByText(/Decision:/)).toBeVisible();

      await page.getByRole("button", { name: "Copy Report" }).click();
      await expect(page.getByText("Copied report.")).toBeVisible();

      const desktopBody = await page.locator("body").innerText();
      expect(desktopBody).toContain("Evidence snapshot");
      expect(desktopBody).not.toContain("fly.dev");
      expect(desktopBody).not.toContain("127.0.0.1:8000");
      expect(desktopBody).not.toContain("threatgenix-api");

      await page.screenshot({
        path: testInfo.outputPath("invoke-anywhere-review-desktop.png"),
        fullPage: true,
      });

      await page.setViewportSize({ width: 390, height: 844 });
      await page.reload();
      await expect(page.getByRole("heading", { name: appName })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Customer-Ready Report", exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Invoke Anywhere", exact: true })).toBeVisible();
      await page.screenshot({
        path: testInfo.outputPath("invoke-anywhere-review-mobile.png"),
        fullPage: true,
      });

      expect(runtimeFailures).toEqual([]);
    } finally {
      await cleanupSyntheticBrowserUser(request, syntheticUser.token);
    }
  });
});

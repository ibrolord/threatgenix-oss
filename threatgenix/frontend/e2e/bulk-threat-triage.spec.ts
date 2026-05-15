import { expect, test } from "@playwright/test";
import type { APIRequestContext, APIResponse, Page } from "@playwright/test";

import {
  API_BASE_URL,
  E2E_PASSWORD,
  buildAuthHeaders,
  seedAuthenticatedSession,
} from "./helpers/auth";

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

async function expectApiOk(response: APIResponse) {
  if (!response.ok()) {
    throw new Error(`API request failed (${response.status()}): ${await response.text()}`);
  }
}

async function registerBulkTriageUser(request: APIRequestContext): Promise<string> {
  const email = `threatgenix-bulk-triage-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@local.test`;
  const registerResponse = await request.post(`${API_BASE_URL}/auth/register`, {
    data: {
      email,
      password: E2E_PASSWORD,
      full_name: "ThreatGenix Bulk Triage QA",
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
    data: {
      email,
      password: E2E_PASSWORD,
    },
  });
  await expectApiOk(loginResponse);

  const payload = (await loginResponse.json()) as { access_token: string };
  expect(payload.access_token).toBeTruthy();
  return payload.access_token;
}

async function createThreatModel(request: APIRequestContext, token: string) {
  const systemName = `Bulk Triage Review ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const response = await request.post(`${API_BASE_URL}/threat-models`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: {
      system_name: systemName,
      description: "Browser bulk triage regression model.",
      data_classification: "Restricted",
      regulatory_scope: ["OSFI B-13", "NIST"],
      deployment_model: "cloud",
    },
  });
  await expectApiOk(response);
  const model = (await response.json()) as { id: string; system_name: string };
  return { id: model.id, systemName: model.system_name };
}

async function createManualThreat(
  request: APIRequestContext,
  token: string,
  threatModelId: string,
  data: {
    title: string;
    description: string;
    strideCategory: string;
    severity: string;
  },
) {
  const response = await request.post(
    `${API_BASE_URL}/threat-models/${threatModelId}/threats/manual`,
    {
      headers: {
        ...buildAuthHeaders(token),
        "Content-Type": "application/json",
      },
      data: {
        threat_subtype: data.title,
        description: data.description,
        stride_category: data.strideCategory,
        severity: data.severity,
      },
    },
  );
  await expectApiOk(response);
  return (await response.json()) as {
    id: string;
    display_id: string;
    status: string;
    dismiss_reason?: string | null;
  };
}

async function getThreats(request: APIRequestContext, token: string, threatModelId: string) {
  const response = await request.get(`${API_BASE_URL}/threat-models/${threatModelId}/threats`, {
    headers: buildAuthHeaders(token),
  });
  await expectApiOk(response);
  return (await response.json()) as Array<{
    id: string;
    status: string;
    dismiss_reason?: string | null;
  }>;
}

async function getThreatHistory(
  request: APIRequestContext,
  token: string,
  threatModelId: string,
  threatId: string,
) {
  const response = await request.get(
    `${API_BASE_URL}/threat-models/${threatModelId}/threats/${threatId}/history`,
    { headers: buildAuthHeaders(token) },
  );
  await expectApiOk(response);
  return (await response.json()) as Array<{
    action: string;
    new_status: string;
    reason: string | null;
  }>;
}

test.describe("bulk threat triage browser journey", () => {
  test.skip(!E2E_PASSWORD, "TG_E2E_PASSWORD is required for authenticated e2e tests");

  test("bulk accepts and dismisses selected threats with persisted audit history", async ({
    page,
    request,
  }, testInfo) => {
    const runtimeFailures = attachRuntimeFailureGuards(page);
    const token = await registerBulkTriageUser(request);
    const model = await createThreatModel(request, token);
    const treasuryBypass = await createManualThreat(request, token, model.id, {
      title: "Treasury approval bypass",
      description: "A privileged actor can bypass dual approval on treasury transfers.",
      strideCategory: "Elevation of Privilege",
      severity: "High",
    });
    const auditSuppression = await createManualThreat(request, token, model.id, {
      title: "Audit event suppression",
      description: "A service account can suppress audit events for payment workflows.",
      strideCategory: "Repudiation",
      severity: "Medium",
    });
    const threatIds = [treasuryBypass.id, auditSuppression.id];
    const displayIds = [treasuryBypass.display_id, auditSuppression.display_id];

    await seedAuthenticatedSession(token, page);
    await page.goto(`/threat-models/${model.id}`);
    await expect(page.getByRole("heading", { name: model.systemName })).toBeVisible();

    for (const displayId of displayIds) {
      await expect(page.getByRole("checkbox", { name: `Select ${displayId}` })).toBeVisible();
      await page.getByRole("checkbox", { name: `Select ${displayId}` }).check();
    }
    await expect(page.getByText("2 threats selected")).toBeVisible();

    await Promise.all([
      page.waitForResponse((response) =>
        response.url().includes(`/api/threat-models/${model.id}/threats/bulk-triage`) &&
        response.status() === 200
      ),
      page.getByRole("button", { name: "Accept Selected" }).click(),
    ]);
    await expect(page.getByText("2 threats selected")).toHaveCount(0);
    for (const threatId of threatIds) {
      await expect(page.locator(`tr[data-threat-id="${threatId}"]`)).toContainText("Accepted");
    }

    let persistedThreats = await getThreats(request, token, model.id);
    for (const threatId of threatIds) {
      const threat = persistedThreats.find((candidate) => candidate.id === threatId);
      expect(threat?.status).toBe("Accepted");
      expect(threat?.dismiss_reason ?? null).toBeNull();
      const history = await getThreatHistory(request, token, model.id, threatId);
      expect(history).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            action: "triaged",
            new_status: "Accepted",
            reason: "Status changed to Accepted",
          }),
        ]),
      );
    }

    for (const displayId of displayIds) {
      await page.getByRole("checkbox", { name: `Select ${displayId}` }).check();
    }
    await page.getByRole("button", { name: "Dismiss Selected" }).click();
    await page
      .getByPlaceholder("Dismiss reason (required)")
      .fill("Consolidated as duplicate findings during QA review.");

    await Promise.all([
      page.waitForResponse((response) =>
        response.url().includes(`/api/threat-models/${model.id}/threats/bulk-triage`) &&
        response.status() === 200
      ),
      page.getByRole("button", { name: "Confirm" }).click(),
    ]);
    await expect(page.getByText("2 threats selected")).toHaveCount(0);
    for (const threatId of threatIds) {
      await expect(page.locator(`tr[data-threat-id="${threatId}"]`)).toContainText("Dismissed");
    }

    persistedThreats = await getThreats(request, token, model.id);
    for (const threatId of threatIds) {
      const threat = persistedThreats.find((candidate) => candidate.id === threatId);
      expect(threat?.status).toBe("Dismissed");
      expect(threat?.dismiss_reason).toBe("Consolidated as duplicate findings during QA review.");
      const history = await getThreatHistory(request, token, model.id, threatId);
      expect(history).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            action: "triaged",
            new_status: "Dismissed",
            reason: "Consolidated as duplicate findings during QA review.",
          }),
          expect.objectContaining({
            action: "triaged",
            new_status: "Accepted",
            reason: "Status changed to Accepted",
          }),
        ]),
      );
    }

    await page.screenshot({
      path: testInfo.outputPath("bulk-threat-triage-dismissed.png"),
      fullPage: true,
    });

    expect(runtimeFailures).toEqual([]);
  });
});

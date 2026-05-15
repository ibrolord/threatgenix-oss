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

async function registerCrudJourneyUser(request: APIRequestContext): Promise<string> {
  const email = `threatgenix-crud-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@local.test`;
  const registerResponse = await request.post(`${API_BASE_URL}/auth/register`, {
    data: {
      email,
      password: E2E_PASSWORD,
      full_name: "ThreatGenix CRUD Journey QA",
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

test.describe("threat model CRUD journey", () => {
  test.skip(!E2E_PASSWORD, "TG_E2E_PASSWORD is required for authenticated e2e tests");

  test("creates, opens, and archives a threat model from the browser", async ({ page, request }) => {
    const runtimeFailures = attachRuntimeFailureGuards(page);
    const token = await registerCrudJourneyUser(request);
    const modelName = `CRUD Browser Review ${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

    await seedAuthenticatedSession(token, page);
    await page.goto("/new");
    await page.getByRole("button", { name: "Start New Review" }).click();
    await page.getByLabel("Application or PR Name").fill(modelName);
    await page.getByLabel("Review Goal").selectOption("Formal Threat Model");
    await page.getByLabel("Review Summary").fill("Browser journey coverage for create, open, and archive.");
    await page.getByLabel("Data Classification").selectOption("Internal");
    await page.getByLabel("Deployment Model").selectOption("cloud");
    await page.getByRole("button", { name: "Start Security Review" }).click();

    await expect(page).toHaveURL(/\/threat-models\/[^/]+\/review$/);
    const match = page.url().match(/\/threat-models\/([^/]+)\/review$/);
    expect(match?.[1]).toBeTruthy();
    const modelId = match![1]!;

    await page.goto("/dashboard");
    await expect(page.getByRole("link", { name: modelName })).toBeVisible();
    await page.getByRole("link", { name: modelName }).click();
    await expect(page).toHaveURL(new RegExp(`/threat-models/${modelId}$`));
    await expect(page.getByRole("heading", { name: modelName })).toBeVisible();

    await page.goto("/dashboard");
    page.once("dialog", (dialog) => dialog.accept());
    await Promise.all([
      page.waitForResponse((response) =>
        response.url().includes(`/api/threat-models/${modelId}/archive`) &&
        response.status() === 200
      ),
      page.getByRole("button", { name: `Archive ${modelName}` }).click(),
    ]);
    await expect(page.getByRole("link", { name: modelName })).toHaveCount(0);

    const listResponse = await request.get(`${API_BASE_URL}/threat-models`, {
      headers: buildAuthHeaders(token),
    });
    await expectApiOk(listResponse);
    const activeModels = (await listResponse.json()) as { id: string }[];
    expect(activeModels.map((model) => model.id)).not.toContain(modelId);

    const directResponse = await request.get(`${API_BASE_URL}/threat-models/${modelId}`, {
      headers: buildAuthHeaders(token),
    });
    await expectApiOk(directResponse);
    const archivedModel = (await directResponse.json()) as { archived_at?: string | null };
    expect(archivedModel.archived_at).toBeTruthy();

    expect(runtimeFailures).toEqual([]);
  });
});

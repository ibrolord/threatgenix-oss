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

async function registerProviderSettingsUser(request: APIRequestContext): Promise<string> {
  const email = `threatgenix-provider-settings-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@local.test`;
  const registerResponse = await request.post(`${API_BASE_URL}/auth/register`, {
    data: {
      email,
      password: E2E_PASSWORD,
      full_name: "ThreatGenix Provider Settings QA",
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

async function getProviders(request: APIRequestContext, token: string) {
  const response = await request.get(`${API_BASE_URL}/llm/providers`, {
    headers: buildAuthHeaders(token),
  });
  await expectApiOk(response);
  return (await response.json()) as {
    available: Array<{ name: string }>;
    active: { provider: string; model: string };
  };
}

test.describe("provider settings browser journey", () => {
  test.skip(!E2E_PASSWORD, "TG_E2E_PASSWORD is required for authenticated e2e tests");

  test("adds BYOK, switches active provider, and clears stale selection on delete", async ({
    page,
    request,
  }, testInfo) => {
    const runtimeFailures = attachRuntimeFailureGuards(page);
    const token = await registerProviderSettingsUser(request);

    await seedAuthenticatedSession(token, page);
    await page.goto("/settings");
    await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
    await expect(page.getByRole("region", { name: "AI runtime health" })).toBeVisible();
    await expect(page.getByRole("region", { name: "Active AI provider controls" })).toBeVisible();

    let openAiRow = page.getByRole("row").filter({ hasText: "OpenAI" });
    await expect(openAiRow).toContainText("Not set");
    await openAiRow.getByRole("button", { name: "Add Key" }).click();
    await openAiRow.getByPlaceholder("API key").fill("sk-qa-provider-settings-1234567890");
    await openAiRow.getByPlaceholder("Model override (optional)").fill("gpt-4o-mini-qa");
    await Promise.all([
      page.waitForResponse((response) =>
        response.url().includes("/api/llm/keys/openai") && response.status() === 200
      ),
      openAiRow.getByRole("button", { name: "Save" }).click(),
    ]);
    await expect(openAiRow).toContainText("Key stored");
    await expect(openAiRow).toContainText("7890");

    await page.reload();
    await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
    await Promise.all([
      page.waitForResponse((response) =>
        response.url().includes("/api/llm/provider") && response.status() === 200
      ),
      page.getByRole("combobox", { name: "Active AI Provider" }).selectOption("openai"),
    ]);

    await page.reload();
    await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
    await expect(page.getByText("Active: openai / gpt-4o-mini-qa")).toBeVisible();
    let providers = await getProviders(request, token);
    expect(providers.available.map((provider) => provider.name)).toContain("openai");
    expect(providers.active).toEqual({
      provider: "openai",
      model: "gpt-4o-mini-qa",
    });

    openAiRow = page.getByRole("row").filter({ hasText: "OpenAI" });
    page.once("dialog", (dialog) => dialog.accept());
    await Promise.all([
      page.waitForResponse((response) =>
        response.url().includes("/api/llm/keys/openai") && response.status() === 204
      ),
      openAiRow.getByRole("button", { name: "Delete" }).click(),
    ]);
    await expect(openAiRow).toContainText("Not set");

    await page.reload();
    await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
    await expect(page.getByText("Active: openai / gpt-4o-mini-qa")).toHaveCount(0);
    providers = await getProviders(request, token);
    expect(providers.available.map((provider) => provider.name)).not.toContain("openai");
    expect(providers.active.provider).not.toBe("openai");

    await page.screenshot({
      path: testInfo.outputPath("provider-settings-byok-cleared.png"),
      fullPage: true,
    });

    expect(runtimeFailures).toEqual([]);
  });
});

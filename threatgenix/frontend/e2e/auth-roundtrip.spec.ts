import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

import { E2E_PASSWORD } from "./helpers/auth";

const AUTH_READY_TIMEOUT_MS = 30000;

function uniqueAuthEmail(): string {
  return `threatgenix-auth-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@local.test`;
}

function attachRuntimeFailureGuards(page: Page): string[] {
  const failures: string[] = [];

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

async function expectAuthenticatedShell(page: Page) {
  await expect(page.getByRole("link", { name: "Dashboard" })).toBeVisible({
    timeout: AUTH_READY_TIMEOUT_MS,
  });
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
  await expect(page).toHaveURL(/\/dashboard$/);
}

async function expectStoredToken(page: Page) {
  await page.waitForFunction(() => Boolean(window.localStorage.getItem("tg_token")), null, {
    timeout: AUTH_READY_TIMEOUT_MS,
  });
}

test.describe("Auth browser roundtrip", () => {
  test.skip(!E2E_PASSWORD, "Set TG_E2E_PASSWORD to run auth browser roundtrip coverage.");
  test.setTimeout(90000);

  test("registers, persists through reload, logs out, and signs back in", async ({ page }) => {
    page.setDefaultTimeout(AUTH_READY_TIMEOUT_MS);
    const runtimeFailures = attachRuntimeFailureGuards(page);
    const email = uniqueAuthEmail();

    await page.goto("/login?mode=register");
    await expect(page.getByRole("heading", { name: "Create account" })).toBeVisible();

    await page.getByLabel("Full Name").fill("ThreatGenix Auth E2E");
    await page.getByLabel("Email").fill(email);
    await page.getByLabel("Password").fill(E2E_PASSWORD!);
    await page.getByRole("button", { name: "Create Account" }).click();

    await expectStoredToken(page);
    await expectAuthenticatedShell(page);

    await page.reload();
    await expectStoredToken(page);
    await expectAuthenticatedShell(page);

    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Dashboard" })).toHaveCount(0);
    await expect
      .poll(() => page.evaluate(() => window.localStorage.getItem("tg_token")))
      .toBeNull();

    await page.getByLabel("Email").fill(email);
    await page.getByLabel("Password").fill(E2E_PASSWORD!);
    await page.getByRole("button", { name: "Sign in" }).click();

    await expectStoredToken(page);
    await expectAuthenticatedShell(page);
    expect(runtimeFailures).toEqual([]);
  });
});

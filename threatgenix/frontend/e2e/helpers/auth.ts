import { expect } from "@playwright/test";
import type { APIRequestContext, Page } from "@playwright/test";

export const API_BASE_URL =
  process.env.TG_E2E_API_BASE_URL ?? "http://127.0.0.1:8000/api";
export const E2E_EMAIL =
  process.env.TG_E2E_EMAIL ?? "threatgenix-dfd-e2e@local.test";
export const E2E_PASSWORD = process.env.TG_E2E_PASSWORD;

const USE_DEDICATED_E2E_ACCOUNT = !process.env.TG_E2E_EMAIL;

export async function seedAuthenticatedSession(token: string, page: Page) {
  await page.addInitScript((accessToken: string) => {
    window.localStorage.setItem("tg_token", accessToken);
    window.localStorage.setItem("tg_dfd_stencil_panel_visible", "true");
    window.localStorage.setItem("tg_tm_inspector_visible", "false");
    window.localStorage.removeItem("tg_dfd_canvas_height");
  }, token);
}

export function buildAuthHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
  };
}

async function registerDedicatedE2EUser(
  request: APIRequestContext,
  email = E2E_EMAIL,
) {
  const response = await request.post(`${API_BASE_URL}/auth/register`, {
    data: {
      email,
      password: E2E_PASSWORD,
      full_name: "ThreatGenix DFD E2E Harness",
    },
  });

  if (response.status() === 409) return;
  if (!response.ok()) {
    const loginAfterRace = await request.post(`${API_BASE_URL}/auth/login`, {
      data: {
        email,
        password: E2E_PASSWORD,
      },
    });
    if (loginAfterRace.ok()) return;

    const responseBody = await response.text();
    throw new Error(
      `Failed to register dedicated E2E user (${response.status()}): ${responseBody}`,
    );
  }

  const verificationCode = response.headers()["x-dev-email-verification-code"];
  if (verificationCode) {
    const verifyResponse = await request.post(`${API_BASE_URL}/auth/verify-email`, {
      data: {
        email,
        code: verificationCode,
      },
    });
    expect(verifyResponse.ok()).toBeTruthy();
  }
}

async function loginWithEmail(request: APIRequestContext, email: string) {
  return request.post(`${API_BASE_URL}/auth/login`, {
    data: {
      email,
      password: E2E_PASSWORD,
    },
  });
}

async function resetPasswordWithDevToken(request: APIRequestContext, email: string) {
  const resetRequest = await request.post(`${API_BASE_URL}/auth/request-password-reset`, {
    data: { email },
  });
  expect(resetRequest.ok()).toBeTruthy();
  const resetPayload = (await resetRequest.json()) as { reset_token?: string };
  if (!resetPayload.reset_token) return false;

  const resetResponse = await request.post(`${API_BASE_URL}/auth/reset-password`, {
    data: {
      token: resetPayload.reset_token,
      new_password: E2E_PASSWORD,
    },
  });
  expect(resetResponse.ok()).toBeTruthy();
  return true;
}

export async function loginForToken(request: APIRequestContext) {
  const response = await loginWithEmail(request, E2E_EMAIL);
  if (response.ok()) {
    const payload = (await response.json()) as { access_token: string };
    expect(payload.access_token).toBeTruthy();
    return payload.access_token;
  }

  if (USE_DEDICATED_E2E_ACCOUNT && (response.status() === 401 || response.status() === 403)) {
    await registerDedicatedE2EUser(request);
    await resetPasswordWithDevToken(request, E2E_EMAIL);
    const recoveredResponse = await loginWithEmail(request, E2E_EMAIL);
    if (recoveredResponse.ok()) {
      const payload = (await recoveredResponse.json()) as { access_token: string };
      expect(payload.access_token).toBeTruthy();
      return payload.access_token;
    }
    throw new Error(
      `E2E login recovery failed (${recoveredResponse.status()}): ${await recoveredResponse.text()}`
    );
  }

  throw new Error(`E2E login failed (${response.status()}): ${await response.text()}`);
}

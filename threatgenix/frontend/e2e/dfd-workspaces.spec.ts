import { randomUUID } from "node:crypto";

import { expect, test } from "@playwright/test";
import type { APIRequestContext, Page } from "@playwright/test";

import {
  API_BASE_URL,
  E2E_PASSWORD,
  buildAuthHeaders,
  loginForToken,
  seedAuthenticatedSession,
} from "./helpers/auth";

const EMPTY_MODEL_ID =
  process.env.TG_E2E_EMPTY_MODEL_ID ?? "00000000-0000-0000-0000-000000000010";
const DFD_READY_TIMEOUT_MS = 30000;
const EMPTY_HARNESS_PREFIX = "Codex DFD Empty Workspace Harness";
const EMPTY_DFD_MESSAGE =
  "No DFD generated yet. Upload a document, load a starter template, or add nodes manually.";
const EMPTY_WORKSPACE_MESSAGE =
  "This DFD workspace is empty. Add the first component, load a template, or duplicate another view when you create the next tab.";

async function waitForDfdShell(page: Page) {
  await expect(page.getByRole("heading", { name: "Data Flow Diagram" })).toBeVisible({
    timeout: DFD_READY_TIMEOUT_MS,
  });
  await expect(page.getByRole("button", { name: "New DFD", exact: true })).toBeVisible({
    timeout: DFD_READY_TIMEOUT_MS,
  });
}

async function waitForDfdReady(page: Page) {
  await waitForDfdShell(page);
  await expect(page.getByRole("button", { name: "Fit" })).toBeVisible({
    timeout: DFD_READY_TIMEOUT_MS,
  });
  const flowSurface = page.locator(".dfd-flow-surface");
  await expect(flowSurface).toBeVisible({ timeout: DFD_READY_TIMEOUT_MS });
  await flowSurface.evaluate((element) => {
    element.scrollIntoView({ block: "center", inline: "nearest" });
  });
  await expect(page.locator(".react-flow__pane")).toBeVisible({
    timeout: DFD_READY_TIMEOUT_MS,
  });
}

async function waitForDfdEmptyMessage(page: Page, message: string) {
  await waitForDfdShell(page);
  await expect(page.getByText(message)).toBeVisible({
    timeout: DFD_READY_TIMEOUT_MS,
  });
}

async function createEmptyWorkspaceHarness(
  request: APIRequestContext,
  token: string
): Promise<string> {
  if (process.env.TG_E2E_EMPTY_MODEL_ID) {
    return EMPTY_MODEL_ID;
  }

  const createResponse = await request.post(`${API_BASE_URL}/threat-models`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: {
      system_name: `${EMPTY_HARNESS_PREFIX} ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      description: "Reusable e2e harness for empty DFD workspace actions.",
      data_classification: "Internal",
      deployment_model: "cloud",
    },
  });
  expect(createResponse.ok()).toBeTruthy();
  const createdModel = (await createResponse.json()) as { id: string };
  return createdModel.id;
}

async function createWorkspaceHarness(
  request: APIRequestContext,
  token: string
): Promise<{ threatModelId: string; rootNodeName: string }> {
  const systemName = `Codex DFD Workspace Harness ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const rootNodeName = "Core Banking API";

  const createResponse = await request.post(`${API_BASE_URL}/threat-models`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: {
      system_name: systemName,
      description: "Reusable e2e harness for top-level DFD workspace tabs.",
      data_classification: "Internal",
      deployment_model: "cloud",
    },
  });
  expect(createResponse.ok()).toBeTruthy();
  const createdModel = (await createResponse.json()) as { id: string };

  const saveResponse = await request.put(`${API_BASE_URL}/threat-models/${createdModel.id}/dfd`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: {
      nodes: [
        {
          id: randomUUID(),
          node_type: "process",
          name: rootNodeName,
          position_x: 260,
          position_y: 220,
          properties: {
            authentication_type: "oauth2",
            network_exposure: "internet",
          },
        },
      ],
      edges: [],
      trust_boundaries: [],
    },
  });
  expect(saveResponse.ok()).toBeTruthy();
  return { threatModelId: createdModel.id, rootNodeName };
}

test.describe("DFD workspaces", () => {
  test.skip(!E2E_PASSWORD, "Set TG_E2E_PASSWORD to run DFD workspace coverage.");
  test.describe.configure({ mode: "serial" });
  test.setTimeout(90000);

  let authToken: string;

  test.beforeAll(async ({ request }) => {
    authToken = await loginForToken(request);
  });

  test("opens workspace and custom-component dialogs from an empty model", async ({
    page,
    request,
  }) => {
    page.setDefaultTimeout(DFD_READY_TIMEOUT_MS);
    const emptyThreatModelId = await createEmptyWorkspaceHarness(request, authToken);

    await seedAuthenticatedSession(authToken, page);
    await page.goto(`/threat-models/${emptyThreatModelId}`);

    await waitForDfdEmptyMessage(page, EMPTY_DFD_MESSAGE);

    await page.getByRole("button", { name: "New DFD", exact: true }).dispatchEvent("click");
    const workspaceDialog = page
      .locator(".dfd-dialog")
      .filter({ has: page.getByRole("heading", { name: "Create New DFD" }) });
    await expect(workspaceDialog).toBeVisible();
    await expect(workspaceDialog.getByText("Duplicate current view")).toBeVisible();
    await workspaceDialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(workspaceDialog).toHaveCount(0);

    const showPaletteButton = page.getByRole("button", { name: "Show Palette", exact: true });
    if (await showPaletteButton.isVisible().catch(() => false)) {
      await showPaletteButton.click();
    } else {
      await expect(page.getByRole("button", { name: "Hide Palette", exact: true })).toBeVisible();
    }
    await page.getByRole("button", { name: "Create custom", exact: true }).click();
    const addComponentDialog = page
      .locator(".dfd-dialog")
      .filter({ has: page.getByRole("heading", { name: "Add DFD Component" }) });
    await expect(addComponentDialog).toBeVisible();
    await expect(addComponentDialog.getByText("Semantic Type")).toBeVisible();
    await expect(addComponentDialog.getByRole("button", { name: "Save Stencil", exact: true })).toBeVisible();
  });

  test("creates a blank workspace tab and keeps it isolated from System View", async ({
    page,
    request,
  }, testInfo) => {
    page.setDefaultTimeout(DFD_READY_TIMEOUT_MS);
    const { threatModelId, rootNodeName } = await createWorkspaceHarness(request, authToken);
    const workspaceName = `Settlement Flow ${Date.now()}`;

    await seedAuthenticatedSession(authToken, page);
    await page.goto(`/threat-models/${threatModelId}`);
    await waitForDfdReady(page);
    await expect(page.getByText(rootNodeName, { exact: true })).toBeVisible({
      timeout: DFD_READY_TIMEOUT_MS,
    });

    await page.getByRole("button", { name: "New DFD", exact: true }).click();
    const workspaceDialog = page
      .locator(".dfd-dialog")
      .filter({ has: page.getByRole("heading", { name: "Create New DFD" }) });
    await expect(workspaceDialog).toBeVisible();
    await workspaceDialog.getByLabel("DFD Name", { exact: true }).fill(workspaceName);
    await workspaceDialog.getByRole("button", { name: "Create DFD", exact: true }).click();

    await expect(page.getByRole("tab", { name: workspaceName, exact: true })).toBeVisible();
    await waitForDfdEmptyMessage(page, EMPTY_WORKSPACE_MESSAGE);

    await page.getByRole("button", { name: /Process/i }).click();
    await expect(page.getByText(EMPTY_WORKSPACE_MESSAGE)).toHaveCount(0);
    await expect(page.getByText("1 nodes · 0 flows · 0 boundaries")).toBeVisible({
      timeout: DFD_READY_TIMEOUT_MS,
    });

    const viewsResponse = await request.get(`${API_BASE_URL}/threat-models/${threatModelId}/dfd/views`, {
      headers: buildAuthHeaders(authToken),
    });
    expect(viewsResponse.ok()).toBeTruthy();
    const views = (await viewsResponse.json()) as Array<{
      id: string;
      name: string;
      view_type: string;
    }>;
    const workspaceView = views.find(
      (view) => view.name === workspaceName && view.view_type === "workspace"
    );
    expect(workspaceView).toBeTruthy();

    const rootDfdResponse = await request.get(`${API_BASE_URL}/threat-models/${threatModelId}/dfd`, {
      headers: buildAuthHeaders(authToken),
    });
    expect(rootDfdResponse.ok()).toBeTruthy();
    const rootDfd = (await rootDfdResponse.json()) as {
      nodes: Array<{ name: string }>;
    };
    expect(rootDfd.nodes.map((node) => node.name)).toEqual([rootNodeName]);

    const workspaceDfdResponse = await request.get(
      `${API_BASE_URL}/threat-models/${threatModelId}/dfd?view_id=${workspaceView?.id}`,
      {
        headers: buildAuthHeaders(authToken),
      }
    );
    expect(workspaceDfdResponse.ok()).toBeTruthy();
    const workspaceDfd = (await workspaceDfdResponse.json()) as {
      nodes: Array<{ name: string }>;
    };
    expect(workspaceDfd.nodes.map((node) => node.name)).toContain("Process");

    await page.getByRole("button", { name: /Hide Palette/i }).click();
    await page.getByRole("tab", { name: "System View", exact: true }).click();
    await waitForDfdReady(page);
    await expect(page.getByText(rootNodeName, { exact: true })).toBeVisible({
      timeout: DFD_READY_TIMEOUT_MS,
    });
    await expect(page.getByText("Process", { exact: true })).toHaveCount(1);

    await page.screenshot({ path: testInfo.outputPath("dfd-workspaces-blank.png"), fullPage: true });
  });

  test("can duplicate the current view into a new workspace tab", async ({
    page,
    request,
  }) => {
    page.setDefaultTimeout(DFD_READY_TIMEOUT_MS);
    const { threatModelId, rootNodeName } = await createWorkspaceHarness(request, authToken);
    const workspaceName = `Duplicate Flow ${Date.now()}`;

    await seedAuthenticatedSession(authToken, page);
    await page.goto(`/threat-models/${threatModelId}`);
    await waitForDfdReady(page);
    await expect(page.getByText(rootNodeName, { exact: true })).toBeVisible({
      timeout: DFD_READY_TIMEOUT_MS,
    });

    await page.getByRole("button", { name: "New DFD", exact: true }).click();
    const workspaceDialog = page
      .locator(".dfd-dialog")
      .filter({ has: page.getByRole("heading", { name: "Create New DFD" }) });
    await workspaceDialog.getByLabel("DFD Name", { exact: true }).fill(workspaceName);
    await workspaceDialog
      .getByRole("radio", { name: /Duplicate current view/i })
      .check();
    await workspaceDialog.getByRole("button", { name: "Create DFD", exact: true }).click();

    await expect(page.getByRole("tab", { name: workspaceName, exact: true })).toBeVisible();
    await expect(page.getByText(rootNodeName, { exact: true })).toBeVisible({
      timeout: DFD_READY_TIMEOUT_MS,
    });
  });
});

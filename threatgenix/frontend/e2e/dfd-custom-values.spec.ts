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

const HARNESS_NAME = "Codex DFD Custom Values Harness";
const DFD_READY_TIMEOUT_MS = 30000;

async function waitForDfdReady(page: Page) {
  await expect(page.getByRole("heading", { name: "Data Flow Diagram" })).toBeVisible({
    timeout: DFD_READY_TIMEOUT_MS,
  });
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

async function ensureCustomValuesHarness(
  request: APIRequestContext,
  token: string
): Promise<{ threatModelId: string; nodeId: string; boundaryId: string }> {
  const listResponse = await request.get(`${API_BASE_URL}/threat-models`, {
    headers: buildAuthHeaders(token),
  });
  expect(listResponse.ok()).toBeTruthy();
  const models = (await listResponse.json()) as Array<{
    id: string;
    system_name: string;
  }>;

  let threatModelId = models.find((model) => model.system_name === HARNESS_NAME)?.id;
  if (!threatModelId) {
    const createResponse = await request.post(`${API_BASE_URL}/threat-models`, {
      headers: {
        ...buildAuthHeaders(token),
        "Content-Type": "application/json",
      },
      data: {
        system_name: HARNESS_NAME,
        description: "Reusable e2e harness for DFD custom dropdown coverage.",
        data_classification: "Internal",
        deployment_model: "cloud",
      },
    });
    expect(createResponse.ok()).toBeTruthy();
    const createdModel = (await createResponse.json()) as { id: string };
    threatModelId = createdModel.id;
  }

  const nodeId = randomUUID();
  const boundaryId = randomUUID();

  const saveResponse = await request.put(`${API_BASE_URL}/threat-models/${threatModelId}/dfd`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: {
      nodes: [
        {
          id: nodeId,
          node_type: "process",
          name: "Custom Metadata Service",
          position_x: 260,
          position_y: 240,
          trust_boundary_id: boundaryId,
          properties: {
            authentication_type: "oauth2",
            network_exposure: "internet",
          },
        },
      ],
      edges: [],
      trust_boundaries: [
        {
          id: boundaryId,
          name: "Custom Boundary Harness",
          node_ids: [nodeId],
          position_x: 120,
          position_y: 120,
          width: 520,
          height: 320,
          boundary_type: "network",
          parent_boundary_id: null,
        },
      ],
    },
  });
  expect(saveResponse.ok()).toBeTruthy();
  return { threatModelId, nodeId, boundaryId };
}

test.describe("DFD custom values", () => {
  test.skip(!E2E_PASSWORD, "Set TG_E2E_PASSWORD to run DFD custom-value coverage.");
  test.setTimeout(90000);

  let authToken: string;

  test.beforeAll(async ({ request }) => {
    authToken = await loginForToken(request);
  });

  test("persists custom node metadata, trust boundary types, and stencil semantic labels", async ({
    page,
    request,
  }, testInfo) => {
    page.setDefaultTimeout(DFD_READY_TIMEOUT_MS);
    const { threatModelId, nodeId, boundaryId } = await ensureCustomValuesHarness(request, authToken);
    const stencilLabel = `Event Broker ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    await seedAuthenticatedSession(authToken, page);
    await page.goto(`/threat-models/${threatModelId}`);
    await waitForDfdReady(page);
    await expect(page.getByText("Custom Metadata Service", { exact: true })).toBeVisible({
      timeout: DFD_READY_TIMEOUT_MS,
    });

    const nodeCanvasLabel = page.getByText("Custom Metadata Service", { exact: true }).first();
    await nodeCanvasLabel.dblclick();
    const nodeDialog = page.locator(".dfd-dialog").filter({ has: page.getByRole("heading", { name: "Edit Node" }) });
    await expect(nodeDialog).toBeVisible();
    await nodeDialog.getByLabel("Authentication", { exact: true }).selectOption("__custom__");
    await nodeDialog.getByPlaceholder("Enter a custom authentication").fill("Passkey / FIDO2");
    await nodeDialog.getByRole("button", { name: "Save", exact: true }).click();

    await page
      .getByTestId(`rf__node-${boundaryId}`)
      .locator(".dfd-boundary-drag-surface")
      .dblclick();
    const boundaryDialog = page
      .locator(".dfd-dialog")
      .filter({ has: page.getByRole("heading", { name: "Edit Trust Boundary" }) });
    await expect(boundaryDialog).toBeVisible();
    await boundaryDialog.getByLabel("Boundary Type", { exact: true }).selectOption("__custom__");
    await boundaryDialog
      .getByPlaceholder("Enter a custom trust boundary type")
      .fill("Partner Network Zone");
    await boundaryDialog.getByRole("button", { name: "Save", exact: true }).click();
    await expect(boundaryDialog).toBeHidden();

    await page.getByRole("button", { name: "Create custom" }).click();
    const addDialog = page
      .locator(".dfd-dialog")
      .filter({ has: page.getByRole("heading", { name: "Add DFD Component" }) });
    await expect(addDialog).toBeVisible();
    await addDialog.getByLabel("Label", { exact: true }).fill(stencilLabel);
    await addDialog.getByLabel("Semantic Type", { exact: true }).selectOption("__custom__");
    await addDialog.getByPlaceholder("Enter the custom semantic type label").fill("Event Broker");
    await addDialog.getByLabel("Underlying Behavior", { exact: true }).selectOption("data_store");
    await addDialog.getByRole("button", { name: "Save Stencil", exact: true }).click();
    await addDialog.getByRole("button", { name: "Cancel", exact: true }).click();

    await expect(page.getByText(stencilLabel, { exact: true })).toBeVisible();

    const dfdResponse = await request.get(`${API_BASE_URL}/threat-models/${threatModelId}/dfd`, {
      headers: buildAuthHeaders(authToken),
    });
    expect(dfdResponse.ok()).toBeTruthy();
    const dfd = (await dfdResponse.json()) as {
      nodes: Array<{ id: string; properties?: Record<string, unknown> }>;
      trust_boundaries: Array<{ id: string; boundary_type?: string | null }>;
    };

    const savedNode = dfd.nodes.find((node) => node.id === nodeId);
    expect(savedNode?.properties?.authentication_type).toBe("Passkey / FIDO2");

    const savedBoundary = dfd.trust_boundaries.find((boundary) => boundary.id === boundaryId);
    expect(savedBoundary?.boundary_type).toBe("Partner Network Zone");

    const templateResponse = await request.get(
      `${API_BASE_URL}/threat-models/${threatModelId}/dfd/component-templates`,
      {
        headers: buildAuthHeaders(authToken),
      }
    );
    expect(templateResponse.ok()).toBeTruthy();
    const templates = (await templateResponse.json()) as Array<{
      label: string;
      semantic_node_type: string;
      semantic_type_label?: string | null;
    }>;

    expect(templates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          label: stencilLabel,
          semantic_node_type: "data_store",
          semantic_type_label: "Event Broker",
        }),
      ])
    );

    await page.reload();
    await waitForDfdReady(page);
    await expect(page.getByText(stencilLabel, { exact: true })).toBeVisible();

    await page.screenshot({ path: testInfo.outputPath("dfd-custom-values.png"), fullPage: true });
  });
});

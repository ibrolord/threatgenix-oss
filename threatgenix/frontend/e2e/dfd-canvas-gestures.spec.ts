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

const THREAT_MODEL_ID =
  process.env.TG_E2E_THREAT_MODEL_ID ?? "00000000-0000-0000-0000-000000000010";
const BASE_CANVAS_HARNESS_NAME = "Codex DFD Base Canvas Harness";
const BASE_CANVAS_NODE_ID = "30000000-0000-0000-0001-000000000001";
const NESTED_HARNESS_NAME = "Codex DFD Nested Boundary Harness";
const NESTED_PARENT_BOUNDARY_ID = "41000000-0000-0000-0002-000000000001";
const NESTED_CHILD_BOUNDARY_ID = "41000000-0000-0000-0002-000000000002";
const NESTED_MEMBER_NODE_ID = "41000000-0000-0000-0001-000000000001";
const GROUP_DRAG_HARNESS_NAME = "Codex DFD Group Drag Harness";
const GROUP_DRAG_BOUNDARY_ID = "42000000-0000-0000-0002-000000000001";
const GROUP_DRAG_CHILD_NODE_ID = "42000000-0000-0000-0001-000000000001";
const GROUP_DRAG_SOLO_NODE_ID = "42000000-0000-0000-0001-000000000002";
const GROUP_DRAG_EDGE_ID = "42000000-0000-0000-0003-000000000001";
const QUICK_ADD_HARNESS_PREFIX = "Codex DFD Quick Add Harness";
const DFD_READY_TIMEOUT_MS = 30000;

function parseTranslate(transform: string): { x: number; y: number } {
  if (!transform || transform === "none") {
    return { x: 0, y: 0 };
  }

  const matrix3dMatch = transform.match(/^matrix3d\((.+)\)$/);
  if (matrix3dMatch) {
    const values = matrix3dMatch[1].split(",").map((value) => Number.parseFloat(value.trim()));
    return { x: values[12] ?? 0, y: values[13] ?? 0 };
  }

  const matrixMatch = transform.match(/^matrix\((.+)\)$/);
  if (matrixMatch) {
    const values = matrixMatch[1].split(",").map((value) => Number.parseFloat(value.trim()));
    return { x: values[4] ?? 0, y: values[5] ?? 0 };
  }

  return { x: 0, y: 0 };
}

async function ensureNestedBoundaryHarness(
  request: APIRequestContext,
  token: string
): Promise<string> {
  const listResponse = await request.get(`${API_BASE_URL}/threat-models`, {
    headers: buildAuthHeaders(token),
  });
  expect(listResponse.ok()).toBeTruthy();
  const models = (await listResponse.json()) as Array<{
    id: string;
    system_name: string;
  }>;

  let threatModelId = models.find((model) => model.system_name === NESTED_HARNESS_NAME)?.id;
  if (!threatModelId) {
    const createResponse = await request.post(`${API_BASE_URL}/threat-models`, {
      headers: {
        ...buildAuthHeaders(token),
        "Content-Type": "application/json",
      },
      data: {
        system_name: NESTED_HARNESS_NAME,
        description: "Reusable e2e harness for nested trust boundary drag coverage.",
        data_classification: "Internal",
        deployment_model: "cloud",
      },
    });
    expect(createResponse.ok()).toBeTruthy();
    const createdModel = (await createResponse.json()) as { id: string };
    threatModelId = createdModel.id;
  }

  const saveResponse = await request.put(`${API_BASE_URL}/threat-models/${threatModelId}/dfd`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: {
      nodes: [
        {
          id: NESTED_MEMBER_NODE_ID,
          node_type: "process",
          name: "Nested Child Service",
          position_x: 860,
          position_y: 460,
          trust_boundary_id: NESTED_CHILD_BOUNDARY_ID,
          properties: {},
        },
      ],
      edges: [],
      trust_boundaries: [
        {
          id: NESTED_PARENT_BOUNDARY_ID,
          name: "Nested Parent Boundary",
          node_ids: [],
          position_x: 480,
          position_y: 180,
          width: 820,
          height: 520,
          boundary_type: "network",
          parent_boundary_id: null,
        },
        {
          id: NESTED_CHILD_BOUNDARY_ID,
          name: "Nested Child Boundary",
          node_ids: [NESTED_MEMBER_NODE_ID],
          position_x: 720,
          position_y: 360,
          width: 420,
          height: 240,
          boundary_type: "cloud",
          parent_boundary_id: NESTED_PARENT_BOUNDARY_ID,
        },
      ],
    },
  });
  expect(saveResponse.ok()).toBeTruthy();
  return threatModelId;
}

async function ensureBaseCanvasHarness(
  request: APIRequestContext,
  token: string
): Promise<string> {
  const listResponse = await request.get(`${API_BASE_URL}/threat-models`, {
    headers: buildAuthHeaders(token),
  });
  expect(listResponse.ok()).toBeTruthy();
  const models = (await listResponse.json()) as Array<{
    id: string;
    system_name: string;
  }>;

  let threatModelId = models.find((model) => model.system_name === BASE_CANVAS_HARNESS_NAME)?.id;
  if (!threatModelId) {
    const createResponse = await request.post(`${API_BASE_URL}/threat-models`, {
      headers: {
        ...buildAuthHeaders(token),
        "Content-Type": "application/json",
      },
      data: {
        system_name: BASE_CANVAS_HARNESS_NAME,
        description: "Reusable e2e harness for generic DFD canvas gesture setup.",
        data_classification: "Internal",
        deployment_model: "cloud",
      },
    });
    expect(createResponse.ok()).toBeTruthy();
    const createdModel = (await createResponse.json()) as { id: string };
    threatModelId = createdModel.id;
  }

  const saveResponse = await request.put(`${API_BASE_URL}/threat-models/${threatModelId}/dfd`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: {
      nodes: [
        {
          id: BASE_CANVAS_NODE_ID,
          node_type: "process",
          name: "Base Canvas Service",
          position_x: 360,
          position_y: 300,
          trust_boundary_id: null,
          properties: {},
        },
      ],
      edges: [],
      trust_boundaries: [],
    },
  });
  expect(saveResponse.ok()).toBeTruthy();
  return threatModelId;
}

async function ensureGroupDragHarness(
  request: APIRequestContext,
  token: string
): Promise<string> {
  const listResponse = await request.get(`${API_BASE_URL}/threat-models`, {
    headers: buildAuthHeaders(token),
  });
  expect(listResponse.ok()).toBeTruthy();
  const models = (await listResponse.json()) as Array<{
    id: string;
    system_name: string;
  }>;

  let threatModelId = models.find((model) => model.system_name === GROUP_DRAG_HARNESS_NAME)?.id;
  if (!threatModelId) {
    const createResponse = await request.post(`${API_BASE_URL}/threat-models`, {
      headers: {
        ...buildAuthHeaders(token),
        "Content-Type": "application/json",
      },
      data: {
        system_name: GROUP_DRAG_HARNESS_NAME,
        description: "Reusable e2e harness for mixed selection drag coverage.",
        data_classification: "Internal",
        deployment_model: "cloud",
      },
    });
    expect(createResponse.ok()).toBeTruthy();
    const createdModel = (await createResponse.json()) as { id: string };
    threatModelId = createdModel.id;
  }

  const saveResponse = await request.put(`${API_BASE_URL}/threat-models/${threatModelId}/dfd`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: {
      nodes: [
        {
          id: GROUP_DRAG_CHILD_NODE_ID,
          node_type: "process",
          name: "Boundary Child",
          position_x: 420,
          position_y: 260,
          trust_boundary_id: GROUP_DRAG_BOUNDARY_ID,
          properties: {},
        },
        {
          id: GROUP_DRAG_SOLO_NODE_ID,
          node_type: "process",
          name: "Solo Node",
          position_x: 940,
          position_y: 320,
          trust_boundary_id: null,
          properties: {},
        },
      ],
      edges: [
        {
          id: GROUP_DRAG_EDGE_ID,
          source_node_id: GROUP_DRAG_CHILD_NODE_ID,
          target_node_id: GROUP_DRAG_SOLO_NODE_ID,
          label: "",
          properties: {},
        },
      ],
      trust_boundaries: [
        {
          id: GROUP_DRAG_BOUNDARY_ID,
          name: "Group Drag Boundary",
          node_ids: [GROUP_DRAG_CHILD_NODE_ID],
          position_x: 240,
          position_y: 150,
          width: 420,
          height: 300,
          boundary_type: "network",
          parent_boundary_id: null,
        },
      ],
    },
  });
  expect(saveResponse.ok()).toBeTruthy();
  return threatModelId;
}

async function createQuickAddHarness(
  request: APIRequestContext,
  token: string
): Promise<{ threatModelId: string; nodeId: string }> {
  const nodeId = randomUUID();
  const createResponse = await request.post(`${API_BASE_URL}/threat-models`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: {
      system_name: `${QUICK_ADD_HARNESS_PREFIX} ${Date.now()}`,
      description: "Reusable e2e harness for palette-open quick-add coverage.",
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
          id: nodeId,
          node_type: "process",
          name: "Payment Processor",
          position_x: 300,
          position_y: 260,
          trust_boundary_id: null,
          properties: {
            authentication_type: "oauth2",
            network_exposure: "internal",
          },
        },
      ],
      edges: [],
      trust_boundaries: [],
    },
  });
  expect(saveResponse.ok()).toBeTruthy();
  return { threatModelId: createdModel.id, nodeId };
}

async function dragBox(
  page: Page,
  from: { x: number; y: number },
  to: { x: number; y: number },
  modifiers: Array<"Shift"> = []
) {
  for (const modifier of modifiers) {
    await page.keyboard.down(modifier);
  }

  await page.mouse.move(from.x, from.y);
  await page.mouse.down();
  await page.mouse.move(to.x, to.y, { steps: 24 });
  await page.mouse.up();

  for (const modifier of modifiers.slice().reverse()) {
    await page.keyboard.up(modifier);
  }
}

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

async function selectGroupDragHarnessItems(page: Page) {
  const pane = page.locator(".react-flow__pane");
  const boundary = page.locator(`.react-flow__node[data-id="${GROUP_DRAG_BOUNDARY_ID}"]`);
  const childNode = page.locator(`.react-flow__node[data-id="${GROUP_DRAG_CHILD_NODE_ID}"]`);
  const soloNode = page.locator(`.react-flow__node[data-id="${GROUP_DRAG_SOLO_NODE_ID}"]`);

  await expect(boundary).toBeVisible();
  await expect(childNode).toBeVisible();
  await expect(soloNode).toBeVisible();

  const paneBox = await pane.boundingBox();
  const boundaryBox = await boundary.boundingBox();
  const childBox = await childNode.boundingBox();
  const soloBox = await soloNode.boundingBox();

  expect(paneBox).not.toBeNull();
  expect(boundaryBox).not.toBeNull();
  expect(childBox).not.toBeNull();
  expect(soloBox).not.toBeNull();

  const start = {
    x: Math.max((paneBox?.x ?? 0) + 16, (boundaryBox?.x ?? 0) - 30),
    y: Math.max((paneBox?.y ?? 0) + 16, (boundaryBox?.y ?? 0) - 30),
  };
  const end = {
    x: Math.min(
      (paneBox?.x ?? 0) + (paneBox?.width ?? 0) - 16,
      (soloBox?.x ?? 0) + (soloBox?.width ?? 0) + 30
    ),
    y: Math.min(
      (paneBox?.y ?? 0) + (paneBox?.height ?? 0) - 16,
      Math.max(
        (boundaryBox?.y ?? 0) + (boundaryBox?.height ?? 0),
        (childBox?.y ?? 0) + (childBox?.height ?? 0),
        (soloBox?.y ?? 0) + (soloBox?.height ?? 0)
      ) + 30
    ),
  };

  await dragBox(page, start, end, ["Shift"]);

  await expect(boundary).toHaveClass(/selected/);
  await expect(childNode).toHaveClass(/selected/);
  await expect(soloNode).toHaveClass(/selected/);

  return { boundary, childNode, soloNode };
}

test.describe("DFD canvas gestures", () => {
  test.skip(!E2E_PASSWORD, "Set TG_E2E_PASSWORD to run the DFD canvas e2e checks.");
  test.describe.configure({ mode: "serial" });
  test.setTimeout(90000);

  let authToken: string;
  let baseThreatModelId = THREAT_MODEL_ID;

  test.beforeAll(async ({ request }) => {
    authToken = await loginForToken(request);
    if (!process.env.TG_E2E_THREAT_MODEL_ID) {
      baseThreatModelId = await ensureBaseCanvasHarness(request, authToken);
    }
  });

  test.beforeEach(async ({ page }) => {
    page.setDefaultTimeout(DFD_READY_TIMEOUT_MS);
    await seedAuthenticatedSession(authToken, page);
    await page.goto(`/threat-models/${baseThreatModelId}`);
    await waitForDfdReady(page);
  });

  test("Shift+drag marquee selects trust boundaries and components together", async ({
    page,
    request,
  }) => {
    const groupDragThreatModelId = await ensureGroupDragHarness(request, authToken);

    await page.goto(`/threat-models/${groupDragThreatModelId}`);
    await waitForDfdReady(page);
    await page.getByRole("button", { name: "Fit" }).click();

    const { boundary, childNode, soloNode } = await selectGroupDragHarnessItems(page);

    await expect(boundary).toHaveClass(/selected/);
    await expect(childNode).toHaveClass(/selected/);
    await expect(soloNode).toHaveClass(/selected/);
  });

  test("palette-open tablet layout keeps quick-add usable", async ({ page, request }) => {
    const { threatModelId, nodeId } = await createQuickAddHarness(request, authToken);

    await page.setViewportSize({ width: 960, height: 760 });
    await page.goto(`/threat-models/${threatModelId}`);

    await waitForDfdReady(page);
    await expect(page.getByRole("button", { name: "Hide Palette", exact: true })).toBeVisible();
    await expect(page.locator(".dfd-stencil-palette")).toBeVisible();

    const flowSurface = page.getByTestId("dfd-flow-surface");
    await expect(flowSurface).toBeVisible();
    const flowBox = await flowSurface.boundingBox();
    expect(flowBox).not.toBeNull();
    expect(flowBox?.width ?? 0).toBeGreaterThan(360);
    expect(flowBox?.height ?? 0).toBeGreaterThan(260);

    await page.getByRole("button", { name: "Fit" }).click();
    const node = page.locator(`.react-flow__node[data-id="${nodeId}"]`);
    await expect(node).toBeVisible();
    await node.locator('button[aria-label="Add or connect a downstream node"]').click();

    const quickMenu = page.locator('.dfd-spawn-menu[aria-label="Quick add DFD node"]');
    await expect(quickMenu).toBeVisible();
    const menuBox = await quickMenu.boundingBox();
    expect(menuBox).not.toBeNull();
    expect(menuBox?.x ?? 0).toBeGreaterThan(flowBox?.x ?? 0);
    expect((menuBox?.x ?? 0) + (menuBox?.width ?? 0)).toBeLessThanOrEqual(
      (flowBox?.x ?? 0) + (flowBox?.width ?? 0) + 4
    );

    await quickMenu.getByRole("button", { name: /Data Store/i }).click();
    await expect(page.locator(".dfd-edge-dialog")).toBeVisible({
      timeout: DFD_READY_TIMEOUT_MS,
    });
    await expect(page.getByText("2 nodes · 1 flows · 0 boundaries")).toBeVisible({
      timeout: DFD_READY_TIMEOUT_MS,
    });
  });

  test("blank-canvas drag pans the viewport", async ({ page }) => {
    const fitButton = page.getByRole("button", { name: "Fit" });
    await fitButton.click();

    const pane = page.locator(".react-flow__pane");
    const viewport = page.locator(".react-flow__viewport");
    const paneBox = await pane.boundingBox();

    expect(paneBox).not.toBeNull();

    const before = parseTranslate(await viewport.evaluate((element) => getComputedStyle(element).transform));

    await dragBox(
      page,
      {
        x: (paneBox?.x ?? 0) + (paneBox?.width ?? 0) - 48,
        y: (paneBox?.y ?? 0) + (paneBox?.height ?? 0) - 48,
      },
      {
        x: (paneBox?.x ?? 0) + (paneBox?.width ?? 0) - 220,
        y: (paneBox?.y ?? 0) + (paneBox?.height ?? 0) - 160,
      }
    );

    const after = parseTranslate(await viewport.evaluate((element) => getComputedStyle(element).transform));
    expect(Math.abs(after.x - before.x) + Math.abs(after.y - before.y)).toBeGreaterThan(10);
  });

  test("dragging a trust boundary carries its member nodes", async ({ page, request }) => {
    const groupDragThreatModelId = await ensureGroupDragHarness(request, authToken);

    await page.goto(`/threat-models/${groupDragThreatModelId}`);
    await waitForDfdReady(page);
    await page.getByRole("button", { name: "Fit" }).click();

    const boundary = page.locator(`.react-flow__node[data-id="${GROUP_DRAG_BOUNDARY_ID}"]`);
    const memberNode = page.locator(`.react-flow__node[data-id="${GROUP_DRAG_CHILD_NODE_ID}"]`);
    const dragHandle = boundary.locator(".dfd-boundary-drag-surface");

    await expect(boundary).toBeVisible();
    await expect(memberNode).toBeVisible();

    const beforeBoundaryBox = await boundary.boundingBox();
    const beforeMemberBox = await memberNode.boundingBox();
    const handleBox = await dragHandle.boundingBox();

    expect(beforeBoundaryBox).not.toBeNull();
    expect(beforeMemberBox).not.toBeNull();
    expect(handleBox).not.toBeNull();

    const delta = { x: 120, y: 80 };
    await page.mouse.move(
      (handleBox?.x ?? 0) + (handleBox?.width ?? 0) / 2,
      (handleBox?.y ?? 0) + (handleBox?.height ?? 0) / 2
    );
    await page.mouse.down();
    await page.mouse.move(
      (handleBox?.x ?? 0) + (handleBox?.width ?? 0) / 2 + delta.x,
      (handleBox?.y ?? 0) + (handleBox?.height ?? 0) / 2 + delta.y,
      { steps: 24 }
    );
    await page.mouse.up();

    const afterBoundaryBox = await boundary.boundingBox();
    const afterMemberBox = await memberNode.boundingBox();

    expect(afterBoundaryBox).not.toBeNull();
    expect(afterMemberBox).not.toBeNull();

    const boundaryDeltaX = (afterBoundaryBox?.x ?? 0) - (beforeBoundaryBox?.x ?? 0);
    const boundaryDeltaY = (afterBoundaryBox?.y ?? 0) - (beforeBoundaryBox?.y ?? 0);
    const memberDeltaX = (afterMemberBox?.x ?? 0) - (beforeMemberBox?.x ?? 0);
    const memberDeltaY = (afterMemberBox?.y ?? 0) - (beforeMemberBox?.y ?? 0);

    expect(boundaryDeltaX).toBeGreaterThan(100);
    expect(boundaryDeltaY).toBeGreaterThan(60);
    expect(Math.abs(memberDeltaX - boundaryDeltaX)).toBeLessThan(2);
    expect(Math.abs(memberDeltaY - boundaryDeltaY)).toBeLessThan(2);
  });

  test("dragging a parent boundary carries nested boundaries and nested members", async ({
    page,
    request,
  }) => {
    const nestedThreatModelId = await ensureNestedBoundaryHarness(request, authToken);

    await page.goto(`/threat-models/${nestedThreatModelId}`);
    await waitForDfdReady(page);
    await page.getByRole("button", { name: "Fit" }).click();

    const parentBoundary = page.locator(
      `[data-testid="dfd-trust-boundary"][data-boundary-id="${NESTED_PARENT_BOUNDARY_ID}"]`
    );
    const childBoundary = page.locator(
      `[data-testid="dfd-trust-boundary"][data-boundary-id="${NESTED_CHILD_BOUNDARY_ID}"]`
    );
    const nestedMemberNode = page.locator(
      `.react-flow__node[data-id="${NESTED_MEMBER_NODE_ID}"]`
    );
    const dragHandle = parentBoundary.locator(".dfd-boundary-drag-surface");

    await expect(parentBoundary).toBeVisible();
    await expect(childBoundary).toBeVisible();
    await expect(nestedMemberNode).toBeVisible();

    const beforeParentBoundaryBox = await parentBoundary.boundingBox();
    const beforeChildBoundaryBox = await childBoundary.boundingBox();
    const beforeNestedMemberBox = await nestedMemberNode.boundingBox();
    const handleBox = await dragHandle.boundingBox();

    expect(beforeParentBoundaryBox).not.toBeNull();
    expect(beforeChildBoundaryBox).not.toBeNull();
    expect(beforeNestedMemberBox).not.toBeNull();
    expect(handleBox).not.toBeNull();

    const delta = { x: 140, y: 96 };
    await page.mouse.move(
      (handleBox?.x ?? 0) + (handleBox?.width ?? 0) / 2,
      (handleBox?.y ?? 0) + (handleBox?.height ?? 0) / 2
    );
    await page.mouse.down();
    await page.mouse.move(
      (handleBox?.x ?? 0) + (handleBox?.width ?? 0) / 2 + delta.x,
      (handleBox?.y ?? 0) + (handleBox?.height ?? 0) / 2 + delta.y,
      { steps: 24 }
    );
    await page.mouse.up();

    const afterParentBoundaryBox = await parentBoundary.boundingBox();
    const afterChildBoundaryBox = await childBoundary.boundingBox();
    const afterNestedMemberBox = await nestedMemberNode.boundingBox();

    expect(afterParentBoundaryBox).not.toBeNull();
    expect(afterChildBoundaryBox).not.toBeNull();
    expect(afterNestedMemberBox).not.toBeNull();

    const parentDeltaX = (afterParentBoundaryBox?.x ?? 0) - (beforeParentBoundaryBox?.x ?? 0);
    const parentDeltaY = (afterParentBoundaryBox?.y ?? 0) - (beforeParentBoundaryBox?.y ?? 0);
    const childDeltaX = (afterChildBoundaryBox?.x ?? 0) - (beforeChildBoundaryBox?.x ?? 0);
    const childDeltaY = (afterChildBoundaryBox?.y ?? 0) - (beforeChildBoundaryBox?.y ?? 0);
    const memberDeltaX = (afterNestedMemberBox?.x ?? 0) - (beforeNestedMemberBox?.x ?? 0);
    const memberDeltaY = (afterNestedMemberBox?.y ?? 0) - (beforeNestedMemberBox?.y ?? 0);

    expect(parentDeltaX).toBeGreaterThan(120);
    expect(parentDeltaY).toBeGreaterThan(80);
    expect(Math.abs(childDeltaX - parentDeltaX)).toBeLessThan(2);
    expect(Math.abs(childDeltaY - parentDeltaY)).toBeLessThan(2);
    expect(Math.abs(memberDeltaX - parentDeltaX)).toBeLessThan(2);
    expect(Math.abs(memberDeltaY - parentDeltaY)).toBeLessThan(2);
  });

  test("dragging a selected component moves the whole mixed selection", async ({
    page,
    request,
  }) => {
    const groupDragThreatModelId = await ensureGroupDragHarness(request, authToken);

    await page.goto(`/threat-models/${groupDragThreatModelId}`);
    await waitForDfdReady(page);
    await page.getByRole("button", { name: "Fit" }).click();

    const { boundary, childNode, soloNode } = await selectGroupDragHarnessItems(page);

    const beforeBoundaryBox = await boundary.boundingBox();
    const beforeChildBox = await childNode.boundingBox();
    const beforeSoloBox = await soloNode.boundingBox();

    expect(beforeBoundaryBox).not.toBeNull();
    expect(beforeChildBox).not.toBeNull();
    expect(beforeSoloBox).not.toBeNull();

    const delta = { x: 140, y: 90 };
    await page.mouse.move(
      (beforeSoloBox?.x ?? 0) + (beforeSoloBox?.width ?? 0) / 2,
      (beforeSoloBox?.y ?? 0) + (beforeSoloBox?.height ?? 0) / 2
    );
    await page.mouse.down();
    await page.mouse.move(
      (beforeSoloBox?.x ?? 0) + (beforeSoloBox?.width ?? 0) / 2 + delta.x,
      (beforeSoloBox?.y ?? 0) + (beforeSoloBox?.height ?? 0) / 2 + delta.y,
      { steps: 30 }
    );
    await page.mouse.up();

    const afterBoundaryBox = await boundary.boundingBox();
    const afterChildBox = await childNode.boundingBox();
    const afterSoloBox = await soloNode.boundingBox();

    expect(afterBoundaryBox).not.toBeNull();
    expect(afterChildBox).not.toBeNull();
    expect(afterSoloBox).not.toBeNull();

    const boundaryDeltaX = (afterBoundaryBox?.x ?? 0) - (beforeBoundaryBox?.x ?? 0);
    const boundaryDeltaY = (afterBoundaryBox?.y ?? 0) - (beforeBoundaryBox?.y ?? 0);
    const childDeltaX = (afterChildBox?.x ?? 0) - (beforeChildBox?.x ?? 0);
    const childDeltaY = (afterChildBox?.y ?? 0) - (beforeChildBox?.y ?? 0);
    const soloDeltaX = (afterSoloBox?.x ?? 0) - (beforeSoloBox?.x ?? 0);
    const soloDeltaY = (afterSoloBox?.y ?? 0) - (beforeSoloBox?.y ?? 0);

    expect(boundaryDeltaX).toBeGreaterThan(120);
    expect(boundaryDeltaY).toBeGreaterThan(70);
    expect(Math.abs(childDeltaX - boundaryDeltaX)).toBeLessThan(2);
    expect(Math.abs(childDeltaY - boundaryDeltaY)).toBeLessThan(2);
    expect(Math.abs(soloDeltaX - boundaryDeltaX)).toBeLessThan(2);
    expect(Math.abs(soloDeltaY - boundaryDeltaY)).toBeLessThan(2);
  });

  test("dragging a selected trust boundary moves the whole mixed selection", async ({
    page,
    request,
  }) => {
    const groupDragThreatModelId = await ensureGroupDragHarness(request, authToken);

    await page.goto(`/threat-models/${groupDragThreatModelId}`);
    await waitForDfdReady(page);
    await page.getByRole("button", { name: "Fit" }).click();

    const { boundary, childNode, soloNode } = await selectGroupDragHarnessItems(page);
    const dragHandle = boundary.locator(".dfd-boundary-drag-surface");

    const beforeBoundaryBox = await boundary.boundingBox();
    const beforeChildBox = await childNode.boundingBox();
    const beforeSoloBox = await soloNode.boundingBox();
    const handleBox = await dragHandle.boundingBox();

    expect(beforeBoundaryBox).not.toBeNull();
    expect(beforeChildBox).not.toBeNull();
    expect(beforeSoloBox).not.toBeNull();
    expect(handleBox).not.toBeNull();

    const delta = { x: 120, y: 84 };
    await page.mouse.move(
      (handleBox?.x ?? 0) + (handleBox?.width ?? 0) / 2,
      (handleBox?.y ?? 0) + (handleBox?.height ?? 0) / 2
    );
    await page.mouse.down();
    await page.mouse.move(
      (handleBox?.x ?? 0) + (handleBox?.width ?? 0) / 2 + delta.x,
      (handleBox?.y ?? 0) + (handleBox?.height ?? 0) / 2 + delta.y,
      { steps: 30 }
    );
    await page.mouse.up();

    const afterBoundaryBox = await boundary.boundingBox();
    const afterChildBox = await childNode.boundingBox();
    const afterSoloBox = await soloNode.boundingBox();

    expect(afterBoundaryBox).not.toBeNull();
    expect(afterChildBox).not.toBeNull();
    expect(afterSoloBox).not.toBeNull();

    const boundaryDeltaX = (afterBoundaryBox?.x ?? 0) - (beforeBoundaryBox?.x ?? 0);
    const boundaryDeltaY = (afterBoundaryBox?.y ?? 0) - (beforeBoundaryBox?.y ?? 0);
    const childDeltaX = (afterChildBox?.x ?? 0) - (beforeChildBox?.x ?? 0);
    const childDeltaY = (afterChildBox?.y ?? 0) - (beforeChildBox?.y ?? 0);
    const soloDeltaX = (afterSoloBox?.x ?? 0) - (beforeSoloBox?.x ?? 0);
    const soloDeltaY = (afterSoloBox?.y ?? 0) - (beforeSoloBox?.y ?? 0);

    expect(boundaryDeltaX).toBeGreaterThan(100);
    expect(boundaryDeltaY).toBeGreaterThan(60);
    expect(Math.abs(childDeltaX - boundaryDeltaX)).toBeLessThan(2);
    expect(Math.abs(childDeltaY - boundaryDeltaY)).toBeLessThan(2);
    expect(Math.abs(soloDeltaX - boundaryDeltaX)).toBeLessThan(2);
    expect(Math.abs(soloDeltaY - boundaryDeltaY)).toBeLessThan(2);
  });
});

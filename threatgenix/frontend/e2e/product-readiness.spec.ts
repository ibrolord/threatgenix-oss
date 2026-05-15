import { randomUUID } from "node:crypto";

import { expect, test } from "@playwright/test";
import type { APIRequestContext, APIResponse, Page } from "@playwright/test";

import {
  API_BASE_URL,
  E2E_PASSWORD,
  buildAuthHeaders,
  seedAuthenticatedSession,
} from "./helpers/auth";

const PRODUCT_READY_TIMEOUT_MS = 45000;

interface ProductReadinessHarness {
  threatModelId: string;
  systemName: string;
  threatCount: number;
  firstThreatId: string;
}

interface JourneyUser {
  token: string;
  email: string;
  organizationId: string | null;
  organizationName: string | null;
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

async function expectApiOk(response: APIResponse) {
  if (!response.ok()) {
    throw new Error(`API request failed (${response.status()}): ${await response.text()}`);
  }
}

async function registerJourneyUser(
  request: APIRequestContext,
  options: {
    emailPrefix?: string;
    fullName?: string;
  } = {},
): Promise<JourneyUser> {
  const prefix = (options.emailPrefix ?? "product-readiness")
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  const email = `threatgenix-${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@local.test`;
  const password = E2E_PASSWORD!;
  const registerResponse = await request.post(`${API_BASE_URL}/auth/register`, {
    data: {
      email,
      password,
      full_name: options.fullName ?? "ThreatGenix Product Readiness QA",
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
    data: { email, password },
  });
  await expectApiOk(loginResponse);
  const payload = (await loginResponse.json()) as { access_token: string };
  expect(payload.access_token).toBeTruthy();

  const meResponse = await request.get(`${API_BASE_URL}/auth/me`, {
    headers: buildAuthHeaders(payload.access_token),
  });
  await expectApiOk(meResponse);
  const me = (await meResponse.json()) as {
    organization_id?: string | null;
    organization_name?: string | null;
  };

  return {
    token: payload.access_token,
    email,
    organizationId: me.organization_id ?? null,
    organizationName: me.organization_name ?? null,
  };
}

async function createProductReadinessHarness(
  request: APIRequestContext,
  token: string,
  options: {
    systemNamePrefix?: string;
    description?: string;
  } = {},
): Promise<ProductReadinessHarness> {
  const systemName = `${options.systemNamePrefix ?? "Codex Product Readiness"} ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const boundaryExternal = randomUUID();
  const boundaryInternal = randomUUID();
  const mobileClient = randomUUID();
  const apiGateway = randomUUID();
  const coreApi = randomUUID();
  const customerDb = randomUUID();
  const auditLog = randomUUID();

  const createResponse = await request.post(`${API_BASE_URL}/threat-models`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: {
      system_name: systemName,
      description: options.description ?? "Customer journey harness for product-readiness QA.",
      data_classification: "Restricted",
      regulatory_scope: ["OSFI B-13", "PCI DSS", "NIST", "ISO 27001"],
      deployment_model: "cloud",
    },
  });
  await expectApiOk(createResponse);
  const createdModel = (await createResponse.json()) as { id: string };

  const saveDfdResponse = await request.put(
    `${API_BASE_URL}/threat-models/${createdModel.id}/dfd`,
    {
      headers: {
        ...buildAuthHeaders(token),
        "Content-Type": "application/json",
      },
      data: {
        nodes: [
          {
            id: mobileClient,
            node_type: "external_entity",
            name: "Mobile Banking Customer",
            position_x: 80,
            position_y: 220,
            properties: {
              network_exposure: "internet",
              trust_level: "untrusted",
            },
          },
          {
            id: apiGateway,
            node_type: "process",
            name: "Payments API Gateway",
            position_x: 360,
            position_y: 220,
            trust_boundary_id: boundaryExternal,
            properties: {
              network_exposure: "internet",
              authentication_type: "none",
              encryption: "none",
              input_validation: "none",
              handles_sensitive_data: true,
            },
          },
          {
            id: coreApi,
            node_type: "process",
            name: "Core Banking API",
            position_x: 680,
            position_y: 220,
            trust_boundary_id: boundaryInternal,
            properties: {
              authentication_type: "oauth2",
              encryption: "tls",
              handles_sensitive_data: true,
            },
          },
          {
            id: customerDb,
            node_type: "data_store",
            name: "Customer Ledger Database",
            position_x: 980,
            position_y: 160,
            trust_boundary_id: boundaryInternal,
            properties: {
              data_classification: "Restricted",
              stores_sensitive_data: true,
            },
          },
          {
            id: auditLog,
            node_type: "data_store",
            name: "Security Audit Log",
            position_x: 980,
            position_y: 360,
            trust_boundary_id: boundaryInternal,
            properties: {
              data_classification: "Confidential",
            },
          },
        ],
        edges: [
          {
            id: randomUUID(),
            source_node_id: mobileClient,
            target_node_id: apiGateway,
            label: "payment token request with customer PII",
            properties: { data_classification: "Restricted", encryption: "none" },
          },
          {
            id: randomUUID(),
            source_node_id: apiGateway,
            target_node_id: coreApi,
            label: "payment initiation command",
            properties: { data_classification: "Restricted" },
          },
          {
            id: randomUUID(),
            source_node_id: coreApi,
            target_node_id: customerDb,
            label: "ledger write and account lookup",
            properties: { data_classification: "Restricted" },
          },
          {
            id: randomUUID(),
            source_node_id: coreApi,
            target_node_id: auditLog,
            label: "security event record",
            properties: { data_classification: "Confidential" },
          },
        ],
        trust_boundaries: [
          {
            id: boundaryExternal,
            name: "External Edge",
            node_ids: [apiGateway],
            position_x: 290,
            position_y: 120,
            width: 260,
            height: 260,
            boundary_type: "network",
            parent_boundary_id: null,
          },
          {
            id: boundaryInternal,
            name: "Restricted Banking Zone",
            node_ids: [coreApi, customerDb, auditLog],
            position_x: 620,
            position_y: 80,
            width: 520,
            height: 420,
            boundary_type: "cloud",
            parent_boundary_id: null,
          },
        ],
      },
    },
  );
  await expectApiOk(saveDfdResponse);

  const generateResponse = await request.post(
    `${API_BASE_URL}/threat-models/${createdModel.id}/threats/generate`,
    { headers: buildAuthHeaders(token) },
  );
  await expectApiOk(generateResponse);
  const generated = (await generateResponse.json()) as {
    threats: Array<{ display_id: string }>;
    warnings?: string[];
  };
  expect(generated.warnings ?? []).toEqual([]);
  expect(generated.threats.length).toBeGreaterThan(0);

  const threatsResponse = await request.get(
    `${API_BASE_URL}/threat-models/${createdModel.id}/threats`,
    { headers: buildAuthHeaders(token) },
  );
  await expectApiOk(threatsResponse);
  const threats = (await threatsResponse.json()) as Array<{ id: string; display_id: string }>;
  expect(threats.length).toBe(generated.threats.length);

  const triageResponse = await request.patch(
    `${API_BASE_URL}/threat-models/${createdModel.id}/threats/${threats[0]!.id}/triage`,
    {
      headers: {
        ...buildAuthHeaders(token),
        "Content-Type": "application/json",
      },
      data: {
        status: "In Progress",
        mitigation_owner: "product-security",
        control_effectiveness: "partial",
        mitigation_notes: "Product-readiness journey verifies audit and review state.",
      },
    },
  );
  await expectApiOk(triageResponse);

  const historyResponse = await request.get(
    `${API_BASE_URL}/threat-models/${createdModel.id}/threats/${threats[0]!.id}/history`,
    { headers: buildAuthHeaders(token) },
  );
  await expectApiOk(historyResponse);
  const history = (await historyResponse.json()) as Array<{ action: string }>;
  expect(history.map((entry) => entry.action)).toContain("triaged");

  const sandboxResponse = await request.post(
    `${API_BASE_URL}/threat-models/${createdModel.id}/validation-lab/try-sandbox`,
    { headers: buildAuthHeaders(token) },
  );
  await expectApiOk(sandboxResponse);

  const validationLabResponse = await request.get(
    `${API_BASE_URL}/threat-models/${createdModel.id}/validation-lab`,
    { headers: buildAuthHeaders(token) },
  );
  await expectApiOk(validationLabResponse);
  const validationLab = (await validationLabResponse.json()) as {
    tools: Array<{ name: string }>;
    evidence_ledger: unknown[];
  };
  expect(validationLab.tools.map((tool) => tool.name).sort()).toEqual([
    "ai-red-team",
    "checkov",
    "nuclei",
    "osv-scanner",
    "semgrep",
    "trivy",
    "trufflehog",
  ]);
  expect(validationLab.evidence_ledger.length).toBeGreaterThan(0);

  const reviewResponse = await request.get(
    `${API_BASE_URL}/threat-models/${createdModel.id}/review`,
    { headers: buildAuthHeaders(token) },
  );
  await expectApiOk(reviewResponse);
  const review = (await reviewResponse.json()) as { focus_statement: string };
  expect(review.focus_statement).toBeTruthy();

  const findingsResponse = await request.get(
    `${API_BASE_URL}/threat-models/${createdModel.id}/review-findings`,
    { headers: buildAuthHeaders(token) },
  );
  await expectApiOk(findingsResponse);
  const findings = (await findingsResponse.json()) as { findings: unknown[] };
  expect(findings.findings.length).toBeGreaterThan(0);

  const csvResponse = await request.get(
    `${API_BASE_URL}/threat-models/${createdModel.id}/threats/export.csv`,
    { headers: buildAuthHeaders(token) },
  );
  await expectApiOk(csvResponse);
  expect(await csvResponse.text()).toContain("STRIDE Category");

  const tmacResponse = await request.get(
    `${API_BASE_URL}/threat-models/${createdModel.id}/tmac?format=yaml&include_operational_state=true&include_binary_assets=false`,
    { headers: buildAuthHeaders(token) },
  );
  await expectApiOk(tmacResponse);
  const tmacContent = await tmacResponse.text();
  expect(tmacContent).toContain(systemName);

  const tmacValidationResponse = await request.post(`${API_BASE_URL}/threat-models/tmac/validate`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: { content: tmacContent },
  });
  await expectApiOk(tmacValidationResponse);

  return {
    threatModelId: createdModel.id,
    systemName,
    threatCount: threats.length,
    firstThreatId: threats[0]!.id,
  };
}

async function createMinimalThreatModel(
  request: APIRequestContext,
  token: string,
  systemNamePrefix: string,
) {
  const systemName = `${systemNamePrefix} ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const response = await request.post(`${API_BASE_URL}/threat-models`, {
    headers: {
      ...buildAuthHeaders(token),
      "Content-Type": "application/json",
    },
    data: {
      system_name: systemName,
      description: "Tenant-isolation control model for cross-tenant QA.",
      data_classification: "Confidential",
      regulatory_scope: ["SOC 2", "HIPAA"],
      deployment_model: "cloud",
    },
  });
  await expectApiOk(response);
  return (await response.json()) as { id: string; system_name: string };
}

async function expectTenantBoundary(response: APIResponse, forbiddenText: string) {
  expect([403, 404]).toContain(response.status());
  const body = await response.text();
  expect(body).not.toContain(forbiddenText);
}

test.describe("product-readiness customer journey", () => {
  test.skip(!E2E_PASSWORD, "Set TG_E2E_PASSWORD to run product-readiness journey coverage.");
  test.setTimeout(150000);

  test("creates a threat model through the buyer-facing intake form", async ({
    page,
    request,
  }) => {
    page.setDefaultTimeout(PRODUCT_READY_TIMEOUT_MS);
    const runtimeFailures = attachRuntimeFailureGuards(page);
    const journeyUser = await registerJourneyUser(request, {
      emailPrefix: "buyer-intake",
      fullName: "Buyer Intake QA",
    });
    await seedAuthenticatedSession(journeyUser.token, page);
    const systemName = `Buyer Intake Payments ${Date.now()}`;

    await page.goto("/new");
    await page.getByRole("button", { name: "Create New Threat Model" }).click();
    await page.getByLabel("System Name").fill(systemName);
    await page.getByLabel("Description").fill("Browser-created model for the buyer-facing intake journey.");
    await page.getByLabel("Data Classification").selectOption("Restricted");
    await page.getByLabel("Deployment Model").selectOption("cloud");
    await page.getByLabel(/OSFI B-13/).check();
    await page.getByRole("button", { name: "Create Threat Model" }).click();

    await expect(page).toHaveURL(/\/threat-models\/[0-9a-f-]+$/);
    await expect(page.getByRole("heading", { name: systemName })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Data Flow Diagram" })).toBeVisible();
    expect(runtimeFailures).toEqual([]);
  });

  test("covers modeling, threats, review, validation, audit, and exports", async ({
    page,
    request,
  }, testInfo) => {
    page.setDefaultTimeout(PRODUCT_READY_TIMEOUT_MS);
    const runtimeFailures = attachRuntimeFailureGuards(page);
    const journeyUser = await registerJourneyUser(request);
    const authToken = journeyUser.token;
    const harness = await createProductReadinessHarness(request, authToken);

    await seedAuthenticatedSession(authToken, page);
    await page.goto(`/threat-models/${harness.threatModelId}`);
    await expect(page.getByRole("heading", { name: harness.systemName })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Data Flow Diagram" })).toBeVisible();
    await expect(page.getByText("Review Findings")).toBeVisible();
    await expect(page.getByText("Payments API Gateway", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Generate Threat Model Document" }).click();
    await expect(page.getByRole("heading", { name: "Generate Threat Model Document" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Generate Document PDF" })).toBeVisible();
    await page.getByRole("button", { name: "Cancel" }).click();
    await page.getByRole("button", { name: "TMAC" }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.keyboard.press("Escape");

    await page.getByRole("link", { name: "Security Review" }).click();
    await expect(page).toHaveURL(new RegExp(`/threat-models/${harness.threatModelId}/review`));
    await expect(page.getByRole("heading", { name: "Security Review" })).toBeVisible();
    await expect(page.getByText(`${harness.threatCount} threats in current review scope`)).toBeVisible();

    await page.getByRole("tab", { name: "Findings" }).click();
    await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible({
      timeout: PRODUCT_READY_TIMEOUT_MS,
    });

    await page.getByRole("tab", { name: "Compliance" }).click();
    await expect(page.getByRole("heading", { name: "Compliance" })).toBeVisible({
      timeout: PRODUCT_READY_TIMEOUT_MS,
    });

    await page.getByRole("tab", { name: /Model Health/ }).click();
    await expect(page.getByRole("heading", { name: "Model Quality" })).toBeVisible({
      timeout: PRODUCT_READY_TIMEOUT_MS,
    });

    await page.getByRole("tab", { name: /^Report/ }).click();
    await expect(page.getByText("Stakeholder report")).toBeVisible({
      timeout: PRODUCT_READY_TIMEOUT_MS,
    });
    await expect(page.getByText("Executive Readout")).toBeVisible({
      timeout: PRODUCT_READY_TIMEOUT_MS,
    });

    await page.goto(`/threat-models/${harness.threatModelId}/validation-lab`);
    await expect(page.getByRole("heading", { name: "Deterministic Evidence Workspace" })).toBeVisible();
    await expect(page.getByText("Tool Readiness")).toBeVisible();
    await expect(page.getByText("Validation Cases")).toBeVisible();
    await expect(page.getByText("Evidence Ledger")).toBeVisible();

    await page.getByRole("link", { name: "Report" }).click();
    await expect(page).toHaveURL(new RegExp(`/threat-models/${harness.threatModelId}/review\\?tab=report`));
    await expect(page.getByText("Stakeholder report")).toBeVisible({
      timeout: PRODUCT_READY_TIMEOUT_MS,
    });

    await page.screenshot({
      path: testInfo.outputPath("product-readiness-journey.png"),
      fullPage: true,
    });

    expect(runtimeFailures).toEqual([]);
  });

  test("proves unique tenant isolation across API and UI", async ({
    page,
    request,
  }, testInfo) => {
    page.setDefaultTimeout(PRODUCT_READY_TIMEOUT_MS);
    const runtimeFailures = attachRuntimeFailureGuards(page);

    const bankTenant = await registerJourneyUser(request, {
      emailPrefix: "aster-bank-payments",
      fullName: "Aster Bank Product Security",
    });
    const healthTenant = await registerJourneyUser(request, {
      emailPrefix: "harbor-health-claims",
      fullName: "Harbor Health Security",
    });

    expect(bankTenant.organizationId).toBeTruthy();
    expect(healthTenant.organizationId).toBeTruthy();
    expect(bankTenant.organizationId).not.toBe(healthTenant.organizationId);

    const bankHarness = await createProductReadinessHarness(request, bankTenant.token, {
      systemNamePrefix: "Aster Bank Real-Time Payments",
      description:
        "Real-world tenant-isolation QA for an internet-facing payments API handling restricted account data.",
    });
    const healthModel = await createMinimalThreatModel(
      request,
      healthTenant.token,
      "Harbor Health Claims Intake",
    );

    const bankListResponse = await request.get(`${API_BASE_URL}/threat-models`, {
      headers: buildAuthHeaders(bankTenant.token),
    });
    await expectApiOk(bankListResponse);
    const bankModels = (await bankListResponse.json()) as Array<{ system_name: string }>;
    expect(bankModels.map((model) => model.system_name)).toContain(bankHarness.systemName);
    expect(bankModels.map((model) => model.system_name)).not.toContain(healthModel.system_name);

    const healthListResponse = await request.get(`${API_BASE_URL}/threat-models`, {
      headers: buildAuthHeaders(healthTenant.token),
    });
    await expectApiOk(healthListResponse);
    const healthModels = (await healthListResponse.json()) as Array<{ system_name: string }>;
    expect(healthModels.map((model) => model.system_name)).toContain(healthModel.system_name);
    expect(healthModels.map((model) => model.system_name)).not.toContain(bankHarness.systemName);

    const healthHeaders = buildAuthHeaders(healthTenant.token);
    await expectTenantBoundary(
      await request.get(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}`, {
        headers: healthHeaders,
      }),
      bankHarness.systemName,
    );
    await expectTenantBoundary(
      await request.get(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/dfd`, {
        headers: healthHeaders,
      }),
      "Payments API Gateway",
    );
    await expectTenantBoundary(
      await request.get(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/threats`, {
        headers: healthHeaders,
      }),
      bankHarness.systemName,
    );
    await expectTenantBoundary(
      await request.get(
        `${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/threats/export.csv`,
        { headers: healthHeaders },
      ),
      "Payments API Gateway",
    );
    await expectTenantBoundary(
      await request.get(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/evidence/status`, {
        headers: healthHeaders,
      }),
      bankHarness.systemName,
    );
    await expectTenantBoundary(
      await request.post(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/evidence/rebuild`, {
        headers: healthHeaders,
      }),
      bankHarness.systemName,
    );
    await expectTenantBoundary(
      await request.get(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/review`, {
        headers: healthHeaders,
      }),
      bankHarness.systemName,
    );
    await expectTenantBoundary(
      await request.get(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/review-findings`, {
        headers: healthHeaders,
      }),
      bankHarness.systemName,
    );
    await expectTenantBoundary(
      await request.get(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/validation-lab`, {
        headers: healthHeaders,
      }),
      bankHarness.systemName,
    );
    await expectTenantBoundary(
      await request.get(
        `${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/tmac?format=yaml&include_operational_state=true`,
        { headers: healthHeaders },
      ),
      bankHarness.systemName,
    );
    await expectTenantBoundary(
      await request.put(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/report-config`, {
        headers: {
          ...healthHeaders,
          "Content-Type": "application/json",
        },
        data: { report_template: "executive" },
      }),
      bankHarness.systemName,
    );
    await expectTenantBoundary(
      await request.post(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/report`, {
        headers: {
          ...healthHeaders,
          "Content-Type": "application/json",
        },
        data: { threat_model_id: bankHarness.threatModelId, dfd_image_base64: "", sections: [] },
      }),
      bankHarness.systemName,
    );
    await expectTenantBoundary(
      await request.post(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/orchestration/jobs`, {
        headers: {
          ...healthHeaders,
          "Content-Type": "application/json",
        },
        data: {
          job_kind: "validation_run",
          objective: "Cross-tenant orchestration attempt should fail.",
          requested_tools: ["semgrep"],
        },
      }),
      bankHarness.systemName,
    );
    await expectTenantBoundary(
      await request.patch(
        `${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/threats/${bankHarness.firstThreatId}/triage`,
        {
          headers: {
            ...healthHeaders,
            "Content-Type": "application/json",
          },
          data: {
            status: "In Progress",
            mitigation_owner: "harbor-health-security",
            mitigation_notes: "Cross-tenant mutation attempt must be rejected.",
          },
        },
      ),
      bankHarness.firstThreatId,
    );
    await expectTenantBoundary(
      await request.put(`${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/dfd`, {
        headers: {
          ...healthHeaders,
          "Content-Type": "application/json",
        },
        data: {
          nodes: [],
          edges: [],
          trust_boundaries: [],
        },
      }),
      "Payments API Gateway",
    );

    const ownerDfdResponse = await request.get(
      `${API_BASE_URL}/threat-models/${bankHarness.threatModelId}/dfd`,
      { headers: buildAuthHeaders(bankTenant.token) },
    );
    await expectApiOk(ownerDfdResponse);
    const ownerDfd = (await ownerDfdResponse.json()) as {
      nodes: Array<{ name: string }>;
    };
    expect(ownerDfd.nodes.map((node) => node.name)).toContain("Payments API Gateway");

    await seedAuthenticatedSession(healthTenant.token, page);
    await page.goto(`/threat-models/${bankHarness.threatModelId}`);
    await expect(
      page.getByRole("heading", { name: /Something went wrong|Threat model not found/ }),
    ).toBeVisible({ timeout: PRODUCT_READY_TIMEOUT_MS });
    await expect(page.getByText(bankHarness.systemName)).toHaveCount(0);

    await page.goto(`/threat-models/${bankHarness.threatModelId}/review`);
    await expect(page.getByRole("heading", { name: "Security review not found" })).toBeVisible({
      timeout: PRODUCT_READY_TIMEOUT_MS,
    });
    await expect(page.getByText(bankHarness.systemName)).toHaveCount(0);

    await page.goto(`/threat-models/${bankHarness.threatModelId}/validation-lab`);
    await expect(page.getByRole("heading", { name: "Deterministic Evidence Workspace" })).toBeVisible({
      timeout: PRODUCT_READY_TIMEOUT_MS,
    });
    await expect(page.getByText("Validation lab unavailable.")).toBeVisible();
    await expect(page.getByText(/may not have access/i)).toBeVisible();
    await expect(page.getByText(bankHarness.systemName)).toHaveCount(0);
    await expect(page.getByText("403: Access denied")).toHaveCount(0);

    await page.screenshot({
      path: testInfo.outputPath("unique-tenant-isolation.png"),
      fullPage: true,
    });

    const unexpectedRuntimeFailures = runtimeFailures.filter(
      (failure) => !failure.includes("status of 403 (Forbidden)"),
    );
    expect(unexpectedRuntimeFailures).toEqual([]);
    expect(runtimeFailures.length).toBeGreaterThan(0);
  });
});

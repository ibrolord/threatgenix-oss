import type { DFDBulkSave, NodeProperties, NodeType } from "../../types/api";

interface DFDTemplateNodeDefinition {
  key: string;
  node_type: NodeType;
  name: string;
  position_x: number;
  position_y: number;
  trust_boundary_key?: string | null;
  properties?: NodeProperties;
}

interface DFDTemplateEdgeDefinition {
  source_key: string;
  target_key: string;
  label?: string;
}

interface DFDTemplateBoundaryDefinition {
  key: string;
  name: string;
  node_keys: string[];
}

export interface DFDTemplateDefinition {
  id: string;
  name: string;
  summary: string;
  domain: string;
  nodes: DFDTemplateNodeDefinition[];
  edges: DFDTemplateEdgeDefinition[];
  trust_boundaries: DFDTemplateBoundaryDefinition[];
}

function createTemplateId(): string {
  return crypto.randomUUID();
}

function getRequiredId(map: Map<string, string>, key: string, label: string): string {
  const value = map.get(key);
  if (!value) {
    throw new Error(`Missing ${label} id for template key "${key}"`);
  }
  return value;
}

export function materializeDFDTemplate(template: DFDTemplateDefinition): DFDBulkSave {
  const boundaryIdByKey = new Map(
    template.trust_boundaries.map((boundary) => [boundary.key, createTemplateId()])
  );
  const nodeIdByKey = new Map(template.nodes.map((node) => [node.key, createTemplateId()]));

  return {
    nodes: template.nodes.map((node) => ({
      id: getRequiredId(nodeIdByKey, node.key, "node"),
      node_type: node.node_type,
      name: node.name,
      position_x: node.position_x,
      position_y: node.position_y,
      trust_boundary_id: node.trust_boundary_key
        ? getRequiredId(boundaryIdByKey, node.trust_boundary_key, "boundary")
        : null,
      properties: node.properties ?? {},
    })),
    edges: template.edges.map((edge) => ({
      id: createTemplateId(),
      source_node_id: getRequiredId(nodeIdByKey, edge.source_key, "source node"),
      target_node_id: getRequiredId(nodeIdByKey, edge.target_key, "target node"),
      label: edge.label,
    })),
    trust_boundaries: template.trust_boundaries.map((boundary) => ({
      id: getRequiredId(boundaryIdByKey, boundary.key, "boundary"),
      name: boundary.name,
      node_ids: boundary.node_keys.map((nodeKey) =>
        getRequiredId(nodeIdByKey, nodeKey, "boundary member")
      ),
    })),
  };
}

export const dfdTemplates: DFDTemplateDefinition[] = [
  {
    id: "web-application",
    name: "Web Application",
    domain: "Banking",
    summary:
      "Standard web application architecture with browser client, load balancer, app server, database, and authentication service.",
    nodes: [
      {
        key: "browser",
        node_type: "external_entity",
        name: "Browser",
        position_x: 0,
        position_y: 120,
        properties: { internet_facing: true },
      },
      {
        key: "load-balancer",
        node_type: "process",
        name: "Load Balancer",
        position_x: 260,
        position_y: 120,
        trust_boundary_key: "dmz",
        properties: { internet_facing: true, uses_encryption: true },
      },
      {
        key: "app-server",
        node_type: "process",
        name: "App Server",
        position_x: 520,
        position_y: 120,
        trust_boundary_key: "internal",
        properties: { uses_auth: true, validates_input: true, uses_encryption: true },
      },
      {
        key: "auth-service",
        node_type: "process",
        name: "Auth Service",
        position_x: 520,
        position_y: 280,
        trust_boundary_key: "internal",
        properties: { uses_auth: true, uses_encryption: true, handles_sensitive_data: true },
      },
      {
        key: "postgresql",
        node_type: "data_store",
        name: "PostgreSQL",
        position_x: 780,
        position_y: 120,
        trust_boundary_key: "data-zone",
        properties: { encrypted_at_rest: true, has_backup: true },
      },
    ],
    edges: [
      { source_key: "browser", target_key: "load-balancer", label: "HTTPS request" },
      { source_key: "load-balancer", target_key: "app-server", label: "Forward request" },
      { source_key: "app-server", target_key: "postgresql", label: "SQL query" },
      { source_key: "postgresql", target_key: "app-server", label: "Query results" },
      { source_key: "app-server", target_key: "auth-service", label: "Token validation" },
    ],
    trust_boundaries: [
      { key: "dmz", name: "DMZ", node_keys: ["load-balancer"] },
      { key: "internal", name: "Internal Network", node_keys: ["app-server", "auth-service"] },
      { key: "data-zone", name: "Data Zone", node_keys: ["postgresql"] },
    ],
  },
  {
    id: "mobile-banking",
    name: "Mobile Banking",
    domain: "Banking",
    summary:
      "Mobile banking architecture with API gateway, authentication, core banking engine, and audit/customer data stores.",
    nodes: [
      {
        key: "mobile-app",
        node_type: "external_entity",
        name: "Mobile App",
        position_x: 0,
        position_y: 140,
        properties: { internet_facing: true },
      },
      {
        key: "api-gateway",
        node_type: "process",
        name: "API Gateway",
        position_x: 260,
        position_y: 140,
        trust_boundary_key: "edge",
        properties: { internet_facing: true, uses_auth: true, validates_input: true, uses_encryption: true },
      },
      {
        key: "auth-service",
        node_type: "process",
        name: "Auth Service",
        position_x: 520,
        position_y: 60,
        trust_boundary_key: "internal",
        properties: { uses_auth: true, uses_encryption: true, handles_sensitive_data: true },
      },
      {
        key: "core-banking",
        node_type: "process",
        name: "Core Banking",
        position_x: 520,
        position_y: 220,
        trust_boundary_key: "internal",
        properties: { uses_auth: true, handles_sensitive_data: true, uses_encryption: true },
      },
      {
        key: "customer-db",
        node_type: "data_store",
        name: "Customer DB",
        position_x: 780,
        position_y: 60,
        trust_boundary_key: "data-zone",
        properties: { stores_credentials: true, encrypted_at_rest: true, has_backup: true },
      },
      {
        key: "audit-log",
        node_type: "data_store",
        name: "Audit Log",
        position_x: 780,
        position_y: 220,
        trust_boundary_key: "data-zone",
        properties: { encrypted_at_rest: true, has_backup: true },
      },
    ],
    edges: [
      { source_key: "mobile-app", target_key: "api-gateway", label: "HTTPS + OAuth2" },
      { source_key: "api-gateway", target_key: "auth-service", label: "Token validation" },
      { source_key: "api-gateway", target_key: "core-banking", label: "Authenticated request" },
      { source_key: "auth-service", target_key: "customer-db", label: "Credential lookup" },
      { source_key: "core-banking", target_key: "customer-db", label: "Account query" },
      { source_key: "core-banking", target_key: "audit-log", label: "Audit event" },
    ],
    trust_boundaries: [
      { key: "edge", name: "Edge Zone", node_keys: ["api-gateway"] },
      { key: "internal", name: "Internal Services", node_keys: ["auth-service", "core-banking"] },
      { key: "data-zone", name: "Data Zone", node_keys: ["customer-db", "audit-log"] },
    ],
  },
  {
    id: "microservices",
    name: "Microservices",
    domain: "Banking",
    summary:
      "Microservices architecture with API gateway, auth, account, and payment services sharing a database.",
    nodes: [
      {
        key: "client",
        node_type: "external_entity",
        name: "Client",
        position_x: 0,
        position_y: 140,
        properties: { internet_facing: true },
      },
      {
        key: "api-gateway",
        node_type: "process",
        name: "API Gateway",
        position_x: 260,
        position_y: 140,
        trust_boundary_key: "edge",
        properties: { internet_facing: true, uses_auth: true, validates_input: true, uses_encryption: true },
      },
      {
        key: "auth-ms",
        node_type: "process",
        name: "Auth MS",
        position_x: 520,
        position_y: 40,
        trust_boundary_key: "internal",
        properties: { uses_auth: true, uses_encryption: true, handles_sensitive_data: true },
      },
      {
        key: "account-ms",
        node_type: "process",
        name: "Account MS",
        position_x: 520,
        position_y: 160,
        trust_boundary_key: "internal",
        properties: { uses_auth: true, handles_sensitive_data: true },
      },
      {
        key: "payment-ms",
        node_type: "process",
        name: "Payment MS",
        position_x: 520,
        position_y: 280,
        trust_boundary_key: "internal",
        properties: { uses_auth: true, handles_sensitive_data: true, uses_encryption: true },
      },
      {
        key: "shared-db",
        node_type: "data_store",
        name: "Shared DB",
        position_x: 780,
        position_y: 160,
        trust_boundary_key: "data-zone",
        properties: { stores_credentials: true, encrypted_at_rest: true, has_backup: true },
      },
    ],
    edges: [
      { source_key: "client", target_key: "api-gateway", label: "HTTPS request" },
      { source_key: "api-gateway", target_key: "auth-ms", label: "Auth check" },
      { source_key: "api-gateway", target_key: "account-ms", label: "Account request" },
      { source_key: "api-gateway", target_key: "payment-ms", label: "Payment request" },
      { source_key: "auth-ms", target_key: "shared-db", label: "Credential query" },
      { source_key: "account-ms", target_key: "shared-db", label: "Account query" },
      { source_key: "payment-ms", target_key: "shared-db", label: "Transaction write" },
    ],
    trust_boundaries: [
      { key: "edge", name: "Edge Zone", node_keys: ["api-gateway"] },
      { key: "internal", name: "Internal Services", node_keys: ["auth-ms", "account-ms", "payment-ms"] },
      { key: "data-zone", name: "Data Zone", node_keys: ["shared-db"] },
    ],
  },
  {
    id: "open-banking-demo",
    name: "Open Banking Demo",
    domain: "Banking",
    summary:
      "Balanced starter with customer channels, a DMZ edge, internal services, and a third-party payment partner.",
    nodes: [
      {
        key: "mobile-app",
        node_type: "external_entity",
        name: "Mobile Banking App",
        position_x: 0,
        position_y: 20,
        properties: { authenticated: true },
      },
      {
        key: "web-portal",
        node_type: "external_entity",
        name: "Web Portal",
        position_x: 0,
        position_y: 160,
        properties: { authenticated: true },
      },
      {
        key: "third-party-fintech",
        node_type: "external_entity",
        name: "Third-Party Fintech API",
        position_x: 0,
        position_y: 300,
        properties: { internet_facing: true },
      },
      {
        key: "api-gateway",
        node_type: "process",
        name: "API Gateway",
        position_x: 260,
        position_y: 140,
        trust_boundary_key: "dmz",
        properties: {
          uses_auth: true,
          validates_input: true,
          internet_facing: true,
          uses_encryption: true,
        },
      },
      {
        key: "auth-service",
        node_type: "process",
        name: "Authentication Service",
        position_x: 560,
        position_y: 60,
        trust_boundary_key: "internal-network",
        properties: { uses_auth: true, uses_encryption: true },
      },
      {
        key: "core-banking",
        node_type: "process",
        name: "Core Banking Engine",
        position_x: 560,
        position_y: 200,
        trust_boundary_key: "internal-network",
        properties: { uses_auth: true, handles_sensitive_data: true },
      },
      {
        key: "customer-db",
        node_type: "data_store",
        name: "Customer Database",
        position_x: 860,
        position_y: 120,
        trust_boundary_key: "internal-network",
        properties: {
          stores_credentials: true,
          encrypted_at_rest: true,
          has_backup: true,
        },
      },
      {
        key: "audit-log",
        node_type: "data_store",
        name: "Audit Log Store",
        position_x: 860,
        position_y: 280,
        trust_boundary_key: "internal-network",
        properties: { encrypted_at_rest: true, has_backup: true },
      },
    ],
    edges: [
      {
        source_key: "mobile-app",
        target_key: "api-gateway",
        label: "HTTPS request",
      },
      {
        source_key: "web-portal",
        target_key: "api-gateway",
        label: "HTTPS request",
      },
      {
        source_key: "api-gateway",
        target_key: "auth-service",
        label: "OAuth token validation",
      },
      {
        source_key: "api-gateway",
        target_key: "core-banking",
        label: "Authenticated API call",
      },
      {
        source_key: "core-banking",
        target_key: "customer-db",
        label: "SQL query (customer data)",
      },
      {
        source_key: "customer-db",
        target_key: "core-banking",
        label: "Query results",
      },
      {
        source_key: "core-banking",
        target_key: "audit-log",
        label: "Audit event",
      },
      {
        source_key: "core-banking",
        target_key: "third-party-fintech",
        label: "Payment instruction",
      },
    ],
    trust_boundaries: [
      {
        key: "dmz",
        name: "DMZ",
        node_keys: ["api-gateway"],
      },
      {
        key: "internal-network",
        name: "Internal Network",
        node_keys: ["auth-service", "core-banking", "customer-db", "audit-log"],
      },
    ],
  },
  {
    id: "northstar-payments",
    name: "Payments Control Plane",
    domain: "Banking",
    summary:
      "Benchmark-style payments platform with partner ingress, fraud and AML services, SWIFT egress, and regulated data stores.",
    nodes: [
      {
        key: "consumer-mobile-app",
        node_type: "external_entity",
        name: "Consumer Mobile App",
        position_x: 0,
        position_y: 40,
        properties: { internet_facing: true },
      },
      {
        key: "open-banking-partner",
        node_type: "external_entity",
        name: "Open Banking Partner",
        position_x: 0,
        position_y: 180,
        properties: { trusted: true, authenticated: true, internet_facing: true },
      },
      {
        key: "treasury-user",
        node_type: "external_entity",
        name: "Treasury Portal User",
        position_x: 0,
        position_y: 320,
        properties: { authenticated: true },
      },
      {
        key: "payments-api-gateway",
        node_type: "process",
        name: "API Gateway",
        position_x: 260,
        position_y: 160,
        trust_boundary_key: "customer-edge",
        properties: {
          internet_facing: true,
          uses_auth: true,
          validates_input: true,
          uses_encryption: true,
        },
      },
      {
        key: "payments-orchestrator",
        node_type: "process",
        name: "Payments Orchestrator",
        position_x: 520,
        position_y: 160,
        trust_boundary_key: "control-plane",
        properties: { handles_sensitive_data: true, uses_encryption: true },
      },
      {
        key: "fraud-scoring",
        node_type: "process",
        name: "Fraud Scoring Engine",
        position_x: 780,
        position_y: 40,
        trust_boundary_key: "control-plane",
        properties: { handles_sensitive_data: true },
      },
      {
        key: "aml-screening",
        node_type: "process",
        name: "AML Screening Service",
        position_x: 780,
        position_y: 160,
        trust_boundary_key: "control-plane",
        properties: { handles_sensitive_data: true },
      },
      {
        key: "swift-connector",
        node_type: "process",
        name: "SWIFT Connector",
        position_x: 780,
        position_y: 280,
        trust_boundary_key: "control-plane",
        properties: { uses_encryption: true },
      },
      {
        key: "case-management-store",
        node_type: "data_store",
        name: "Case Management Store",
        position_x: 1060,
        position_y: 20,
        trust_boundary_key: "restricted-data",
        properties: { encrypted_at_rest: true, has_backup: true },
      },
      {
        key: "core-banking-ledger",
        node_type: "data_store",
        name: "Core Banking Ledger",
        position_x: 1060,
        position_y: 140,
        trust_boundary_key: "restricted-data",
        properties: { encrypted_at_rest: true, has_backup: true },
      },
      {
        key: "card-token-vault",
        node_type: "data_store",
        name: "Card Token Vault",
        position_x: 1060,
        position_y: 260,
        trust_boundary_key: "restricted-data",
        properties: { stores_credentials: true, encrypted_at_rest: true },
      },
    ],
    edges: [
      {
        source_key: "consumer-mobile-app",
        target_key: "payments-api-gateway",
        label: "OAuth2 + payment initiation",
      },
      {
        source_key: "open-banking-partner",
        target_key: "payments-api-gateway",
        label: "mTLS signed payment request",
      },
      {
        source_key: "treasury-user",
        target_key: "payments-api-gateway",
        label: "privileged batch approval",
      },
      {
        source_key: "payments-api-gateway",
        target_key: "payments-orchestrator",
        label: "normalized payment instruction",
      },
      {
        source_key: "payments-orchestrator",
        target_key: "fraud-scoring",
        label: "transaction scoring request",
      },
      {
        source_key: "payments-orchestrator",
        target_key: "aml-screening",
        label: "sanctions screening request",
      },
      {
        source_key: "payments-orchestrator",
        target_key: "swift-connector",
        label: "signed SWIFT payment message",
      },
      {
        source_key: "payments-orchestrator",
        target_key: "core-banking-ledger",
        label: "posting and balance update",
      },
      {
        source_key: "payments-orchestrator",
        target_key: "card-token-vault",
        label: "tokenization lookup",
      },
      {
        source_key: "fraud-scoring",
        target_key: "case-management-store",
        label: "investigation case record",
      },
      {
        source_key: "payments-orchestrator",
        target_key: "open-banking-partner",
        label: "payment status callback",
      },
    ],
    trust_boundaries: [
      {
        key: "customer-edge",
        name: "Customer and Partner Edge",
        node_keys: ["payments-api-gateway"],
      },
      {
        key: "control-plane",
        name: "Payments Control Plane",
        node_keys: ["payments-orchestrator", "fraud-scoring", "aml-screening", "swift-connector"],
      },
      {
        key: "restricted-data",
        name: "Restricted Data Zone",
        node_keys: ["case-management-store", "core-banking-ledger", "card-token-vault"],
      },
    ],
  },
  {
    id: "medledger-clinical",
    name: "Clinical Exchange",
    domain: "Healthcare",
    summary:
      "Healthcare benchmark with patient-facing identity, partner insurer integration, break-glass access, and clinical archives.",
    nodes: [
      {
        key: "patient-user",
        node_type: "external_entity",
        name: "Patient Portal User",
        position_x: 0,
        position_y: 20,
        properties: { internet_facing: true },
      },
      {
        key: "insurer-api",
        node_type: "external_entity",
        name: "Insurer API",
        position_x: 0,
        position_y: 150,
        properties: { trusted: true, authenticated: true },
      },
      {
        key: "vendor-technician",
        node_type: "external_entity",
        name: "Vendor Support Technician",
        position_x: 0,
        position_y: 280,
        properties: { authenticated: true },
      },
      {
        key: "identity-gateway",
        node_type: "process",
        name: "Identity Gateway",
        position_x: 260,
        position_y: 90,
        trust_boundary_key: "patient-edge",
        properties: {
          internet_facing: true,
          uses_auth: true,
          validates_input: true,
          uses_encryption: true,
        },
      },
      {
        key: "clinical-bus",
        node_type: "process",
        name: "Clinical Integration Bus",
        position_x: 540,
        position_y: 90,
        trust_boundary_key: "clinical-operations",
        properties: { handles_sensitive_data: true, uses_encryption: true },
      },
      {
        key: "break-glass-service",
        node_type: "process",
        name: "Break-Glass Service",
        position_x: 540,
        position_y: 220,
        trust_boundary_key: "clinical-operations",
        properties: { uses_auth: true, handles_sensitive_data: true },
      },
      {
        key: "vendor-bastion",
        node_type: "process",
        name: "Vendor Support Bastion",
        position_x: 540,
        position_y: 350,
        trust_boundary_key: "clinical-operations",
        properties: { uses_auth: true, uses_encryption: true },
      },
      {
        key: "imaging-gateway",
        node_type: "process",
        name: "Imaging AI Gateway",
        position_x: 820,
        position_y: 220,
        trust_boundary_key: "clinical-operations",
        properties: { handles_sensitive_data: true },
      },
      {
        key: "ehr-store",
        node_type: "data_store",
        name: "Electronic Health Record Store",
        position_x: 1080,
        position_y: 60,
        trust_boundary_key: "restricted-data",
        properties: { encrypted_at_rest: true, has_backup: true },
      },
      {
        key: "pacs-archive",
        node_type: "data_store",
        name: "PACS Archive",
        position_x: 1080,
        position_y: 180,
        trust_boundary_key: "restricted-data",
        properties: { encrypted_at_rest: true, has_backup: true },
      },
      {
        key: "lab-results",
        node_type: "data_store",
        name: "Lab Results Repository",
        position_x: 1080,
        position_y: 300,
        trust_boundary_key: "restricted-data",
        properties: { encrypted_at_rest: true, has_backup: true },
      },
    ],
    edges: [
      {
        source_key: "patient-user",
        target_key: "identity-gateway",
        label: "patient login and records access",
      },
      {
        source_key: "identity-gateway",
        target_key: "clinical-bus",
        label: "authenticated patient session",
      },
      {
        source_key: "clinical-bus",
        target_key: "ehr-store",
        label: "patient chart query",
      },
      {
        source_key: "clinical-bus",
        target_key: "pacs-archive",
        label: "imaging retrieval",
      },
      {
        source_key: "clinical-bus",
        target_key: "lab-results",
        label: "laboratory results query",
      },
      {
        source_key: "insurer-api",
        target_key: "clinical-bus",
        label: "eligibility and claims status",
      },
      {
        source_key: "break-glass-service",
        target_key: "ehr-store",
        label: "emergency override query",
      },
      {
        source_key: "vendor-technician",
        target_key: "vendor-bastion",
        label: "privileged vendor session",
      },
      {
        source_key: "vendor-bastion",
        target_key: "pacs-archive",
        label: "diagnostics session",
      },
      {
        source_key: "clinical-bus",
        target_key: "imaging-gateway",
        label: "imaging inference request",
      },
    ],
    trust_boundaries: [
      {
        key: "patient-edge",
        name: "Patient and Partner Edge",
        node_keys: ["identity-gateway"],
      },
      {
        key: "clinical-operations",
        name: "Clinical Operations Zone",
        node_keys: ["clinical-bus", "break-glass-service", "vendor-bastion", "imaging-gateway"],
      },
      {
        key: "restricted-data",
        name: "Restricted Clinical Data Zone",
        node_keys: ["ehr-store", "pacs-archive", "lab-results"],
      },
    ],
  },
  {
    id: "gridforge-ot",
    name: "Industrial OT",
    domain: "Operational Technology",
    summary:
      "OT scenario with remote maintenance ingress, plant DMZ controls, historian storage, and PLC command staging.",
    nodes: [
      {
        key: "supplier-portal-user",
        node_type: "external_entity",
        name: "Supplier Portal User",
        position_x: 0,
        position_y: 40,
      },
      {
        key: "remote-vendor",
        node_type: "external_entity",
        name: "Remote Maintenance Vendor",
        position_x: 0,
        position_y: 180,
        properties: { authenticated: true },
      },
      {
        key: "sre-analyst",
        node_type: "external_entity",
        name: "Site Reliability Analyst",
        position_x: 0,
        position_y: 320,
        properties: { authenticated: true },
      },
      {
        key: "vpn-gateway",
        node_type: "process",
        name: "VPN Gateway",
        position_x: 260,
        position_y: 180,
        trust_boundary_key: "external-access",
        properties: { internet_facing: true, uses_auth: true, uses_encryption: true },
      },
      {
        key: "ot-jump-host",
        node_type: "process",
        name: "OT Jump Host",
        position_x: 540,
        position_y: 60,
        trust_boundary_key: "plant-dmz",
        properties: { uses_auth: true },
      },
      {
        key: "maintenance-orchestrator",
        node_type: "process",
        name: "Maintenance Orchestrator",
        position_x: 540,
        position_y: 200,
        trust_boundary_key: "plant-dmz",
        properties: { uses_auth: true },
      },
      {
        key: "telemetry-broker",
        node_type: "process",
        name: "Telemetry Broker",
        position_x: 540,
        position_y: 340,
        trust_boundary_key: "plant-dmz",
        properties: { uses_encryption: true },
      },
      {
        key: "predictive-analytics",
        node_type: "process",
        name: "Predictive Analytics Service",
        position_x: 820,
        position_y: 340,
        trust_boundary_key: "plant-dmz",
        properties: { handles_sensitive_data: true },
      },
      {
        key: "field-gateway",
        node_type: "process",
        name: "Field Gateway",
        position_x: 1080,
        position_y: 200,
        trust_boundary_key: "ot-core",
        properties: { uses_auth: true },
      },
      {
        key: "plant-historian",
        node_type: "data_store",
        name: "Plant Historian",
        position_x: 1080,
        position_y: 60,
        trust_boundary_key: "ot-core",
        properties: { encrypted_at_rest: true, has_backup: true },
      },
      {
        key: "plc-command-store",
        node_type: "data_store",
        name: "PLC Command Store",
        position_x: 1080,
        position_y: 340,
        trust_boundary_key: "ot-core",
        properties: { encrypted_at_rest: true, has_backup: true },
      },
    ],
    edges: [
      {
        source_key: "remote-vendor",
        target_key: "vpn-gateway",
        label: "remote maintenance tunnel",
      },
      {
        source_key: "sre-analyst",
        target_key: "vpn-gateway",
        label: "emergency operator session",
      },
      {
        source_key: "vpn-gateway",
        target_key: "ot-jump-host",
        label: "interactive privileged session",
      },
      {
        source_key: "ot-jump-host",
        target_key: "maintenance-orchestrator",
        label: "approved maintenance task",
      },
      {
        source_key: "maintenance-orchestrator",
        target_key: "field-gateway",
        label: "maintenance job dispatch",
      },
      {
        source_key: "field-gateway",
        target_key: "telemetry-broker",
        label: "plant telemetry stream",
      },
      {
        source_key: "telemetry-broker",
        target_key: "plant-historian",
        label: "time-series archive write",
      },
      {
        source_key: "predictive-analytics",
        target_key: "plant-historian",
        label: "analytics query",
      },
      {
        source_key: "maintenance-orchestrator",
        target_key: "plc-command-store",
        label: "command package staging",
      },
      {
        source_key: "supplier-portal-user",
        target_key: "maintenance-orchestrator",
        label: "supplier work order upload",
      },
    ],
    trust_boundaries: [
      {
        key: "external-access",
        name: "External Access Zone",
        node_keys: ["vpn-gateway"],
      },
      {
        key: "plant-dmz",
        name: "Plant DMZ",
        node_keys: [
          "ot-jump-host",
          "maintenance-orchestrator",
          "telemetry-broker",
          "predictive-analytics",
        ],
      },
      {
        key: "ot-core",
        name: "OT Core Zone",
        node_keys: ["field-gateway", "plant-historian", "plc-command-store"],
      },
    ],
  },
];

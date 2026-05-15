import { Link } from "react-router-dom";

const quickStartExample = `tmac_version: "1.0"
metadata:
  system_name: Payment API
  description: Public API that authorizes and settles card transactions.
  data_classification: Restricted
  regulatory_scope:
    - PCI DSS
  deployment_model: cloud
dfd:
  nodes:
    - id: "9f0f0a18-1bf4-4e83-8d7d-d1de0dc5b2d8"
      node_type: external_entity
      name: Customer Browser
      properties: {}
    - id: "8f90dcab-34ad-4317-95be-46ccf2a28b8d"
      node_type: process
      name: API Gateway
      properties:
        validates_input: true
  edges:
    - id: "b96c4891-f7d1-48ba-8951-a6f3b75aa56f"
      source_node_id: "9f0f0a18-1bf4-4e83-8d7d-d1de0dc5b2d8"
      target_node_id: "8f90dcab-34ad-4317-95be-46ccf2a28b8d"
      label: HTTPS Request
      properties: {}
  trust_boundaries: []
views:
  built_in_views:
    - view_type: context
      name: Context View
    - view_type: container
      name: System View
threats: []`;

const threatExample = `- id: "c84737f7-a1e2-4845-a8e2-7b15b79dc6fd"
  display_id: T-001
  description: API Gateway accepts requests from an external actor without authentication.
  stride_category: Spoofing
  threat_subtype: Missing authentication
  severity: High
  source: Rules
  status: Open
  affected_node_ids:
    - "8f90dcab-34ad-4317-95be-46ccf2a28b8d"
  affected_edge_ids:
    - "b96c4891-f7d1-48ba-8951-a6f3b75aa56f"
  mitigation_plan: Enable workload authentication and reject unsigned traffic
  control_effectiveness: none
  residual_risk_level: High`;

const sections = [
  {
    title: "What TMAC Covers",
    points: [
      "Threat model metadata, evidence, reporting configuration, the root DFD graph, views, threats, assumptions, controls, templates, and property options.",
      "Optional governance and collaboration state such as snapshots, reviews, collaborators, assignments, and notifications.",
      "Embedded reporting assets when binary export/import is explicitly enabled.",
    ],
  },
  {
    title: "Authoring Rules",
    points: [
      "Keep ids stable when you are editing an existing model. Node, edge, boundary, threat, assumption, and control references are validated.",
      "Use `Load Scaffold` when starting from scratch. The scaffold gives you the recommended top-level sections and built-in views.",
      "Use `replace` to update the current live model and `create_new` to fork the draft into a new threat model id.",
    ],
  },
  {
    title: "Layout and Positions",
    points: [
      "`position_x` and `position_y` are not required for DFD nodes when importing TMAC. ThreatGenix now auto-generates initial node layout coordinates during validation/import if they are missing.",
      "Trust boundary geometry can still be provided explicitly, but missing boundary position and size values are backfilled from the member nodes.",
      "Built-in view layout snapshots can stay empty until you customize layout. Custom view snapshots should normally match the embedded graph they describe.",
    ],
  },
  {
    title: "Validation Guarantees",
    points: [
      "Graph integrity checks cover duplicate ids, missing node/edge/boundary references, `response_to_id` references, trust-boundary parent cycles, and missing component-template references.",
      "Threats, assumptions, controls, and governance snapshots are checked against the ids they reference.",
      "Validation is deterministic. `/tmac validate` and `/tmac diff` use the backend validator and diff engine, not free-form generation.",
    ],
  },
];

function CodeBlock({ code }: { code: string }) {
  return (
    <pre className="tmac-docs-code">
      <code>{code}</code>
    </pre>
  );
}

export default function TMACReferencePage() {
  return (
    <div className="tmac-docs-page">
      <div className="tmac-docs-shell">
        <div className="tmac-docs-hero">
          <div>
            <Link to="/dashboard" className="tmac-docs-back">
              &larr; Back to Dashboard
            </Link>
            <h1>TMAC Reference</h1>
            <p>
              ThreatGenix Threat Model as Code is a deterministic exchange format for exporting,
              validating, diffing, and importing threat models without relying on LLM generation.
            </p>
          </div>
          <div className="tmac-docs-hero-card">
            <span className="tmac-docs-chip">Version 1.0</span>
            <span className="tmac-docs-chip tmac-docs-chip-accent">
              Node positions optional on import
            </span>
            <p>
              Canonical repo doc: <code>docs/threat-model-as-code.md</code>
            </p>
          </div>
        </div>

        <div className="tmac-docs-grid">
          <section className="tmac-docs-card">
            <h2>Quick Start</h2>
            <p>
              This is the smallest useful TMAC document shape for a real system. Author the graph
              first, then add threats, assumptions, and controls as you iterate.
            </p>
            <CodeBlock code={quickStartExample} />
          </section>

          <section className="tmac-docs-card">
            <h2>Threat Entry Example</h2>
            <p>
              Threats reference the DFD ids they affect. If you rename a node, keep its id stable
              so the threat references still validate.
            </p>
            <CodeBlock code={threatExample} />
          </section>

          {sections.map((section) => (
            <section className="tmac-docs-card" key={section.title}>
              <h2>{section.title}</h2>
              <ul className="tmac-docs-list">
                {section.points.map((point) => (
                  <li key={point}>{point}</li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}

# Threat Model as Code

ThreatGenix TMAC is a deterministic, versioned representation of a threat model that can be exported, validated, diffed, and imported without relying on LLM generation.

## Format

- Canonical document format: YAML by default, JSON also supported.
- Version marker: `tmac_version: "1.0"`.
- Canonical ordering and float normalization are applied on export and validation so diffs stay stable.

## Quick Start

Use `Load Scaffold` in the TMAC editor or start from a minimal document like this:

```yaml
tmac_version: "1.0"
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
threats: []
```

## DFD Authoring Notes

- `dfd.nodes`, `dfd.edges`, and `dfd.trust_boundaries` are the canonical root graph.
- Node ids, edge ids, and boundary ids should stay stable when you edit an existing model.
- `properties` is required on nodes and edges, even if it is an empty object.
- `position_x` and `position_y` for DFD nodes are now optional at TMAC import/validation time.
  - If you omit them, ThreatGenix auto-generates an initial layout so you can author the graph structure first and refine layout later.
  - Trust boundary position and size values can also be omitted; ThreatGenix backfills them from the member nodes when possible.
- Built-in view `layout_snapshot` entries can remain empty until you actually customize view layout.

## Threat Authoring Notes

Threats reference the DFD ids they affect. A typical entry looks like:

```yaml
- id: "c84737f7-a1e2-4845-a8e2-7b15b79dc6fd"
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
  residual_risk_level: High
```

- `affected_node_ids` and `affected_edge_ids` must exist in the root DFD graph.
- Controls, assumptions, and governance snapshots are validated against the ids they reference.
- `replace` is the mode for updating the current live model.
- `create_new` is the mode for forking the draft into a new threat model id.

## Coverage

TMAC can represent:

- metadata
- evidence
- reporting configuration
- root DFD graph
- built-in view layout snapshots
- custom DFD views with embedded graphs
- threats
- assumptions
- controls
- component templates
- property options
- governance snapshots and reviews
- collaboration state

## Scope Contract

ThreatGenix supports two practical exchange scopes:

- Core TMAC:
  - portable by default
  - includes the threat model, DFD, views, threats, assumptions, controls, templates, and property options
  - excludes operational workflow state and embedded binary assets unless explicitly enabled
- Full TMAC:
  - includes governance and collaboration state
  - can also include embedded reporting binaries such as report logos and architecture diagrams

This keeps normal import/export safe across environments while still allowing full-fidelity archival and migration when requested.

## Export Rules

- Default export omits:
  - governance snapshots and reviews
  - collaborators, assignments, and notifications
  - embedded reporting binaries
- Export can explicitly include:
  - operational workflow state
  - embedded binary assets

## Import Rules

- `preview` validates and summarizes without writing.
- `replace` keeps the target threat model id.
- `create_new` creates a new threat model id even if `metadata.id` is present in the TMAC file.

Import defaults:

- `apply_operational_state = false`
- `apply_binary_assets = false`

When those flags are off, ThreatGenix still validates the full TMAC document but preserves existing workflow state and binaries on replace, or omits them on create-new.

## Deterministic Assistant Contract

The assistant supports deterministic TMAC commands:

- `/tmac help`
- `/tmac scaffold`
- `/tmac validate <yaml|json>`
- `/tmac diff <yaml|json>`

These commands are handled by backend validators and diff logic, not by free-form model generation.

## Validation Guarantees

TMAC validation checks:

- root DFD graph integrity
- missing node position defaults are materialized before schema validation
- trust-boundary parent cycles
- edge `response_to_id` references
- threat affected node and edge references
- control-to-threat mappings
- assumption anchors
- custom-view embedded graph integrity
- component template references from node properties
- governance and collaboration cross-references

## Current Non-Goals

- partial merge semantics
- assistant-authored TMAC generation
- binary asset deduplication
- cross-document include/import statements

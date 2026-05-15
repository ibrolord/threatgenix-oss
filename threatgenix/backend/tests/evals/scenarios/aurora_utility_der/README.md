# Aurora Utility DER Benchmark

This scenario is the long-lived stress fixture for mixed IT/OT threat modeling in ThreatGenix.

It is intentionally harder than the bank, healthcare, OT, and airline baselines because it combines:

- customer-facing outage workflows
- DER market dispatch and settlement
- safety-relevant feeder and restoration decisions
- offline field operations
- vendor diagnostics near OT control paths
- break-glass dispatch authority
- governance, collaboration, and immutable decision evidence

Files in this directory:

- `metadata.yaml`: scenario metadata used by the eval harness
- `gold_threat_themes.yaml`: benchmark threat themes and expected coverage
- `must_not_hallucinate.yaml`: themes that should not appear
- `gold_dfd.json`: gold DFD fixture
- `threat_model.tmac.yaml`: full Threat Model as Code fixture for direct import into ThreatGenix
- `narrative.pdf`: architecture narrative
- `structured.pdf`: structured architecture brief
- `delta.pdf`: change request that shifts the threat landscape

Recommended uses:

- TMAC validation/import regression
- DFD quality-gate benchmarking
- assistant threat-modeling evals
- browser smoke tests against a dense, nuanced model
- future scenario expansion for wildfire, mutual-aid, or satellite-failover changes

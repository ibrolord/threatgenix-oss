# Feature Test Tracker

This tracker turns the Opus code-read QA plan into a living work queue. Update
`Status`, `Owner`, and linked issue or PR as tests are added and failures are
fixed.

## Status Workflow

- `open`: gap identified, no failing test yet.
- `repro-confirmed`: failing automated test or recorded manual reproduction exists.
- `in-progress`: owner is implementing the fix or missing coverage.
- `fix-in-review`: PR is open and CI is running.
- `awaiting-retest`: fix merged, release journey needs retest.
- `closed-verified`: automated test and retest gate passed.
- `closed-wontfix`: explicitly accepted with rationale.

## Severity

- `S0`: boot failure, data loss, auth bypass, tenant leak, secret exposure, or publication hygiene regression.
- `S1`: release-critical journey unusable.
- `S2`: degraded feature with workaround.
- `S3`: cosmetic or low-risk defect.
- `S4`: known limitation or future tracking item.

## Owner Rules

- Auth/account, tenant isolation, startup, migrations, reports, scans: backend.
- DFD canvas, routing, dashboard, forms, triage UI: frontend.
- Rules and threat scoring: rules.
- AI provider behavior, embeddings, threat intelligence: AI.
- CI, hygiene, packaging, release gates: DevOps.
- A cross-layer failure is owned by the first failing layer, with the second
  layer assigned as reviewer.

## Matrix

| ID | Area | User promise | Existing coverage | Missing or weak coverage | Type | Priority | Severity | Owner | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| QA-001 | Boot | Local stack starts and health is green | `test_health.py`, basic e2e smoke | Compose-up smoke against real stack and deep health | integration | P0 | S0 | backend | open |
| QA-002 | Auth | Register, login, reload, logout all work | auth API and React context tests | Browser auth roundtrip | browser E2E | P0 | S1 | frontend | open |
| QA-003 | Auth hardening | Dev auth tokens never leak in production | startup/security tests | Release journey retest for production auth gate | startup | P0 | S0 | backend | awaiting-retest |
| QA-004 | Tenant isolation | Users cannot access other users' data | partial SaaS foundation tests | Route matrix across all owned resources | API contract | P0 | S0 | backend | open |
| QA-005 | Migration readiness | Partially migrated DB does not serve traffic | migration/startup tests | Downgrade/stale schema health degradation test | migration | P0 | S0 | backend | open |
| QA-006 | Threat model CRUD | User can create, open, list, and archive models | backend and dashboard tests | Browser create/archive journey | browser E2E | P1 | S1 | frontend | open |
| QA-007 | Document upload | Architecture document becomes DFD input | parser and upload tests | End-to-end extraction plus retention purge | integration | P1 | S1 | backend | open |
| QA-008 | DFD API | Nodes, edges, boundaries, views persist | broad DFD tests | Quick-add, view regeneration, repository suggestion contracts | API contract | P1 | S1 | backend | open |
| QA-009 | DFD UI | Canvas editing works in browser | component and Playwright specs | Visual regression and save-state assertion | browser E2E | P2 | S2 | frontend | open |
| QA-010 | DFD quality gates | Modeling issues are visible and actionable | service tests | UI rendering of quality issues | browser E2E | P2 | S2 | frontend | open |
| QA-011 | Rules engine | STRIDE output is deterministic | rules unit tests | Golden DFD to golden threat set | unit | P0 | S1 | rules | open |
| QA-012 | Rule suppression | Properties suppress or trigger correct rules | targeted suppression tests | Broader property permutation sweep | unit | P2 | S2 | rules | open |
| QA-013 | AI enhancement | Available AI improves threat output | AI service tests | Stubbed provider end-to-end contract | API contract | P1 | S1 | AI | open |
| QA-014 | AI degradation | Provider outage does not block rules | partial analyze tests | Browser banner and deterministic threat fallback | browser E2E | P0 | S1 | AI | open |
| QA-015 | Threat triage | Accept, dismiss, bulk update, and audit persist | API and modal tests | Bulk triage browser flow | browser E2E | P1 | S1 | frontend | open |
| QA-016 | Threat diff | Re-analysis shows new and removed threats | diff tests | Browser edit-and-reanalyze journey | browser E2E | P2 | S2 | frontend | open |
| QA-017 | Compliance | Threats show relevant controls | compliance tests | Framework coverage by STRIDE sample | API contract | P1 | S1 | backend | open |
| QA-018 | Threat intelligence | ATT&CK, CAPEC, CWE, KEV, and advisory context appears | threat-intel tests | Sync smoke and UI rendering | integration | P2 | S2 | AI | open |
| QA-019 | PDF report | Exported PDF is complete and parseable | PDF tests | Parse generated PDF for required sections and image | integration | P0 | S1 | backend | open |
| QA-020 | Report config | Template, logo, watermark, attestation persist | partial tests | Report-config and template-library contract test | API contract | P1 | S2 | backend | open |
| QA-021 | CSV export | Threat CSV export is scoped and valid | weak direct coverage | CSV header, row, and owner-scope contract | API contract | P1 | S1 | backend | open |
| QA-022 | Dashboard | Portfolio cards and trends reflect data | dashboard tests | Browser data-update journey | browser E2E | P2 | S2 | frontend | open |
| QA-023 | Validation Lab | Safe dry-run evidence flow works | validation tests | Allowed-path sandbox dry run | integration | P1 | S1 | backend | open |
| QA-024 | Scan credentials | Credentials are encrypted and scoped | credential tests | Key-rotation behavior | unit | P2 | S2 | backend | open |
| QA-025 | Application review | Bundle to findings to decision works | broad app-review tests | Browser flow with mocked scanners | browser E2E | P1 | S1 | frontend | open |
| QA-026 | TMAC | Threat model code round-trips | TMAC tests | Import, mutate, export, diff minimality | unit | P2 | S2 | backend | open |
| QA-027 | Provider settings | Provider switching and BYOK are usable | API and BYOK tests | Settings-page browser flow | browser E2E | P1 | S1 | frontend | open |
| QA-028 | Security headers | Common hardening headers are present | health and catalog header tests | Release journey retest for deployed headers | security | P0 | S0 | backend | awaiting-retest |
| QA-029 | Rate limiting | Auth endpoints throttle bursts | partial limiter presence | Burst-login 429 test | security | P1 | S1 | backend | open |
| QA-030 | Production gates | Unsafe production defaults fail closed | per-setting production gate matrix | Release journey retest for packaged production config | startup | P0 | S0 | backend | awaiting-retest |
| QA-031 | OSS hygiene | Public tree has no obvious secrets or private strings | hygiene script and CI job | Negative fixture test or CI assertion | security | P0 | S0 | DevOps | open |
| QA-032 | CLI | CLI emits valid MCP config | CI wheel smoke | CLI argument combination tests | unit | P2 | S2 | backend | open |
| QA-033 | Document retention | Raw upload text is purged | weak direct coverage | Time-controlled purge test | unit | P1 | S1 | backend | open |
| QA-034 | Lazy chunk reload | Stale chunks recover cleanly | weak direct coverage | Unit test for reload-once guard | unit | P2 | S3 | frontend | open |
| QA-035 | Product identity | Legacy naming does not return | product identity test and hygiene script | Keep regression active | security | P1 | S1 | DevOps | open |

## Retest Gates

| Priority | Required before close |
| --- | --- |
| P0 | Automated regression test, full relevant CI job, manual release journey retest |
| P1 | Automated regression test and relevant CI job |
| P2 | Automated test or documented manual retest |

## Progress Notes

- 2026-05-15: QA-003 and QA-030 gained a per-setting pytest matrix in
  `threatgenix/backend/tests/test_startup_readiness.py`. Automated coverage is
  ready for focused retest; production release journey retest remains before
  closure.
- 2026-05-15: QA-028 gained direct middleware assertions in
  `threatgenix/backend/tests/test_security_headers.py` for `/api/health`,
  `/api/threat-catalog`, and HTTPS-only HSTS behavior. Production release
  journey retest remains before closure.

## Release Exit Criteria

- No open `S0` or `S1` items.
- All P0 and P1 automated tests pass in CI.
- Browser E2E smoke passes against the local self-hosted stack.
- `scripts/check-oss-hygiene.sh` passes.
- `docs/qa/feature-test-tracker.md` reflects the latest issue/PR state.

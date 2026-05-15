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
| QA-001 | Boot | Local stack starts and health is green | configurable deep e2e smoke and Compose release retest | Keep regression active | integration | P0 | S0 | backend | closed-verified |
| QA-002 | Auth | Register, login, reload, logout all work | auth API, React context tests, and Compose browser auth roundtrip | Keep regression active | browser E2E | P0 | S1 | frontend | closed-verified |
| QA-003 | Auth hardening | Dev auth tokens never leak in production | startup/security tests and local P0 retest | Keep regression active | startup | P0 | S0 | backend | closed-verified |
| QA-004 | Tenant isolation | Users cannot access other users' data | owned-resource route matrix, SaaS foundation tests, and Compose product-readiness tenant smoke | Keep regression active | API contract | P0 | S0 | backend | closed-verified |
| QA-005 | Migration readiness | Partially migrated DB does not serve traffic | startup missing-schema regression and local P0 retest | Keep regression active | migration | P0 | S0 | backend | closed-verified |
| QA-006 | Threat model CRUD | User can create, open, list, and archive models | backend archive contract, active-list filtering, and Compose browser create/open/archive journey | Keep regression active | browser E2E | P1 | S1 | frontend | closed-verified |
| QA-007 | Document upload | Architecture document becomes DFD input | Docker-backed upload-to-DFD e2e plus retention purge regression | Keep regression active | integration | P1 | S1 | backend | closed-verified |
| QA-008 | DFD API | Nodes, edges, boundaries, views persist | broad DFD tests plus Docker-backed quick-add, view-regeneration, and repository-suggestion contracts | Keep regression active | API contract | P1 | S1 | backend | closed-verified |
| QA-009 | DFD UI | Canvas editing works in browser | component and Playwright specs | Visual regression and save-state assertion | browser E2E | P2 | S2 | frontend | open |
| QA-010 | DFD quality gates | Modeling issues are visible and actionable | service tests | UI rendering of quality issues | browser E2E | P2 | S2 | frontend | open |
| QA-011 | Rules engine | STRIDE output is deterministic | rules unit tests, golden DFD threat-set regression, and Compose product-readiness threat generation smoke | Intentional rule change approval/update process | unit | P0 | S1 | rules | closed-verified |
| QA-012 | Rule suppression | Properties suppress or trigger correct rules | targeted suppression tests | Broader property permutation sweep | unit | P2 | S2 | rules | open |
| QA-013 | AI enhancement | Available AI improves threat output | AI service tests | Stubbed provider end-to-end contract | API contract | P1 | S1 | AI | open |
| QA-014 | AI degradation | Provider outage does not block rules | analyze fallback tests, browser degradation banner regression, and frontend release retest | Keep regression active | browser E2E | P0 | S1 | AI | closed-verified |
| QA-015 | Threat triage | Accept, dismiss, bulk update, and audit persist | API and modal tests | Bulk triage browser flow | browser E2E | P1 | S1 | frontend | open |
| QA-016 | Threat diff | Re-analysis shows new and removed threats | diff tests | Browser edit-and-reanalyze journey | browser E2E | P2 | S2 | frontend | open |
| QA-017 | Compliance | Threats show relevant controls | compliance tests plus live framework coverage by STRIDE sample | Keep regression active | API contract | P1 | S1 | backend | closed-verified |
| QA-018 | Threat intelligence | ATT&CK, CAPEC, CWE, KEV, and advisory context appears | threat-intel tests | Sync smoke and UI rendering | integration | P2 | S2 | AI | open |
| QA-019 | PDF report | Exported PDF is complete and parseable | real PDF render/parse test with required sections and DFD image plus Compose product-readiness export smoke | Keep regression active | integration | P0 | S1 | backend | closed-verified |
| QA-020 | Report config | Template, logo, watermark, attestation persist | partial tests | Report-config and template-library contract test | API contract | P1 | S2 | backend | open |
| QA-021 | CSV export | Threat CSV export is scoped and valid | live HTTP CSV header, row, and owner-scope contract in Docker-backed e2e | Keep regression active | API contract | P1 | S1 | backend | closed-verified |
| QA-022 | Dashboard | Portfolio cards and trends reflect data | dashboard tests | Browser data-update journey | browser E2E | P2 | S2 | frontend | open |
| QA-023 | Validation Lab | Safe dry-run evidence flow works | validation tests | Allowed-path sandbox dry run | integration | P1 | S1 | backend | open |
| QA-024 | Scan credentials | Credentials are encrypted and scoped | credential tests | Key-rotation behavior | unit | P2 | S2 | backend | open |
| QA-025 | Application review | Bundle to findings to decision works | broad app-review tests | Browser flow with mocked scanners | browser E2E | P1 | S1 | frontend | open |
| QA-026 | TMAC | Threat model code round-trips | TMAC tests | Import, mutate, export, diff minimality | unit | P2 | S2 | backend | open |
| QA-027 | Provider settings | Provider switching and BYOK are usable | API and BYOK tests | Settings-page browser flow | browser E2E | P1 | S1 | frontend | open |
| QA-028 | Security headers | Common hardening headers are present | health and catalog header tests plus local P0 retest | Keep regression active | security | P0 | S0 | backend | closed-verified |
| QA-029 | Rate limiting | Auth endpoints throttle bursts | backend auth security unit test plus live HTTP e2e burst-login regression | Keep regression active in backend and e2e suites | security | P1 | S1 | backend | closed-verified |
| QA-030 | Production gates | Unsafe production defaults fail closed | per-setting production gate matrix and local P0 retest | Keep regression active | startup | P0 | S0 | backend | closed-verified |
| QA-031 | OSS hygiene | Public tree has no obvious secrets or private strings | hygiene script self-test and local release retest | Keep regression active | security | P0 | S0 | DevOps | closed-verified |
| QA-032 | CLI | CLI emits valid MCP config | CI wheel smoke | CLI argument combination tests | unit | P2 | S2 | backend | open |
| QA-033 | Document retention | Raw upload text is purged | time-controlled live DB purge test | Keep regression active | unit | P1 | S1 | backend | closed-verified |
| QA-034 | Lazy chunk reload | Stale chunks recover cleanly | weak direct coverage | Unit test for reload-once guard | unit | P2 | S3 | frontend | open |
| QA-035 | Product identity | Legacy naming does not return | product identity test, hygiene script, and local release retest | Keep regression active | security | P1 | S1 | DevOps | closed-verified |

## Retest Gates

| Priority | Required before close |
| --- | --- |
| P0 | Automated regression test, full relevant CI job, manual release journey retest |
| P1 | Automated regression test and relevant CI job |
| P2 | Automated test or documented manual retest |

## Progress Notes

- 2026-05-15: QA-001 e2e smoke gained environment-configurable Postgres targets
  and now asserts `/api/health?deep=true` returns a connected database signal.
  The test compose DB default moved to host port `55433` to avoid local Postgres
  collisions; full frontend/compose release retest remains before closure.
- 2026-05-15: QA-005 gained a startup regression that returns a missing required
  schema column and proves lifespan fails before serving traffic with a useful
  `alembic upgrade head` message. Downgraded-schema release retest remains
  before closure.
- 2026-05-15: QA-031 gained `scripts/check-oss-hygiene.sh --self-test`, which
  creates negative fixtures for secret patterns, private/customer strings,
  legacy product naming, tracked `.env`, and uncommented provider credentials.
  CI now runs the self-test after the normal hygiene scan.
- 2026-05-15: QA-002 gained
  `threatgenix/frontend/e2e/auth-roundtrip.spec.ts`, which creates a unique
  account through the browser, verifies token persistence across reload, logs
  out, and signs back in with the same credentials.
- 2026-05-15: QA-004 gained
  `threatgenix/backend/tests/test_tenant_isolation_route_matrix.py`, a
  parametrized cross-tenant denial matrix for representative owned-resource
  routes: threat model detail/export, DFD, threats, scans, evidence, and
  validation lab. Full-stack release retest remains before closure.
- 2026-05-15: QA-011 gained
  `threatgenix/backend/tests/test_rules_golden.py`, which freezes a PCI checkout
  DFD to the expected deterministic STRIDE threat set including rule order,
  display IDs, categories, severity, affected nodes, affected edges, and boundary
  flags.
- 2026-05-15: QA-014 gained
  `threatgenix/frontend/src/pages/ThreatModelPage.test.tsx`, which mocks an AI
  provider outage response from `/analyze` and proves the page keeps the
  deterministic rule threat visible while surfacing the AI degradation alert.
- 2026-05-15: QA-019 extended
  `threatgenix/backend/tests/test_pdf_report.py` to generate a real WeasyPrint
  PDF, parse it with PyMuPDF, verify required report sections and threat content,
  and assert an embedded DFD image is present.
- 2026-05-15: P0 release retest passed locally on the self-hosted Compose stack
  with isolated host ports (`DB_PORT=55432 BACKEND_PORT=8010 FRONTEND_PORT=5180`).
  Evidence: Compose deep health returned `database=connected` and
  `alembic_revision=083`; browser smoke passed
  `auth-roundtrip.spec.ts` plus `product-readiness.spec.ts` with 4 tests; backend
  P0 pytest subset passed 97 tests; Docker-backed `test_00_smoke.py` passed 5
  tests using the backend venv; frontend `typecheck` and `build` passed; OSS
  hygiene and hygiene self-test passed.
- 2026-05-15: QA-003 and QA-030 gained a per-setting pytest matrix in
  `threatgenix/backend/tests/test_startup_readiness.py`. Automated coverage is
  ready for focused retest; production release journey retest remains before
  closure.
- 2026-05-15: QA-028 gained direct middleware assertions in
  `threatgenix/backend/tests/test_security_headers.py` for `/api/health`,
  `/api/threat-catalog`, and HTTPS-only HSTS behavior. Production release
  journey retest remains before closure.
- 2026-05-15: QA-029 gained `tests/e2e/test_08_auth_rate_limit.py` plus stricter
  backend auth-security assertions. The live backend burst sends 12 invalid
  login attempts and verifies the first 10 fail authentication with 401 while
  subsequent attempts return 429 with a rate-limit response.
- 2026-05-15: The Docker-backed `tests/e2e make e2e` target now runs against a
  real authenticated e2e user and passed 66 tests. The retest also refreshed
  stale report-export, concurrency, and compliance assertions to match current
  product gates and API fields.
- 2026-05-15: QA-035 closed after `productIdentity.test.ts`,
  `scripts/check-oss-hygiene.sh`, and `scripts/check-oss-hygiene.sh --self-test`
  all passed locally, preserving the ThreatGenix public branding and legacy-name
  guard.
- 2026-05-15: QA-021 gained `tests/e2e/test_09_threat_csv_export.py`, which
  verifies threat CSV headers, row count, generated threat IDs, residual-risk
  values, attachment filename, and cross-tenant denial against the live backend.
  The Docker-backed `make e2e` target passed 67 tests with this contract included.
- 2026-05-15: QA-017 gained
  `tests/e2e/test_10_compliance_framework_coverage.py`, which verifies every
  STRIDE category returns seeded controls across NIST 800-53, OSFI B-13,
  PCI DSS 4.0, and ISO 27001 through the live API. The Docker-backed `make e2e`
  target passed 68 tests with this contract included.
- 2026-05-15: QA-033 gained `tests/e2e/test_11_document_retention.py` plus a
  deterministic `now` parameter on `purge_expired_documents`. The test inserts
  expired and future documents into the live e2e database, verifies only expired
  `raw_text` is purged, and proves `parsed_components` remains intact. The
  Docker-backed `make e2e` target passed 69 tests with this contract included.
- 2026-05-15: QA-007 closed on the same Docker-backed e2e evidence: document
  upload tests now exercise fixture PDF upload, parser/Bedrock-stub extraction,
  DFD generation, DFD readback, and the time-controlled retention purge
  regression without leaving raw text beyond expiry.
- 2026-05-15: QA-006 gained soft-archive product support with migration 084,
  active portfolio filtering, a dashboard archive control, and
  `threatgenix/frontend/e2e/threat-model-crud.spec.ts`. The Compose browser
  journey creates a review, opens it from the dashboard, archives it, verifies it
  leaves active lists, and confirms direct readback retains `archived_at`. The
  Docker-backed `make e2e` target passed 70 tests with the API archive contract
  included.
- 2026-05-15: QA-008 gained `tests/e2e/test_12_dfd_contracts.py`, covering
  DFD quick-add edge direction/properties, view regeneration, decomposition
  seeds, workspace readback, and repository-derived DFD suggestion preview/apply
  persistence. The regression exposed and fixed dropped repository seed
  provenance on node properties. The Docker-backed `make e2e` target passed 72
  tests with this contract included.

## Release Exit Criteria

- No open `S0` or `S1` items.
- All P0 and P1 automated tests pass in CI.
- Browser E2E smoke passes against the local self-hosted stack.
- `scripts/check-oss-hygiene.sh` passes.
- `docs/qa/feature-test-tracker.md` reflects the latest issue/PR state.

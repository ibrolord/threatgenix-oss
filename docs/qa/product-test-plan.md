# Product Test Plan

This plan is based on a read-only Claude Opus code inspection of the OSS repo at
commit `8e0f5e1`. It is intentionally code-grounded: every feature area below
maps to implementation files and existing tests, not only README claims.

## Feature Inventory

| Area | Main code surfaces | Existing coverage |
| --- | --- | --- |
| Auth, account, email verification, password reset | `threatgenix/backend/app/api/auth.py`, `threatgenix/backend/app/services/auth.py`, `threatgenix/frontend/src/pages/LoginPage.tsx`, `threatgenix/frontend/src/auth/AuthContext.tsx` | `test_auth_api.py`, `test_auth_security.py`, `AuthContext.test.tsx`, `LoginPage.test.tsx` |
| BYOK and provider settings | `threatgenix/backend/app/api/llm.py`, `threatgenix/backend/app/services/llm_client.py`, `threatgenix/backend/app/services/key_encryption.py`, `threatgenix/frontend/src/pages/SettingsPage.tsx` | `test_llm_api.py`, `test_byok.py`, `test_credential_crypto.py` |
| Threat model CRUD and dashboard | `threatgenix/backend/app/api/threat_models.py`, `threatgenix/backend/app/api/dashboard.py`, `threatgenix/frontend/src/pages/DashboardPage.tsx`, `threatgenix/frontend/src/pages/ThreatModelPage.tsx` | `test_threat_models.py`, `test_dashboard.py`, `DashboardPage.test.tsx` |
| Document upload and extraction | `threatgenix/backend/app/api/documents.py`, `threatgenix/backend/app/services/doc_parser.py`, `threatgenix/backend/app/services/ai_extraction.py`, `threatgenix/frontend/src/components/DocumentUpload.tsx` | `test_documents.py`, `test_doc_parser.py`, `DocumentUpload.test.tsx` |
| DFD canvas, nodes, edges, boundaries, views | `threatgenix/backend/app/api/dfd.py`, `threatgenix/backend/app/services/dfd_*.py`, `threatgenix/frontend/src/components/dfd/*` | `test_dfd.py`, `test_dfd_views_and_quality.py`, `DFDCanvas.test.tsx`, frontend DFD Playwright specs |
| STRIDE rules engine | `threatgenix/backend/app/services/rules/*`, `threatgenix/backend/app/services/rules/rule_definitions.yaml`, `threatgenix/backend/app/api/threats.py` | `test_engine.py`, `test_conditions.py`, `test_loader.py`, `test_rationale.py`, `test_renderer.py` |
| AI enhancement and graceful degradation | `threatgenix/backend/app/services/ai_enhancement.py`, `threatgenix/backend/app/services/ai_threat_merger.py`, `threatgenix/backend/app/services/llm_client.py`, `threatgenix/backend/app/api/threats.py` | `test_ai_enhancement.py`, `test_ai_merger.py`, `test_analyze.py`, `test_llm_client_boundary.py` |
| Threat triage, diff, detail, residual risk | `threatgenix/backend/app/api/threats.py`, `threatgenix/backend/app/services/threat_diff.py`, `threatgenix/frontend/src/components/threats/*`, `threatgenix/frontend/src/pages/ThreatDetailPage.tsx` | `test_threats_api.py`, `test_threat_diff*.py`, `ThreatTriageModal.test.tsx` |
| Compliance and threat intelligence | `threatgenix/backend/app/api/compliance.py`, `threatgenix/backend/app/api/threat_intel.py`, `threatgenix/backend/app/services/threat_intel/*`, `threatgenix/backend/app/seed.py` | `test_compliance_*.py`, `test_threat_intel*.py`, `test_seed_compliance.py` |
| Report export and templates | `threatgenix/backend/app/services/pdf_report.py`, `threatgenix/backend/app/services/report_templates.py`, `threatgenix/backend/app/templates/*.html`, `threatgenix/frontend/src/components/ReportExportModal.tsx` | `test_pdf_report.py`, `ReportExportModal.test.tsx` |
| Evidence graph and environment evidence | `threatgenix/backend/app/api/evidence.py`, `threatgenix/backend/app/api/environment.py`, `threatgenix/backend/app/services/evidence_*.py`, `threatgenix/frontend/src/components/EnvironmentEvidencePanel.tsx` | `test_environment_api.py`, `test_environment_evidence.py`, `test_evidence_graph.py` |
| Scans, validation lab, sandbox, scheduler | `threatgenix/backend/app/api/scans.py`, `threatgenix/backend/app/api/validation_lab.py`, `threatgenix/backend/app/services/validation_*.py`, `threatgenix/frontend/src/pages/ValidationLabPage.tsx` | `test_scan_*.py`, `test_validation_*.py`, `ValidationLabPage.test.tsx` |
| Application security review workflow | `threatgenix/backend/app/api/application_reviews.py`, `threatgenix/backend/app/api/review_agent.py`, `threatgenix/backend/app/services/security_review_*.py`, `threatgenix/frontend/src/pages/ApplicationReviewPage.tsx` | `test_application_review*.py`, `test_review_*.py`, `test_security_review_*.py`, application review Playwright specs |
| Orchestration, agent orchestration, GitHub integration | `threatgenix/backend/app/api/orchestration.py`, `threatgenix/backend/app/api/threat_agent_orchestration.py`, `threatgenix/backend/app/api/github_integration.py`, `threatgenix/backend/app/services/orchestration*.py` | `test_orchestration*.py`, `test_threat_agent_orchestration*.py`, `test_github_pr_integration.py` |
| Startup, migration, security headers, OSS hygiene | `threatgenix/backend/app/main.py`, `threatgenix/backend/migrations/versions/*`, `scripts/check-oss-hygiene.sh`, `.github/workflows/ci.yml` | `test_startup_readiness.py`, `test_migration_guards.py`, `test_health.py`, CI hygiene job |

## Release-Critical Product Journeys

1. First-run boot: local stack starts, `/api/health` returns `status=ok`, frontend renders login.
2. Account lifecycle: register, login, reload, `/api/auth/me`, logout, protected route redirect.
3. Create first threat model from intake and land on the model workspace.
4. Upload an architecture document and generate DFD nodes, edges, and boundaries.
5. Edit the DFD manually: add, rename, connect, group, and save components.
6. Generate deterministic STRIDE threats with rule IDs, severity, and rationale.
7. Run AI enhancement when available and degrade cleanly when the provider is unavailable.
8. Triage threats: filter, sort, accept, dismiss, bulk update, and persist audit notes.
9. Open threat detail and show threat intelligence plus compliance mappings.
10. Export PDF report with DFD, threat table, compliance, and attestation content.
11. Export CSV and verify ownership scope.
12. Dashboard summary and trends update after model and threat changes.
13. Validation Lab dry-run imports evidence safely and binds results to threats.
14. Application review flow accepts a bundle, normalizes scanner output, and produces a decision.
15. Tenant isolation blocks cross-user access to models, DFDs, threats, scans, reviews, and evidence.
16. Production startup refuses dangerous defaults.

## Automation Layers

| Layer | Command or tool | Purpose |
| --- | --- | --- |
| Backend unit/API | `cd threatgenix/backend && python -m pytest -q` | Pure service tests and FastAPI route tests |
| Backend lint | `cd threatgenix/backend && ruff check app tests` | Style and obvious Python defects |
| Frontend unit | `cd threatgenix/frontend && npm test` | Component, hook, and utility behavior |
| Frontend type/lint | `cd threatgenix/frontend && npm run typecheck && npm run lint` | Type and lint gate |
| Frontend build | `cd threatgenix/frontend && npm run build` | Production bundle check |
| API integration | `cd tests/e2e && python -m pytest -v` | Real Postgres plus backend subprocess |
| Browser E2E | `cd threatgenix/frontend && npm run test:e2e` | Real UI journeys through Playwright |
| Migration/startup | `test_migration_guards.py`, `test_startup_readiness.py` | Production safety and schema readiness |
| Security/hygiene | `scripts/check-oss-hygiene.sh` | Secret/private-string/publication guard |
| Manual exploratory | `docs/qa/manual-exploratory.md` | Release-candidate human pass |

## First Tests To Add

| Order | Target | Assertion |
| --- | --- | --- |
| 1 | `tests/e2e/test_00_smoke.py` | Full stack health returns `status=ok`, deep DB check passes, Alembic revision is current. |
| 2 | `threatgenix/backend/tests/test_startup_readiness.py` | Production rejects each dangerous default independently. |
| 3 | `threatgenix/backend/tests/test_migration_guards.py` | Partial migration leaves health degraded with useful missing-schema output. |
| 4 | `threatgenix/backend/tests/test_security_headers.py` | `/api/health` and one owned route include expected hardening headers. |
| 5 | `threatgenix/backend/tests/test_tenant_isolation_matrix.py` | Wrong-user access fails across models, DFD, threats, scans, reviews, evidence, and environment routes. |
| 6 | `threatgenix/backend/tests/test_engine_golden.py` | Fixed DFD fixture produces a stable threat ID/severity golden output. |
| 7 | `threatgenix/backend/tests/test_doc_cleanup_purges.py` | Uploaded document raw text is purged after retention threshold. |
| 8 | `tests/e2e/test_02_demo_flow.py` | AI-provider outage still returns deterministic threats and an explicit skipped reason. |
| 9 | `threatgenix/backend/tests/test_pdf_report_contents.py` | Generated PDF contains model name, STRIDE, key compliance frameworks, and a DFD image. |
| 10 | `threatgenix/backend/tests/test_threats_export_csv.py` | CSV export has headers, rows, and owner scoping. |
| 11 | `threatgenix/backend/tests/test_compliance_coverage.py` | Sampled STRIDE categories map to the expected compliance framework families. |
| 12 | `threatgenix/frontend/e2e/auth-roundtrip.spec.ts` | Register, logout, login, reload, dashboard remains accessible. |
| 13 | `threatgenix/frontend/e2e/dfd-edit-and-analyze.spec.ts` | Create a model, build a small DFD, analyze, and see threats. |
| 14 | `threatgenix/frontend/e2e/triage-bulk.spec.ts` | Bulk triage persists after refresh. |
| 15 | `tests/e2e/test_01_api_contracts.py` | DFD quick-add and view-regeneration endpoints return schema-valid results. |

## Open Risks

- The OSS repo still contains a broad product surface: DFD modeling, threat rules,
  application review, scanners, orchestration, BYOK, reports, and GitHub flows.
  A release must either test all of it or intentionally hide unsupported areas.
- Real AI-provider behavior is non-deterministic and should be tested with stubs
  or cassettes in CI.
- The migration chain is long. Upgrade and partial-migration tests matter for
  self-hosted users.
- Validation runners are high-risk because they can execute scanner tools. Keep
  real scanner execution behind isolated runners and explicit allowlists.
- Current CI has unit and build gates but not a full browser E2E release gate.

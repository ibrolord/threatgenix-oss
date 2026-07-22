# Changelog

## v1.0.2-oss - 2026-07-22

Launch-readiness release for the self-hosted v1 product.

### Fixed

- Prevented host `node_modules` and build artifacts from entering the frontend
  Docker context, which broke the documented Compose quick start on Apple
  Silicon with a missing Linux Rollup binary.
- Made the login rate limit configurable for self-hosted teams behind shared
  NAT while preserving the secure `10/minute` default.
- Made the live API smoke test accept a configurable base URL for isolated and
  non-default-port deployments.
- Replaced the README clone placeholder with the public repository URL.
- Removed an undefined Vite HTML placeholder that generated noisy production
  build output.
- Removed a false-positive secret fixture from the current-tree Gitleaks scan
  without weakening the BYOK test.
- Updated WeasyPrint to 69.0 to resolve CVE-2026-49452 before launch.
- Aligned the visible application, API, CLI, PDF, and package versions with the
  OSS release.

### Updated

- Extended the OSS hygiene gate with a regression that requires the frontend
  Docker context to exclude host dependencies and build output.

### Release Gates

- Fresh Docker Compose build and startup passed on Apple Silicon with PostgreSQL
  connected, Alembic revision `084`, backend health green, and frontend HTTP 200.
- Full backend pytest passed with 1,852 tests; 7 optional live-tool/provider
  tests remained skipped.
- Frontend typecheck, lint, 121 Vitest tests, and production build passed.
- Docker-backed API integration passed 74 tests.
- Live API journey passed 19/19 checks.
- Browser E2E passed all 20 customer journeys, including auth roundtrip, tenant
  isolation, DFD editing, triage, provider settings, application review, and
  exports.
- The Python dependency audit reported no known vulnerabilities after the
  WeasyPrint security update.
- The v1.0.2 CLI wheel built, installed into a clean virtual environment, and
  passed its installed `--help` and MCP configuration entry-point checks.
- OSS hygiene, hygiene self-test, and current-tree Gitleaks scan passed.

## v1.0.1-oss - 2026-05-16

Provider and embedding support release for self-hosted deployments.

### Added

- Z.ai generation provider support through the OpenAI-compatible chat API.
- Z.ai BYOK support in the backend provider API and Settings page.
- Configurable threat-intel embeddings through Bedrock, OpenAI, OpenRouter,
  Z.ai, or another OpenAI-compatible embedding endpoint.
- Embedding dimension guardrails that reject non-1024-dimensional vectors before
  they can be written to the shipped pgvector `Vector(1024)` schema.
- README, self-hosting, and env example documentation for Z.ai and configurable
  embedding providers.

### Release Gates

- GitHub CI passed for hygiene, backend, and frontend jobs.
- Full backend pytest passed locally.
- Full frontend Vitest, typecheck, lint, and production build passed locally.
- OSS hygiene scan passed locally and in GitHub CI.

## v1.0.0-oss - 2026-05-16

Initial open-source self-hosted release.

### Included

- Docker Compose self-hosted stack with FastAPI, React/Vite, PostgreSQL, and pgvector.
- Threat model CRUD, DFD editing, STRIDE rules, AI-assisted threat enhancement, triage, compliance, PDF/CSV export, validation evidence, application review, BYOK provider settings, and production startup gates.
- Local-first AI support with Ollama, optional external provider configuration, AWS Bedrock support through IAM, and BYOK for direct API providers.
- Single-source repository or pull-request evidence import per threat model/review.
- OSS hygiene scan for secrets, private/customer strings, and legacy product-name leaks.
- `python-multipart` pinned to `0.0.27` to include the upstream multipart
  header denial-of-service fix.

### Not Included

- Hosted SaaS deployment configuration.
- Managed cloud scanner runner infrastructure.
- Production secrets, provider credentials, private customer artifacts, or internal planning notes.
- Coordinated multi-repository review orchestration.

### Release Gates

- No open S0 or S1 rows in `docs/qa/feature-test-tracker.md`.
- `scripts/check-oss-hygiene.sh` passing.
- Release-critical self-hosted Docker browser/API paths closed in the QA tracker.

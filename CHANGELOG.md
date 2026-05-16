# Changelog

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

# Changelog

## v1.0.0-oss - 2026-05-15

Initial open-source self-hosted release.

### Included

- Docker Compose self-hosted stack with FastAPI, React/Vite, PostgreSQL, and pgvector.
- Threat model CRUD, DFD editing, STRIDE rules, AI-assisted threat enhancement, triage, compliance, PDF/CSV export, validation evidence, application review, BYOK provider settings, and production startup gates.
- Local-first AI support with Ollama, optional external provider configuration, AWS Bedrock support through IAM, and BYOK for direct API providers.
- Single-source repository or pull-request evidence import per threat model/review.
- OSS hygiene scan for secrets, private/customer strings, and legacy product-name leaks.

### Not Included

- Hosted SaaS deployment configuration.
- Managed cloud scanner runner infrastructure.
- Production secrets, provider credentials, private customer artifacts, or internal planning notes.
- Coordinated multi-repository review orchestration.

### Release Gates

- No open S0 or S1 rows in `docs/qa/feature-test-tracker.md`.
- `scripts/check-oss-hygiene.sh` passing.
- Release-critical self-hosted Docker browser/API paths closed in the QA tracker.

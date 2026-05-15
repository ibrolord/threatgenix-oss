# Semantic Bank Validation Fixture

Purpose-built local target for deterministic validation-runner smoke tests.
The files intentionally contain known findings so the runner can prove that
installed tools execute, normalize output, and create evidence without scanning
arbitrary customer paths.

Expected tool coverage:

- Semgrep: `app.py` contains a JWT decode call with signature verification disabled.
- OSV Scanner: `vulnerable-npm-lock.fixture.json` is materialized as a temporary
  `package-lock.json` by the smoke test so GitHub does not treat the fixture as
  a real repository dependency.
- Checkov/Trivy: `infra/main.tf` exposes deliberately weak Terraform controls.

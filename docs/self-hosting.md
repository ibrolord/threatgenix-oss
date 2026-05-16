# Self-Hosting ThreatGenix

This guide applies to the `v1.0.0-oss` self-hosted release.

The default self-hosted path is Docker Compose from the app root:

```bash
cd threatgenix
docker compose up --build
```

This starts:

- PostgreSQL with pgvector on `localhost:5432`
- FastAPI backend on `localhost:8000`
- Vite frontend on `localhost:5173`

On startup, the backend runs `alembic upgrade head` before serving requests so a
fresh self-hosted database is schema-ready and migration-stamped.

If those ports are already used on your workstation, set host-port overrides
without changing the container-to-container wiring:

```bash
DB_PORT=55432 BACKEND_PORT=8010 FRONTEND_PORT=5180 docker compose up --build
```

## Production Notes

The Compose file is a development baseline, not a complete production stack. A production deployment should add:

- TLS termination
- Persistent database backups
- Strong `SECRET_KEY`
- Restricted `ALLOWED_ORIGINS`
- Explicit `TRUSTED_HOSTS`
- Centralized logs
- Object storage or retention policy for uploaded artifacts
- Separate worker isolation for live scanner execution

ThreatGenix fails startup in `APP_ENV=production` or `APP_ENV=staging` when the
most dangerous defaults are still present. At minimum, production configuration
must use:

```env
APP_ENV=production
SECRET_KEY=<generated 32+ character secret>
DATABASE_URL=postgresql+asyncpg://...
ALLOWED_ORIGINS=https://threatgenix.example.com
TRUSTED_HOSTS=api.threatgenix.example.com
AUTH_EXPOSE_DEV_TOKENS=false
```

Production startup rejects wildcard CORS, non-HTTPS browser origins, loopback
origins, wildcard trusted hosts, loopback trusted hosts, the development secret
key, and local Compose database hosts.

## AI Providers

The local default is Ollama. External providers are configured through environment variables and should be enabled only after your organization approves provider data transfer.

## Repository Evidence Boundary

ThreatGenix OSS v1 supports a single GitHub repository, pull request, uploaded archive, or manifest bundle as repository evidence for a threat model at a time. Importing or uploading repository evidence again replaces the currently saved repository evidence for that model. Coordinated multi-repository review orchestration is not exposed in this release.

## Validation Runners

ThreatGenix can import validation evidence without executing scanners. Live scanner execution is higher risk and should run only on a trusted worker with scoped paths and resource limits.

## Release Hygiene

Before publishing a fork, release, or container image source context, run:

```bash
scripts/check-oss-hygiene.sh
```

The scan blocks high-signal secret patterns, tracked `.env` files, uncommented
provider keys in env examples, old private customer names, and the legacy product
name outside its regression test.

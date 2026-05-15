# Self-Hosting ThreatGenix

The default self-hosted path is Docker Compose from the app root:

```bash
cd threatgenix
docker compose up --build
```

This starts:

- PostgreSQL with pgvector on `localhost:5432`
- FastAPI backend on `localhost:8000`
- Vite frontend on `localhost:5173`

## Production Notes

The Compose file is a development baseline, not a complete production stack. A production deployment should add:

- TLS termination
- Persistent database backups
- Strong `SECRET_KEY`
- Restricted `ALLOWED_ORIGINS`
- Centralized logs
- Object storage or retention policy for uploaded artifacts
- Separate worker isolation for live scanner execution

## AI Providers

The local default is Ollama. External providers are configured through environment variables and should be enabled only after your organization approves provider data transfer.

## Validation Runners

ThreatGenix can import validation evidence without executing scanners. Live scanner execution is higher risk and should run only on a trusted worker with scoped paths and resource limits.

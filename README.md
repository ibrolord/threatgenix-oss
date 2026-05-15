# ThreatGenix

ThreatGenix is a self-hosted threat modeling and security-review workspace. It helps teams model systems as DFDs, generate STRIDE findings, attach validation evidence, review risks, and export structured security review output.

This repository is the open-source self-hosted edition. It is intended for local development, internal security teams, and teams that want to run ThreatGenix on their own infrastructure.

## What Is Included

- FastAPI backend with PostgreSQL/pgvector persistence
- React/Vite frontend for DFD editing, review workflows, validation evidence, and reporting
- CLI and MCP entry points for review automation
- Local Docker Compose stack for self-hosted development
- Optional LLM providers, including local Ollama and external providers configured by environment variable
- Optional validation-tool ingestion and controlled scanner execution paths

## What Is Not Included

- Hosted SaaS deployment configuration
- Private customer evidence, production smoke artifacts, or internal planning notes
- Managed cloud runner infrastructure
- Production secrets or provider credentials

## Quick Start

Requirements:

- Docker and Docker Compose
- Node.js 20+
- Python 3.12+
- Optional: Ollama if you want local AI-assisted features

Start the local stack:

```bash
cd threatgenix
docker compose up --build
```

Then open:

- Frontend: http://localhost:5173
- Backend health: http://localhost:8000/api/health

The local development stack uses safe example settings from `threatgenix/backend/.env.example`. For production, create a real `.env`, set `APP_ENV=production`, replace `SECRET_KEY`, use a managed PostgreSQL URL, and configure explicit AI provider credentials.

## Local Development

Backend:

```bash
cd threatgenix/backend
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd threatgenix/frontend
npm ci
npm run dev
```

Tests:

```bash
cd threatgenix
make test-backend
make test-frontend
```

## Configuration

Primary configuration lives in `threatgenix/backend/.env.example`.

The safest local AI path is Ollama:

```bash
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
```

External AI providers are opt-in. Do not set provider API keys unless your deployment policy allows sending review context to that provider.

## Security Notes

ThreatGenix is a security-analysis tool, not a security certification engine. Its output should be reviewed by a qualified engineer before it is used for release, compliance, or risk acceptance decisions.

For production use:

- Rotate `SECRET_KEY` before first boot.
- Use TLS and a managed PostgreSQL deployment.
- Keep uploaded architecture, source, scanner, and report artifacts inside your own trust boundary.
- Enable live scanner execution only on isolated runner hosts with tightly scoped target paths.
- Review `SECURITY.md` before exposing the app beyond localhost.

## License

MIT. See `LICENSE`.

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

## How To Run It

Requirements:

- Docker and Docker Compose
- Node.js 20+
- Python 3.12+
- Optional: Ollama if you want local AI-assisted features

### Option A: Docker Compose

```bash
git clone <your-fork-url> threatgenix-oss
cd threatgenix-oss/threatgenix
docker compose up --build
```

Open:

- Frontend: http://localhost:5173
- Backend health: http://localhost:8000/api/health

If local services already use those host ports, keep Compose isolated with:

```bash
DB_PORT=55432 BACKEND_PORT=8010 FRONTEND_PORT=5180 docker compose up --build
```

The Compose stack is a local development baseline. It binds the backend and
frontend to `127.0.0.1` by default, starts PostgreSQL with pgvector, and uses the
safe example settings in `threatgenix/backend/.env.example`. The backend runs
`alembic upgrade head` before serving requests so fresh self-hosted databases are
migration-stamped.

Stop it with:

```bash
docker compose down
```

Reset the local database:

```bash
make reset-db
```

### Option B: Run From Source

Start PostgreSQL:

```bash
cd threatgenix-oss/threatgenix
make dev-db
```

Start the backend:

```bash
cd threatgenix-oss/threatgenix/backend
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

In a second terminal, start the frontend:

```bash
cd threatgenix-oss/threatgenix/frontend
npm ci
npm run dev
```

Open http://localhost:5173 and create a local account from the sign-up screen.
The frontend proxies `/api` requests to the backend on `127.0.0.1:8000`.

## How To Configure AI

ThreatGenix runs without an external AI provider. Deterministic threat rules,
DFD editing, evidence workflows, and reporting still work.

For local AI, run Ollama and keep the default provider. If Ollama is not already
running, start it in a separate terminal:

```bash
ollama serve
```

Then pull the default model:

```bash
ollama pull llama3.1
```

```env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
```

For AWS Bedrock, use IAM credentials in the runtime environment:

```env
LLM_PROVIDER=bedrock
AWS_DEFAULT_REGION=ca-central-1
BEDROCK_REGION=ca-central-1
BEDROCK_MODEL_ID=ca.amazon.nova-lite-v1:0
BEDROCK_EMBEDDING_MODEL_ID=amazon.titan-embed-text-v2:0
```

For direct provider APIs, set `LLM_PROVIDER` to one of `anthropic`, `openai`,
`openrouter`, `gemini`, `xai`, or `perplexity` and set the matching API key.
The app also supports BYOK for those direct API providers from the Settings
page. Bedrock uses AWS IAM and is not stored as a per-user BYOK key.

External AI providers are opt-in. Do not set provider API keys unless your
deployment policy allows sending review context to that provider.

## How To Validate A Setup

Run the backend and frontend checks:

```bash
cd threatgenix-oss/threatgenix
make lint
make test-backend
make test-frontend
```

Run the open-source hygiene gate before publishing a fork, release, or source
context. This command runs from the repository root:

```bash
cd threatgenix-oss
scripts/check-oss-hygiene.sh
```

The hygiene gate blocks high-signal secret patterns, tracked `.env` files,
uncommented provider keys in env examples, private/customer strings, and legacy
product naming leaks.

## How To Prepare Production

Create a real production environment file. Do not use the checked-in development
defaults:

```env
APP_ENV=production
SECRET_KEY=<generated 32+ character secret>
DATABASE_URL=postgresql+asyncpg://...
ALLOWED_ORIGINS=https://threatgenix.example.com
TRUSTED_HOSTS=api.threatgenix.example.com
AUTH_EXPOSE_DEV_TOKENS=false
LLM_PROVIDER=ollama
ALLOW_EXTERNAL_AI_PROVIDERS_IN_PRODUCTION=false
```

Production and staging startup fail closed when dangerous defaults are present:
wildcard CORS, HTTP browser origins, loopback origins, missing or wildcard
trusted hosts, local Compose database hosts, default/short secrets, or exposed
development auth tokens.

Before exposing the app beyond localhost:

- Put TLS in front of the backend and frontend.
- Run `alembic upgrade head` against the production database.
- Use managed PostgreSQL with pgvector and backups.
- Keep uploaded architecture, source, scanner, and report artifacts inside your own trust boundary.
- Enable live scanner execution only on isolated runner hosts with scoped paths and resource limits.

See `docs/self-hosting.md` and `SECURITY.md` for the production checklist.

## Troubleshooting

- Backend will not start in production: check `SECRET_KEY`, `DATABASE_URL`,
  `ALLOWED_ORIGINS`, `TRUSTED_HOSTS`, and the Alembic revision.
- Frontend cannot reach the API: confirm the backend is on `http://127.0.0.1:8000`
  or set `VITE_API_PROXY_TARGET`.
- AI calls fail with Ollama: confirm `ollama serve` is running and the configured
  model has been pulled.
- Bedrock calls fail: confirm AWS credentials, region, and model IDs are
  available to the backend process.
- Vector retrieval is unavailable: confirm PostgreSQL has pgvector enabled and
  threat-intel sync has been run with embeddings enabled.

## Security Notes

ThreatGenix is a security-analysis tool, not a security certification engine. Its output should be reviewed by a qualified engineer before it is used for release, compliance, or risk acceptance decisions.

For production use:

- Set a generated `SECRET_KEY` with at least 32 characters before first boot.
- Use TLS, a managed PostgreSQL deployment, and database backups.
- Set `ALLOWED_ORIGINS` to your HTTPS frontend origin. Do not use `*` or loopback origins.
- Set `TRUSTED_HOSTS` to the public API host so host-header attacks fail closed.
- Keep uploaded architecture, source, scanner, and report artifacts inside your own trust boundary.
- Enable live scanner execution only on isolated runner hosts with tightly scoped target paths.
- Run `scripts/check-oss-hygiene.sh` before publishing a fork or release.
- Review `SECURITY.md` before exposing the app beyond localhost.

## License

MIT. See `LICENSE`.

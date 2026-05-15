# Contributing

Thanks for considering a contribution to ThreatGenix.

## Development Setup

```bash
cd threatgenix/backend
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

cd ../frontend
npm ci
```

Run local checks before opening a pull request:

```bash
cd threatgenix
make test-backend
make test-frontend
make lint
```

## Pull Request Expectations

- Keep changes focused.
- Add or update tests for behavior changes.
- Do not include secrets, private customer artifacts, production logs, or local `.env` files.
- Prefer deterministic fixtures over live external calls.
- Keep AI-assisted features honest about what evidence was actually inspected.

## Code Style

- Backend: Python 3.12, FastAPI, SQLAlchemy, Pydantic, pytest, ruff.
- Frontend: React, TypeScript, Vite, Vitest.
- Keep public docs self-hosted and deployment-neutral unless a deployment guide is explicitly scoped.

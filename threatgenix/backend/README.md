# ThreatGenix Backend

FastAPI backend for the ThreatGenix self-hosted app.

## Setup

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

The CLI package is built from this directory:

```bash
python -m pip wheel . --no-deps -w /tmp/threatgenix-wheelhouse
```

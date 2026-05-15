.PHONY: dev dev-db dev-backend dev-frontend test test-backend test-frontend lint migrate seed clean reset-db

BACKEND_PYTHON ?= $(shell if [ -x backend/.venv/bin/python ]; then echo .venv/bin/python; else echo python; fi)

# Development
dev:
	docker compose up --build

dev-db:
	docker compose up -d db

dev-backend: migrate
	cd backend && $(BACKEND_PYTHON) -m uvicorn app.main:app --reload --port 8000

dev-frontend:
	cd frontend && npm run dev

# Testing
test: test-backend test-frontend

test-backend:
	cd backend && $(BACKEND_PYTHON) -m pytest -v

test-frontend:
	cd frontend && npm run typecheck && npm test

# Linting
lint:
	cd backend && ruff check app tests
	cd frontend && npm run typecheck && npm run lint

# Database
migrate:
	cd backend && alembic upgrade head

migrate-down:
	cd backend && alembic downgrade -1

seed:
	cd backend && $(BACKEND_PYTHON) -m app.seed

# Docker
up:
	docker compose up -d

down:
	docker compose down

reset-db:
	docker compose down db -v
	docker compose up -d db
	@echo "Waiting for Postgres..."
	@sleep 3
	docker compose restart backend
	@echo "DB reset complete. Tables will be recreated on backend startup."

clean:
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf backend/.pytest_cache frontend/dist frontend/node_modules

# tests/e2e/Makefile

.PHONY: e2e e2e-live e2e-record setup teardown

DOCKER_COMPOSE := docker compose -f docker-compose.test.yml
PYTHON ?= $(shell if [ -x ../../threatgenix/backend/.venv/bin/python ]; then echo ../../threatgenix/backend/.venv/bin/python; else echo python; fi)
PYTEST := $(PYTHON) -m pytest -xvs --tb=short

setup:
	$(DOCKER_COMPOSE) up -d --wait
	@echo "Test Postgres ready on port 5433"

teardown:
	$(DOCKER_COMPOSE) down -v

e2e: setup
	$(PYTEST) test_00_smoke.py test_01_api_contracts.py test_02_demo_flow.py \
	  test_03_concurrency.py test_04_data_integrity.py test_05_performance.py \
	  test_06_domain.py test_09_threat_csv_export.py \
	  test_10_compliance_framework_coverage.py test_11_document_retention.py \
	  test_12_dfd_contracts.py test_08_auth_rate_limit.py
	@echo "Frontend visual tests run via MCP during agent invocation"

e2e-record: setup
	VCR_MODE=record $(PYTEST) test_02_demo_flow.py
	@echo "Bedrock responses recorded to fixtures/bedrock_responses/"

e2e-live: setup
	VCR_MODE=live $(PYTEST) test_02_demo_flow.py test_01_api_contracts.py
	@echo "All tests ran against live Bedrock"

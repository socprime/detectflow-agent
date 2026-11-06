# DetectFlow Agent — root Makefile.
#
# This Makefile drives:
#   - The pytest INTEGRATION stack (`make integration-*`) under tests/integration/
#   - Local lint / format / test / audit shortcuts
#   - Local builds of the prod Dockerfiles (Dockerfile.correlation / Dockerfile.agent)

.PHONY: help \
        integration-up integration-up-ollama integration-down integration-clean \
        integration-logs integration-status integration-build test-integration \
        test test-unit \
        lint fmt audit sync env-check \
        build-correlation build-agent build-images

# Tools / variables ---------------------------------------------------------
UV               := uv run
COMPOSE          := docker compose -f tests/integration/docker-compose.yml
COMPOSE_OLLAMA   := $(COMPOSE) -f tests/integration/docker-compose.ollama.yml

IMAGE_TAG        ?= dev
CORRELATION_IMAGE ?= detectflow-agent-correlation
AGENT_IMAGE      ?= detectflow-agent-agent

PYTEST_ARGS      ?=

# ---------- Integration stack (tests/integration/) -------------------------

integration-up: ## Bring up Kafka + 2 Flink application clusters + LLM stub
	$(COMPOSE) up -d --build
	@echo
	@echo "Stack up."
	@echo "  Correlation Flink UI: http://localhost:8081"
	@echo "  Agent       Flink UI: http://localhost:8082"
	@echo "  LLM stub healthz:     http://localhost:8001/healthz"

integration-up-ollama: ## Same stack but with Ollama (real LLM) instead of FastAPI stub
	$(COMPOSE_OLLAMA) up -d --build

integration-down: ## Stop integration containers, keep volumes
	$(COMPOSE) down

integration-clean: ## Stop integration containers AND remove volumes
	$(COMPOSE) down -v
	$(COMPOSE_OLLAMA) down -v 2>/dev/null || true

integration-logs: ## Tail integration stack logs
	$(COMPOSE) logs -f --tail=100

integration-status: ## Show running integration containers + Flink job list
	$(COMPOSE) ps
	@echo
	@echo "== Correlation cluster (http://localhost:8081) =="
	@curl -s http://localhost:8081/v1/jobs/overview 2>/dev/null \
	    | python -m json.tool 2>/dev/null \
	    || echo "(correlation JM not reachable yet)"
	@echo
	@echo "== Agent cluster (http://localhost:8082) =="
	@curl -s http://localhost:8082/v1/jobs/overview 2>/dev/null \
	    | python -m json.tool 2>/dev/null \
	    || echo "(agent JM not reachable yet)"

integration-build: ## Rebuild integration images without bringing the stack up
	$(COMPOSE) build

# ---------- Tests ----------------------------------------------------------

test: test-unit ## Default test target (alias for test-unit)

test-unit: ## Run the unit-test suite
	$(UV) pytest $(PYTEST_ARGS)

test-integration: ## Run pytest against the integration stack (must be `make integration-up` first)
	$(UV) pytest -m integration $(PYTEST_ARGS)

# ---------- Lint & format --------------------------------------------------

lint: ## Ruff check and format check only, no autofix
	$(UV) ruff check .
	$(UV) ruff format --check .

fmt: ## Apply ruff fixes + format in-place
	$(UV) ruff check --fix .
	$(UV) ruff format .

audit: ## Audit dependencies for known vulnerabilities
	uvx pysentry-rs@0.5.0 --fail-on critical

env-check: ## Load Settings() from .env.example
	@$(UV) python -c "from app.config.settings import Settings; Settings(_env_file='.env.example'); print('OK')"

# ---------- Dependency sync ------------------------------------------------

sync: ## uv sync with both extras + dev group
	uv sync --all-extras

# ---------- Production images ----------------------------------------------
# Lets a contributor verify a Dockerfile change locally without spinning up a stack.

build-correlation: ## Build the correlation-job prod image
	docker build -f Dockerfile.correlation -t $(CORRELATION_IMAGE):$(IMAGE_TAG) .

build-agent: ## Build the agent-job prod image
	docker build -f Dockerfile.agent -t $(AGENT_IMAGE):$(IMAGE_TAG) .

build-images: build-correlation build-agent ## Build both prod images

# ---------- Help -----------------------------------------------------------

help: ## Show this help
	@echo "DetectFlow Agent — root Makefile"
	@echo ""
	@echo "  Integration stack:"
	@grep -hE '^integration-[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}; {printf "    %-26s %s\n", $$1, $$2}'
	@echo ""
	@echo "  Tests:"
	@grep -hE '^test[a-zA-Z_-]*:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}; {printf "    %-26s %s\n", $$1, $$2}'
	@echo ""
	@echo "  Lint, format, audit:"
	@grep -hE '^(lint|fmt|audit|env-check):.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}; {printf "    %-26s %s\n", $$1, $$2}'
	@echo ""
	@echo "  Dependencies & images:"
	@grep -hE '^(sync|build-[a-zA-Z_-]+):.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}; {printf "    %-26s %s\n", $$1, $$2}'

.DEFAULT_GOAL := help

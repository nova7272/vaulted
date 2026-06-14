# ============================================
# XRPL Vault - Makefile
# ============================================

.PHONY: help setup dev dev-tools down clean build test lint fmt check db-reset logs oracle storage migrate

# Output colors
CYAN := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RESET := \033[0m

help: ## Show help
	@echo "$(CYAN)XRPL Vault - Development Commands$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(RESET) %s\n", $$1, $$2}'

# ============================================
# Environment setup
# ============================================

setup: ## Initial project setup
	@echo "$(CYAN)Setting up project...$(RESET)"
	@cp -n .env.example .env 2>/dev/null || true
	@echo "$(GREEN)✓ Created .env file$(RESET)"
	@docker compose pull
	@echo "$(GREEN)✓ Docker images pulled$(RESET)"
	@echo ""
	@echo "$(YELLOW)Next steps:$(RESET)"
	@echo "  1. Edit the .env file"
	@echo "  2. Run: make dev"

# ============================================
# Docker Compose
# ============================================

dev: ## Start dev environment (PostgreSQL + Redis)
	@echo "$(CYAN)Starting dev environment...$(RESET)"
	docker compose up -d postgres redis
	@sleep 3
	@$(MAKE) migrate
	@echo ""
	@echo "$(GREEN)✓ Services started:$(RESET)"
	@echo "  PostgreSQL: localhost:5432"
	@echo "  Redis:      localhost:6379"
	@echo ""
	@echo "Next steps:"
	@echo "  make oracle   - start Oracle server"
	@echo "  make storage  - start Storage Node"

dev-tools: ## Start dev environment + web interfaces (Adminer, Redis Commander)
	@echo "$(CYAN)Starting dev environment with tools...$(RESET)"
	docker compose --profile dev-tools up -d
	@sleep 3
	@$(MAKE) migrate
	@echo ""
	@echo "$(GREEN)✓ Services started:$(RESET)"
	@echo "  PostgreSQL:       localhost:5432"
	@echo "  Redis:            localhost:6379"
	@echo "  Adminer (DB UI):  http://localhost:8080"
	@echo "  Redis Commander:  http://localhost:8081"

down: ## Stop all services
	@echo "$(CYAN)Stopping services...$(RESET)"
	docker compose --profile dev-tools down
	@echo "$(GREEN)✓ Services stopped$(RESET)"

clean: ## Stop services and delete data
	@echo "$(YELLOW)Warning: this will delete all data!$(RESET)"
	@read -p "Continue? [y/N] " confirm && [ "$$confirm" = "y" ]
	docker compose --profile dev-tools down -v
	@echo "$(GREEN)✓ Services stopped, data deleted$(RESET)"

logs: ## Show service logs
	docker compose logs -f

logs-postgres: ## Show PostgreSQL logs
	docker compose logs -f postgres

logs-redis: ## Show Redis logs
	docker compose logs -f redis

# ============================================
# Rust / Cargo
# ============================================

build: ## Build project
	cargo build --workspace

build-release: ## Build release version
	cargo build --release --workspace

test: ## Run tests
	cargo test --workspace

test-verbose: ## Run tests with verbose output
	cargo test --workspace -- --nocapture

test-crypto: ## Run crypto module tests only
	cargo test -p xrpl-vault-crypto-core

lint: ## Check code with linter
	cargo clippy --all-targets --all-features -- -D warnings

fmt: ## Format code
	cargo fmt

fmt-check: ## Check formatting
	cargo fmt -- --check

check: ## Full check (cargo check)
	cargo check --workspace

# ============================================
# Database
# ============================================

migrate: ## Apply migrations
	@echo "$(CYAN)Applying migrations...$(RESET)"
	@docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -f /docker-entrypoint-initdb.d/init.sql 2>/dev/null || true
	@for f in migrations/002*.sql migrations/003*.sql; do \
		if [ -f "$$f" ]; then \
			echo "  Applying $$(basename $$f)..."; \
			docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault < "$$f" 2>/dev/null || true; \
		fi \
	done
	@echo "$(GREEN)✓ Migrations applied$(RESET)"

db-reset: ## Reset database (recreate tables)
	@echo "$(YELLOW)Resetting database...$(RESET)"
	docker compose exec postgres psql -U xrpl_vault -d xrpl_vault -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	@$(MAKE) migrate
	@echo "$(GREEN)✓ Database reset$(RESET)"

db-shell: ## Open psql shell
	docker compose exec postgres psql -U xrpl_vault -d xrpl_vault

redis-shell: ## Open redis-cli
	docker compose exec redis redis-cli

# ============================================
# Run services
# ============================================

oracle: ## Start Oracle server
	@echo "$(CYAN)Starting Oracle server...$(RESET)"
	DATABASE_URL=postgres://xrpl_vault:dev_password_change_me@localhost:5432/xrpl_vault \
	ORACLE_HOST=127.0.0.1 \
	ORACLE_PORT=3000 \
	XRPL_WALLET_SEED=snBL9AaUVoAj1oCEASs599pCu1Wsc \
	XRPL_NODE_URL=https://s.altnet.rippletest.net:51234 \
	RUST_LOG=xrpl_vault_oracle=debug,tower_http=debug \
	cargo run --bin oracle

storage: ## Start Storage Node
	@echo "$(CYAN)Starting Storage Node...$(RESET)"
	@mkdir -p ./data/fragments
	NODE_ID=node-eu-1 \
	PORT=9001 \
	STORAGE_DIR=./data/fragments \
	RUST_LOG=storage_node=info \
	cargo run --bin storage-node

# ============================================
# Full Flow Test
# ============================================

test-flow: ## Test full flow (requires running services)
	@echo "$(CYAN)Testing full flow...$(RESET)"
	@curl -s http://localhost:3000/health > /dev/null || (echo "$(YELLOW)Oracle is not running. Run: make oracle$(RESET)" && exit 1)
	@curl -s http://localhost:9001/health > /dev/null || (echo "$(YELLOW)Storage is not running. Run: make storage$(RESET)" && exit 1)
	@echo "$(GREEN)✓ All services are running$(RESET)"
	cargo test --package xrpl-vault-oracle --test integration -- --nocapture


# ============================================
# Documentation
# ============================================

docs: ## Generate documentation
	cargo doc --no-deps --workspace --open

docs-crypto: ## Crypto module documentation
	cargo doc -p xrpl-vault-crypto-core --no-deps --open

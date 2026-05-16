# ============================================
# XRPL Vault - Makefile
# ============================================

.PHONY: help setup dev dev-tools down clean build test lint fmt check db-reset logs oracle storage migrate security-audit security-audit-strict sensitive-log-audit

# Цвета для вывода
CYAN := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RESET := \033[0m

help: ## Показать справку
	@echo "$(CYAN)XRPL Vault - Команды разработки$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(RESET) %s\n", $$1, $$2}'

# ============================================
# Настройка окружения
# ============================================

setup: ## Первоначальная настройка проекта
	@echo "$(CYAN)Настройка проекта...$(RESET)"
	@cp -n .env.example .env 2>/dev/null || true
	@echo "$(GREEN)✓ Создан .env файл$(RESET)"
	@docker compose pull
	@echo "$(GREEN)✓ Docker образы загружены$(RESET)"
	@echo ""
	@echo "$(YELLOW)Следующие шаги:$(RESET)"
	@echo "  1. Отредактируйте .env файл"
	@echo "  2. Запустите: make dev"

# ============================================
# Docker Compose
# ============================================

dev: ## Запустить dev окружение (PostgreSQL + Redis)
	@echo "$(CYAN)Запуск dev окружения...$(RESET)"
	docker compose up -d postgres redis
	@sleep 3
	@$(MAKE) migrate
	@echo ""
	@echo "$(GREEN)✓ Сервисы запущены:$(RESET)"
	@echo "  PostgreSQL: localhost:5432"
	@echo "  Redis:      localhost:6379"
	@echo ""
	@echo "Следующие шаги:"
	@echo "  make oracle   - запустить Oracle сервер"
	@echo "  make storage  - запустить Storage Node"

dev-tools: ## Запустить dev окружение + веб-интерфейсы (Adminer, Redis Commander)
	@echo "$(CYAN)Запуск dev окружения с инструментами...$(RESET)"
	docker compose --profile dev-tools up -d
	@sleep 3
	@$(MAKE) migrate
	@echo ""
	@echo "$(GREEN)✓ Сервисы запущены:$(RESET)"
	@echo "  PostgreSQL:       localhost:5432"
	@echo "  Redis:            localhost:6379"
	@echo "  Adminer (DB UI):  http://localhost:8080"
	@echo "  Redis Commander:  http://localhost:8081"

down: ## Остановить все сервисы
	@echo "$(CYAN)Остановка сервисов...$(RESET)"
	docker compose --profile dev-tools down
	@echo "$(GREEN)✓ Сервисы остановлены$(RESET)"

clean: ## Остановить сервисы и удалить данные
	@echo "$(YELLOW)Внимание: это удалит все данные!$(RESET)"
	@read -p "Продолжить? [y/N] " confirm && [ "$$confirm" = "y" ]
	docker compose --profile dev-tools down -v
	@echo "$(GREEN)✓ Сервисы остановлены, данные удалены$(RESET)"

logs: ## Показать логи сервисов
	docker compose logs -f

logs-postgres: ## Показать логи PostgreSQL
	docker compose logs -f postgres

logs-redis: ## Показать логи Redis
	docker compose logs -f redis

# ============================================
# Rust / Cargo
# ============================================

build: ## Собрать проект
	cargo build --workspace

build-release: ## Собрать релизную версию
	cargo build --release --workspace

test: ## Запустить тесты
	cargo test --workspace

test-verbose: ## Запустить тесты с подробным выводом
	cargo test --workspace -- --nocapture

test-crypto: ## Запустить только тесты крипто-модуля
	cargo test -p xrpl-vault-crypto-core

lint: ## Проверить код линтером
	cargo clippy --all-targets --all-features -- -D warnings

fmt: ## Форматировать код
	cargo fmt

fmt-check: ## Проверить форматирование
	cargo fmt -- --check

check: ## Полная проверка (cargo check)
	cargo check --workspace

# ============================================
# База данных
# ============================================

migrate: ## Применить миграции
	@echo "$(CYAN)Применение миграций...$(RESET)"
	@docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -f /docker-entrypoint-initdb.d/init.sql 2>/dev/null || true
	@for f in migrations/002*.sql migrations/003*.sql; do \
		if [ -f "$$f" ]; then \
			echo "  Applying $$(basename $$f)..."; \
			docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault < "$$f" 2>/dev/null || true; \
		fi \
	done
	@echo "$(GREEN)✓ Миграции применены$(RESET)"

db-reset: ## Сбросить базу данных (пересоздать таблицы)
	@echo "$(YELLOW)Сброс базы данных...$(RESET)"
	docker compose exec postgres psql -U xrpl_vault -d xrpl_vault -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	@$(MAKE) migrate
	@echo "$(GREEN)✓ База данных сброшена$(RESET)"

db-shell: ## Открыть psql shell
	docker compose exec postgres psql -U xrpl_vault -d xrpl_vault

redis-shell: ## Открыть redis-cli
	docker compose exec redis redis-cli

# ============================================
# Запуск сервисов
# ============================================

oracle: ## Запустить Oracle сервер
	@echo "$(CYAN)Запуск Oracle сервера...$(RESET)"
	DATABASE_URL=postgres://xrpl_vault:dev_password_change_me@localhost:5432/xrpl_vault \
	ORACLE_HOST=127.0.0.1 \
	ORACLE_PORT=3000 \
	XRPL_WALLET_SEED=snBL9AaUVoAj1oCEASs599pCu1Wsc \
	XRPL_NODE_URL=https://s.altnet.rippletest.net:51234 \
	RUST_LOG=xrpl_vault_oracle=debug,tower_http=debug \
	cargo run --bin oracle

storage: ## Запустить Storage Node
	@echo "$(CYAN)Запуск Storage Node...$(RESET)"
	@mkdir -p ./data/fragments
	NODE_ID=node-eu-1 \
	PORT=9001 \
	STORAGE_DIR=./data/fragments \
	RUST_LOG=storage_node=info \
	cargo run --bin storage-node

# ============================================
# Full Flow Test
# ============================================

test-flow: ## Тест полного flow (требует запущенных сервисов)
	@echo "$(CYAN)Тестирование полного flow...$(RESET)"
	@curl -s http://localhost:3000/health > /dev/null || (echo "$(YELLOW)Oracle не запущен. Запустите: make oracle$(RESET)" && exit 1)
	@curl -s http://localhost:9001/health > /dev/null || (echo "$(YELLOW)Storage не запущен. Запустите: make storage$(RESET)" && exit 1)
	@echo "$(GREEN)✓ Все сервисы работают$(RESET)"
	cargo test --package xrpl-vault-oracle --test integration -- --nocapture


# ============================================
# Security / Hardening
# ============================================

sensitive-log-audit: ## Проверить, что sensitive values не логируются напрямую
	./scripts/check-sensitive-logs.sh

security-audit: ## Запустить hardening audit без fail-fast на advisory warnings
	./scripts/security-audit.sh

security-audit-strict: ## Запустить hardening audit в CI-строгом режиме
	./scripts/security-audit.sh --strict

# ============================================
# Документация
# ============================================

docs: ## Сгенерировать документацию
	cargo doc --no-deps --workspace --open

docs-crypto: ## Документация крипто-модуля
	cargo doc -p xrpl-vault-crypto-core --no-deps --open

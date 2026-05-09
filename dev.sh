#!/bin/bash
# =============================================================
# XRPL Vault - Development Environment Setup & Test Script
# =============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Auto-detect docker compose command (v2 plugin vs v1 standalone)
if docker compose version > /dev/null 2>&1; then
    DC="docker compose"
elif docker-compose version > /dev/null 2>&1; then
    DC="docker-compose"
else
    DC="docker compose"  # fallback, will error with a clear message
fi

# =============================================================
# Commands
# =============================================================

cmd_start() {
    log_info "Starting PostgreSQL and Redis..."
    $DC up -d postgres redis

    log_info "Waiting for PostgreSQL to be ready..."
    for i in {1..30}; do
        if $DC exec -T postgres pg_isready -U xrpl_vault -d xrpl_vault > /dev/null 2>&1; then
            log_success "PostgreSQL is ready"
            break
        fi
        sleep 1
    done

    log_info "Running SQL migrations..."
    run_migrations

    log_success "Infrastructure started!"
    echo ""
    echo "PostgreSQL: localhost:5432 (user: xrpl_vault, db: xrpl_vault)"
    echo "Redis:      localhost:6379"
    echo ""
    echo "Run 'make oracle' to start the Oracle server"
    echo "Run 'make storage' to start the Storage Node"
}

cmd_stop() {
    log_info "Stopping all containers..."
    $DC down
    log_success "Stopped"
}

cmd_reset() {
    log_warn "This will delete all data!"
    read -p "Are you sure? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        $DC down -v
        log_success "All data deleted"
    fi
}

cmd_status() {
    echo ""
    echo "=== Container Status ==="
    $DC ps
    echo ""
    echo "=== PostgreSQL ==="
    if $DC exec -T postgres pg_isready -U xrpl_vault -d xrpl_vault > /dev/null 2>&1; then
        log_success "PostgreSQL is running"

        # Show tables
        echo ""
        $DC exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "\dt" 2>/dev/null || true
    else
        log_error "PostgreSQL is not running"
    fi
    echo ""
}

run_migrations() {
    log_info "Applying migrations..."

    # Apply init.sql
    if $DC exec -T postgres psql -U xrpl_vault -d xrpl_vault -f /docker-entrypoint-initdb.d/init.sql > /dev/null 2>&1; then
        log_success "init.sql applied (or already exists)"
    fi

    # Apply other migrations
    for migration in migrations/002*.sql migrations/003*.sql; do
        if [ -f "$migration" ]; then
            name=$(basename "$migration")
            log_info "Applying $name..."
            $DC exec -T postgres psql -U xrpl_vault -d xrpl_vault < "$migration" > /dev/null 2>&1 || true
        fi
    done

    log_success "Migrations complete"
}

cmd_migrate() {
    run_migrations
}

cmd_psql() {
    log_info "Connecting to PostgreSQL..."
    $DC exec postgres psql -U xrpl_vault -d xrpl_vault
}

cmd_oracle() {
    log_info "Starting Oracle server..."

    # Check if postgres is running
    if ! $DC exec -T postgres pg_isready -U xrpl_vault -d xrpl_vault > /dev/null 2>&1; then
        log_error "PostgreSQL is not running. Run './dev.sh start' first"
        exit 1
    fi

    # Load .env if exists
    if [ -f .env ]; then
        export $(cat .env | grep -v '^#' | xargs)
    fi

    # Set defaults
    export DATABASE_URL="${DATABASE_URL:-postgres://xrpl_vault:dev_password_change_me@localhost:5432/xrpl_vault}"
    export ORACLE_HOST="${ORACLE_HOST:-127.0.0.1}"
    export ORACLE_PORT="${ORACLE_PORT:-3000}"
    export NODE_SECRET="${NODE_SECRET:-dev-node-secret-change-me}"
    export RUST_LOG="${RUST_LOG:-xrpl_vault_oracle=debug,tower_http=debug}"

    cargo run --bin oracle
}

cmd_storage() {
    log_info "Starting Storage Node..."

    export NODE_ID="${NODE_ID:-node-local-1}"
    export PORT="${PORT:-9001}"
    export STORAGE_DIR="${STORAGE_DIR:-./data/fragments}"
    export ORACLE_URL="${ORACLE_URL:-http://localhost:3000}"
    export NODE_SECRET="${NODE_SECRET:-dev-node-secret-change-me}"
    export RUST_LOG="${RUST_LOG:-storage_node=info}"

    mkdir -p "$STORAGE_DIR"

    cargo run --bin storage-node
}

cmd_test_flow() {
    log_info "Testing full flow: auth → upload → mint → transfer"

    # Check services
    log_info "Checking Oracle..."
    if ! curl -s http://localhost:3000/health > /dev/null 2>&1; then
        log_error "Oracle is not running on localhost:3000"
        exit 1
    fi
    log_success "Oracle is running"

    log_info "Checking Storage Node..."
    if ! curl -s http://localhost:9001/health > /dev/null 2>&1; then
        log_error "Storage Node is not running on localhost:9001"
        exit 1
    fi
    log_success "Storage Node is running"

    # Run integration test
    log_info "Running integration tests..."
    cargo test --package xrpl-vault-oracle -- --nocapture

    log_success "All tests passed!"
}

cmd_build() {
    log_info "Building all crates..."
    cargo build --workspace
    log_success "Build complete"
}

cmd_check() {
    log_info "Running cargo check..."
    cargo check --workspace
    log_success "Check complete"
}

cmd_help() {
    echo "XRPL Vault Development Script"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Infrastructure:"
    echo "  start     - Start PostgreSQL and Redis, run migrations"
    echo "  stop      - Stop all containers"
    echo "  reset     - Stop and delete all data"
    echo "  status    - Show container status"
    echo "  migrate   - Run SQL migrations"
    echo "  psql      - Open PostgreSQL CLI"
    echo ""
    echo "Services:"
    echo "  oracle    - Start Oracle server"
    echo "  storage   - Start Storage Node"
    echo ""
    echo "Development:"
    echo "  build     - Build all crates"
    echo "  check     - Run cargo check"
    echo "  test-flow - Test full flow"
    echo ""
}

# =============================================================
# Main
# =============================================================

case "${1:-help}" in
    start)    cmd_start ;;
    stop)     cmd_stop ;;
    reset)    cmd_reset ;;
    status)   cmd_status ;;
    migrate)  cmd_migrate ;;
    psql)     cmd_psql ;;
    oracle)   cmd_oracle ;;
    storage)  cmd_storage ;;
    build)    cmd_build ;;
    check)    cmd_check ;;
    test-flow) cmd_test_flow ;;
    help|--help|-h) cmd_help ;;
    *)
        log_error "Unknown command: $1"
        cmd_help
        exit 1
        ;;
esac
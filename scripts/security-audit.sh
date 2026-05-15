#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STRICT=0
if [[ "${1:-}" == "--strict" ]]; then
  STRICT=1
fi

section() {
  printf '\n\033[36m==> %s\033[0m\n' "$1"
}

section "Sensitive logging scan"
./scripts/check-sensitive-logs.sh

section "Rust formatting/check/tests"
cargo fmt -- --check
cargo check --workspace
cargo test --workspace

section "Rust dependency audit"
if command -v cargo-audit >/dev/null 2>&1; then
  # RUSTSEC-2023-0071 is pulled into Cargo.lock through sqlx-mysql/rsa metadata,
  # but is not reachable in the built workspace graph:
  #   cargo tree --target all -i sqlx-mysql
  #   cargo tree --target all -i rsa
  # both report "nothing to print".
  cargo audit --ignore RUSTSEC-2023-0071
else
  echo "cargo-audit is not installed; skipping Rust dependency advisory scan."
  echo "Install with: cargo install cargo-audit"
  if [[ "$STRICT" -eq 1 ]]; then
    exit 1
  fi
fi

section "Frontend lint/typecheck/build/audit"
(
  cd crates/desktop-client/ui
  npm ci
  npm run lint
  npx tsc --noEmit --project tsconfig.json
  npm run build
  if [[ "$STRICT" -eq 1 ]]; then
    npm audit --audit-level=high
  else
    npm audit || true
  fi
)

section "Done"
echo "Security audit completed. Use --strict in CI to fail on missing cargo-audit or high npm advisories."

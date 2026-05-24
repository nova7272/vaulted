# Project Base Rules

> Auto-detected conventions from the current codebase. Edit as needed when the project intentionally changes direction.

## Naming Conventions
- Rust crates use kebab-case package names and snake_case module/file names.
- Rust variables and functions use `snake_case`.
- Rust types, enums, traits, and React component names use `PascalCase`.
- TypeScript variables and functions use `camelCase`; union/string literal state types are used for compact UI state such as screen names.
- SQL migration files use numeric prefixes such as `012_qr_device_pairing.sql`.

## Module Structure
- Keep shared cryptographic/domain primitives in `crates/crypto-core`.
- Keep desktop-only local state, Tauri commands, secure storage, and filesystem integration in `crates/desktop-client`.
- Keep React UI under `crates/desktop-client/ui/src`, grouped into `components/`, `screens/`, `contexts/`, and `utils/`.
- Keep Oracle API, auth, database, middleware, storage-token, XRPL verification, and migration logic in `crates/oracle`.
- Keep storage fragment serving and token verification in `crates/storage-node`.
- Keep schema changes in `migrations/`; do not bury schema mutations inside application code.
- Keep developer/security automation in `Makefile` and `scripts/`.

## Error Handling
- Prefer crate-local `Result<T>` aliases and typed errors based on `thiserror` for library and service logic.
- Convert `sqlx`, crypto, HTTP, and infrastructure errors at the boundary where context is known.
- Oracle HTTP handlers should return structured API errors that map to status codes and JSON error bodies.
- Use `anyhow::Result<()>` for process bootstrap and orchestration code where the caller cannot recover.

## Logging
- Use `tracing` in Rust services and Tauri backend code.
- Control verbosity through `RUST_LOG`/EnvFilter.
- Never log seed phrases, private keys, file keys, decrypted content, access tokens, or raw secret-bearing QR payloads.
- Prefer explicit security-aware log messages for configuration source and operational mode.

## Testing And Verification
- For Rust changes, prefer the narrowest useful command first, then `cargo test --workspace` for broader verification.
- For Oracle/API changes, include migration and integration-test impact in the test plan.
- For UI changes, run `npm run lint`, `npx tsc --noEmit --project tsconfig.json`, and `npm run build` from `crates/desktop-client/ui` when dependencies are available.
- For security-sensitive changes, run `./scripts/check-sensitive-logs.sh` and the relevant `./scripts/security-audit.sh` mode.

## Agent Workflow Rules
- Decompose shell commands instead of chaining unrelated operations in one command.
- Do not fetch external skills or dependencies in this WSL environment unless the user explicitly restores working DNS/network access.
- Treat existing user changes as authoritative; do not revert unrelated files.

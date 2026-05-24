# Vaulted Project Description

## Overview
Vaulted is an encrypted file vault built around a first-party Vaulted seed, local XRPL wallet signing, deterministic NFT metadata, and recipient-bound `KeyEnvelope` sharing. Private seed material, file keys, and decrypted file content are intended to stay on the desktop client; the Oracle indexes and verifies state but must not receive plaintext file keys.

## Detected Stack
- **Primary language:** Rust 2021 workspace
- **Desktop shell:** Tauri 2
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS
- **Backend API:** Axum on Tokio
- **Database:** PostgreSQL via `sqlx`
- **Cache/session support:** Redis
- **Local infrastructure:** Docker Compose for PostgreSQL, Redis, Adminer, and Redis Commander
- **Cryptography:** AES-GCM, ChaCha20-Poly1305, Ed25519, X25519, BIP39, HKDF, BLAKE3, SHA-2, XRPL signing helpers, legacy PRE compatibility
- **Observability:** `tracing` and `tracing-subscriber`
- **Testing/tooling:** `cargo test --workspace`, `cargo clippy`, `cargo fmt`, UI `npm run lint`, `tsc`, Vite build, custom security scripts

## Workspace Modules
- **`crates/crypto-core`:** Shared cryptographic primitives, Vaulted identity derivation, seed handling, file encryption, `KeyEnvelope`, manifests, QR payloads, secure notes, and local XRPL wallet/signing logic.
- **`crates/desktop-client`:** Tauri desktop application that performs local encryption/decryption, seed-derived identity and wallet operations, QR flows, secure storage, and calls Oracle/storage APIs.
- **`crates/desktop-client/ui`:** React/Vite UI for authentication, files, uploads, secure notes, activity, settings, Oracle login, toasts, status checks, and QR rendering.
- **`crates/oracle`:** Axum service for registry, auth, manifests, QR coordination, grants, device state, XRPL ledger verification, migrations, rate limiting, token issuance, and storage-node coordination.
- **`crates/storage-node`:** Storage service for encrypted file fragments and storage-token verification.

## Existing Project Patterns
- Rust crates use `thiserror` enums plus crate-local `Result<T>` aliases for structured errors.
- Service entry points use `anyhow::Result<()>` for bootstrap code and convert typed errors near API boundaries.
- HTTP-facing errors are converted into structured JSON responses in `crates/oracle/src/error.rs`.
- Runtime logging uses `tracing::*` with `RUST_LOG`/EnvFilter configuration.
- Database schema evolves through SQL migrations in `migrations/`; Oracle also runs embedded migrations during startup.
- Local dev workflows are centralized in `Makefile` and `docker-compose.yml`.
- Security-hardening checks live in `scripts/`, notably sensitive log auditing and security audit wrappers.

## Security Principles
- Client-side encryption must remain the default boundary: plaintext file content and file keys do not leave the desktop client.
- Vaulted seed material derives encryption identity, signing identity, XRPL wallet material, file keys, recipient-bound envelopes, and signed manifests.
- XRPL transactions are built and signed locally; server-side code verifies ledger state and submitted blobs.
- Sharing uses recipient-bound `KeyEnvelope` grants rather than server-readable keys.
- QR flows rely on signed canonical payloads for device pairing, XRPL signing approval, and file grant approval.
- Oracle may index manifests, verify ledger state, gate storage access, and issue signed tokens, but it must not be able to decrypt files.

## Architecture
See `.ai-factory/ARCHITECTURE.md` for detailed architecture guidelines.

**Pattern:** Explicit Architecture with workspace-level bounded contexts and pragmatic vertical slices inside larger crates.

## Non-Functional Requirements
- **Security:** Preserve client-side secret boundaries, avoid logging sensitive values, and run the existing security scripts before sensitive releases.
- **Reliability:** Keep Oracle migrations idempotent and service startup explicit about database, Redis, XRPL, and signing-key configuration.
- **Observability:** Use `tracing` for Rust services and avoid ad hoc `println!`/`dbg!` in production paths.
- **Compatibility:** Treat legacy PRE and external-wallet migration paths as compatibility code unless a task explicitly modernizes them.
- **Validation:** Run Rust workspace checks and UI checks appropriate to the touched area.

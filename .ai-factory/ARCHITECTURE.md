# Architecture: Explicit Architecture With Workspace Bounded Contexts

## Overview
Vaulted already has strong module boundaries through its Cargo workspace. The best fit is an explicit, domain-centered architecture at the workspace level: crypto/domain primitives stay inward in `crypto-core`, while Tauri, Axum, SQL, Redis, XRPL network calls, and storage-node HTTP behavior live in outer adapter crates.

Within larger crates, especially `oracle` and `desktop-client`, use pragmatic vertical slices by feature while preserving dependency direction. This keeps daily development practical without weakening the security boundary that plaintext, seed material, and file keys stay client-side.

## Decision Rationale
- **Project type:** Security-sensitive encrypted file vault with desktop, API, storage, database, and XRPL integration.
- **Tech stack:** Rust workspace, Tauri 2, Axum/Tokio, React/TypeScript, PostgreSQL, Redis.
- **Key factor:** Cryptographic boundaries and trust boundaries must be explicit and easy to audit.

## Folder Structure
```text
.
+-- crates/
|   +-- crypto-core/              # Inner domain/crypto primitives; no UI, DB, HTTP server, or Tauri coupling
|   |   +-- src/
|   |       +-- identity.rs
|   |       +-- envelope.rs
|   |       +-- manifest.rs
|   |       +-- qr_payload.rs
|   |       +-- seed.rs
|   |       +-- xrpl_wallet.rs
|   +-- desktop-client/           # Local trusted client adapter and composition root
|   |   +-- src/                  # Tauri commands, local state, secure storage, HTTP clients
|   |   +-- ui/src/               # React UI grouped by screens, components, contexts, utils
|   +-- oracle/                   # Server-side coordination boundary
|   |   +-- src/
|   |       +-- auth.rs
|   |       +-- db.rs
|   |       +-- middleware.rs
|   |       +-- models.rs
|   |       +-- storage_token.rs
|   |       +-- xrpl_verify.rs
|   |       +-- main.rs           # Axum composition root
|   +-- storage-node/             # Encrypted fragment storage adapter
+-- migrations/                   # PostgreSQL schema evolution
+-- scripts/                      # Security and developer automation
+-- docker-compose.yml            # Local infrastructure
+-- Makefile                      # Common workflows
```

## Dependency Rules
- Allowed: `desktop-client`, `oracle`, and `storage-node` depend on `crypto-core`.
- Allowed: outer crates adapt `crypto-core` types into HTTP, database, filesystem, QR, and UI workflows.
- Allowed: React UI calls Tauri commands; Tauri commands perform trusted local operations and remote API calls.
- Forbidden: `crypto-core` must not depend on Tauri, Axum, SQLx, Redis, HTTP clients, filesystem UI concerns, or service configuration.
- Forbidden: Oracle must not receive or reconstruct plaintext file content, file keys, seed phrases, or private wallet material.
- Forbidden: storage nodes must not depend on Oracle internals; they should validate signed tokens and store encrypted fragments.

## Layer And Module Communication
- The desktop client owns secret-bearing operations and sends only encrypted artifacts, signed manifests, `tx_blob`s, grants, and approval payloads outward.
- Oracle coordinates registry, auth, ledger verification, grants, and storage access through typed request/response models and database state.
- Storage nodes accept encrypted fragments and signed storage tokens; they should not know user seed or file-key semantics.
- PostgreSQL schema changes flow through `migrations/` and embedded Oracle migrations, not ad hoc runtime DDL.

## Key Principles
1. Keep cryptographic invariants in `crypto-core`; callers should compose primitives, not duplicate cryptographic logic.
2. Treat every boundary crossing as a trust transition: desktop to Oracle, Oracle to storage node, Oracle to XRPL, and UI to Tauri.
3. Prefer typed errors and typed payloads over loosely structured strings for recoverable behavior.
4. Keep startup/configuration in composition roots such as `crates/oracle/src/main.rs` and Tauri initialization.
5. Preserve local-first secret ownership even when adding convenience flows.

## Code Examples

### Boundary-Friendly Crypto API
```rust
use xrpl_vault_crypto_core::{CryptoError, Result};

pub fn seal_file_key_for_recipient(file_key: &[u8], recipient_key: &[u8]) -> Result<Vec<u8>> {
    if file_key.is_empty() {
        return Err(CryptoError::InvalidKey("file key is empty".to_string()));
    }

    // Keep encryption logic in crypto-core; outer crates should call this kind of API.
    todo!("call the project KeyEnvelope sealing primitive")
}
```

### Oracle Adapter Converts Infrastructure Errors
```rust
use crate::error::{ApiError, Result};

pub async fn load_manifest(pool: &sqlx::PgPool, id: uuid::Uuid) -> Result<ManifestRow> {
    sqlx::query_as!(ManifestRow, "SELECT * FROM manifests WHERE id = $1", id)
        .fetch_one(pool)
        .await
        .map_err(ApiError::from)
}
```

## Anti-Patterns
- Do not add database, HTTP, Redis, or Tauri dependencies to `crypto-core`.
- Do not copy crypto routines into Oracle, storage-node, or React code to avoid importing a shared function.
- Do not log seed phrases, private keys, file keys, decrypted file content, access tokens, or secret-bearing QR payloads.
- Do not let Oracle become a decryption service or a hidden owner of user wallet material.
- Do not add cross-crate shortcuts that make storage-node depend on Oracle implementation details.

# Vaulted

Vaulted is a local-first encrypted file vault that uses XRPL NFTs as ownership anchors.

Files are encrypted on the user's device before upload. The Vaulted desktop client keeps seed material, wallet keys, file keys, and plaintext file content local. The Oracle coordinates metadata, grants, device state, and ledger verification, but it cannot decrypt files. Storage nodes store ciphertext fragments only.

## What it does

- Creates a local Vaulted identity from a user-controlled seed phrase.
- Encrypts files client-side before they are sent to storage nodes.
- Uses XRPL NFT ownership as the public ownership anchor for a vaulted file.
- Builds and signs XRPL transactions locally in the desktop client.
- Lets owners download and decrypt their files locally.
- Supports recipient-bound sharing through encrypted `KeyEnvelope` grants.
- Lets the Oracle verify ledger state and issue storage access tokens without receiving plaintext file keys.

## Why XRPL

XRPL is a good fit for Vaulted because it provides fast finality, low transaction costs, native NFT primitives, and mature testnet tooling. Vaulted uses those properties to anchor file ownership without putting file content or decryption keys on-chain.

In this model, the ledger answers ownership questions: who currently controls the NFT associated with a vault object. Vaulted keeps the private data path separate: files remain encrypted locally, sharing keys are sealed to recipients, and storage nodes only see ciphertext.

## Architecture

```text
Vaulted seed phrase
├─ Vaulted identity signing key
├─ Vaulted identity encryption key
├─ device key
├─ XRPL wallet keypair
├─ per-file encryption keys
├─ recipient-bound KeyEnvelopes
└─ signed manifests
```

```text
Desktop Client (Tauri + React)
├─ creates/restores the local Vaulted identity
├─ encrypts and decrypts files locally
├─ derives XRPL wallet material locally
├─ builds and signs XRPL NFT transactions locally
├─ prepares manifests and grant approvals
└─ talks to the Oracle and storage nodes over HTTP

Oracle
├─ verifies manifests and XRPL ledger state
├─ maintains vault object, grant, and device records
├─ coordinates storage access
└─ issues signed storage tokens

Storage Nodes
└─ store encrypted file fragments only
```

Private seed material, private wallet keys, file keys, and plaintext file content are not sent to the Oracle or storage nodes.

## Current status

Vaulted is an MVP for local development and XRPL testnet demonstrations. The core flow is implemented around local-first encryption, local XRPL signing, NFT-backed ownership, Oracle verification, encrypted storage fragments, and recipient-bound sharing.

The project is not production hardened yet. Production use requires operational hardening, key management review, deployment security, monitoring, backup strategy, and broader security review.

## Project structure

```text
vaulted/
├── crates/
│   ├── crypto-core/       # cryptography, identities, manifests, QR payloads, XRPL helpers
│   ├── desktop-client/    # Tauri desktop app and React UI
│   ├── oracle/            # Axum registry, manifest, grant, device, and ledger verification service
│   └── storage-node/      # encrypted fragment storage service
├── migrations/            # PostgreSQL schema migrations
├── data/                  # local development fragment storage
├── docker-compose.yml     # local PostgreSQL, Redis, and optional dev tools
├── Makefile               # common local development commands
├── QUICKSTART.md          # local setup and demo flow
└── SECURITY.md            # security model and production checklist
```

## Quick start

```bash
git clone https://github.com/nova7272/vaulted.git
cd vaulted
cp .env.example .env
make dev
```

Start the Oracle and storage node in separate terminals:

```bash
make oracle
```

```bash
make storage
```

Run the desktop client:

```bash
cd crates/desktop-client
cargo tauri dev
```

See [QUICKSTART.md](QUICKSTART.md) for the full local setup and demo flow.

## Tests and checks

Rust:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

Desktop UI:

```bash
cd crates/desktop-client/ui
npm run typecheck
npm run build
npm run lint
```

## Security model

- Files are encrypted locally before upload.
- The Vaulted seed stays on the client and is the recovery root for local identity and wallet material.
- XRPL transactions are built and signed locally by the desktop client.
- The Oracle verifies ledger state, manifests, grants, devices, and storage access, but cannot decrypt files.
- Storage nodes store encrypted fragments only.
- Sharing uses recipient-bound `KeyEnvelope` objects instead of exposing plaintext file keys to the Oracle.

See [SECURITY.md](SECURITY.md) for more detail.

## License

MIT

# Vaulted

Vaulted is an encrypted file vault built around a first-party Vaulted seed, local XRPL wallet signing, deterministic NFT metadata, and recipient-bound `KeyEnvelope` sharing.

## Current architecture

```text
Vaulted seed phrase
├─ Vaulted encryption identity
├─ Vaulted signing identity
├─ Vaulted XRPL wallet keypair
├─ file keys
├─ recipient-bound KeyEnvelopes
└─ signed manifests
```

```text
Desktop Client (Tauri)
├─ encrypts/decrypts files locally
├─ derives identity and XRPL wallet locally from the Vaulted seed
├─ signs XRPL NFT mint transactions locally
├─ renders QR approval requests for device pairing, XRPL signing, and file grants
└─ talks to Oracle and storage nodes over HTTP

Oracle
├─ registry / index / auth service
├─ validates client-generated manifests and metadata
├─ verifies XRPL ledger state before finalizing vault objects
├─ stores grant and device state
└─ issues signed storage access tokens

Storage Nodes
└─ store encrypted fragments only
```

Private seed material, file keys, and decrypted file content never leave the client.

## Key security principles

1. **Client-side encryption** — file keys are generated locally and files are encrypted before upload.
2. **Vaulted seed identity** — identity, encryption, signing, and XRPL wallet material derive from the user-controlled Vaulted seed.
3. **Local XRPL signing** — the client builds and signs XRPL transactions locally, then submits `tx_blob` for ledger verification.
4. **Recipient-bound sharing** — grants use `KeyEnvelope` objects sealed to the recipient identity encryption key.
5. **QR trust model** — device pairing, XRPL signing approval, and file grant approval use signed canonical QR payloads.
6. **Oracle cannot decrypt files** — Oracle indexes manifests, verifies ledger state, and gates storage access, but does not receive plaintext file keys.

## Project structure

```text
xrpl-vault/
├── crates/
│   ├── crypto-core/       # AES, identity derivation, KeyEnvelope, QR payloads, XRPL signing
│   ├── desktop-client/    # Tauri app, local wallet/signing, file decrypt/open flows, React UI
│   ├── oracle/            # registry, auth, manifest, QR, grants, device, and XRPL verification service
│   └── storage-node/      # encrypted fragment storage
├── migrations/            # PostgreSQL schema and compatibility migrations
├── docker-compose.yml     # local PostgreSQL + Redis
└── scripts/               # developer helpers
```

Legacy PRE and external-wallet compatibility code can still exist in migrations and old transfer paths, but new sharing is based on `KeyEnvelope` grants and Vaulted identities.

## Quick start

```bash
# Start infrastructure
make dev

# Run Oracle
make oracle

# Run storage node
make storage

# Run workspace tests
cargo test --workspace
```

Desktop UI checks:

```bash
cd crates/desktop-client/ui
npm ci
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
```

## Environment variables

| Variable | Description | Default |
| --- | --- | --- |
| `DATABASE_URL` | PostgreSQL connection string | required for Oracle |
| `REDIS_URL` | Redis connection string | optional/dev dependent |
| `XRPL_NODE_URL` | XRPL WebSocket URL for desktop XRPL flows | `wss://s.altnet.rippletest.net:51233` |
| `XRPL_RPC_URL` | XRPL HTTP JSON-RPC URL for Oracle ledger verification | `https://s.altnet.rippletest.net:51234` |
| `ORACLE_SIGNING_KEY` | Ed25519 signing key for JWT/storage tokens | generated in dev |
| `RUST_LOG` | Rust logging level | `info` |

## Validation commands

```bash
cargo check --workspace
cargo test --workspace

cd crates/desktop-client/ui
npm ci
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
```

## License

MIT

# Vaulted

Vaulted is an encrypted file vault built around a first-party Vaulted seed, local XRPL wallet signing, deterministic NFT metadata, and recipient-bound `KeyEnvelope` sharing.

## MVP status

The current production-MVP checkpoint has runtime evidence through local XRPL mint, Oracle finalize/by-NFT linkage, owner download/decrypt, NFT transfer/re-encryption, recipient accept, and recipient decrypt after re-encryption.

The detailed checkpoint, safe runtime phases, and final-pass checklist live in [docs/RUNTIME_VERIFICATION.md](docs/RUNTIME_VERIFICATION.md).

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

## XRPL Grants demo flow

Use the runtime verification document for the detailed checklist. The local demo path is:

1. Start Postgres/Redis with Docker Compose.
2. Start Oracle and confirm `/health`.
3. Start storage-node and confirm `/health`.
4. Launch the desktop client.
5. Create or restore a 12-word Vaulted wallet.
6. Confirm Wallet balance, receive address/QR, and Send XRP on testnet.
7. Upload an encrypted file.
8. Mint the ownership NFT locally.
9. Finalize the vault object in Oracle.
10. Download/decrypt as owner.
11. Transfer NFT/file access to a recipient.
12. Confirm the recipient incoming offer.
13. Accept with local `NFTokenAcceptOffer`.
14. Confirm recipient decrypt after re-encryption.

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
cargo fmt --all --check
cargo check --workspace
cargo test --workspace

cd crates/desktop-client/ui
npm ci
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
cd ../../..

./scripts/check-sensitive-logs.sh
git diff --check
```

## Documentation and security notes

- Runtime evidence and final-pass status are tracked in [docs/RUNTIME_VERIFICATION.md](docs/RUNTIME_VERIFICATION.md).
- Do not log, render, paste, or commit wallet recovery words, private material, local file keys, tokenized storage URLs, raw storage keys, transaction blobs, approval payloads, or decrypted file contents.
- Oracle and storage-node must not receive plaintext file content or plaintext file keys.

## License

MIT

# Vaulted Quick Start

This guide starts the local PostgreSQL and Redis services, runs the Oracle and storage node, and launches the desktop client against XRPL testnet defaults.

## Clone repository

```bash
git clone https://github.com/nova7272/vaulted.git
cd vaulted
```

## Configure `.env`

```bash
cp .env.example .env
```

The default file is intended for local development. Check these values before starting services:

```bash
DATABASE_URL=postgres://xrpl_vault:dev_password_change_me@localhost:5432/xrpl_vault
REDIS_URL=redis://localhost:6379
XRPL_NODE_URL=wss://s.altnet.rippletest.net:51233
XRPL_RPC_URL=https://s.altnet.rippletest.net:51234
XRPL_NETWORK=testnet
ORACLE_HOST=0.0.0.0
ORACLE_PORT=3000
```

Do not put production seed phrases, wallet private keys, file keys, or recovery material in `.env`. The desktop client creates and stores Vaulted identity and wallet material locally.

## Start Postgres/Redis

```bash
make dev
```

Check container status:

```bash
docker compose ps
```

## Start Oracle

Run in a separate terminal:

```bash
make oracle
```

Health check:

```bash
curl http://localhost:3000/health
```

## Start Storage Node

Run in another terminal:

```bash
make storage
```

Health check:

```bash
curl http://localhost:9001/health
```

## Run desktop client

```bash
cd crates/desktop-client
cargo tauri dev
```

The desktop client uses the local Oracle by default. XRPL flows are configured for testnet unless you change the network settings.

## Run checks

From the repository root:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

For the desktop UI:

```bash
cd crates/desktop-client/ui
npm run typecheck
npm run build
npm run lint
```

## Demo flow

1. Start Postgres, Redis, Oracle, storage node, and the desktop client.
2. Create or restore a Vaulted seed phrase in the desktop client.
3. Confirm the wallet address and XRPL testnet balance.
4. Upload a file; Vaulted encrypts it locally before storage.
5. Mint the ownership NFT with a locally signed XRPL transaction.
6. Let the Oracle verify the ledger state and finalize the vault object.
7. Download and decrypt the file as the owner.
8. Share access with a recipient identity using a `KeyEnvelope` grant.
9. Confirm the recipient can accept access and decrypt locally after re-encryption.

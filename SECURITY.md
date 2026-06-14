# Vaulted Security Guide

## Overview

Vaulted is designed around a local-first security model. Seed material, private wallet keys, file keys, and plaintext file content stay on the client. The Oracle coordinates registry, manifest, grant, device, and ledger-verification workflows. Storage nodes store encrypted fragments only.

Vaulted is currently an MVP for local development and XRPL testnet demonstrations. Production deployments need additional operational hardening and independent security review.

## Trust boundaries

```text
Client
├─ owns seed phrase and local identity keys
├─ owns XRPL wallet keys
├─ creates file keys
├─ encrypts and decrypts file content
├─ signs manifests and approvals
└─ signs XRPL transactions

Oracle
├─ verifies manifests and XRPL ledger state
├─ stores vault object, grant, and device records
├─ issues storage access tokens
└─ cannot decrypt files

Storage Node
├─ receives encrypted fragments
├─ returns encrypted fragments
└─ does not receive plaintext file keys
```

The main rule is simple: plaintext file content, plaintext file keys, seed phrases, and wallet private keys should never leave the client.

## Seed and key handling

The Vaulted seed phrase is the user's recovery root. It derives or protects local identity, encryption, signing, and XRPL wallet material. Losing it can make encrypted files unrecoverable.

Operational rules:

- Do not store seed phrases, wallet private keys, file keys, recovery material, or decrypted file content in `.env`.
- Do not log seed phrases, wallet private keys, file keys, recovery material, transaction blobs, storage tokens, or decrypted file content.
- Use secure OS storage for local secrets in desktop builds.
- Treat local development wallets as testnet-only unless the deployment has been reviewed for production use.

## Oracle role

The Oracle is a coordination and verification service. It can:

- verify client-generated manifests;
- verify XRPL ledger state for NFT ownership;
- store vault object metadata;
- store grant and device state;
- issue signed storage access tokens.

The Oracle should not receive plaintext file content or plaintext file keys. A database compromise should not be enough to decrypt stored files if client-side key material remains protected.

Important environment variables:

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `ENVIRONMENT` | No | `development` | Set to `production` for strict security settings |
| `DATABASE_URL` | Yes | local dev value | PostgreSQL connection string |
| `REDIS_URL` | No | unset | Redis connection string for optional cache/session flows |
| `ORACLE_SIGNING_KEY` | Yes in production | generated in dev | Ed25519 key used for Oracle-signed tokens |
| `CORS_ORIGINS` | Yes in production | permissive in dev | Comma-separated allowed origins |
| `RATE_LIMIT_RPM` | No | `60` | Requests per minute per IP |
| `JWT_EXPIRATION_HOURS` | No | `24` | Token lifetime in hours |
| `XRPL_RPC_URL` | No | XRPL testnet JSON-RPC | XRPL endpoint used for ledger verification |

## Storage-node role

Storage nodes persist encrypted fragments and return them to authorized clients. They should not receive plaintext files, plaintext file keys, or seed material.

Important environment variables:

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `REQUIRE_AUTH` | No | `false` | Require Oracle-signed storage tokens |
| `ORACLE_PUBLIC_KEY` | Required when auth is enabled | unset | Oracle Ed25519 public key |
| `NODE_ID` | No | `node-local-1` | Unique storage node identifier |
| `ORACLE_URL` | No | unset | Oracle URL for registration and heartbeat |
| `STORAGE_DIR` | No | local data directory | Fragment storage path |

Production storage nodes should use HTTPS, enforce size/rate limits, restrict management access, and back up encrypted fragment data.

## XRPL signing

XRPL transactions are built and signed locally by the desktop client. The Oracle can verify ledger state and coordinate finalization, but it should not custody the user's XRPL wallet keys.

For production:

- keep wallet keys client-side;
- use testnet settings only for local demos;
- confirm NFT metadata and ownership identifiers before signing;
- treat transaction blobs and approval payloads as sensitive operational data.

## File sharing / KeyEnvelope

Vaulted sharing uses recipient-bound `KeyEnvelope` records:

```text
file key
  -> sealed to recipient identity encryption public key
  -> bound to vault object id, recipient identity id, and recipient key id
```

The Oracle may store and verify grant state, but it should not receive the plaintext file key. Recipients decrypt the file key locally with their identity encryption key, then decrypt file content locally.

## Production checklist

Oracle:

- [ ] Set `ENVIRONMENT=production`.
- [ ] Generate and protect `ORACLE_SIGNING_KEY`.
- [ ] Configure restricted `CORS_ORIGINS`.
- [ ] Use HTTPS behind a trusted reverse proxy.
- [ ] Use strong PostgreSQL credentials and encrypted backups.
- [ ] Review rate limits for auth, QR, identity, grants, and storage-token endpoints.
- [ ] Enable operational logging that avoids sensitive values.
- [ ] Run dependency, container, and infrastructure vulnerability scans in CI.

Storage nodes:

- [ ] Set `REQUIRE_AUTH=true`.
- [ ] Configure `ORACLE_PUBLIC_KEY`.
- [ ] Use HTTPS.
- [ ] Restrict management endpoints to trusted networks.
- [ ] Back up encrypted fragment data.
- [ ] Enforce upload/download size and rate limits.

Desktop client:

- [ ] Distribute with the correct Oracle and XRPL network settings.
- [ ] Store local secrets only in secure OS storage.
- [ ] Disable sensitive logging around seed phrases, file keys, private keys, filenames when sensitive, and plaintext metadata.
- [ ] Consider certificate pinning for production builds.

## Incident response

Oracle signing key compromise:

1. Generate a new `ORACLE_SIGNING_KEY`.
2. Restart Oracle with the new key.
3. Re-authenticate clients.
4. Invalidate old token families where applicable.
5. Review audit events for suspicious grant, device, and storage-token activity.

Storage node compromise:

1. Take the node offline.
2. Revoke or disable node registration in Oracle.
3. Rotate storage credentials and inspect logs.
4. Re-replicate encrypted fragments to healthy nodes where needed.

Recipient-key compromise:

1. Revoke active grants for affected identities.
2. Ask affected users to rotate identity/device keys.
3. Re-share only after manually confirming the new recipient fingerprint.

Database compromise:

1. Rotate Oracle signing keys and database credentials.
2. Revoke suspicious sessions and grants.
3. Review grant, device, and storage-token activity.
4. Confirm that plaintext file content and client-side key material were not exposed.

## Local security checks

Before a release, run the checks that are available in this repository:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace

cd crates/desktop-client/ui
npm run typecheck
npm run build
npm run lint
```

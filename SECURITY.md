# Vaulted Security Guide

## Overview

Vaulted protects files by keeping seed material, private keys, file keys, and plaintext file data on the client. Oracle provides registry, auth, manifest verification, QR coordination, grant state, and storage-token services. Storage nodes store encrypted fragments only.

## Environment variables

### Oracle Server

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `ENVIRONMENT` | No | `development` | Set to `production` for strict security settings |
| `ORACLE_SIGNING_KEY` | Yes in prod | generated in dev | Ed25519 private key for JWT/storage-token signing |
| `CORS_ORIGINS` | Yes in prod | permissive in dev | Comma-separated allowed origins |
| `RATE_LIMIT_RPM` | No | `60` | Requests per minute per IP |
| `JWT_EXPIRATION_HOURS` | No | `24` | Token lifetime in hours |
| `XRPL_NODE_URL` | No | XRPL testnet WebSocket | XRPL node used for ledger verification/submission |

### Storage Node

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `REQUIRE_AUTH` | No | `false` | Require Oracle-signed storage tokens |
| `ORACLE_PUBLIC_KEY` | Required when auth is enabled | - | Oracle Ed25519 public key |
| `NODE_ID` | No | `node-local-1` | Unique storage node identifier |
| `ORACLE_URL` | No | - | Oracle URL for registration/heartbeat |

### Desktop Client

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `ORACLE_URL` | No | `http://localhost:3000` | Oracle server URL |

## Authentication and trust flows

### Vaulted identity

```text
Vaulted seed phrase
├─ identity signing key
├─ identity encryption key
├─ device key
└─ XRPL wallet keypair
```

The seed phrase is the user recovery root. Losing it can make encrypted data unrecoverable.

### QR login / pairing / approvals

Vaulted QR payloads use a canonical JSON body, a protocol marker, intent-specific validation, and Vaulted identity signatures. Current intents include:

- login;
- pair device;
- sign XRPL transaction;
- approve file grant.

### File sharing

New sharing grants use recipient-bound `KeyEnvelope` objects:

```text
file key → sealed to recipient identity encryption public key
         → bound to vault object id + recipient identity id + recipient key id
```

Oracle stores and verifies grant state, but does not receive plaintext file keys.

## Protected API requests

Protected endpoints require:

```http
Authorization: Bearer <jwt_token>
```

When storage auth is enabled, storage nodes additionally require Oracle-signed operation tokens.

## Production checklist

### Oracle

- [ ] Set `ENVIRONMENT=production`.
- [ ] Generate and store `ORACLE_SIGNING_KEY` securely.
- [ ] Configure restricted `CORS_ORIGINS`.
- [ ] Use HTTPS behind a reverse proxy.
- [ ] Use strong PostgreSQL credentials.
- [ ] Enable external audit logging.
- [ ] Review rate limits for auth, QR, identity, grants, and storage-token endpoints.
- [ ] Run dependency audits in CI.

### Storage Nodes

- [ ] Set `REQUIRE_AUTH=true`.
- [ ] Configure `ORACLE_PUBLIC_KEY`.
- [ ] Use HTTPS.
- [ ] Restrict management endpoints to trusted networks.
- [ ] Back up encrypted fragment data.
- [ ] Enforce upload/download size and rate limits.

### Desktop Client

- [ ] Distribute with the correct Oracle URL.
- [ ] Store local secrets only in secure OS storage.
- [ ] Disable sensitive logging around seed phrases, file keys, private keys, and plaintext metadata.
- [ ] Consider certificate pinning for production builds.

## Cryptographic details

### File encryption

- File content is encrypted client-side.
- File keys are random per file.
- Sharing uses X25519 + HKDF-SHA256 + XChaCha20-Poly1305 `KeyEnvelope` sealing.

### Identity and signing

- Vaulted identity signing uses Ed25519.
- QR payloads and manifests are signed over canonical, domain-separated bytes.
- XRPL NFT mint transactions are built and signed locally by the client.

### Storage tokens

- Algorithm: Ed25519.
- Payload includes storage key, operation, issued-at, and expiration data.

## Incident response

### Oracle signing key compromise

1. Generate a new `ORACLE_SIGNING_KEY`.
2. Restart Oracle.
3. Re-authenticate clients.
4. Invalidate old token families where applicable.

### Storage node compromise

1. Take the node offline.
2. Revoke node registration in Oracle.
3. Data remains encrypted, but rotate storage credentials and inspect logs.
4. Re-replicate fragments to healthy nodes.

### Directory or recipient-key compromise

1. Revoke trust for affected recipient fingerprints.
2. Revoke active grants for affected identities.
3. Ask recipients to rotate identity/device keys if needed.
4. Re-share only after manually confirming the new fingerprint.

### Database compromise

1. Rotate Oracle signing keys and database credentials.
2. Revoke suspicious sessions and grants.
3. Review audit events for unauthorized grant/device changes.
4. Plaintext files should remain protected as long as client seed material and file keys were not compromised.

## Hardening audit commands

Run the non-strict local audit before opening a release branch:

```bash
make security-audit
```

This runs:

- sensitive logging scan;
- `cargo fmt -- --check`;
- `cargo check --workspace`;
- `cargo test --workspace`;
- `cargo audit` when `cargo-audit` is installed;
- frontend install, lint, typecheck, build, and `npm audit` report.

For CI, use strict mode:

```bash
make security-audit-strict
```

Strict mode fails when `cargo-audit` is missing and when `npm audit --audit-level=high` reports high-or-critical advisories.

To run only the sensitive logging guard:

```bash
make sensitive-log-audit
```

The sensitive logging guard is intentionally conservative. It scans logging statements for seed phrases, private keys, file keys, decrypted/plaintext content, local paths, filenames, tokens, and similar values. False positives should be fixed by changing the log message to a count, status, or redacted identifier rather than by logging the raw value.

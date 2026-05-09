# XRPL Vault Security Guide

## Overview

This document describes security features and configuration for XRPL Vault components.

## Environment Variables

### Oracle Server

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENVIRONMENT` | No | `development` | Set to `production` for strict security |
| `ORACLE_SIGNING_KEY` | **Yes** (prod) | generated | Ed25519 private key for JWT signing (64 hex chars) |
| `CORS_ORIGINS` | **Yes** (prod) | permissive | Comma-separated allowed origins (e.g., `https://app.example.com`) |
| `RATE_LIMIT_RPM` | No | `60` | Requests per minute per IP |
| `JWT_SECRET` | No | `development_...` | Legacy, use ORACLE_SIGNING_KEY |
| `JWT_EXPIRATION_HOURS` | No | `24` | Token lifetime in hours |

### Storage Node

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REQUIRE_AUTH` | No | `false` | Set to `true` to require signed tokens |
| `ORACLE_PUBLIC_KEY` | Required if REQUIRE_AUTH | - | Oracle's Ed25519 public key (64 hex chars) |
| `NODE_ID` | No | `node-local-1` | Unique node identifier |
| `ORACLE_URL` | No | - | Oracle URL for registration/heartbeat |

### Desktop Client

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ORACLE_URL` | No | `http://localhost:3000` | Oracle server URL |
| `XAMAN_API_KEY` | Yes | - | Xaman (formerly XUMM) API key |
| `XAMAN_API_SECRET` | Yes | - | Xaman API secret |

---

## Authentication Flow

### 1. User Login via Xaman

```
Client                    Xaman                    Oracle
   |                        |                        |
   |---(1) Create Payload-->|                        |
   |<--(2) QR Code/DeepLink-|                        |
   |                        |                        |
   |      [User signs in Xaman]                      |
   |                        |                        |
   |<--(3) Signature--------|                        |
   |                        |                        |
   |---(4) Get Challenge------------------------>    |
   |<--(5) Challenge: "xrpl-vault-auth:{wallet}"    |
   |                        |                        |
   |---(6) POST /auth/token {wallet, signature, challenge}->|
   |<--(7) JWT Token---------------------------------|
   |                        |                        |
   [Client stores token, uses in Authorization header]
```

### 2. Protected API Requests

All protected endpoints require:
```http
Authorization: Bearer <jwt_token>
```

### 3. Storage Node Access

When `REQUIRE_AUTH=true`, storage nodes require signed tokens:

```
Client                    Oracle                  Storage Node
   |                        |                        |
   |---(1) Request file access with JWT------------>|
   |<--(2) Signed download URLs---------------------|
   |                        |                        |
   |---(3) GET /fragments/{key}?token={signed_token}------->|
   |<--(4) Encrypted fragment data------------------|
```

---

## Production Checklist

### Oracle

- [ ] Set `ENVIRONMENT=production`
- [ ] Generate and set `ORACLE_SIGNING_KEY`:
  ```bash
  openssl rand -hex 32
  ```
- [ ] Configure `CORS_ORIGINS` with your domains
- [ ] Use HTTPS (TLS termination via reverse proxy)
- [ ] Set up PostgreSQL with strong credentials
- [ ] Enable audit logging to external system

### Storage Nodes

- [ ] Set `REQUIRE_AUTH=true`
- [ ] Set `ORACLE_PUBLIC_KEY` (get from Oracle logs at startup)
- [ ] Use HTTPS
- [ ] Firewall: allow only Oracle IP for management endpoints
- [ ] Regular backups of fragment data

### Desktop Client

- [ ] Distribute with correct Oracle URL
- [ ] Use secure storage for Xaman credentials
- [ ] Enable certificate pinning if possible

---

## Security Architecture

### Data Protection

1. **At Rest**: Files are AES-256-GCM encrypted client-side before upload
2. **In Transit**: TLS for all communications
3. **Key Management**: PRE (Proxy Re-Encryption) allows secure transfer without exposing keys

### Access Control

1. **NFT Ownership**: Only NFT holder can access file data
2. **JWT Authentication**: All mutating API calls require valid JWT
3. **Signed Storage Tokens**: Storage nodes verify Oracle-signed tokens

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Stolen JWT | Short expiration (24h), logout invalidation |
| Man-in-the-Middle | TLS required in production |
| Storage node compromise | Data is encrypted, tokens are time-limited |
| Oracle compromise | Cannot decrypt files (no AES keys) |
| Replay attacks | Tokens include timestamp, expiration |
| Rate abuse | IP-based rate limiting |

---

## Cryptographic Details

### JWT Signing
- Algorithm: EdDSA (Ed25519)
- Key size: 256 bits
- Token format: `header.payload.signature` (base64url)

### Storage Tokens
- Algorithm: EdDSA (Ed25519)
- Format: `payload.signature` (base64url)
- Payload: JSON with `nft_token_id`, `storage_key`, `operation`, `exp`, `iat`

### File Encryption
- Algorithm: AES-256-GCM
- Key derivation: HKDF-SHA256 from user's XRPL signature
- PRE scheme: Umbral (threshold proxy re-encryption)

---

## Incident Response

### JWT Key Compromise

1. Generate new `ORACLE_SIGNING_KEY`
2. Restart Oracle
3. All users will need to re-authenticate

### Storage Node Compromise

1. Take node offline
2. Revoke node registration in Oracle
3. Data remains encrypted - no immediate user action needed
4. Consider re-encrypting files with new keys

### Database Compromise

1. Rotate `ORACLE_SIGNING_KEY`
2. Users must re-register (new PRE keys)
3. Encrypted AES keys in DB are useless without user's PRE private key

# Vaulted Wallet Mode: Xaman removal, own XRPL wallet, QR login/signing

This iteration switches the project direction from an external Xaman signer to a first-party Vaulted wallet model.

## Core model

```text
Vaulted seed phrase
├─ Vaulted identity keys
│  ├─ Ed25519 signing key
│  ├─ X25519 encryption key
│  ├─ device auth key
│  └─ metadata key
└─ XRPL wallet keys
   ├─ secp256k1 signing key
   ├─ compressed XRPL public key
   └─ XRPL classic address
```

The XRPL wallet key is derived from the same BIP-39 seed but with a separate domain separator:

```text
Vaulted v1 wallet xrpl
Vaulted v1 wallet xrpl secp256k1 signing
```

The XRPL wallet key is **not** used for file encryption and the Vaulted encryption/signing keys are **not** used for XRPL transactions.

## What changed

### `crates/crypto-core`

Added:

- `src/xrpl_wallet.rs`
- `VaultedXrplWallet`
- `VaultedQrSigningRequest`
- `VaultedSignedXrplTransaction`
- `build_nftoken_mint_tx(...)`

This provides:

- deterministic XRPL secp256k1 wallet derivation from Vaulted seed;
- XRPL classic address generation;
- application-level transaction signing payloads for QR/offline signing;
- NFTokenMint JSON builder with hex-encoded URI.

### `crates/desktop-client`

Added Tauri commands:

- `get_vaulted_xrpl_wallet`
- `create_vaulted_nft_mint_qr_request`
- `sign_vaulted_xrpl_qr_request`
- `start_vaulted_qr_login`
- `poll_vaulted_qr_login`
- `confirm_vaulted_qr_login`

Desktop state now unlocks both:

- Vaulted identity keys;
- Vaulted-owned XRPL wallet keys.

Xaman commands are disabled and no longer exposed in the Tauri invoke handler for the wallet-mode build.

### `crates/oracle`

Removed Xaman from active routing/configuration:

- no `XAMAN_API_KEY` / `XAMAN_API_SECRET` required;
- no `/api/v1/xaman/payload` routes in the active router;
- `/auth/token-xaman-payload` and `/auth/token-signin` are no longer registered.

Added QR login endpoints:

```text
POST /api/v1/auth/qr/start
GET  /api/v1/auth/qr/status/:login_request_id
POST /api/v1/auth/qr/confirm
```

Added migration:

```text
migrations/011_qr_login_and_vaulted_wallet.sql
```

This creates `qr_login_requests` and extends `linked_wallets` with wallet source/public key fields.

## QR login flow

```text
Desktop:
1. Calls /auth/qr/start.
2. Shows qr_payload.

Mobile / trusted device:
3. Scans qr_payload.
4. Unlocks local Vaulted seed through PIN/biometrics.
5. Signs canonical QR login message with Vaulted identity Ed25519 key.
6. Calls /auth/qr/confirm.

Desktop:
7. Polls /auth/qr/status/:id.
8. Receives Oracle JWT after approval.
```

The QR payload contains only:

```text
login_request_id
challenge
oracle_url
expires_at
optional desktop device public key/name
```

It never contains:

```text
seed phrase
private key
master key
file key
refresh token
encrypted keystore
```

## QR XRPL signing flow

```text
Desktop:
1. Builds unsigned NFTokenMint JSON.
2. Displays VaultedQrSigningRequest as QR.

Mobile / offline signer:
3. Scans QR.
4. Shows human-readable summary.
5. Signs transaction payload with Vaulted-derived XRPL wallet key.
6. Returns VaultedSignedXrplTransaction.

Desktop:
7. Imports signed payload.
8. Broadcast/submission layer can serialize/submit to XRPL.
```

## Remaining integration work

This patch adds the first-party wallet and QR protocol layer. The remaining production work is:

- full XRPL binary transaction serialization/submission for signed transactions;
- UI screens for QR login and QR signing;
- mobile signer application or mobile module;
- optional persistent encrypted keystore for trusted desktop device pairing;
- migration/removal of old Xaman UI/components from frontend screens.

## Build note

I could not run `cargo test` in this execution environment because Rust/Cargo is not installed here. Run in WSL:

```bash
cargo test --workspace
```

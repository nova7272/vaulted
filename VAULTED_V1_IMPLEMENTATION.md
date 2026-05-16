# Vaulted v1 seed identity implementation notes

This branch migrates the project away from deriving encryption/PRE keys from Xaman/XRPL SignIn signatures.

## Implemented core changes

- `crates/crypto-core`
  - Added BIP-39 seed generation/restore validation (`seed.rs`).
  - Added domain-separated Vaulted identity derivation (`identity.rs`): Ed25519 signing, X25519 encryption, device auth, metadata key and legacy PRE migration seed.
  - Added X25519 + HKDF + XChaCha20-Poly1305 key envelopes (`envelope.rs`).
  - Added signed manifest structs, SHA-256 `manifest_hash`, Ed25519 signing/verification and NFT metadata structs (`manifest.rs`).
  - Added secure note encryption helper using random note keys and owner key envelopes (`secure_note.rs`).
  - Added AES-GCM AAD encryption/decryption helpers and nonce/tamper tests.
  - Disabled legacy signature-based key derivation APIs at runtime.

- `crates/desktop-client`
  - Added Tauri commands:
    - `create_vaulted_wallet`
    - `restore_vaulted_wallet`
    - `validate_vaulted_seed`
    - `has_vaulted_wallet`
  - Added in-memory Vaulted identity state derived only from seed phrase.
  - Xaman SignIn no longer derives encryption keys; it is treated as external wallet auth/linking.
  - Added frontend onboarding for create/restore seed phrase and Xaman linking.
  - Added Oracle client methods for identity, vault object and grant endpoints.

- `crates/oracle`
  - Added `POST /api/v1/identity/register`.
  - Added `GET /api/v1/identity/challenge/:identity_id`.
  - Added `POST /api/v1/identity/token`.
  - Added `POST /api/v1/vault-objects/register` with optional manifest signature/hash verification.
  - Added `GET /api/v1/vault-objects/:id`.
  - Added `POST /api/v1/grants`.
  - Added `GET /api/v1/grants/incoming?identity_id=...`.
  - Added migration `010_vaulted_identity_manifest_layer.sql` for identities, devices, linked wallets, vault objects, grants and audit events.

- `crates/storage-node`
  - Added declared encrypted fragment hash verification on upload using `?fragment_hash=sha256:...` or `?fragment_hash=blake3:...`.
  - Upload response now includes `encrypted_hash`.
  - Existing path traversal checks remain in place.

## Security posture after this change

- Xaman/XRPL signatures are not accepted as encryption seed material.
- Oracle receives only public identity keys and manifest pointers, not mnemonics, private keys or plaintext file keys.
- NFT remains an ownership/recovery anchor; confidentiality comes from key envelopes and the Vaulted seed identity.
- Existing PRE flows are left as a compatibility/migration layer, initialized from the Vaulted seed-derived legacy seed rather than Xaman signatures.

## Validation note

The execution environment used for this modification did not include `cargo`/`rustc`, so Rust compilation could not be run here. The code was updated statically and the UI could not be built because `node_modules` were not present.

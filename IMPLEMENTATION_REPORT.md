# Vaulted priority implementation report

This archive includes the latest Priority 3 continuation changes.

## Implemented in this pass

- Added durable client-generated NFT metadata publication before local mint.
- Added `POST /api/v1/vault/publish-metadata`.
- Oracle verifies:
  - caller owns the prepared vault,
  - `metadata_hash == sha256(metadata_json)`,
  - metadata JSON is valid,
  - `external_url` matches the mint URI,
  - `properties.manifest_hash` matches the prepared manifest hash,
  - public metadata keys do not include sensitive/private field names.
- Oracle stores the exact public metadata JSON under `nft_metadata.manifest.public_metadata`.
- Public `GET /nft/{id}/metadata.json` now serves the stored client-generated metadata when available.
- Public `GET /nft/{id}/image.svg` can serve the exact SVG embedded in the stored metadata data URI.
- `finalize-mint` now requires metadata to be published first, before ledger verification/finalization.
- Desktop Oracle API now supports `publish_vault_metadata`.
- Added Tauri command `publish_vaulted_nft_metadata`.
- Upload UI now publishes metadata before local NFTokenMint signing/submission.

## Resulting flow

1. Client encrypts file and prepares vault in Oracle.
2. Client generates deterministic NFT preview/metadata locally.
3. Client publishes the exact public metadata JSON to Oracle.
4. Client locally signs/submits NFTokenMint using the published metadata URI.
5. Oracle verifies the XRPL ledger transaction and finalizes the vault object.

## Remaining work

- Live XRPL testnet validation of the full flow.
- Move metadata/image to IPFS/Arweave/object storage if Oracle DB-backed public metadata is not sufficient for production.
- Convert transfer/burn/offer/claim flows to local Vaulted signing.
- Add mocked unit/integration tests for publish-metadata and ledger verification.
- Continue production hardening: rate limits, metadata immutability enforcement, CORS/security headers, audit/telemetry scrubber.

## Implemented in this pass

- Hardened `POST /api/v1/vault/publish-metadata` immutability:
  - first publication stores client-generated public NFT metadata;
  - replaying the exact same URI/hash is idempotent;
  - attempts to replace already-published metadata are rejected with conflict.
- Added unit coverage for metadata safety validation:
  - accepts minimized Vaulted public metadata;
  - rejects manifest-hash mismatch;
  - rejects external URL mismatch;
  - rejects nested sensitive keys such as plaintext filenames.
- Added unit coverage for public SVG data URI decoding:
  - accepts valid SVG data URI;
  - rejects non-SVG content;
  - rejects wrong data URI prefix.
- Added deterministic test coverage for pending local-mint upload token generation.

## Remaining work after this pass

- Add DB-backed integration tests for publish/finalize endpoints with a test database or mocked repository.
- Add mocked XRPL client tests for `verify_local_nft_mint` edge cases.
- Continue Priority 4 QR trust model: scan to login, pair device, sign XRPL transaction, approve grant.

## 2026-05-13 — Priority 4 foundation: canonical QR payload layer

Implemented the first Priority 4 foundation step before mobile scanner UI work:

- Added `crypto-core::qr_payload` as the canonical shared QR payload layer.
- Added `VaultedQrIntent` with the four target QR modes:
  - `login`
  - `pair_device`
  - `sign_xrpl_transaction`
  - `approve_file_grant`
- Added `VaultedQrPayloadBody` with deterministic/canonical signing bytes.
- Added `VaultedSignedQrPayload` with Ed25519 signing and verification.
- Added compact QR JSON round-trip helpers.
- Added structural validation for intent-specific required fields.
- Added tests for all Priority 4 modes, signature verification, tamper failure, JSON roundtrip and required-field enforcement.
- Preserved the existing QR login compatibility payload while adding a nested `canonicalPayload` field for the new QR trust model.
- Removed the remaining test-only unused import warning in `nft_public.rs`.

The next QR step is to connect this canonical payload layer to explicit desktop/mobile workflows for device pairing, XRPL transaction signing and file-grant approval.

## 2026-05-13 — Priority 4 continuation: Scan to Pair Device endpoints

Implemented the first concrete workflow on top of the canonical QR payload layer:

- Added migration `012_qr_device_pairing.sql` for `qr_device_pairing_requests`.
- Added Oracle endpoints:
  - `POST /api/v1/auth/qr/pair/start`
  - `GET /api/v1/auth/qr/pair/status/:pairing_request_id`
  - `POST /api/v1/auth/qr/pair/confirm`
- Pair-device QR payloads now include the nested canonical `VaultedQrPayloadBody` with intent `pair_device`.
- Confirmation verifies the Vaulted identity signing public key and an Ed25519 signature over a domain-separated pair-device approval message.
- Successful confirmation inserts or reactivates the paired public device key in `identity_devices`.
- Pairing status returns the paired device id and approval timestamp when available.
- Added desktop Oracle API methods for starting, polling and confirming device pairing.
- Added Tauri commands:
  - `start_vaulted_device_pairing`
  - `poll_vaulted_device_pairing`
  - `confirm_vaulted_device_pairing`
- Added unit tests for pair-device signature-message stability and public-key validation.

Remaining Priority 4 work:

- Add actual QR rendering/UI for device pairing.
- Add mobile scanner/approval screen.
- Add Scan to Sign XRPL Transaction using the canonical QR payload layer.
- Add Scan to Approve File Grant.
- Add device list and revoke UI/API.

## Priority 4 update: Scan-to-Sign-XRPL-Transaction skeleton

Implemented the next QR trust-mode workflow after Scan-to-Login and Scan-to-Pair-Device.

### Added

- Migration `013_qr_xrpl_signing.sql` with `qr_xrpl_signing_requests`.
- Oracle endpoints:
  - `POST /api/v1/auth/qr/xrpl-sign/start`
  - `GET /api/v1/auth/qr/xrpl-sign/status/:signing_request_id`
  - `POST /api/v1/auth/qr/xrpl-sign/confirm`
- Canonical QR payload usage with `intent = sign_xrpl_transaction`.
- Stable `tx_json_hash` using SHA-256 of the transaction JSON.
- Domain-separated approval message:
  - request id
  - challenge
  - oracle URL
  - transaction JSON hash
  - expected XRPL account
  - requester device id/name
  - authorizing device id
- Ed25519 verification against the Vaulted identity signing public key.
- Status polling with approval signature and approving device id.
- Desktop Oracle API helpers for start/status/confirm XRPL signing requests.
- Tauri commands:
  - `start_vaulted_xrpl_signing_request`
  - `poll_vaulted_xrpl_signing_request`
  - `confirm_vaulted_xrpl_signing_request`
- Unit tests for XRPL signing approval message stability and transaction JSON hash determinism.

### Notes

This is the backend/desktop foundation for the QR trust model. It does not yet provide a mobile scanner UI or a full mobile-side transaction signing screen. The current model records a trusted-device approval over a transaction hash and context, which can be used by the desktop flow before local signing/submission or extended later for mobile-side signing.

## Priority 4 update: Scan-to-Approve-File-Grant skeleton

Implemented the final QR mode foundation from the Priority 4 list.

### Added

- Migration `014_qr_file_grant_approval.sql` with `qr_file_grant_requests`.
- Oracle endpoints:
  - `POST /api/v1/auth/qr/grant/start`
  - `GET /api/v1/auth/qr/grant/status/:grant_request_id`
  - `POST /api/v1/auth/qr/grant/confirm`
- Canonical QR payload usage with `intent = approve_file_grant`.
- Stable file-grant context hash over:
  - vault object id
  - grant id
  - recipient identity id
  - recipient-encrypted file key
  - permissions
  - optional grant expiration
- Domain-separated approval message:
  - request id
  - challenge
  - oracle URL
  - vault object id
  - grant id
  - recipient identity id
  - grant context hash
  - requester device id/name
  - authorizing device id
- Oracle validation before starting a request:
  - owner identity exists through the active vault object
  - vault object owner matches the approving identity
  - recipient identity exists
  - permissions and encrypted file key are present
- Confirmation verifies the Vaulted identity signing public key and Ed25519 approval signature.
- Successful confirmation creates/activates the corresponding row in `grants`.
- Status polling exposes approval signature, created grant id and approval timestamp.
- Desktop Oracle API helpers for start/status/confirm file-grant approval.
- Tauri commands:
  - `start_vaulted_file_grant_approval`
  - `poll_vaulted_file_grant_approval`
  - `confirm_vaulted_file_grant_approval`
- Unit tests for file-grant approval message stability and context-hash determinism.

### Remaining QR work

- QR rendering UI for all canonical QR payloads.
- Mobile scanner and approval screens.
- Device list and revoke/session management.
- WebSocket/SSE push instead of polling, optional.
- Full grant UI that generates recipient key envelopes and invokes the QR approval flow.

## Priority 5 update: canonical grant key envelope fields

Started the manifest/key-envelope migration for grants without breaking legacy callers.

### Added

- Migration `015_key_envelope_grants.sql`.
- `grants.key_envelope JSONB` and `grants.key_envelope_version`.
- `qr_file_grant_requests.key_envelope JSONB` and `qr_file_grant_requests.key_envelope_version`.
- Backfill for existing rows by wrapping legacy `encrypted_file_key` in a compatibility envelope:
  - `protocol = vaulted-key-envelope-v1`
  - `alg = legacy-pre-aes-key`
  - `recipient_type = grant-recipient`
- Oracle `create_grant` now accepts canonical `key_envelope` and stores it as the source-of-truth grant payload.
- Legacy `encrypted_file_key` is retained as a compatibility mirror for older API clients.
- Incoming grants now return both:
  - `key_envelope` as canonical data
  - `encrypted_file_key` as deprecated compatibility data
- QR file-grant approval now hashes and stores the full `key_envelope` in the grant context instead of hashing only a bare encrypted key string.
- Desktop QR file-grant start command now sends a canonical envelope-shaped payload while keeping its old command argument for compatibility.

### Remaining Priority 5 work

- Generate real `KeyEnvelope` values in the sharing UI instead of compatibility envelopes.
- Use recipient `encryption_public_key` from `vaulted_identities` to seal file keys.
- Remove legacy PRE transfer endpoints once transfer/burn/claim flows have local-signing replacements.
- Migrate old `encrypted_aes_key`, `pre_public_key`, and `re_encryption_key` DTOs that belong to legacy NFT transfer paths.
- Add grant revocation and expiration enforcement in client UX.

## Priority 5 update — recipient-bound KeyEnvelope construction

Implemented the next grants/key-envelope migration layer:

- Added `seal_key_for_recipient_hex` in `crypto-core::envelope` so callers can build real X25519 recipient envelopes from a public encryption key encoded as hex.
- Added tests proving hex-public-key envelope construction round-trips with `open_key_envelope`.
- Added Oracle public identity lookup: `GET /api/v1/identity/:identity_id`, returning only public identity fields.
- Added desktop Oracle client support for public Vaulted identity lookup.
- Updated `start_vaulted_file_grant_approval` to support real recipient-bound envelopes:
  - optional `fileKeyBase64` supplies the raw content/file key for wrapping;
  - optional `recipientEncryptionPublicKey` can be supplied directly;
  - if missing, desktop resolves the recipient public encryption key via Oracle identity lookup;
  - generated envelope uses `X25519-HKDF-SHA256-XCHACHA20POLY1305` and grant-specific AAD.
- Kept compatibility mode for existing callers that only have legacy `encryptedFileKey`.
- Hardened Oracle grant envelope validation:
  - envelope recipient identity must match the grant recipient;
  - real X25519 envelopes must include recipient key id, ephemeral public key, nonce, and encrypted file key.
- Added QR grant tests for real envelope acceptance and recipient mismatch rejection.

Remaining Priority 5 work:

- Update UI sharing flows to provide `fileKeyBase64` instead of legacy `encryptedFileKey`.
- Persist / recover owner-side file keys in a safe local keystore so grants can be generated after upload.
- Use `KeyEnvelope` directly inside manifests and remove legacy `encrypted_aes_key` / PRE transfer paths from old file APIs.
- Add grant revocation and expiration enforcement in download/access paths.

## Priority 5 update — recipient key fingerprint / TOFU trust foundation

Implemented the trust layer that should sit before recipient-bound KeyEnvelope creation:

- Added `encryption_public_key_fingerprint_hex` in `crypto-core::identity`.
- Added `format_fingerprint_groups` for UI-friendly fingerprint display.
- Added deterministic fingerprint tests.
- Public identity lookup now also returns `encryption_public_key_fingerprint`.
- Added migration `016_recipient_key_trust.sql`.
- Added `identity_trusted_recipient_keys` table for TOFU/manual/QR-verified trust decisions.
- Added Oracle endpoints:
  - `POST /api/v1/identity/trust-recipient-key`
  - `GET /api/v1/identity/trust-recipient-key`
- Oracle validates that trusted keys match the active recipient identity record and that submitted fingerprints are correct.
- Added desktop Oracle API helpers for recipient key trust.
- Added Tauri commands:
  - `compute_recipient_encryption_key_fingerprint`
  - `get_vaulted_recipient_key_trust`
  - `trust_vaulted_recipient_key`
- `start_vaulted_file_grant_approval` now supports `requireTrustedRecipient`; when enabled for real envelopes, the recipient key must be trusted before the grant request is started.
- Embedded migrations list now includes the newer 010–016 migrations for fallback startup paths.

Remaining Priority 5 work after this step:

- Add UI fingerprint confirmation before granting access.
- Add QR/manual trust source display and warnings for changed recipient keys.
- Add trust revoke endpoint and device/key rotation UX.
- Enforce grant expiration/revocation in access/download paths.
- Move sharing UI completely to `fileKeyBase64` + recipient identity lookup.
- Remove compatibility `encrypted_file_key` mirror once legacy callers are gone.

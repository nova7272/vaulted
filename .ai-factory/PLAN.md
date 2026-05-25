# Plan: Oracle Post-Mint Vault Object Linking
Created: 2026-05-25
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, focused Oracle/desktop/UI checks only
- **Logging:** diagnostic allow-list only
- **Docs:** no docs checkpoint for this task
- **Security:** preserve all Vaulted secret boundaries

## Scope
- Diagnose and minimally fix Oracle post-mint finalization so a successful XRPL mint creates or updates `vault_objects.nft_token_id` with the real NFTokenID.
- Ignore stale-sequence and `tefPAST_SEQ` behavior for this task.
- Do not plan XRPL retry changes.

## Current Findings
- `submitted.nftTokenId` is required in [UploadScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/UploadScreen.tsx:277). If absent after an accepted submit, the UI throws before Oracle finalization/linking.
- When present, `UploadScreen.tsx` calls `register_minted_vault_object` with `nftTokenId: submitted.nftTokenId`, `txHash`, `manifestUri`, `manifestHash`, and `vaultObjectId` at [UploadScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/UploadScreen.tsx:285).
- `submitted.nftTokenId` comes from desktop `extract_minted_nftoken_id(tx_hash)` only when the submit is accepted at [commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs:568). If extraction fails, it returns `None`.
- `register_minted_vault_object` sends the real `nft_token_id` to `/api/v1/vault/finalize-mint`, then separately calls `/api/v1/vault-objects/register` with the same real NFTokenID at [commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs:609).
- Oracle `finalize_vault_mint` updates `nft_metadata.nft_token_id`, `metadata_hash`, status, manifest patch, and `file_replicas`, but it does not update `vault_objects` at [vault.rs](/home/riggle/vaulted/crates/oracle/src/api/vault.rs:591).
- `/api/v1/vault-objects/by-nft/{NFTokenID}` reads only `vault_objects.nft_token_id` where `status = 'active'` at [vault_objects.rs](/home/riggle/vaulted/crates/oracle/src/api/vault_objects.rs:177). It does not read `nft_metadata`.
- Therefore a finalized `nft_metadata` row can still produce a 404 from `/vault-objects/by-nft` if the later `/vault-objects/register` call failed, did not run, or wrote a different key.

## Questions Answered
- **Is `submitted.nftTokenId` present after `tesSUCCESS`?** Code does not guarantee it; accepted submit attempts extraction by `tx_hash`. Runtime must confirm the actual minted flow. If absent, UI stops before `register_minted_vault_object`.
- **Is `register_minted_vault_object` called after `tesSUCCESS`?** Only when `submitted.accepted === true` and `submitted.nftTokenId` is present.
- **Does desktop send the real NFTokenID or pending metadata hash/upload key?** In the inspected success path, desktop sends `submitted.nftTokenId` as the real NFTokenID. The pending key remains `result.vault_id`/initial `result.nft_token_id` context.
- **Does Oracle update `nft_metadata` but not `vault_objects`?** Yes. `finalize_vault_mint` updates `nft_metadata` and `file_replicas`; `vault_objects` is updated only by the separate register endpoint.
- **Does by-NFT lookup read from the same table/key that finalize writes?** No. Finalize writes `nft_metadata.nft_token_id`; by-NFT lookup reads `vault_objects.nft_token_id`.

## Tasks

- [x] 1. Add safe diagnostics around post-mint linking boundaries
  - Files likely to change:
    - [crates/desktop-client/ui/src/screens/UploadScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/UploadScreen.tsx)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/oracle/src/api/vault.rs](/home/riggle/vaulted/crates/oracle/src/api/vault.rs)
    - [crates/oracle/src/api/vault_objects.rs](/home/riggle/vaulted/crates/oracle/src/api/vault_objects.rs)
  - Deliverable: enough tracing to distinguish missing extracted NFTokenID, skipped register command, finalize failure, register failure, or by-NFT table mismatch.
  - Allowed diagnostic fields only: `NFTokenID`, `tx_hash`, `metadata_hash`, `metadata_uri_len`, HTTP status code, lookup key type, and status enum.
  - Do not log seed, private keys, JWT, AES keys, plaintext files, recovery phrase, mnemonic entropy, `tx_blob`, signatures, decrypted content, or raw file metadata.

- [x] 2. Make Oracle finalization update the lookup table atomically
  - Files likely to change:
    - [crates/oracle/src/api/vault.rs](/home/riggle/vaulted/crates/oracle/src/api/vault.rs)
    - Optional tests in Oracle test modules if an existing pattern fits.
  - Deliverable: after ledger verification succeeds, the same transaction that updates `nft_metadata.nft_token_id` also upserts or updates the corresponding `vault_objects` row by `vault_id`.
  - Expected behavior: `vault_objects.id = vault_id`, `vault_objects.nft_token_id = real NFTokenID`, `nft_chain = xrpl:testnet`, `manifest_uri`, `manifest_hash`, and `status = active` are consistent after `/vault/finalize-mint`.
  - Dependency note: use existing `vault_objects` schema; do not introduce a migration unless the current schema prevents the fix.
  - Logging requirements: log finalization/link update success or failure with allowed fields only.

- [x] 3. Keep desktop registration idempotent and surface failures clearly
  - Files likely to change:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/src/oracle/api.rs](/home/riggle/vaulted/crates/desktop-client/src/oracle/api.rs)
    - [crates/desktop-client/ui/src/screens/UploadScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/UploadScreen.tsx)
  - Deliverable: keep the existing `finalize_vault_mint` then `register_vault_object` path safe to retry, but make it clear whether finalize succeeded and register/link lookup failed.
  - Expected behavior: no remint is suggested for a post-mint Oracle link failure; the recoverable path is linking/finalization retry with the known real NFTokenID and `tx_hash`.
  - Logging requirements: use only the allowed diagnostic fields; no secret-bearing UI or log output.

- [x] 4. Add focused tests for finalize/by-NFT consistency
  - Files likely to change:
    - Existing Oracle API tests if present, otherwise a small test near `vault.rs`/`vault_objects.rs` helpers.
  - Deliverable: coverage proving that finalization with a real NFTokenID makes `/vault-objects/by-nft/{NFTokenID}` resolvable through `vault_objects`.
  - Include a negative or idempotency case if cheap: repeated finalize/register with the same vault and token should not create a conflicting row.
  - Logging requirements: tests must not print forbidden payloads.

## Verification Commands

Run commands separately, not chained:

```bash
cargo fmt --all --check
cargo check -p xrpl-vault-oracle
cargo test -p xrpl-vault-oracle
cargo check -p xrpl-vault-desktop
cargo test -p xrpl-vault-desktop
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
cd ../../..
./scripts/check-sensitive-logs.sh
git diff --check
```

## Runtime Checks
- After a successful mint, capture only safe fields: `engine_result`, `tx_hash`, `NFTokenID`, `metadata_hash`, and `metadata_uri_len`.
- Confirm `submitted.nftTokenId` is present in the UI success path before invoking `register_minted_vault_object`.
- Confirm `register_minted_vault_object` is invoked exactly once for the successful mint and sends the real NFTokenID, not the pending upload key or metadata hash.
- Confirm `/api/v1/vault/finalize-mint` returns success and updates both `nft_metadata.nft_token_id` and `vault_objects.nft_token_id`.
- Confirm `GET /api/v1/vault-objects/by-nft/{NFTokenID}` returns 200 for each minted NFTokenID and the response `nft_token_id` equals the lookup NFTokenID.
- Confirm the Files tab no longer shows Oracle link unavailable for the finalized minted NFTs.

## Out Of Scope
- No stale-sequence or `tefPAST_SEQ` retry changes.
- No XRPL signing, serialization, or submit retry changes.
- No reset/logout/runtime state clearing.
- No seed, wallet secret, encryption, or plaintext handling changes.

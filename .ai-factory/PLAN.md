# Plan: No-Remint Recovery For Pending Mint Finalization After Restart
Created: 2026-05-25
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, focused Oracle/desktop/UI checks
- **Logging:** diagnostic allow-list only
- **Docs:** no docs checkpoint for this task
- **Security:** preserve all Vaulted secret boundaries; do not remint or reset runtime state

## Scope
- Recover a successful on-chain XRPL mint whose Oracle finalization did not run before app restart.
- Do not remint.
- Do not touch XRPL signing/serialization, stale-sequence or `tefPAST_SEQ` retry logic, encryption/decryption, wallet/key derivation, or plaintext handling.
- Keep recovery idempotent and safe to retry.

## Known Pending Mint
- `vault_id=b524fe14-4976-448f-a3c6-1f43c249a5ff`
- `tx_hash=2E084681288AEC19132D70F2B970AE78089D6A66B27E25EC95683F5BF7ECBB7F`
- `NFTokenID=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC`
- `metadata_hash=sha256:6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403`
- `metadata_uri=http://127.0.0.1:3000/nft/sha256:6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403/metadata.json`
- Oracle `nft_metadata` row exists with `status=pending_claim`.
- `vault_objects` has no row for this metadata hash or NFTokenID.
- `/api/v1/vault-objects/by-nft/{NFTokenID}` still returns 404.

## Findings From Code Inspection
- The `Finalize existing mint` button did not appear after restart because [UploadScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/UploadScreen.tsx) stores `result`, `mintResult`, and `nftPreview` only in React memory. There is no `localStorage`, `sessionStorage`, or desktop-side pending mint persistence for the accepted `tx_hash`.
- The command added in `e7248df`, `finalize_pending_vault_mint`, already does the correct no-remint core operation when supplied with `vault_object_id`, `manifest_uri`, `manifest_hash`, and `tx_hash`.
- `register_minted_vault_object_inner` already reuses Oracle `finalize_vault_mint`, then the idempotent `/vault-objects/register` path.
- Oracle `finalize_vault_mint` already updates `nft_metadata`, `file_replicas`, and upserts `vault_objects` in one transaction.
- Current Oracle `GET /api/v1/vault/{id}` returns status and pending token information, but the desktop client type only exposes `vault_id`, `nft_token_id`, `status`, and `offer_index`; it does not currently give the desktop a typed `metadata_hash` and public `metadata_uri` recovery payload.
- There is no current authenticated API that lists recoverable `pending_claim` rows for the owner.

## Questions Answered
- **Why did the recovery button not appear after restart?** The button is conditional on in-memory `mintResult?.accepted && mintResult.txHash && !mintResult.nftTokenId` plus `result`; all of that is lost on app restart.
- **Is there persisted UI/local state for successful `tx_hash`?** No evidence in `UploadScreen.tsx`; the accepted submit result is not persisted.
- **Should `tx_hash` be stored when submit succeeds?** Yes for future robustness, but the smallest current recovery should not rely on state that was never persisted for this already-minted token.
- **Can the app discover `pending_claim` rows with metadata URI/hash and ask user for `tx_hash`?** Not with current typed desktop APIs. Oracle can read the row, but the API surface should expose only safe recovery fields.
- **Is a manual repair command enough for now?** A manual UI action with `vault_id` and `tx_hash` is the smallest safe user-accessible fix. A raw Tauri command alone is not enough after restart because there is no easy supported way for the user to invoke it.
- **What is the smallest safe fix?** Add a narrow recovery command that resolves safe pending mint fields by `vault_id`, extracts the real `NFTokenID` from the validated XRPL `tx_hash`, and reuses `register_minted_vault_object_inner`; expose it via a small Upload-screen recovery action.

## Preferred Design
- Add an authenticated Oracle recovery lookup for a single vault id, or extend `GET /api/v1/vault/{id}` with optional safe fields:
  - `vault_id`
  - `status`
  - `metadata_hash`
  - `metadata_uri`
  - optional `vault_object_nft_token_id`
  - optional `owner_identity_id`
- Add a desktop command such as `recover_pending_vault_mint(vault_id, tx_hash)`:
  - Loads safe recovery fields from Oracle.
  - Requires `status` to be `pending_claim` or treats already `active` plus matching by-NFT link as idempotent success.
  - Calls `extract_minted_nftoken_id(tx_hash)`.
  - Calls existing `register_minted_vault_object_inner` with recovered `manifest_hash` and `manifest_uri`.
  - Does not mint, sign, submit, decrypt, reset state, or touch file plaintext.
- Add a minimal Upload-screen recovery action:
  - Inputs: `vault_id`, `tx_hash`.
  - Button: `Finalize previous mint`.
  - Result: shows the recovered `NFTokenID` and returns the app to the claimed/linked state.

## Tasks

- [x] 1. Add a safe Oracle recovery lookup for one pending vault
  - Files likely to change:
    - [crates/oracle/src/api/vault.rs](/home/riggle/vaulted/crates/oracle/src/api/vault.rs)
    - [crates/desktop-client/src/oracle/api.rs](/home/riggle/vaulted/crates/desktop-client/src/oracle/api.rs)
  - Deliverable: desktop can request safe recovery fields for a specific `vault_id` owned by the authenticated wallet.
  - Expected behavior: response includes `vault_id`, `status`, `metadata_hash`, and `metadata_uri` for `pending_claim` rows without returning encrypted manifest, encrypted keys, raw file metadata, JWTs, or plaintext.
  - Logging requirements: if logs are added, only log `vault_id`, `metadata_hash`, metadata URI length, lookup key type, `owner_identity_id`, status enum, HTTP status code, and request phase.
  - Dependency notes: prefer extending the existing `GET /api/v1/vault/{id}` response if backward compatible; otherwise add a narrow route such as `GET /api/v1/vault/{id}/mint-recovery`.

- [x] 2. Add a no-remint desktop recovery command
  - Files likely to change:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/src/main.rs](/home/riggle/vaulted/crates/desktop-client/src/main.rs)
    - [crates/desktop-client/src/oracle/api.rs](/home/riggle/vaulted/crates/desktop-client/src/oracle/api.rs)
  - Deliverable: command `recover_pending_vault_mint(vaultId, txHash)` or equivalent resolves persisted Oracle metadata, extracts `NFTokenID` from XRPL validated tx metadata, then reuses `register_minted_vault_object_inner`.
  - Expected behavior: the known pending mint finalizes without reminting and writes `vault_objects.nft_token_id=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC`.
  - Idempotency: if recovery is rerun for the same `vault_id` and `tx_hash`, it updates the same `vault_objects` row and returns success; it must not create conflicting rows.
  - Logging requirements: only `NFTokenID`, `tx_hash`, `metadata_hash`, metadata URI length, lookup key type, `vault_id`, `owner_identity_id`, status enum, `engine_result`, HTTP status code, and request phase.
  - Dependency notes: do not alter XRPL signing, submit, serialization, retry, or wallet derivation code.

- [x] 3. Add a minimal user-accessible recovery action after restart
  - Files likely to change:
    - [crates/desktop-client/ui/src/screens/UploadScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/UploadScreen.tsx)
    - [crates/desktop-client/ui/src/utils/formatError.ts](/home/riggle/vaulted/crates/desktop-client/ui/src/utils/formatError.ts)
  - Deliverable: a small recovery control on the Upload screen that accepts `vault_id` and `tx_hash`, calls the new desktop recovery command, and shows a safe success/error state.
  - Expected behavior: after app restart, the user can finalize the known successful mint by entering the known `vault_id` and `tx_hash`; the app must not call `mint_vaulted_nft_locally`.
  - Logging requirements: UI must not print forbidden fields; displayed diagnostics should be limited to `NFTokenID`, `tx_hash`, `metadata_hash`, status enum, and request phase.
  - Dependency notes: keep the existing in-memory `Finalize existing mint` path, but route both it and the manual recovery action through the same desktop recovery/finalization logic if practical.

- [x] 4. Persist future accepted submit recovery state
  - Files likely to change:
    - [crates/desktop-client/ui/src/screens/UploadScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/UploadScreen.tsx)
    - Optional desktop-local helper in [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs) only if browser storage is not appropriate.
  - Deliverable: when an XRPL submit returns `accepted=true` and a `tx_hash`, persist only safe recovery fields needed to show the recovery action after restart: `vault_id`, `tx_hash`, `metadata_hash`, `metadata_uri`, status enum, and timestamp.
  - Expected behavior: future post-submit extraction failures can be recovered after restart without re-entering all fields.
  - Logging requirements: no secret-bearing fields; do not persist file paths, plaintext file names, raw metadata JSON, encrypted AES keys, JWTs, seeds, or tx blobs.
  - Dependency notes: this task helps future failures, but task 2 and task 3 must be enough to recover the known current mint even if no prior state exists.

- [x] 5. Add focused tests and run verification
  - Files likely to change:
    - Oracle tests near [crates/oracle/src/api/vault.rs](/home/riggle/vaulted/crates/oracle/src/api/vault.rs)
    - Desktop tests near [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs) or [crates/desktop-client/src/xrpl/client.rs](/home/riggle/vaulted/crates/desktop-client/src/xrpl/client.rs)
    - UI type/lint checks for [UploadScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/UploadScreen.tsx)
  - Deliverable: coverage that recovery lookup returns only safe fields, recovery reuses existing finalization/register logic, and missing/invalid recovery data produces actionable safe errors.
  - Expected behavior: no tests or logs expose forbidden values.
  - Logging requirements: test output must not include seed, private keys, JWT, AES keys, plaintext, recovery phrase, mnemonic entropy, `tx_blob`, signatures, decrypted content, or raw file metadata.

## One-Time Recovery Action Proposal
- After implementation, open Upload and use the recovery control with:
  - `vault_id=b524fe14-4976-448f-a3c6-1f43c249a5ff`
  - `tx_hash=2E084681288AEC19132D70F2B970AE78089D6A66B27E25EC95683F5BF7ECBB7F`
- The app should recover `metadata_hash` and `metadata_uri` from Oracle, extract `NFTokenID` from XRPL, then call the existing Oracle finalization/register flow.
- Do not press `Mint vault NFT` for this vault.

## Database Verification Commands

Run commands separately and select only safe columns.

Check pending row before recovery:

```bash
docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "SELECT id AS vault_id, nft_token_id, metadata_hash, status, manifest #>> '{public_metadata,metadata_uri}' AS metadata_uri, manifest #>> '{xrpl_tx_hash}' AS xrpl_tx_hash FROM nft_metadata WHERE id = 'b524fe14-4976-448f-a3c6-1f43c249a5ff';"
```

Check missing vault object before recovery:

```bash
docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "SELECT id, owner_identity_id, manifest_hash, manifest_uri, nft_chain, nft_token_id, status FROM vault_objects WHERE id = 'b524fe14-4976-448f-a3c6-1f43c249a5ff' OR nft_token_id = '00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC' OR manifest_hash = 'sha256:6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403';"
```

Check active owner identity availability:

```bash
docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "SELECT vi.id AS owner_identity_id, vi.status, lw.chain, lw.address FROM vaulted_identities vi LEFT JOIN linked_wallets lw ON lw.identity_id = vi.id WHERE vi.status = 'active' ORDER BY vi.updated_at DESC LIMIT 20;"
```

Check post-recovery link:

```bash
docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "SELECT nm.id AS vault_id, nm.nft_token_id AS metadata_nft_token_id, nm.status AS metadata_status, nm.metadata_hash, nm.manifest #>> '{xrpl_tx_hash}' AS xrpl_tx_hash, vo.id AS vault_object_id, vo.nft_token_id AS vault_object_nft_token_id, vo.status AS vault_object_status FROM nft_metadata nm LEFT JOIN vault_objects vo ON vo.id = nm.id::text WHERE nm.id = 'b524fe14-4976-448f-a3c6-1f43c249a5ff';"
```

## Runtime Verification Commands

Check Oracle health:

```bash
curl -i http://127.0.0.1:3000/health
```

After recovery, verify by-NFT lookup through the authenticated app path. If using raw curl, do not print or paste JWTs:

```bash
curl -i http://127.0.0.1:3000/api/v1/vault-objects/by-nft/00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC
```

If raw curl is blocked by auth, verify through the desktop Files tab or an authenticated local command that does not print tokens.

## Verification Commands After Code Changes

Run commands separately:

```bash
cargo fmt --all --check
cargo check -p xrpl-vault-oracle
cargo test -p xrpl-vault-oracle
cargo check -p xrpl-vault-desktop
cargo test -p xrpl-vault-desktop
```

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
```

```bash
./scripts/check-sensitive-logs.sh
git diff --check
```

## Expected Successful State
- The known pending mint is finalized without a second XRPL mint.
- `nft_metadata.id=b524fe14-4976-448f-a3c6-1f43c249a5ff` has:
  - `nft_token_id=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC`
  - `status=active`
  - `manifest.xrpl_tx_hash=2E084681288AEC19132D70F2B970AE78089D6A66B27E25EC95683F5BF7ECBB7F`
- `vault_objects.id=b524fe14-4976-448f-a3c6-1f43c249a5ff` exists with:
  - `manifest_hash=sha256:6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403`
  - `nft_token_id=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC`
  - `status=active`
- `/api/v1/vault-objects/by-nft/00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC` returns 200 through the authenticated app path.
- Re-running recovery for the same `vault_id` and `tx_hash` returns the same linked object and creates no duplicate or conflicting row.

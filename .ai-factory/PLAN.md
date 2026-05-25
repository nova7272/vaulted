# Plan: Runtime Diagnose And Relink Minted Vault Objects
Created: 2026-05-25
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, only after evidence points to a minimal code or repair path
- **Logging:** diagnostic allow-list only
- **Docs:** no docs checkpoint for this task
- **Security:** preserve all Vaulted secret boundaries

## Scope
- Diagnose why existing minted NFTs still return 404 from `/api/v1/vault-objects/by-nft/{NFTokenID}` after commit `d92c579`.
- Diagnose why the current `Mint vault NFT` button fails after `Encrypted vault registered`.
- Create a minimal idempotent relink/recovery path for already minted NFTs only if `vault_id` and manifest metadata can be recovered from Oracle DB or safe local runtime state.
- Do not remint old NFTs.

## Known Runtime Evidence
- Commit `d92c579 Link vault objects after local mint finalization` is applied.
- Services started.
- Already minted NFTs still return 404 from `/api/v1/vault-objects/by-nft/{NFTokenID}`.
- Upload screen can create/register encrypted vault metadata and shows `Encrypted vault registered`.
- Clicking `Mint vault NFT` currently ends with generic UI error: `Something went wrong. Please try again.`
- Metadata URI example:
  - `http://127.0.0.1:3000/nft/sha256:6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403/metadata.json`

## Known Minted NFTs
- `NFTokenID=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4F80E92655010D42BA`
  - `tx_hash=1121120F413DB9B4BD4284226754D8436C9F3D17BECCCE89304F3840B0B98B7D`
- `NFTokenID=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4F97CEF756010D42BB`
  - `tx_hash=887322BE984053DC3D2BBEA2F8CB976D699763CD6C98D97D9E408A275E5BD138`

## Code Findings
- `finalize_vault_mint` now requires `owner_identity_id`, checks it is an active `vaulted_identities.id`, then upserts `vault_objects` inside the same DB transaction at [vault.rs](/home/riggle/vaulted/crates/oracle/src/api/vault.rs:501).
- Existing old minted NFTs will not be repaired by `d92c579` unless finalize/register is re-run or a safe relink repair updates `vault_objects`.
- `register_minted_vault_object` sends `owner_identity_id: identity.identity_id_hex()` to finalize, then calls `/vault-objects/register` as an idempotent follow-up at [commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs:598).
- The current mint button calls `publish_vaulted_nft_metadata`, `mint_vaulted_nft_locally`, then `register_minted_vault_object`; failures are collapsed through `formatError` at [UploadScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/UploadScreen.tsx:241).
- `formatError` returns `Something went wrong. Please try again.` when the cleaned error is long or contains stack-like text at [formatError.ts](/home/riggle/vaulted/crates/desktop-client/ui/src/utils/formatError.ts:206). Oracle JSON error bodies can plausibly be hidden here.
- The Oracle client currently returns `Oracle API error: HTTP <status>: <raw JSON body>` for failed responses at [api.rs](/home/riggle/vaulted/crates/desktop-client/src/oracle/api.rs:136), so UI generic text does not prove the backend error is generic.

## Questions To Answer With Runtime Evidence
- Are the old NFT `tx_hash` values present anywhere in Oracle DB?
- Can each known `NFTokenID` be mapped to a `vault_id` or `manifest_hash` from existing DB/local state?
- Does `nft_metadata` contain the real `nft_token_id` while `vault_objects` lacks it?
- Does `vault_objects` contain rows keyed by pending upload key or rows with missing `nft_token_id`?
- Is `owner_identity_id` available and active when `finalize_vault_mint` is called?
- What exact safe error is returned by Oracle/desktop for the current mint failure?
- Does the UI hide the real error behind generic `Something went wrong`?
- Is there already a safe command/API path to retry finalize/register without remint?
- If not, what is the smallest safe repair path?

## Tasks

- [x] Runtime fix implemented: post-submit NFTokenID extraction now polls the validated XRPL `tx` response and directly supports `meta.nftoken_id` / `meta.NFTokenID` before falling back to existing affected-node parsing.
  - Changed files:
    - [crates/desktop-client/src/xrpl/client.rs](/home/riggle/vaulted/crates/desktop-client/src/xrpl/client.rs)
  - Verification: desktop tests cover direct validated `meta.nftoken_id`, uppercase `NFTokenID`, existing `CreatedNode`, existing `ModifiedNode`, and missing metadata fallback.
  - Logging requirements: extraction diagnostics use only allowed fields.

- [x] Runtime recovery implemented: a successful submitted mint can be finalized later without reminting by extracting `NFTokenID` from the known `tx_hash` and reusing the existing `register_minted_vault_object` / Oracle finalize path.
  - Changed files:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/src/main.rs](/home/riggle/vaulted/crates/desktop-client/src/main.rs)
    - [crates/desktop-client/ui/src/screens/UploadScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/UploadScreen.tsx)
    - [crates/desktop-client/ui/src/utils/formatError.ts](/home/riggle/vaulted/crates/desktop-client/ui/src/utils/formatError.ts)
  - Expected recovery for current pending mint:
    - `vault_id=b524fe14-4976-448f-a3c6-1f43c249a5ff`
    - `tx_hash=2E084681288AEC19132D70F2B970AE78089D6A66B27E25EC95683F5BF7ECBB7F`
    - `NFTokenID=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC`
    - `metadata_hash=sha256:6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403`
  - UI behavior: if mint submit succeeded but `NFTokenID` was unavailable, the screen can show `Finalize existing mint` and complete Oracle linking without another XRPL mint.
  - Error behavior: missing `NFTokenID` maps to a safe actionable error instead of the generic fallback.

- [ ] 1. Collect safe runtime logs for current mint failure
  - Files likely to inspect/change:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/src/oracle/api.rs](/home/riggle/vaulted/crates/desktop-client/src/oracle/api.rs)
    - [crates/oracle/src/api/vault.rs](/home/riggle/vaulted/crates/oracle/src/api/vault.rs)
    - [crates/desktop-client/ui/src/utils/formatError.ts](/home/riggle/vaulted/crates/desktop-client/ui/src/utils/formatError.ts)
  - Deliverable: identify the exact failing phase: XRPL submit, missing `submitted.nftTokenId`, finalize validation, owner identity validation, ledger verification, `vault_objects` upsert, or post-finalize register.
  - Logging requirements: only `NFTokenID`, `tx_hash`, `metadata_hash`, metadata URI length, HTTP status code, lookup key type, `vault_id`, `owner_identity_id`, status enum, `engine_result`, and request phase.
  - Dependency note: this task gates all code/repair decisions.

- [ ] 2. Inspect Oracle DB state for old minted NFTs and current prepared vault
  - Files likely to inspect/change:
    - No source changes expected in this task.
  - Deliverable: table mapping each known `NFTokenID`/`tx_hash` to DB evidence: `nft_metadata.id`, `nft_metadata.nft_token_id`, `metadata_hash`, published metadata URI, manifest `xrpl_tx_hash`, `vault_objects.id`, `vault_objects.nft_token_id`, `owner_identity_id`, and status.
  - Logging requirements: do not print encrypted AES keys, encrypted manifest content, raw manifest JSON, JWTs, or plaintext file metadata. Select only safe columns listed in the command section.
  - Dependency note: this task determines whether relink is possible without reminting.

- [ ] 3. Decide and implement the smallest safe diagnosis improvement if runtime error is hidden
  - Files likely to change only if evidence shows the UI/desktop hides the actionable error:
    - [crates/desktop-client/ui/src/utils/formatError.ts](/home/riggle/vaulted/crates/desktop-client/ui/src/utils/formatError.ts)
    - [crates/desktop-client/src/oracle/api.rs](/home/riggle/vaulted/crates/desktop-client/src/oracle/api.rs)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
  - Deliverable: preserve a safe actionable error such as owner identity inactive, missing NFTokenID, Oracle validation status, or XRPL `engine_result`, without exposing forbidden fields.
  - Expected behavior: `Mint vault NFT` no longer collapses allowed Oracle/XRPL diagnostics into only `Something went wrong`.
  - Logging requirements: only allowed diagnostics; do not show request/response bodies wholesale if they may contain forbidden content.

- [ ] 4. Design and implement an idempotent relink path for recoverable old NFTs
  - Files likely to change only after task 2 proves a mapping exists:
    - Prefer existing Oracle API/desktop command if safe.
    - If no safe path exists, add the smallest repair-only path in [crates/oracle/src/api/vault.rs](/home/riggle/vaulted/crates/oracle/src/api/vault.rs) or [crates/oracle/src/api/vault_objects.rs](/home/riggle/vaulted/crates/oracle/src/api/vault_objects.rs), plus a desktop command only if needed.
  - Deliverable: for each old minted NFT with recoverable `vault_id`, manifest URI/hash, owner wallet, and active `owner_identity_id`, update/upsert `vault_objects` so `/by-nft/{NFTokenID}` resolves.
  - Expected behavior: repair is idempotent; repeated repair for the same `vault_id`/`NFTokenID` updates the same row and creates no conflicting rows.
  - Logging requirements: log `NFTokenID`, `tx_hash`, `metadata_hash`, metadata URI length, lookup key type, `vault_id`, `owner_identity_id`, status enum, and request phase only.
  - Dependency note: do not add repair if DB/local state cannot prove the mapping.

- [ ] 5. Add focused tests and run verification
  - Files likely to change:
    - Oracle unit/integration tests near [vault.rs](/home/riggle/vaulted/crates/oracle/src/api/vault.rs) or [vault_objects.rs](/home/riggle/vaulted/crates/oracle/src/api/vault_objects.rs)
    - Desktop/UI tests only if error-formatting code changes.
  - Deliverable: prove idempotent relink/upsert behavior and safe error propagation for the observed failure class.
  - Logging requirements: tests must not print forbidden values.

## Database Inspection Commands

Run commands separately. These commands select only safe diagnostic columns.

Check infrastructure and DB readiness:

```bash
docker compose ps postgres
docker compose exec postgres pg_isready -U xrpl_vault -d xrpl_vault
```

Find known NFT/tx rows in `nft_metadata`:

```bash
docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "SELECT id, nft_token_id, metadata_hash, status, offer_index, manifest #>> '{public_metadata,metadata_uri}' AS metadata_uri, manifest #>> '{xrpl_tx_hash}' AS xrpl_tx_hash FROM nft_metadata WHERE nft_token_id IN ('00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4F80E92655010D42BA','00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4F97CEF756010D42BB') OR manifest #>> '{xrpl_tx_hash}' IN ('1121120F413DB9B4BD4284226754D8436C9F3D17BECCCE89304F3840B0B98B7D','887322BE984053DC3D2BBEA2F8CB976D699763CD6C98D97D9E408A275E5BD138') ORDER BY updated_at DESC;"
```

Find rows by the latest visible metadata hash:

```bash
docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "SELECT id, nft_token_id, metadata_hash, status, offer_index, manifest #>> '{public_metadata,metadata_uri}' AS metadata_uri, manifest #>> '{public_metadata,metadata_hash}' AS metadata_json_hash, manifest #>> '{xrpl_tx_hash}' AS xrpl_tx_hash FROM nft_metadata WHERE metadata_hash IN ('6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403','sha256:6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403') OR manifest #>> '{public_metadata,metadata_uri}' LIKE '%6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403%' ORDER BY updated_at DESC;"
```

Compare `nft_metadata` and `vault_objects` by vault id, manifest hash, and NFT token id:

```bash
docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "SELECT nm.id AS vault_id, nm.nft_token_id AS metadata_nft_token_id, nm.metadata_hash, nm.status AS metadata_status, nm.manifest #>> '{public_metadata,metadata_uri}' AS metadata_uri, nm.manifest #>> '{xrpl_tx_hash}' AS xrpl_tx_hash, vo.id AS vault_object_id, vo.nft_token_id AS vault_object_nft_token_id, vo.owner_identity_id, vo.status AS vault_object_status FROM nft_metadata nm LEFT JOIN vault_objects vo ON vo.id = nm.id::text OR vo.manifest_hash = nm.metadata_hash OR vo.nft_token_id = nm.nft_token_id WHERE nm.nft_token_id IN ('00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4F80E92655010D42BA','00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4F97CEF756010D42BB') OR nm.manifest #>> '{xrpl_tx_hash}' IN ('1121120F413DB9B4BD4284226754D8436C9F3D17BECCCE89304F3840B0B98B7D','887322BE984053DC3D2BBEA2F8CB976D699763CD6C98D97D9E408A275E5BD138') OR nm.manifest #>> '{public_metadata,metadata_uri}' LIKE '%6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403%' ORDER BY nm.updated_at DESC;"
```

Inspect candidate `vault_objects` rows that may be missing or carrying pending keys:

```bash
docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "SELECT id, owner_identity_id, manifest_hash, manifest_uri, nft_chain, nft_token_id, status, updated_at FROM vault_objects WHERE nft_token_id IN ('00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4F80E92655010D42BA','00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4F97CEF756010D42BB') OR manifest_uri LIKE '%6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403%' OR manifest_hash IN ('6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403','sha256:6329e957301d68c7b4dac47f8a09ee7e61d3385a38d83fd615abc67e8f1b2403') ORDER BY updated_at DESC;"
```

Check active identity availability for candidate owners:

```bash
docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "SELECT vi.id AS owner_identity_id, vi.status, lw.chain, lw.address FROM vaulted_identities vi LEFT JOIN linked_wallets lw ON lw.identity_id = vi.id WHERE vi.status = 'active' ORDER BY vi.updated_at DESC LIMIT 20;"
```

## Log Grep Commands

Use existing runtime log files if services were started with `tee`; otherwise restart with safe `RUST_LOG` settings and reproduce once.

Oracle logs:

```bash
rg -n "finalize-mint|Finalized Vaulted mint|owner_identity_id|validation_error|xrpl_error|database_error|vault_mint_finalized|vault object" /tmp/vaulted-oracle.log
```

Desktop logs:

```bash
rg -n "Vaulted NFTokenMint submit result|Failed to extract minted NFTokenID|Registering locally minted vault object|Oracle mint finalization completed|Vault object manifest link registered|engine_result|HTTP 400|HTTP 409|HTTP 502|owner_identity_id" /tmp/vaulted-desktop.log
```

If logs do not exist, start fresh diagnostic sessions:

```bash
RUST_LOG=xrpl_vault_oracle=debug,tower_http=debug cargo run -p xrpl-vault-oracle --bin oracle
```

```bash
RUST_LOG=xrpl_vault_desktop=debug cargo run -p xrpl-vault-desktop
```

## Runtime Verification Commands

After DB/log diagnosis and any approved repair:

```bash
curl -i http://127.0.0.1:3000/health
```

Use an authenticated app/API request for protected by-NFT lookups without printing JWTs:

```bash
curl -i http://127.0.0.1:3000/api/v1/vault-objects/by-nft/00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4F80E92655010D42BA
```

```bash
curl -i http://127.0.0.1:3000/api/v1/vault-objects/by-nft/00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4F97CEF756010D42BB
```

If endpoint auth blocks raw `curl`, verify through the desktop Files tab or a local authenticated command that does not print tokens.

## Verification Commands After Code Changes

Run only if implementation changes are made:

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

## Expected Successful State
- Each recoverable old `NFTokenID` maps to exactly one `vault_objects` row with:
  - `id = recovered vault_id`
  - `nft_token_id = real NFTokenID`
  - `manifest_hash` and `manifest_uri` matching the prepared/published metadata
  - `owner_identity_id` active
  - `status = active`
- `GET /api/v1/vault-objects/by-nft/{NFTokenID}` returns 200 through an authenticated path.
- Files tab no longer shows Oracle link unavailable for relinked NFTs.
- Current `Mint vault NFT` failure surfaces a safe actionable error instead of only `Something went wrong`.
- Any repair/relink can be re-run for the same `vault_id`/`NFTokenID` without duplicate or conflicting rows.

## Out Of Scope
- Do not remint old NFTs.
- Do not touch XRPL signing/serialization.
- Do not touch stale-sequence or `tefPAST_SEQ` retry logic unless runtime evidence proves the current button error is only stale sequence.
- Do not touch encryption/decryption, wallet/key derivation, plaintext file handling, or runtime state reset/logout.

# Plan: Fix Transfer Confirm-Signed Payload Shape
Created: 2026-05-27
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes. Add focused serialization/deserialization tests around the confirm-signed payload shape and run narrow Rust package checks before workspace checks.
- **Logging:** standard, security-safe diagnostics only. Allowed: command name, phase, transfer id, offer index, tx hash, endpoint status, status enum, validation reason. Forbidden: `tx_blob`, signatures, JWTs, storage tokens, AES keys, plaintext/decrypted content, seed phrase, private keys, raw encrypted key material, tokenized URLs, raw storage keys.
- **Docs:** no docs changes for this fix.
- **Roadmap linkage:** `VAULTED_AGENT_INSTRUCTIONS.md` section 18, item 8: `Complete transfer/re-encryption`.

## Runtime Evidence
- NFT token id: `00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC`
- Recipient address: `rEpL6nvbvrxxR4HDKT4g1P8KAhHrQ2KQus`
- `NFTokenCreateOffer` submit succeeded with `engine_result=tesSUCCESS`
- XRPL tx hash: `779504A054633772C741E95E999419D9110B5E690B2D7F1A46ABDCCB4D4AB01D`
- Extracted offer index: `21DE5973654BA063B81A3F63FEF66478D81762AA1FF83E66A40027F740AB1708`
- Oracle transfer initiate succeeded with `transfer_id=e9e46f99-4aa6-48ec-94ea-f16d7f2d21eb`
- Failure: `POST /api/v1/transfers/confirm-signed -> 422 Unprocessable Entity`

## Finding
- **Likely exact mismatch:** desktop sends `ConfirmTransferOfferSignedRequest` as camelCase JSON because [crates/desktop-client/src/oracle/api.rs](/home/riggle/vaulted/crates/desktop-client/src/oracle/api.rs) has `#[serde(rename_all = "camelCase")]`, so the payload is:

```json
{
  "transferId": "e9e46f99-4aa6-48ec-94ea-f16d7f2d21eb",
  "offerIndex": "21DE5973654BA063B81A3F63FEF66478D81762AA1FF83E66A40027F740AB1708"
}
```

- Oracle’s local request struct in [crates/oracle/src/api/transfers.rs](/home/riggle/vaulted/crates/oracle/src/api/transfers.rs) is:

```rust
#[derive(serde::Deserialize)]
pub struct ConfirmOfferSignedRequest {
    pub transfer_id: Uuid,
    pub offer_index: String,
}
```

- Because it lacks `#[serde(rename_all = "camelCase")]`, serde expects `transfer_id` and `offer_index`. Axum returns `422 Unprocessable Entity` during JSON extraction/deserialization before `confirm_offer_signed` runs application validation.

## Answers To Scope Questions
- **What JSON shape does Oracle expect now?** `{"transfer_id": "...", "offer_index": "..."}`.
- **What JSON shape does desktop send now?** `{"transferId": "...", "offerIndex": "..."}`.
- **Does Oracle expect `offerIndex` vs `nftOfferIndex` vs `signedPayload`?** Current Oracle code expects only `offer_index`, no `nft_offer_index` or signed payload.
- **Does it require `tx_hash` / `xrpl_tx_hash`?** No. Current confirm-signed updates `nft_offer_index` and status only; tx hash is not stored at this step.
- **Does it require status pending/signing before confirm?** Yes. The row must be `status = 'pending'`; otherwise the handler returns application `400 BadRequest`.
- **Is desktop sending camelCase while Oracle expects snake_case?** Yes. This is the likely 422 cause.
- **Does Oracle validate the submitted offer on-chain?** No. Current handler only checks auth sender, pending status, and updates DB.
- **Is 422 from Axum JSON deserialize, validation, or application error?** Likely Axum JSON deserialize because required snake_case fields are absent from the camelCase body. Application validation would map through `ApiError`, not Axum’s extractor-level 422.

## Minimal Files To Change
- [crates/oracle/src/api/transfers.rs](/home/riggle/vaulted/crates/oracle/src/api/transfers.rs)
  - Add `#[serde(rename_all = "camelCase")]` to `ConfirmOfferSignedRequest`.
  - Optionally add safe structured logs around confirm-signed request acceptance and validation failure phases using transfer id / offer index only.
- [crates/desktop-client/src/oracle/api.rs](/home/riggle/vaulted/crates/desktop-client/src/oracle/api.rs)
  - Keep current camelCase request unless implementation chooses the less preferred alternative of switching desktop to snake_case.
  - Add/adjust a unit test if there is an existing API serialization test pattern.
- [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
  - Inspect only; change only if extra endpoint status diagnostics are needed around `confirm_transfer_offer_signed`.
- [crates/oracle/src/api/mod.rs](/home/riggle/vaulted/crates/oracle/src/api/mod.rs)
  - No expected change; route is already mounted at `/transfers/confirm-signed`.

## Tasks

- [x] 1. Align Oracle confirm-signed request casing
  - Deliverable: Oracle accepts the desktop camelCase payload `{ transferId, offerIndex }` for `/api/v1/transfers/confirm-signed`.
  - Expected behavior: Axum no longer returns 422 for the runtime payload shape; handler proceeds to auth/status validation.
  - Files likely to change:
    - [crates/oracle/src/api/transfers.rs](/home/riggle/vaulted/crates/oracle/src/api/transfers.rs)
  - Logging requirements: do not log JWTs, tx blobs, signatures, keys, or raw request bodies; only safe transfer id, offer index, phase, and status.
  - Dependency notes: do not change XRPL signing, mint/finalize, auth, QR, storage, or owner download paths.

- [x] 2. Add focused payload-shape tests
  - Deliverable: add a narrow test proving `ConfirmOfferSignedRequest` deserializes from camelCase and, if practical, rejects or documents snake_case behavior.
  - Expected behavior: test fails on current code and passes after adding `rename_all = "camelCase"`.
  - Files likely to change:
    - [crates/oracle/src/api/transfers.rs](/home/riggle/vaulted/crates/oracle/src/api/transfers.rs)
    - [crates/desktop-client/src/oracle/api.rs](/home/riggle/vaulted/crates/desktop-client/src/oracle/api.rs) only if a matching client serialization unit test is useful and low cost.
  - Logging requirements: tests must not print tx blobs, signatures, JWTs, keys, raw encrypted material, or plaintext.
  - Dependency notes: no database integration test required for this casing fix.

- [x] 3. Verify confirm-signed status transition assumptions
  - Deliverable: inspect the initiate -> confirm-signed -> incoming query path and verify the transition remains `pending` -> `completed` with `nft_offer_index` set, because incoming transfers query `status = 'completed' AND nft_offer_index IS NOT NULL`.
  - Expected behavior: no status model changes unless evidence shows the runtime transfer row is not `pending` after initiate.
  - Files likely to inspect/change:
    - [crates/oracle/src/api/transfers.rs](/home/riggle/vaulted/crates/oracle/src/api/transfers.rs)
    - [crates/oracle/src/api/mod.rs](/home/riggle/vaulted/crates/oracle/src/api/mod.rs) inspect only if route behavior is still suspect.
  - Logging requirements: allowed diagnostics only; no raw request body logging.
  - Dependency notes: this task should remain read-mostly unless the status mismatch is proven.

## Verification Commands
Narrow checks:

```bash
cargo fmt --all --check
cargo test -p xrpl-vault-oracle confirm
cargo check -p xrpl-vault-oracle
cargo check -p xrpl-vault-desktop
```

Full checks before commit:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
./scripts/check-sensitive-logs.sh
git diff --check
```

Frontend checks are not required unless implementation changes frontend files. If frontend is changed unexpectedly:

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
cd ../../..
```

## Runtime Retest Steps
- Do not re-submit the already successful XRPL offer if the pending transfer row and offer index still exist.
- Start Oracle with the fixed binary and existing database state.
- Confirm transfer row still exists and is pending, if DB access is available:

```bash
docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "SELECT id, status, nft_offer_index FROM transfer_requests WHERE id = 'e9e46f99-4aa6-48ec-94ea-f16d7f2d21eb';"
```

- If row is `pending`, manually retry the existing confirm step with the already extracted offer index through the desktop flow if it can resume, or with an authenticated request using the owner’s active Oracle token without printing the token:

```text
POST /api/v1/transfers/confirm-signed
{
  "transferId": "e9e46f99-4aa6-48ec-94ea-f16d7f2d21eb",
  "offerIndex": "21DE5973654BA063B81A3F63FEF66478D81762AA1FF83E66A40027F740AB1708"
}
```

- Expected response: `200 OK`, `success=true`, `status="transferring"` or existing response status string from handler.
- Verify incoming transfer appears for recipient through `/api/v1/transfers/incoming/{recipient}` or Files screen.
- Then continue recipient claim flow in the existing desktop runtime.
- If the transfer row is no longer pending, create one new runtime transfer attempt after the fix and confirm the same endpoint no longer returns 422.

## Out Of Scope
- `NFTokenCreateOffer` signing/serialization changes.
- `NFTokenAcceptOffer` signing/serialization changes.
- QR/auth.
- Wallet tab or Send XRP.
- Owner download/decrypt.
- Seed policy.
- Mint/finalize.
- Storage.
- Broad UI polish or retry/recovery UX.
- Oracle schema changes unless unavoidable and proven by inspection.

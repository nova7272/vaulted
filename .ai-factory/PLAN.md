# Plan: Finish XRPL Mint Submit Diagnostics

Created: 2026-05-24
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes
- **Logging:** safe allow-list only
- **Docs:** no docs checkpoint for this implementation task
- **Security:** preserve all existing Vaulted secret boundaries

## Requirements
- Finish diagnostics for locally signed XRPL `NFTokenMint` submit failures.
- Do not implement broader mint fixes yet; this task only exposes enough safe signal to diagnose the actual failure.
- Keep changes minimal and reviewable.
- Never log or display: `tx_blob`, seed, private keys, JWT/Oracle token, AES keys, plaintext files, recovery phrase, or mnemonic entropy.
- Allowed diagnostics only: `engine_result`, `engine_result_message`, `tx_hash`, `accepted`, classic address, metadata URI length, endpoint status code.
- Non-`tes*` submit results must reach the frontend with `engine_result` and `engine_result_message`.
- UI must show a specific XRPL failure instead of only generic `Blockchain transaction failed`.

## Context
- Required context files were read first:
  - `AGENTS.md`
  - `.ai-factory/DESCRIPTION.md`
  - `.ai-factory/ARCHITECTURE.md`
  - `.ai-factory/rules/base.md`
  - `.ai-factory/VAULTED_AGENT_INSTRUCTIONS.md`
- Immediate task order confirms this is task #1: "Finish XRPL mint submit diagnostics."
- Existing relevant flow:
  - `crates/desktop-client/ui/src/screens/UploadScreen.tsx` calls `mint_vaulted_nft_locally` with `submit: true`.
  - `crates/desktop-client/src/commands.rs` signs, submits, and returns `VaultedSubmitResponse`.
  - `crates/desktop-client/src/xrpl/client.rs` sends the XRPL `submit` request and parses `engine_result`, `engine_result_message`, and `tx_hash`.
  - `crates/desktop-client/ui/src/utils/formatError.ts` currently maps broad XRPL errors to a generic blockchain failure.

## Likely Files To Change
- `crates/desktop-client/src/xrpl/client.rs`
  - Tighten submit logging to the allow-list only.
  - Remove broad rejected-response logging such as raw `result`.
  - Add or adjust unit tests around submit-result classification/diagnostic extraction if extraction is factored into a pure helper.
- `crates/desktop-client/src/commands.rs`
  - Add command-level diagnostic context for local mint submit: `accepted`, `engine_result`, `engine_result_message`, `tx_hash`, classic address, and metadata URI length.
  - Keep the public `submit_vaulted_xrpl_tx_blob` command from requiring metadata context; use an internal helper or optional diagnostic context for `mint_vaulted_nft_locally`.
  - Ensure non-`tes*` results are returned as `VaultedSubmitResponse`, not collapsed into a generic error before the frontend receives them.
- `crates/desktop-client/ui/src/screens/UploadScreen.tsx`
  - Preserve the typed `VaultedSubmitResponse` path.
  - On `submitted.accepted === false`, surface `engineResult` and `engineResultMessage` in a user-readable failure string without exposing forbidden values.
  - Keep success behavior unchanged.
- `crates/desktop-client/ui/src/utils/formatError.ts`
  - Add explicit mappings for common XRPL engine results before the generic XRPL fallback, for example `tecINSUFF_RESERVE`, `tefPAST_SEQ`, `terQUEUED`, and `actNotFound`.
  - Preserve the raw engine code in safe user-facing text only when useful; do not display raw sensitive payloads.
- `crates/desktop-client/src/oracle/api.rs` only if endpoint status diagnostics are needed during implementation.
  - If changed, log only method/path/status code for Oracle calls, not request or response bodies and not auth headers.

## Tasks

- [x] 1. Sanitize XRPL submit logging
- [x] 2. Add command-level safe mint diagnostics
- [x] 3. Preserve structured rejected-submit response to the UI
- [x] 4. Improve XRPL error mapping
- [x] 5. Verify allow-list compliance

### 1. Sanitize XRPL submit logging
Deliverable:
- In `crates/desktop-client/src/xrpl/client.rs`, keep `XrplClient::submit` logs limited to `engine_result`, `engine_result_message`, `tx_hash`, and accepted/rejected status.
- Remove any broad raw response/result logging from submit rejection paths.

Logging requirements:
- `INFO` for accepted submit.
- `WARN` for rejected submit.
- No raw `result`, `tx_json`, `tx_blob`, request JSON, wallet seed, private key, JWT, AES key, or plaintext content.

Tests:
- Add a pure helper if needed, such as `parse_submit_result`, with unit coverage for accepted and rejected XRPL submit payloads.
- Assert rejected payload extraction preserves `engine_result`, `engine_result_message`, and `tx_hash`.

### 2. Add command-level safe mint diagnostics
Deliverable:
- In `crates/desktop-client/src/commands.rs`, log command-level mint submit result with only:
  - `accepted`
  - `engine_result`
  - `engine_result_message`
  - `tx_hash`
  - classic address
  - metadata URI length
- Keep `submit_vaulted_xrpl_tx_blob` usable as an external command without requiring callers to pass metadata URI.
- Prefer an internal helper for mint flow, for example a private submit function that accepts optional diagnostic context.

Logging requirements:
- `INFO` for command-level submit result.
- `WARN` when accepted submit cannot produce `NFTokenID`.
- No `tx_blob` in logs, errors, or UI.

Tests:
- If the helper is pure or can be factored cleanly, add unit coverage for metadata URI length/address diagnostic context.
- Otherwise keep this task covered by compile checks and the existing submit-response type path.

### 3. Preserve structured rejected-submit response to the UI
Deliverable:
- Verify `VaultedSubmitResponse` remains the frontend contract for non-`tes*` responses.
- In `crates/desktop-client/ui/src/screens/UploadScreen.tsx`, keep the failed submit path based on `submitted.accepted === false` and include `engineResult` plus `engineResultMessage` in the thrown/displayed error.
- Do not include `txBlob` or signed transaction payload data in any thrown error.

Logging requirements:
- No new browser console logs for secret-bearing values.
- UI error text may include engine result and message only.

Tests:
- No UI test harness exists in the repo; verify through TypeScript typecheck and build.

### 4. Improve XRPL error mapping
Deliverable:
- In `crates/desktop-client/ui/src/utils/formatError.ts`, add specific XRPL mappings ahead of the generic `"Blockchain transaction failed"` fallback.
- Include mappings from the agent instructions:
  - `actNotFound` -> wallet not funded
  - `tecINSUFF_RESERVE` -> not enough XRP reserve
  - `tefPAST_SEQ` -> stale/already-used sequence with retry guidance
  - `terQUEUED` -> transaction queued/checking status
  - request timeout -> XRPL connection timeout guidance

Logging requirements:
- This is UI formatting only; no diagnostic logging.
- Do not add sensitive-value interpolation.

Tests:
- If practical, extract a small pure formatter helper and add tests only if the current UI tooling supports it without adding new test infrastructure.
- Otherwise rely on `npm run typecheck` and `npm run build`.

### 5. Verify allow-list compliance
Deliverable:
- Review the changed diff for forbidden logging/display of `tx_blob`, seed, private keys, JWT, AES keys, plaintext files, or mnemonic entropy.
- Run sensitive-log audit.

Logging requirements:
- All new logs must be allow-listed by this plan.

Tests:
- `./scripts/check-sensitive-logs.sh`

## Verification Commands
Run commands separately, not chained.

Rust formatting:
```bash
cargo fmt --all --check
```

Desktop Rust check:
```bash
cargo check -p xrpl-vault-desktop
```

Desktop Rust tests:
```bash
cargo test -p xrpl-vault-desktop
```

Focused XRPL client tests if helper tests are added:
```bash
cargo test -p xrpl-vault-desktop xrpl::client
```

Sensitive log audit:
```bash
./scripts/check-sensitive-logs.sh
```

Frontend lint:
```bash
npm run lint
```
Run from `crates/desktop-client/ui`.

Frontend typecheck:
```bash
npx tsc --noEmit --project tsconfig.json
```
Run from `crates/desktop-client/ui`.

Frontend build:
```bash
npm run build
```
Run from `crates/desktop-client/ui`.

## Manual Runtime Verification
- Start Oracle and storage services if runtime verification is requested.
- Upload a file until the local mint step.
- On mint failure, confirm logs show only allowed diagnostics:
  - `engine_result`
  - `engine_result_message`
  - `tx_hash`
  - `accepted`
  - classic address
  - metadata URI length
  - endpoint status code, if implemented
- Confirm UI shows the XRPL engine result/message instead of only `Blockchain transaction failed`.
- Confirm no log or UI output includes `tx_blob`, seed, private keys, JWT, AES keys, plaintext files, or mnemonic entropy.

## Out Of Scope
- Do not fix the underlying NFTokenMint failure in this task unless the diagnostics change itself reveals a trivial typo that must be corrected to compile.
- Do not alter seed policy, wallet tab, QR login, transfer/re-encryption, storage-node behavior, or Oracle mint authority.
- Do not add external dependencies or fetch external skills.

## Addendum: Safe XRPL Submit Transport Diagnostics

Runtime evidence after commit `316cea7` showed submit starts but no `engine_result` is parsed. This addendum tracks the approved follow-up plan to capture pre-parse transport failures without logging raw request/response JSON, params, `tx_blob`, `tx_json`, seed, private keys, JWT, AES keys, plaintext files, recovery phrase, or mnemonic entropy.

- [x] Add submit-only transport diagnostics with `request_id`, `method="submit"`, `phase`, `transport_error_kind`, safe `transport_error_message`, and `timeout` when applicable.
- [x] Preserve accepted/rejected submit logs with `engine_result`, `engine_result_message`, `tx_hash`, and `accepted`.
- [x] Add focused pure helper tests.
- [x] Run required Rust and sensitive-log checks.

## Addendum: Safe XRPL JSON-RPC Error Fields

Runtime evidence after commit `dbae0bc` showed the submit path receives an XRPL JSON-RPC error response, but only logs `transport_error_message=Unknown`.

- [x] Extract only top-level safe XRPL error response fields: `error`, `error_code`, `error_message`, and `status`.
- [x] Include those fields in the submit-specific `xrpl_error_response` log without raw JSON request/response data, params, `tx_blob`, or `tx_json`.
- [x] Add focused tests for present fields, missing fields, and ignored nested forbidden fields.

## Addendum: Inspect Remaining NFTokenMint Binary Serialization

Runtime evidence after commit `90a8d70` showed AccountID serialization was fixed, but XRPL still rejects the locally signed `NFTokenMint` before producing `engine_result`.

- [x] Inspect remaining `NFTokenMint` binary serialization helpers in `crates/crypto-core/src/xrpl_wallet.rs`.
- [x] Verify field headers for `URI`, `SigningPubKey`, `TxnSignature`, `NFTokenTaxon`, `LastLedgerSequence`, `Fee`, `Flags`, `Sequence`, and `Account`.
- [x] Verify canonical field ordering by type code then field code.
- [x] Verify variable-length encoding for 20-byte AccountID, 33-byte public key, 70-byte DER fixture, and 111-byte URI fixture.
- [x] Add deterministic helper tests for field bytes without logging signed blobs or secret material.

## Addendum: Diagnose invalidTransaction Before Engine Result

Runtime evidence showed XRPL returns `invalidTransaction` before `engine_result`, with no NFTokenMint in `account_tx`.

- [x] Inspect submit request format and local NFTokenMint signing/serialization path.
- [x] Add safe structural diagnostics for transaction type, metadata URI length, account, sequence, fee, last ledger sequence, transaction blob length, and hex validity.
- [x] Add focused tests for transaction blob hex validation.

## Addendum: Fix Local XRPL NFTokenMint Serialization

Serializer inspection found a narrow AccountID encoding defect: the Account field wrote the `0x81` field header directly followed by 20 AccountID bytes, but XRPL AccountID fields require a variable-length prefix (`0x14`) before the 20-byte value.

- [x] Add the AccountID variable-length prefix in the supported XRPL serializer.
- [x] Add regression tests for XRPL field header encoding, AccountID length-prefix encoding, and NFTokenMint binary blob structure.

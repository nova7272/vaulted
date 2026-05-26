# Plan: Send Testnet XRP From Vaulted Wallet
Created: 2026-05-26
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, include focused Rust unit tests and UI type/build checks.
- **Logging:** standard safe diagnostics only: command name, request phase, validation status, amount XRP, fee drops, reserve XRP, engine_result, tx_hash, and status enum.
- **Docs:** no docs changes unless implementation discovers existing wallet docs are directly wrong.
- **Security:** keep signing local. Never log seed phrase, private keys, derived keys, AES keys, JWTs, `tx_blob`, signatures, plaintext files, decrypted content, recovery phrase, mnemonic entropy, or raw restore input.

## Scope
- Add a minimal Send XRP form to the existing Wallet tab for testnet XRP payments from the in-memory Vaulted-derived XRPL wallet.
- Validate destination classic address and numeric amount before signing.
- Validate funded status and spendable balance after reserve plus fee before signing/submission.
- Support optional DestinationTag only if it can be validated and encoded cleanly without widening scope.
- Build, sign, and submit a `Payment` locally through the desktop client using the in-memory Vaulted XRPL wallet.
- Return safe submit result fields to UI: `engine_result`, `engine_result_message`, `tx_hash`.
- Refresh wallet overview and transaction history after successful submit.
- Require explicit UI confirmation before submit.

## Out Of Scope
- NFT mint signing/serialization beyond the minimum serializer refactor needed to avoid breaking existing mint support.
- Oracle post-mint linking/finalization.
- Pending mint recovery.
- Oracle XRPL HTTP RPC config.
- 12-word seed policy.
- Auth restart/logout lifecycle.
- File encryption/decryption.
- Transfer/re-encryption.
- QR login.
- Runtime reset/logout.

## Current Integration Points
- Wallet UI lives in `crates/desktop-client/ui/src/screens/WalletScreen.tsx`, with styles in `crates/desktop-client/ui/src/index.css`.
- Read-only wallet commands already exist in `crates/desktop-client/src/commands.rs`: `get_wallet_overview`, `get_xrpl_transaction_history`, and `check_xrpl_account_status`.
- XRPL network helpers are in `crates/desktop-client/src/xrpl/client.rs`: `account_info`, `fee_drops`, `ledger_current_index`, `submit`, and `SubmitResult`.
- Local signing is in `crates/crypto-core/src/xrpl_wallet.rs`. It currently supports only `NFTokenMint`; `Payment` must be added without regressing mint serialization/signing tests.
- Tauri command registration is in `crates/desktop-client/src/main.rs`.

## Tasks

- [x] 1. Add Payment transaction support in crypto-core
  - Files likely to change:
    - [crates/crypto-core/src/xrpl_wallet.rs](/home/riggle/vaulted/crates/crypto-core/src/xrpl_wallet.rs)
    - [crates/crypto-core/src/lib.rs](/home/riggle/vaulted/crates/crypto-core/src/lib.rs) if a public builder is exported
  - Deliverable: add a small `build_xrp_payment_tx(account, destination, amount_drops, destination_tag)` helper and update `validate_supported_signable_tx` / serialization so `Payment` with XRP drops can be signed by `VaultedXrplWallet::sign_xrpl_transaction_json`.
  - Expected behavior: required fields are `TransactionType=Payment`, `Account`, `Destination`, `Amount` as drops string, `Fee`, `Sequence`, and `LastLedgerSequence`; optional `DestinationTag` is a `u32`.
  - Logging requirements: none in crypto-core.
  - Dependency notes: preserve existing `NFTokenMint` behavior and tests; do not add Tauri, HTTP, or network dependencies to `crypto-core`.

- [x] 2. Add desktop send command with validation and local submit
  - Files likely to change:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/src/main.rs](/home/riggle/vaulted/crates/desktop-client/src/main.rs)
  - Deliverable: add `send_xrp_payment` Tauri command accepting `{ destination, amountXrp, destinationTag? }`, validating input, fetching account/fee/sequence/ledger fields, signing locally, submitting through `XrplClient::submit`, and returning a safe response.
  - Expected behavior:
    - Reject invalid or non-classic destination before network submit.
    - Reject non-numeric, zero, negative, NaN, infinite, or over-precision amount before signing.
    - Reject unfunded accounts.
    - Reject sends where `balance_drops - reserve_drops - fee_drops < amount_drops`.
    - Reject invalid destination tags if supported: non-integer, negative, or greater than `u32::MAX`.
    - Never return or log `tx_blob`, signatures, private keys, or seed material.
  - Logging requirements: log `command=send_xrp_payment`, `request_phase`, validation status, amount XRP, fee drops, reserve XRP, engine_result, tx_hash, and status enum only.
  - Dependency notes: reuse `fetch_xrpl_signing_fields`, `drops_to_xrp_string`, `XrplClient::account_info`, `fee_drops`, `ledger_current_index`, and `submit` patterns. Do not route through Oracle.

- [x] 3. Add Wallet tab send form and explicit confirmation
  - Files likely to change:
    - [crates/desktop-client/ui/src/screens/WalletScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/WalletScreen.tsx)
    - [crates/desktop-client/ui/src/index.css](/home/riggle/vaulted/crates/desktop-client/ui/src/index.css)
  - Deliverable: add a compact Send panel with destination address, XRP amount, optional destination tag, submit button, confirmation state/modal, pending state, validation messages, and safe result display.
  - Expected behavior:
    - Client-side validation mirrors backend basics but backend remains authoritative.
    - Submit requires an explicit confirmation showing destination, amount XRP, fee estimate if available, and reserve/spendable warning.
    - On accepted submit, show `engine_result`, `engine_result_message`, and `tx_hash`, then refresh overview and history.
    - On rejection or validation failure, show safe error text without secret-bearing diagnostics.
  - Logging requirements: no console logging; no signed payload or signature display.
  - Dependency notes: keep existing Receive and History sections intact; do not introduce a landing page or unrelated wallet UI redesign.

- [x] 4. Add focused tests for signing, validation, and parsing
  - Files likely to change:
    - [crates/crypto-core/src/xrpl_wallet.rs](/home/riggle/vaulted/crates/crypto-core/src/xrpl_wallet.rs)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
  - Deliverable: add unit tests for Payment signing serialization and pure validation helpers for amount/destination tag/spendable-balance logic.
  - Expected behavior:
    - `Payment` signing produces a non-empty hex `tx_blob`, 64-char `tx_hash`, and includes `TxnSignature`.
    - mismatched `Account` is rejected for Payment just like mint.
    - amount parsing rejects zero, negatives, malformed strings, too many decimal places, NaN/infinity, and values that cannot fit in drops.
    - spendable check accounts for reserve and fee before amount.
  - Logging requirements: tests must not print or snapshot secret material.
  - Dependency notes: avoid live XRPL in unit tests; runtime network submit is covered by manual checklist.

- [x] 5. Run verification and runtime testnet checklist
  - Files likely to change:
    - none beyond implementation files above
  - Deliverable: run local compile/test/UI/security checks and perform one manual testnet send only with explicit user-controlled testnet funds.
  - Expected behavior: workspace stays green; runtime send returns safe submit result and wallet history updates.
  - Logging requirements: inspect logs for forbidden fields, especially `tx_blob` and signatures.
  - Dependency notes: do not reset runtime state, log out, clear wallets, modify `.env`, or use real/mainnet funds.

## Verification Commands

Run Rust checks:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

Run UI checks:

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
cd ../../..
```

Run security/diff checks:

```bash
./scripts/check-sensitive-logs.sh
git diff --check
```

## Runtime Testnet Send Checklist

- Confirm the active XRPL network is testnet in the Wallet tab.
- Confirm the Vaulted wallet is funded and shows a balance greater than reserve plus expected send amount plus fee.
- Use a testnet destination classic address beginning with `r`.
- If using DestinationTag, use only a non-negative integer within `u32` range.
- Enter a small XRP amount, for example `0.000001` to `1`, depending on faucet balance.
- Click Send, review the explicit confirmation, and submit only after destination and amount match.
- Verify UI shows only safe result fields: `engine_result`, `engine_result_message`, and `tx_hash`.
- Verify overview refreshes and balance changes after successful submit.
- Verify transaction history refreshes and contains a sent `Payment` row with the destination as counterparty.
- Review desktop logs for forbidden values: no seed phrase, private key, derived key, AES key, JWT, `tx_blob`, signature, plaintext, decrypted content, or recovery phrase.

## Expected Successful State
- Wallet tab can send testnet XRP from the local Vaulted-derived XRPL wallet after explicit confirmation.
- Signing and submission remain entirely local to the desktop client.
- Backend validation prevents invalid destination, invalid amount, unfunded account, and insufficient spendable balance.
- The UI shows safe submit results and refreshes balance/history after accepted submit.
- Existing NFT mint behavior remains unchanged.

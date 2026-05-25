# Plan: Add Wallet Tab
Created: 2026-05-25
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, focused desktop Rust tests plus UI lint/type/build
- **Logging:** safe operational diagnostics only: command name, request phase, XRPL network/status, `engine_result`, `tx_hash`, public classic address when necessary, fee/reserve amounts, and HTTP/status codes
- **Docs:** no broad docs work; update README/QUICKSTART only if Wallet tab usage or runtime demo steps are already documented there
- **Security:** never log seed phrase, mnemonic entropy, private keys, derived keys, AES keys, JWTs, plaintext files, `tx_blob`, signatures, decrypted content, or recovery phrase outside the intended backup ceremony

## Roadmap Linkage
- **Milestone:** `VAULTED_AGENT_INSTRUCTIONS.md` immediate next task 6, "Add wallet tab"
- **Rationale:** Items 1-5 in the immediate task list are complete: mint diagnostics/fix, end-to-end mint verification, and 12-word seed policy. Auth lifecycle was also stabilized at the green checkpoint. The next unfinished production-MVP requirement is a dedicated Wallet tab.

## Scope
- Add a dedicated Wallet screen/tab for the Vaulted-derived XRPL wallet.
- Minimal MVP surface:
  - XRP balance from XRPL `account_info`
  - wallet classic address
  - copy address
  - receive QR
- send XRP on testnet is deferred to a separate follow-up task
  - transaction history from XRPL `account_tx`
  - XRPL connection status
  - testnet/mainnet/devnet badge
- Reuse existing local Vaulted XRPL wallet and read-only XRPL query infrastructure.
- Keep all signing local.
- Do not move wallet features out of Settings unless required for navigation clarity; avoid broad Settings refactors.

## Findings
- `VAULTED_AGENT_INSTRUCTIONS.md` section 18 lists `Add wallet tab` as the next item after the completed mint/seed work.
- `VAULTED_AGENT_INSTRUCTIONS.md` section 11 defines Wallet tab MVP requirements: balance, classic address, copy, receive QR, send XRP, transaction history, XRPL connection status, and testnet/mainnet badge.
- There is no `WalletScreen.tsx` under `crates/desktop-client/ui/src/screens`.
- `App.tsx` screen union currently includes `files`, `upload`, `settings`, `activity`, and `secure-notes`, but not `wallet`.
- `Sidebar.tsx` navigation does not include Wallet.
- `SettingsScreen.tsx` contains wallet details and calls `get_xrp_balance`, but this is not a dedicated Wallet tab.
- `get_xrp_balance` in `crates/desktop-client/src/commands.rs` currently returns `"0"` after session check, so balance is not live.
- `check_xrpl_account_status` already returns funded/unfunded status, balance, reserve requirement, network label, and faucet action.
- `get_vaulted_xrpl_wallet` already returns the safe public wallet details needed by the UI.
- `XrplClient` already supports WebSocket `account_info`, `fee`, and `submit`; it has safe submit diagnostics for `engine_result`, `engine_result_message`, and `tx_hash`.
- No first-class transaction-history command was found before this pass. Send-XRP remains intentionally out of scope for this read-only MVP.

## Questions Answered
- **Which roadmap item is next?** Add Wallet tab.
- **Why is it next?** It is the next unfinished item in the immediate task list after completed mint flow and seed-policy work, and it is required by the XRPL Grants MVP checklist before send-XRP and transfer/demo flows can be complete.
- **Is there already a Wallet tab?** No dedicated Wallet tab was found. Wallet information exists in Settings and the top bar only.
- **Does balance load from XRPL today?** `check_xrpl_account_status` can load live balance, but `get_xrp_balance` is currently a stub returning `"0"`.
- **Is send XRP implemented today?** No narrow desktop command for building/signing/submitting a Payment transaction was found.
- **Can this be done without touching XRPL mint/signing serialization?** Yes. This pass adds only read-only XRPL queries and UI.

## Tasks

- [x] 1. Add backend wallet summary and history commands
  - Files likely to change:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/src/main.rs](/home/riggle/vaulted/crates/desktop-client/src/main.rs)
    - [crates/desktop-client/src/xrpl/client.rs](/home/riggle/vaulted/crates/desktop-client/src/xrpl/client.rs) only if reusable `account_tx` support is cleaner there
  - Deliverable: safe commands such as `get_wallet_overview` and `get_xrpl_transaction_history`, or equivalent narrow names following existing command style.
  - Expected behavior: overview returns public classic address, network label, funded/unfunded status, balance XRP if available, reserve requirement, fee hint if available, faucet link for testnet unfunded accounts, and connection status. History returns a compact public list from `account_tx`: tx hash, transaction type, direction, amount XRP when Payment, counterparty, ledger/date/status when available.
  - Logging requirements: log command name, request phase, network/status, public account address only when necessary, and XRPL status/error code. Do not log raw XRPL response bodies if they may include unrelated fields.
  - Dependency notes: reuse `check_xrpl_account_status_inner`, `xrpl_network_label`, `drops_to_xrp_string`, and existing XRPL client patterns where possible.

- [x] 2. Defer local send-XRP command to follow-up
  - Files likely to change:
    - none in this pass
  - Deliverable: no Payment signing/submission code is added in the read-only Wallet MVP.
  - Expected behavior: Wallet tab supports public overview, receive QR, and history only. Send XRP remains a separate follow-up plan/task.
  - Logging requirements: no send-related logging is introduced.
  - Dependency notes: do not change NFT mint signing/serialization, stale-sequence retry logic, or Payment signing.

- [x] 3. Add Wallet screen UI and navigation
  - Files likely to change:
    - [crates/desktop-client/ui/src/App.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/App.tsx)
    - [crates/desktop-client/ui/src/components/Sidebar.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/Sidebar.tsx)
    - [crates/desktop-client/ui/src/screens/WalletScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/WalletScreen.tsx)
    - [crates/desktop-client/ui/src/App.css](/home/riggle/vaulted/crates/desktop-client/ui/src/App.css) or [crates/desktop-client/ui/src/index.css](/home/riggle/vaulted/crates/desktop-client/ui/src/index.css)
    - [crates/desktop-client/ui/src/utils/formatError.ts](/home/riggle/vaulted/crates/desktop-client/ui/src/utils/formatError.ts) if safe XRPL send errors need mapping
  - Deliverable: new Wallet tab in the sidebar and a usable Wallet screen with balance, address copy, receive QR, connection/network badge, and transaction history.
  - Expected behavior: user can view/copy their address, scan a receive QR, refresh balance/history, and see unfunded faucet guidance on testnet.
  - Logging requirements: avoid `console.log`; UI errors should show safe user-facing messages without raw stack traces or secret-bearing payloads.
  - Dependency notes: use existing `QrCode` component; keep UI consistent with current dark operational design; do not add a marketing landing page.

- [x] 4. Add focused tests for wallet behavior
  - Files likely to change:
    - [crates/crypto-core/src/xrpl_wallet.rs](/home/riggle/vaulted/crates/crypto-core/src/xrpl_wallet.rs)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/src/xrpl/client.rs](/home/riggle/vaulted/crates/desktop-client/src/xrpl/client.rs)
  - Deliverable: tests for compact account-history parsing and safe public response shaping where practical.
  - Expected behavior: tests do not hit live XRPL unless existing test patterns already do; prefer pure helpers and parsed fixture JSON.
  - Logging requirements: test output must not include seed phrases, private keys, signed blobs, signatures, or raw secret material.
  - Dependency notes: avoid UI test tooling unless already present; normal TypeScript lint/type/build covers the new Wallet screen.

- [x] 5. Run focused verification and prepare runtime checks
  - Files likely to change:
    - none beyond code/test files above
  - Deliverable: green local checks and a short runtime verification checklist for the implementer to execute with a funded testnet account.
  - Expected behavior: Rust and UI checks pass; sensitive log check remains clean; runtime wallet tab can load status/history and display a receive QR without exposing secrets.
  - Logging requirements: use only allowed diagnostics during runtime verification.
  - Dependency notes: do not push; commit locally only after checks pass in implementation phase.

## Tests To Add Or Update
- `cargo test -p xrpl-vault-desktop`:
  - Parse compact `account_tx` history from representative XRPL JSON.
  - Verify non-Payment rows do not fabricate payment direction or amount.
- UI checks:
  - Existing `npm run lint`, `npx tsc --noEmit --project tsconfig.json`, and `npm run build` should cover the new screen types and imports.

## Verification Commands

Run commands separately:

```bash
cargo fmt --all --check
cargo check -p xrpl-vault-crypto-core
cargo test -p xrpl-vault-crypto-core
cargo check -p xrpl-vault-desktop
cargo test -p xrpl-vault-desktop
```

Run UI checks:

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
cd ../../..
```

Run security and diff checks:

```bash
./scripts/check-sensitive-logs.sh
git diff --check
```

Optional broader green gate:

```bash
cargo check --workspace
cargo test --workspace
```

## Runtime Checks
- Start Oracle/storage/desktop using the existing local dev workflow.
- Restore/unlock the 12-word test wallet; do not create a new wallet unless explicitly testing onboarding.
- Open Wallet tab.
- Confirm network badge matches configured XRPL endpoint.
- Confirm classic address matches the top-bar address.
- Confirm receive QR encodes the classic address only.
- If account is unfunded, confirm balance/status says unfunded and testnet faucet action appears.
- If account is funded, confirm live XRP balance loads from `account_info`.
- Refresh transaction history and confirm recent transactions from `account_tx` appear without raw JSON.
- Confirm logs contain no seed phrase, private keys, derived keys, JWTs, `tx_blob`, signatures, plaintext, decrypted content, or recovery phrase.

## Out Of Scope
- XRPL mint signing/serialization.
- Oracle post-mint linking/finalization.
- Pending mint recovery.
- Oracle XRPL HTTP RPC config.
- 12-word seed policy.
- Auth restart/logout lifecycle.
- File encryption/decryption.
- Transfer/re-encryption.
- QR login implementation.
- Runtime reset/logout behavior.
- Send XRP / Payment signing and submission.
- Mainnet production send policy beyond displaying the network badge and validating the configured endpoint.

## Expected Successful State
- Sidebar contains a Wallet tab.
- Wallet tab shows live XRPL account status, balance, classic address, receive QR, and network badge.
- Wallet tab shows live XRPL account status, balance, classic address, receive QR, network badge, and transaction history refresh.
- No secret material is logged, persisted, or displayed outside intended UI surfaces.

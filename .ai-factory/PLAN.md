# Plan: Complete Transfer And Recipient Decrypt
Created: 2026-05-27
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes. Add focused Rust tests for XRPL transfer signing support and any pure Oracle/desktop helpers; run UI lint/typecheck/build if `FilesScreen.tsx` changes.
- **Logging:** standard, security-safe diagnostics only. Allowed: command name, phase, NFT token id, transfer id, offer index, tx hash, engine result/message, accepted boolean, endpoint status, byte counts. Forbidden: seed phrase, mnemonic entropy, private keys, derived keys, AES keys, JWTs, storage tokens, `tx_blob`, signatures, plaintext files, decrypted content, recovery phrase, QR payloads, QR approval signatures, raw encrypted key material, tokenized URLs, raw storage keys.
- **Docs:** no docs changes in the implementation task; update `docs/RUNTIME_VERIFICATION.md` later when the full runtime milestone is proven.
- **Roadmap linkage:** `VAULTED_AGENT_INSTRUCTIONS.md` section 18, item 8: `Complete transfer/re-encryption`.

## Next Roadmap Item
- **Next item:** Complete transfer/re-encryption.
- **Why it is next:** The user-provided completed checkpoints cover immediate tasks 1-7 plus owner download/decrypt. In `VAULTED_AGENT_INSTRUCTIONS.md`, the next unfinished production-MVP task is item 8. It also maps directly to the remaining XRPL Grants checklist items: `Transfer NFT/file access to another user works` and `Recipient decrypts after re-encryption`.

## Current Findings
- The Oracle transfer API exists in [crates/oracle/src/api/transfers.rs](/home/riggle/vaulted/crates/oracle/src/api/transfers.rs), including initiate, confirm-signed, incoming, complete, history, and cancel routes.
- Desktop transfer commands exist in [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs), but `create_transfer_offer`, `wait_for_transfer_offer`, `claim_nft`, and `wait_for_claim` are disabled legacy external-wallet placeholders.
- UI transfer/claim buttons in [crates/desktop-client/ui/src/screens/FilesScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/FilesScreen.tsx) currently show `Local XRPL ... signing is not implemented yet`.
- `crypto-core` local XRPL signing currently supports `NFTokenMint` and `Payment` only in [crates/crypto-core/src/xrpl_wallet.rs](/home/riggle/vaulted/crates/crypto-core/src/xrpl_wallet.rs), so it must add `NFTokenCreateOffer` and `NFTokenAcceptOffer` before desktop can submit transfer transactions locally.
- Owner/grant decrypt infrastructure exists; keep the completed owner download path intact and use it only as a reference for recipient decrypt verification.

## Likely Files To Inspect/Change
- [crates/crypto-core/src/xrpl_wallet.rs](/home/riggle/vaulted/crates/crypto-core/src/xrpl_wallet.rs): add validation/serialization tests for `NFTokenCreateOffer` and `NFTokenAcceptOffer`.
- [crates/desktop-client/src/xrpl/nft.rs](/home/riggle/vaulted/crates/desktop-client/src/xrpl/nft.rs): reuse or adjust transaction builders for create/accept offer JSON.
- [crates/desktop-client/src/xrpl/client.rs](/home/riggle/vaulted/crates/desktop-client/src/xrpl/client.rs): inspect existing account info/fee/submit helpers and offer-index derivation needs.
- [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs): implement local offer create/submit, recipient accept/submit, Oracle confirm/complete, and safe command-level status responses.
- [crates/desktop-client/src/oracle/api.rs](/home/riggle/vaulted/crates/desktop-client/src/oracle/api.rs): add typed clients for transfer `confirm-signed`, incoming transfers, by-offer/by-nft, and finalize if needed.
- [crates/oracle/src/api/transfers.rs](/home/riggle/vaulted/crates/oracle/src/api/transfers.rs): inspect status transitions for pending/transferring/completed/finalized ambiguity; minimally fix only if local transfer flow cannot complete reliably.
- [crates/oracle/src/models.rs](/home/riggle/vaulted/crates/oracle/src/models.rs): inspect transfer request/response models if typed client gaps require model changes.
- [crates/oracle/src/api/mod.rs](/home/riggle/vaulted/crates/oracle/src/api/mod.rs): inspect routes only if client paths do not match mounted API.
- [crates/desktop-client/ui/src/screens/FilesScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/FilesScreen.tsx): replace placeholder transfer/claim UX with local-signing progress, errors, and refresh behavior.

## Tasks

- [x] 1. Add local XRPL signing support for NFT offer transactions
  - Deliverable: `VaultedXrplWallet::sign_xrpl_transaction_json` accepts `NFTokenCreateOffer` and `NFTokenAcceptOffer` with required fields and common signing fields.
  - Expected behavior: signed blobs are submission-ready through the same XRPL submit path used by mint/payment.
  - Logging: no secret logs; tests must not print `tx_blob` or signatures.
  - Dependencies: required before desktop transfer commands can move off legacy placeholders.

- [x] 2. Implement desktop owner transfer offer creation/submission
  - Deliverable: `initiate_transfer` creates recipient re-encryption data, builds a zero-amount destination sell offer, signs locally, submits to XRPL, derives or fetches the offer index, and calls Oracle `confirm-signed`.
  - Expected behavior: owner sees concrete success/failure, and recipient incoming offers list refreshes after successful offer creation.
  - Logging: safe phase logs with NFT id, transfer id, destination address, tx hash, engine result/message, accepted; never log `tx_blob`, keys, JWTs, or raw re-encryption material.
  - Dependencies: depends on task 1 and existing `generate_transfer_key`.

- [x] 3. Implement recipient NFT accept/claim and Oracle finalization
  - Deliverable: recipient claim flow signs/submits `NFTokenAcceptOffer`, confirms ledger submission, then calls Oracle `complete_transfer` with transfer id and tx hash.
  - Expected behavior: Oracle owner changes to recipient, re-encrypted AES key is active, transfer history updates, and incoming offer disappears or becomes completed.
  - Logging: safe claim phase logs with offer index, transfer id, tx hash, engine result/message; no signatures, `tx_blob`, keys, or decrypted content.
  - Dependencies: depends on tasks 1-2.

- [ ] 4. Wire UI transfer and claim flows to local commands
  - Deliverable: remove the “not implemented yet” transfer/claim placeholders in `FilesScreen.tsx`; show processing, submitted, accepted, and failed states with actionable messages.
  - Expected behavior: owner can start transfer from a minted vault NFT; recipient can accept an incoming offer; lists refresh after each success.
  - Logging: UI must not render raw stack traces, `tx_blob`, signatures, key material, QR payloads, or plaintext/decrypted content.
  - Dependencies: depends on tasks 2-3.

- [ ] 5. Verify recipient decrypt after transfer
  - Deliverable: after transfer completion, recipient can download/decrypt the transferred/shared file through the existing recipient grant or transferred-owner path, with old owner access behavior explicitly observed.
  - Expected behavior: recipient output file decrypts successfully; Oracle/storage/desktop logs remain free of forbidden values.
  - Logging: safe download/decrypt phases only; no tokenized URLs, storage tokens, AES keys, plaintext, or output content.
  - Dependencies: depends on task 3 and completed owner download/decrypt path.

- [ ] 6. Add focused tests and run gates
  - Deliverable: tests for XRPL offer transaction signing plus any helper/status mapping added during implementation.
  - Expected behavior: Rust workspace and frontend checks pass for touched areas.
  - Logging: tests do not print or snapshot secrets, transaction blobs, signatures, key material, or plaintext.
  - Dependencies: final verification task.

## Tests To Add/Update
- `crates/crypto-core/src/xrpl_wallet.rs`
  - `signs_nftoken_create_offer_as_xrpl_tx_blob`
  - `signs_nftoken_accept_offer_as_xrpl_tx_blob`
  - rejects missing `NFTokenID` / `Amount` / `NFTokenSellOffer`
  - rejects mismatched `Account`
- `crates/desktop-client/src/commands.rs`
  - focused pure-helper tests only if new offer-index, status, or error mapping helpers are extracted.
- `crates/oracle/src/api/transfers.rs`
  - add narrow tests only if status transition logic is changed.
- `crates/desktop-client/ui/src/screens/FilesScreen.tsx`
  - no new UI test harness required; verify through lint/typecheck/build and runtime.

## Verification Commands
Rust:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
./scripts/check-sensitive-logs.sh
git diff --check
```

Frontend, if UI changes:

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
npm audit --audit-level=high
cd ../../..
```

Narrow checks during implementation:

```bash
cargo test -p xrpl-vault-crypto-core xrpl_wallet
cargo check -p xrpl-vault-desktop
cargo check -p xrpl-vault-oracle
```

## Runtime Checks
- Start Postgres/Redis, Oracle, storage-node, and desktop using existing dev workflow; do not reset runtime state or modify `.env`.
- Use two registered Vaulted identities/wallets with funded XRPL testnet accounts.
- Owner uploads/mints or uses an already active minted vault object.
- Owner starts transfer to recipient wallet address.
- Confirm XRPL `NFTokenCreateOffer` succeeds and returns safe diagnostics.
- Confirm Oracle transfer status becomes ready for recipient claim and incoming transfer appears for recipient.
- Recipient accepts the offer; confirm XRPL `NFTokenAcceptOffer` succeeds.
- Confirm Oracle owner/final transfer state updates and by-NFT lookup remains valid.
- Confirm `account_nfts` shows the NFT under recipient account after claim.
- Recipient downloads/decrypts the file successfully.
- Inspect desktop/Oracle/storage logs for forbidden values, especially `tx_blob`, signatures, JWTs, AES/file keys, plaintext/decrypted content, storage tokens, tokenized URLs, QR payloads, and raw encrypted key material.

## Out Of Scope
- XRPL mint signing/serialization.
- Oracle post-mint linking/finalization.
- Pending mint recovery.
- Oracle XRPL HTTP RPC configuration.
- 12-word seed policy.
- Auth restart/logout lifecycle.
- Desktop launch/window fallback.
- Wallet tab and Send XRP / Payment command.
- QR login flow.
- Owner download/decrypt path changes except inspection/reference.
- Broad UI polish for the XRPL Grants demo.
- Runtime verification doc/README updates.
- Mobile app implementation.
- `git push`, runtime reset/logout, clearing app data, deleting user data, or `.env` changes.

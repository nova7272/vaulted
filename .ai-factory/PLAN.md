# Plan: Complete Demo-Safe QR Login Flow
Created: 2026-05-26
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, include focused Oracle/desktop QR login tests and UI lint/type/build checks.
- **Logging:** standard safe diagnostics only: command name, request phase, QR request id, status enum, identity id, device id, expiration status, and endpoint status. Do not log QR approval signatures or tokens.
- **Docs:** no docs changes unless implementation discovers existing QR login docs are directly wrong.
- **Security:** never log or display seed phrase, mnemonic entropy, private keys, derived keys, AES keys, JWTs, `tx_blob`, signatures, plaintext files, decrypted content, recovery phrase, or raw restore input outside the existing seed backup ceremony.

## Next Roadmap Item
- **Next item:** QR login works or has a clearly implemented demo-safe QR flow.
- **Source:** `.ai-factory/VAULTED_AGENT_INSTRUCTIONS.md` section 10, and the XRPL Grants MVP checklist item: `QR login works or demo-safe QR flow is clearly implemented`.
- **Why this is next:** The Wallet tab requirements are now satisfied through balance, receive QR, history, and runtime-tested Send XRP. The remaining checklist still requires QR login before moving deeper into the full file-vault transfer/re-encryption flow. Current code has backend/desktop QR login primitives, but the locked Auth screen only exposes Create and Restore, and the existing Oracle login modal displays raw JSON rather than a user-ready QR/login flow.

## Scope
- Add QR login as the third primary Auth screen action alongside Restore and Create.
- Reuse existing `start_vaulted_qr_login`, `poll_vaulted_qr_login`, and `confirm_vaulted_qr_login` primitives where possible.
- Make the QR login UI demo-safe:
  - show a scannable QR payload instead of only raw JSON;
  - show expiration state/timer;
  - provide retry and cancel;
  - provide copy payload for demos where scanning is unavailable;
  - surface clear safe errors.
- Add an unlocked trusted-device approval UI that can paste/parse a QR login payload and call the local approval command, so the demo can complete without a separate mobile app.
- Make Oracle QR login replay and expiry behavior explicit in tests.
- Keep seed-based restore as the only way to unlock local encrypted file access on the same desktop after restart unless a trusted unlocked device approves QR login.

## Important Constraint
QR login must not imply that Oracle can reconstruct local encryption identity or file keys. If the approved QR login only establishes an Oracle session and the local Vaulted seed identity is not present, the UI must clearly keep local vault/decrypt actions locked or label the flow as trusted-device Oracle login. Do not create a fake seedless local decrypt path.

## Current Integration Points
- Auth entry screen:
  - [crates/desktop-client/ui/src/screens/AuthScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/AuthScreen.tsx)
- Existing QR login modal:
  - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
- Existing QR code component:
  - [crates/desktop-client/ui/src/components/QrCode.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/QrCode.tsx)
- Desktop QR commands:
  - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
- Tauri command registration:
  - [crates/desktop-client/src/main.rs](/home/riggle/vaulted/crates/desktop-client/src/main.rs)
- Oracle QR endpoints and tests:
  - [crates/oracle/src/api/qr_auth.rs](/home/riggle/vaulted/crates/oracle/src/api/qr_auth.rs)
- QR login schema:
  - [migrations/011_qr_login_and_vaulted_wallet.sql](/home/riggle/vaulted/migrations/011_qr_login_and_vaulted_wallet.sql)

## Tasks

- [x] 1. Confirm QR login behavior boundary and response shape
  - Files likely to inspect/change:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/src/auth/session.rs](/home/riggle/vaulted/crates/desktop-client/src/auth/session.rs)
    - [crates/oracle/src/api/qr_auth.rs](/home/riggle/vaulted/crates/oracle/src/api/qr_auth.rs)
  - Deliverable: define the exact QR-login result semantics for the desktop UI: approved Oracle session, identity id, status, expiration, and whether local Vaulted identity is present.
  - Expected behavior: no UI or command should claim local decrypt/unlock if the in-memory seed identity is absent.
  - Logging requirements: log only request phase, login request id, status enum, identity id, and expiration status.
  - Dependency notes: do not alter auth restart/logout lifecycle or seed persistence policy.

- [x] 2. Add QR login entry point to Auth screen
  - Files likely to change:
    - [crates/desktop-client/ui/src/screens/AuthScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/AuthScreen.tsx)
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
    - [crates/desktop-client/ui/src/App.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/App.tsx) if the modal must be owned above `AuthScreen`
    - [crates/desktop-client/ui/src/index.css](/home/riggle/vaulted/crates/desktop-client/ui/src/index.css)
  - Deliverable: Auth screen shows three primary actions: Sign in with seed phrase, Sign in with QR code, Create new wallet.
  - Expected behavior: QR login starts from the locked screen, shows QR payload, expiration timer, retry, cancel, and safe result/error states.
  - Logging requirements: no `console.log`/`console.error` for QR payloads, errors, tokens, or signatures.
  - Dependency notes: preserve the existing seed backup ceremony and restore validation.

- [x] 3. Replace raw QR payload display with scannable and copyable demo-safe UI
  - Files likely to change:
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
    - [crates/desktop-client/ui/src/components/QrCode.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/QrCode.tsx)
    - [crates/desktop-client/ui/src/index.css](/home/riggle/vaulted/crates/desktop-client/ui/src/index.css)
  - Deliverable: render a QR code for the compact login payload and keep copy payload as an explicit fallback.
  - Expected behavior: user can scan or copy the payload; UI avoids showing tokens, signatures, or seed material; expiration is visible.
  - Logging requirements: no frontend logging of payload contents.
  - Dependency notes: do not introduce network dependencies or new QR libraries unless existing `QrCode` cannot encode the payload.

- [x] 4. Add trusted-device approval UI for demos
  - Files likely to change:
    - [crates/desktop-client/ui/src/screens/SettingsScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/SettingsScreen.tsx)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs) if a payload-parsing approval helper is needed
    - [crates/desktop-client/src/main.rs](/home/riggle/vaulted/crates/desktop-client/src/main.rs) only if adding a new Tauri command
  - Deliverable: an unlocked Vaulted device can paste a QR login payload, review safe request details, and approve it with local Vaulted identity signing.
  - Expected behavior: approval uses `confirm_vaulted_qr_login`; signatures stay local and are not displayed; malformed, expired, or wrong-shape payloads show safe errors.
  - Logging requirements: command name, request phase, login request id, validation status, identity id, device id, status enum only.
  - Dependency notes: keep this as a demo-safe bridge, not a mobile app implementation.

- [x] 5. Add focused QR login tests
  - Files likely to change:
    - [crates/oracle/src/api/qr_auth.rs](/home/riggle/vaulted/crates/oracle/src/api/qr_auth.rs)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs) if new parsing helpers are added
  - Deliverable: tests for expired QR rejected, replay/consumed QR rejected, invalid signature rejected, and payload parsing validation if added.
  - Expected behavior: existing QR/device-pairing tests continue passing; new tests do not log or snapshot tokens/signatures.
  - Logging requirements: none in tests beyond default test output.
  - Dependency notes: avoid live Oracle/XRPL network in unit tests.

- [ ] 6. Run verification and runtime QR login checklist
  - Files likely to change:
    - none beyond implementation files above
  - Deliverable: local checks plus a manual runtime QR login demo using one locked desktop flow and one unlocked trusted-device approval flow.
  - Expected behavior: QR login reaches approved/consumed state once, retry works after expiration, replay is rejected, and no forbidden values appear in logs/UI.
  - Logging requirements: inspect logs for tokens, signatures, seed phrase, private keys, AES keys, and plaintext.
  - Dependency notes: do not reset runtime state, log out, clear wallets, modify `.env`, or change seed policy.

## Tests To Add Or Update
- Oracle QR login tests:
  - expired login request cannot be approved;
  - consumed/approved login request cannot be replayed;
  - invalid signature is rejected;
  - status polling consumes an approved request exactly once.
- Desktop command tests, only if adding pure parsing helpers:
  - valid QR login payload parses to request id/challenge/oracle URL;
  - malformed payloads are rejected safely;
  - missing challenge/request id is rejected.
- UI verification:
  - `npm run lint`;
  - `npx tsc --noEmit --project tsconfig.json`;
  - `npm run build`.

## Verification Commands

Run Rust checks:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

Run targeted checks while iterating:

```bash
cargo test -p xrpl-vault-oracle qr
cargo test -p xrpl-vault-desktop qr
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

## Runtime Checks
- Start Postgres/Redis, Oracle, storage-node, and desktop using the existing project commands.
- On a locked desktop Auth screen, select Sign in with QR code.
- Confirm a QR code renders, expiration is visible, and retry/cancel work.
- On an unlocked trusted Vaulted device/session, paste or scan the QR login payload and approve.
- Confirm the locked desktop observes `approved` then `consumed` and enters the intended authenticated state.
- Poll or reuse the same QR login id again and confirm replay is rejected or remains consumed.
- Let a QR request expire and confirm UI shows expired with retry.
- Review logs and UI for forbidden values: no seed phrase, mnemonic entropy, private keys, derived keys, AES keys, JWTs, `tx_blob`, signatures, plaintext files, decrypted content, recovery phrase, or raw restore input.

## Out Of Scope
- XRPL mint signing/serialization.
- Oracle post-mint linking/finalization.
- Pending mint recovery.
- Oracle XRPL HTTP RPC config.
- 12-word seed policy.
- Auth restart/logout lifecycle.
- Desktop launch/window fallback.
- Read-only Wallet tab.
- Send XRP / Payment command.
- File upload/mint flow changes.
- Owner download/decrypt changes.
- NFT transfer/re-encryption and recipient decrypt.
- Mobile app implementation.
- Runtime reset/logout or clearing local data.
- README/demo script updates unless the QR flow directly needs a short command note.

## Expected Successful State
- The Auth screen exposes the required three actions.
- QR login is demonstrably usable in a demo-safe flow with an unlocked trusted Vaulted device approving a locked desktop login request.
- QR login has explicit expiration, retry, cancel, and replay protections.
- No secret-bearing material is logged, returned, or displayed.

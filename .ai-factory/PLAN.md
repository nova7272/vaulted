# Plan: Verify Login Logout Restart Behavior
Created: 2026-05-25
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, focused desktop Rust and UI checks
- **Logging:** diagnostics are allow-list only: `auth_state`, command name, `wallet_exists`, `identity_exists`, locked/unlocked status, `validation_status`, and error code/status
- **Docs:** no broad docs work; update only user-facing auth copy if behavior changes
- **Security:** never log seed phrase, mnemonic entropy, private key, derived keys, AES keys, JWTs, plaintext files, `tx_blob`, signatures, decrypted content, or recovery phrase outside the intended backup ceremony

## Roadmap Linkage
- **Milestone:** `VAULTED_AGENT_INSTRUCTIONS.md` next task, "Verify login/logout/restart behavior"
- **Rationale:** XRPL mint/finalize/linking and strict 12-word seed policy are complete; auth/session lifecycle is the next MVP stability gate.

## Scope
- Verify and minimally fix auth/session behavior across fresh start, wallet creation, restore from 12-word seed, app restart, logout/lock, and unlock after restart.
- Preserve the current security boundary: seed-derived identity, XRPL wallet, and PRE keypair stay local and are not sent to Oracle.
- Do not implement seed persistence unless runtime/code evidence proves it is already an intended local secure-storage path; the safer expected restart behavior is locked until the user restores/unlocks with the 12-word phrase.
- Do not touch XRPL signing/serialization, Oracle finalize/linking, file encryption/decryption, transfer/re-encryption, QR login implementation, Wallet tab, or destructive reset/logout behavior except where explicitly identified by this plan.

## Findings
- [crates/desktop-client/src/state.rs](/home/riggle/vaulted/crates/desktop-client/src/state.rs:74) stores `Session`, legacy PRE keypair, Vaulted identity, and XRPL wallet in `RwLock<Option<...>>` memory fields.
- [crates/desktop-client/src/state.rs](/home/riggle/vaulted/crates/desktop-client/src/state.rs:100) initializes all auth/session fields to `None` on app startup.
- [crates/desktop-client/src/state.rs](/home/riggle/vaulted/crates/desktop-client/src/state.rs:117) persists only a device fingerprint file; it is not a wallet/identity persistence mechanism.
- [crates/desktop-client/src/state.rs](/home/riggle/vaulted/crates/desktop-client/src/state.rs:234) `clear_session` clears session, legacy PRE keypair, Vaulted identity, and XRPL wallet from memory only.
- [crates/desktop-client/src/state.rs](/home/riggle/vaulted/crates/desktop-client/src/state.rs:281) `init_vaulted_identity_from_mnemonic` derives Vaulted identity, XRPL wallet, and legacy PRE keypair from the provided mnemonic and stores them in memory.
- [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs:56) `create_vaulted_wallet` generates the 12-word phrase, unlocks identity/wallet in memory, sets a session, and returns the mnemonic only for the backup ceremony.
- [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs:81) `restore_vaulted_wallet` validates/restores from a 12-word phrase, unlocks identity/wallet in memory, and sets a session without returning the mnemonic.
- [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs:1754) `logout` calls `clear_session`; no file deletion is visible there.
- [crates/desktop-client/src/storage/keystore.rs](/home/riggle/vaulted/crates/desktop-client/src/storage/keystore.rs:131) has legacy encrypted seed/PRE keypair storage helpers, but current Vaulted seed create/restore flow does not appear to call `Keystore::save_seed` or `load_keypair`.
- [crates/desktop-client/ui/src/App.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/App.tsx:99) startup checks only `is_authenticated`; after a process restart this returns false because the session is memory-only.
- [crates/desktop-client/ui/src/App.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/App.tsx:111) logout calls `oracle_logout` and `logout`, then returns to Auth UI.
- [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs:4492) Oracle auth status can force `state.clear_session()` and page reload after prior Oracle authentication failure; this is memory-only but should be included in lifecycle tests.
- [crates/desktop-client/src/state.rs](/home/riggle/vaulted/crates/desktop-client/src/state.rs:653) token refresh errors may include response body; implementation should verify this cannot leak JWT/refresh token material into logs.

## Questions Answered
- **After create wallet, what is persisted?** Based on inspected code, only the device fingerprint is persisted. The Vaulted identity, XRPL wallet, PRE keypair, and session are memory-only. The seed phrase is displayed only in the backup ceremony and is not saved by the current create/restore path.
- **After restart, how does app decide whether wallet exists, locked, or authenticated?** `App.tsx` calls `is_authenticated`, which checks only the in-memory session. Because startup initializes session/identity/wallet to `None`, restart appears as unauthenticated/locked and shows Auth UI.
- **Does restore from a valid 12-word phrase recreate the same Vaulted identity/wallet address?** Crypto-core already has separate deterministic identity and wallet tests. Add one focused test that derives both identity and XRPL wallet twice from the same generated 12-word phrase to prove the binding is stable across restore.
- **Does logout mean lock session or destructive reset?** Current `logout` clears memory-only session, identity, XRPL wallet, and PRE keypair. It does not call keystore deletion or delete user data. The UI label says "Sign out"; plan should clarify this as a non-destructive lock/sign-out.
- **Are seed/private keys ever logged, stored in plaintext, or shown outside backup/restore?** No direct seed/private-key logging was found in create/restore paths. Existing auth/token refresh logs need a targeted audit to ensure JWT/refresh-token response bodies are not logged. The seed phrase appears in UI only during create backup and restore input.
- **Is there any path that accidentally deletes identity/runtime state?** `logout` and Oracle-session-expiry clear runtime memory state. No destructive identity/file deletion is visible in those paths. `Keystore::delete_keypair` exists but is not wired to logout.
- **What exact files need minimal changes?** Likely `crates/desktop-client/src/state.rs`, `crates/desktop-client/src/commands.rs`, `crates/desktop-client/src/auth/session.rs` for tests/helper state, `crates/desktop-client/ui/src/App.tsx`, `crates/desktop-client/ui/src/screens/AuthScreen.tsx`, and `crates/desktop-client/ui/src/utils/formatError.ts` only if copy/error behavior needs clarity.

## Tasks

- [x] 1. Add a safe auth lifecycle status surface
  - Files likely to change:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/src/main.rs](/home/riggle/vaulted/crates/desktop-client/src/main.rs)
    - [crates/desktop-client/src/state.rs](/home/riggle/vaulted/crates/desktop-client/src/state.rs) only if helper methods are needed
  - Deliverable: a narrow command such as `get_auth_lifecycle_status` returning only safe fields: `auth_state`, `wallet_exists`, `identity_exists`, `session_exists`, `locked`, and optional error/status code.
  - Expected behavior: fresh start reports locked/no in-memory wallet; create/restore reports unlocked; logout reports locked; no seed, private key, JWT, address, or public key is required in this status payload.
  - Logging requirements: no logs by default; if diagnostics are added, log command name, `auth_state`, booleans, locked/unlocked status, and validation status only.
  - Dependency notes: do not persist seeds, change derivation, or alter QR login.

- [x] 2. Make startup/locked behavior explicit in UI
  - Files likely to change:
    - [crates/desktop-client/ui/src/App.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/App.tsx)
    - [crates/desktop-client/ui/src/screens/AuthScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/AuthScreen.tsx)
    - [crates/desktop-client/ui/src/utils/formatError.ts](/home/riggle/vaulted/crates/desktop-client/ui/src/utils/formatError.ts) only if safe error text needs mapping
  - Deliverable: app startup distinguishes "unlocked authenticated session" from "locked, restore with 12-word phrase" without implying destructive reset or lost wallet.
  - Expected behavior: after restart, Auth UI guides the user to restore/unlock the same Vaulted wallet with the 12-word phrase; it must not offer reset/logout/clear-data as the recovery path.
  - Logging requirements: no `console.log` for auth state; `console.error` must not include seed phrases, JWTs, or pasted restore text.
  - Dependency notes: keep Auth screen backup ceremony unchanged and do not touch QR login implementation.

- [x] 3. Clarify logout as non-destructive lock/sign-out
  - Files likely to change:
    - [crates/desktop-client/src/state.rs](/home/riggle/vaulted/crates/desktop-client/src/state.rs)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/ui/src/App.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/App.tsx)
  - Deliverable: `logout`/sign-out behavior is verified to clear only memory session and unlocked keys, not user data, seed material on disk, Oracle vault state, files, or identity binding.
  - Expected behavior: logout returns to Auth UI; restoring the same 12-word phrase reopens the same identity/wallet binding.
  - Logging requirements: if the logout log is adjusted, use safe wording like `auth_state=locked`, `wallet_exists=false`, `identity_exists=false`; do not log wallet address unless necessary.
  - Dependency notes: do not call `Keystore::delete_keypair`, remove files, reset local app data, or alter runtime upload/mint state.

- [x] 4. Add focused deterministic restore and session lifecycle tests
  - Files likely to change:
    - [crates/crypto-core/src/identity.rs](/home/riggle/vaulted/crates/crypto-core/src/identity.rs)
    - [crates/crypto-core/src/xrpl_wallet.rs](/home/riggle/vaulted/crates/crypto-core/src/xrpl_wallet.rs)
    - [crates/desktop-client/src/state.rs](/home/riggle/vaulted/crates/desktop-client/src/state.rs)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
  - Deliverable: tests prove a generated 12-word phrase derives the same Vaulted identity id and XRPL classic address after restore; `AppState::new` starts locked; `init_vaulted_identity_from_mnemonic` unlocks; `clear_session` locks and removes in-memory identity/wallet without deleting persisted device fingerprint.
  - Expected behavior: tests never print or snapshot the mnemonic; they only compare derived public identifiers in memory.
  - Logging requirements: no test output containing seed words, entropy, private keys, JWTs, decrypted data, or plaintext files.
  - Dependency notes: keep tests local to crypto-core/desktop; avoid Tauri UI automation unless needed.

- [x] 5. Audit and sanitize auth/session logs and errors
  - Files likely to change:
    - [crates/desktop-client/src/state.rs](/home/riggle/vaulted/crates/desktop-client/src/state.rs)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/ui/src/App.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/App.tsx)
    - [crates/desktop-client/ui/src/contexts/OracleAuthContext.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/contexts/OracleAuthContext.tsx) only if console diagnostics are unsafe
  - Deliverable: no auth lifecycle log/error path prints seed, recovery phrase, private key, JWT/access token, refresh token, tx blob, decrypted content, or raw restore input.
  - Expected behavior: token refresh failures expose only status/error code or generic status; restore validation errors do not echo the submitted mnemonic.
  - Logging requirements: allowed diagnostics only: `auth_state`, command name, booleans, locked/unlocked status, validation status, and error code/status.
  - Dependency notes: do not broaden logging to include wallet addresses unless already public and necessary.

## Manual Runtime Test Matrix

Run in a local dev session without resetting app data unless explicitly approved.

| Scenario | Steps | Expected State | Security Checks |
| --- | --- | --- | --- |
| Fresh app start | Start desktop with no active in-memory session | Auth UI appears; auth lifecycle status is locked; no destructive reset prompt | Logs contain no seed/private/JWT/plaintext |
| Create wallet | Click Create wallet, save 12-word phrase offline, check confirmation, continue | App enters Files; wallet/identity/session report unlocked | Seed phrase shown only in backup ceremony |
| Restart after create | Close and restart app | App returns to Auth/locked; it does not claim wallet is deleted | No seed/private data logged; no reset/logout suggestion |
| Restore same wallet | Restore using the saved 12-word phrase | App enters Files; derived identity/wallet binding matches prior create evidence | Restore input is not logged or displayed after submit |
| Logout/sign out | Click sign-out button | App returns to Auth/locked; memory identity/wallet/session cleared | No data files deleted; no seed/private data logged |
| Unlock after logout | Restore same 12-word phrase again | Same identity/wallet binding is restored | No plaintext/secret leakage |
| Oracle token expiry path | If reachable, let Oracle auth expire or simulate failed refresh | Only session memory is locked/cleared; user data remains | Refresh errors do not print access/refresh tokens or response secrets |

## Verification Commands

Run commands separately:

```bash
cargo fmt --all --check
cargo check -p xrpl-vault-crypto-core
cargo test -p xrpl-vault-crypto-core
cargo check -p xrpl-vault-desktop
cargo test -p xrpl-vault-desktop
```

Run UI checks if `App.tsx`, `AuthScreen.tsx`, or related frontend files change:

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

Optional broader check if auth/session changes have wider impact:

```bash
cargo test --workspace
```

## Expected Successful State
- Fresh start and app restart are clearly treated as locked/unauthenticated, not destructive reset or lost wallet.
- Wallet creation unlocks an in-memory session and shows the 12-word phrase only during the backup ceremony.
- Restore from the same 12-word phrase recreates the same Vaulted identity and XRPL wallet binding.
- Logout/sign-out clears only in-memory session and unlocked keys.
- No seed phrase, mnemonic entropy, private key, derived secret, JWT, plaintext file, `tx_blob`, signature, decrypted content, or restore phrase is logged or displayed outside the intended UI flow.

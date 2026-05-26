# Plan: Fix QR Login Poll Lifecycle After Approval
Created: 2026-05-26
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, include focused UI lint/type/build checks; run desktop Rust checks only if `poll_vaulted_qr_login` response handling or logs change.
- **Logging:** add only safe QR lifecycle diagnostics: UI step, command name, QR request id, status enum, poll token id, mounted/open boolean, expiry status, and cancellation reason. Do not log QR payload contents, challenge, approval signatures, tokens, seed phrases, private keys, JWTs, AES keys, `tx_blob`, plaintext, decrypted content, or recovery phrase.
- **Docs:** no docs changes.
- **Scope:** minimal diagnosis and fix for the locked QR modal failing to observe `approved` or `consumed` after a trusted device approval.

## Runtime Evidence
- QR start reaches Oracle.
- QR polling runs at the rate-limit-safe cadence and returns `pending`.
- Trusted-device approval reaches Oracle and desktop logs `confirm_vaulted_qr_login phase=result approved=true status=approved`.
- The locked QR modal poller does not later log `poll_vaulted_qr_login phase=status_result status=approved` or `status=consumed` for request ids `c5202e7d-dddc-47c2-8914-043d7f121c8f` and `09e69b3f-f9f2-4e38-b49d-3ed62b549c5a`.

## Current Findings
- `poll_vaulted_qr_login` logs `status_result` immediately after the Oracle status response and before local session mutation, so absence of `approved`/`consumed` strongly suggests the locked modal stopped invoking the poll command before the approved status was observable.
- `OracleLoginModal.tsx` has several silent poll exits:
  - token mismatch before `poll_begin`;
  - token mismatch after `invoke`;
  - `waitForPollDelay(...)` returning false;
  - loop ending when `Date.now() > expiresAt + grace`.
- Token invalidation currently happens on `Retry`, `Cancel`, modal close/unmount cleanup, and the modal-open reset effect. The reset effect also schedules autostart with `requestAnimationFrame`, so it is the main area to instrument for unexpected restarts/cancellations.
- `copyPayload` only sets `copied` and should not intentionally cancel polling.
- `AuthScreen` closes the modal only from `onClose` or after `handleQrLoginSuccess` sees an Oracle-only success; it should not close before the locked poller observes success.
- `SettingsScreen` approval UI calls `confirm_vaulted_qr_login` and does not poll status, so it should not consume the approved status by itself.

## Questions To Answer During Implementation
- Which exact path stops the poll loop after pending checks: token mismatch, wait cancellation, expiry, modal close, or an unhandled error?
- Does the modal-open reset effect run more than once for a single open session?
- Does any parent lifecycle path set `showQrLogin=false` before success?
- Is the locked modal still mounted after copying the fallback payload and switching to the trusted-device workflow?
- Is the QR request expiring earlier than the UI timer implies?
- Should the modal run an immediate status check when focus returns, while still preserving the 7000ms normal interval?

## Tasks

- [x] 1. Add safe lifecycle diagnostics around silent poll exits
  - Files likely to change:
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
  - Deliverable: log safe debug events for `poll_cancelled`, `poll_wait_cancelled`, `poll_expired`, `modal_open_reset`, `modal_cleanup`, `retry_start`, and `cancel_clicked`.
  - Expected behavior: runtime logs can prove whether polling stops because the token changed, the modal closed/unmounted, the request expired, or a terminal error occurred.
  - Logging requirements: include `ui_step`, QR request id when available, token id, current token id, `is_open`, `is_expired`, and cancellation reason only. Do not log QR payload, challenge, signatures, tokens, or secret-bearing values.
  - Dependency notes: this is diagnostic-only and must not change Oracle, crypto, or approval semantics.

- [x] 2. Make modal autostart/reset run only for a real open-session transition
  - Files likely to change:
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
  - Deliverable: replace the current `isOpen/startOnOpen/startLogin` reset effect with an explicit open-session guard, such as an `openSessionIdRef` or previous-open ref, so state reset and autostart happen once per modal open.
  - Expected behavior: parent re-renders or stable callback churn cannot silently invalidate the active poll token during an open QR request.
  - Logging requirements: log `modal_open_reset` once per opened modal session and `modal_cleanup` only when the modal actually closes/unmounts, with token id and open/session id only.
  - Dependency notes: preserve `startOnOpen` for the locked Auth screen and default false behavior for the App-level Oracle modal.

- [x] 3. Keep polling alive across copy/fallback and approval-window timing
  - Files likely to change:
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
  - Deliverable: ensure `copyPayload` and fallback UI state never invalidate the token, and consider an immediate safe poll on window focus/visibility return while the same request is still waiting and unexpired.
  - Expected behavior: after the user copies the fallback payload, approves from a trusted session, and returns to the locked modal, the locked modal observes `approved` or `consumed` without waiting for an unrelated restart.
  - Logging requirements: if focus/visibility polling is added, log `ui_step=focus_poll_requested` with request id, token id, and expiry status only.
  - Dependency notes: avoid duplicate concurrent poll loops; any immediate poll should reuse the active token/request guard.

- [x] 4. Preserve success and terminal error handling
  - Files likely to change:
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs) only if response semantics need safe diagnostic clarification
  - Deliverable: keep success behavior for `approved` and `consumed`; keep `expired` and `rejected` terminal; keep rate-limit backoff recoverable.
  - Expected behavior: approved Oracle-only login is reported honestly, and local decrypt still requires restoring the 12-word phrase when local identity is absent.
  - Logging requirements: keep existing `poll_begin`, `poll_result`, and rate-limit logs; if Rust changes are needed, log only command, phase, QR request id, status enum, and endpoint status.
  - Dependency notes: do not change QR approval crypto, Oracle routes, Oracle rate limits, seed policy, auth lifecycle, encryption/decryption, or transfer flows.

- [x] 5. Run focused checks and runtime verification
  - Files likely to change:
    - none beyond implementation files above
  - Deliverable: run UI checks and relevant desktop checks, then verify the locked modal observes approved/consumed in runtime.
  - Expected behavior: no rate-limit regression, no stale-poll cancellation, and no forbidden data in logs.
  - Logging requirements: inspect frontend console and desktop logs for forbidden values before commit.
  - Dependency notes: do not reset runtime state, log out, clear wallets, delete user data, or modify `.env`.

## Minimal Fix Proposal
- Start with frontend-only changes in `OracleLoginModal.tsx`.
- Add safe diagnostics to every currently silent poll return before changing behavior broadly.
- Refactor the modal open/reset effect so it cannot invalidate a live poll except on explicit close/unmount, retry, or cancel.
- Keep the 7000ms base poll interval and expiry-aware loop from the previous checkpoint.
- If the diagnostics show the modal is alive but waiting through the approval window, add a guarded immediate poll on window focus/visibility return for the active request.
- Change `crates/desktop-client/src/commands.rs` only if the poll command needs an additional safe status/cancellation diagnostic; do not alter response semantics unless runtime evidence proves a mismatch.

## Checks

Frontend checks:

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
cd ../../..
```

Rust checks if desktop Rust changes:

```bash
cargo fmt --all --check
cargo check -p xrpl-vault-desktop
cargo test -p xrpl-vault-desktop
```

Security/diff checks:

```bash
./scripts/check-sensitive-logs.sh
git diff --check
```

## Runtime Verification Steps
- Start Oracle and desktop with the existing dev workflow; do not reset runtime state.
- From the locked Auth screen, open QR login and confirm `start_vaulted_qr_login phase=success qr_request_id=...`.
- Confirm each pending poll has a matching frontend `poll_begin`/desktop `poll_vaulted_qr_login phase=begin`/desktop `status_result status=pending`.
- Copy the fallback payload and approve it from the trusted unlocked session.
- Confirm the locked modal keeps polling after copy/approval and logs either:
  - `poll_vaulted_qr_login phase=status_result status=approved`, or
  - `poll_vaulted_qr_login phase=status_result status=consumed`.
- Confirm the UI transitions to success or honest Oracle-session-only messaging.
- Leave a QR unapproved until expiration and confirm it reaches the terminal expired state with retry available.
- Confirm retry cancels the old token and starts a fresh request id.
- Confirm cancel stops pending polling/backoff and logs the cancellation reason.
- Confirm Oracle logs do not show auth rate-limit exceedance during normal pending polling.
- Review frontend console and desktop logs for forbidden values: no QR payload contents, challenge, approval signature, token/JWT, seed/private material, AES key, `tx_blob`, plaintext, decrypted content, or recovery phrase.

## Out Of Scope
- QR approval crypto semantics.
- Oracle QR endpoints or database behavior.
- Oracle rate-limit configuration or middleware.
- Wallet tab, Send XRP, XRPL mint/signing/serialization.
- 12-word seed policy.
- Auth restart/logout lifecycle beyond observing modal lifecycle.
- File encryption/decryption.
- Transfer and re-encryption flows.
- Runtime reset/logout, clearing app data, or `.env` changes.

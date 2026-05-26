# Plan: Diagnose QR Login Frontend-To-Tauri Invocation
Created: 2026-05-26
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, include focused Rust/UI compile checks; add unit tests only if implementation adds a pure error-classification helper.
- **Logging:** add temporary or durable safe command-boundary diagnostics only: command name, request phase, QR request id when available, status enum, endpoint status/error class, and UI step. Do not log QR payload contents, approval signatures, tokens, seed phrases, private keys, JWTs, AES keys, `tx_blob`, plaintext, decrypted content, or recovery phrase.
- **Docs:** no docs changes.
- **Scope:** diagnosis and minimal fix only. Do not change QR approval crypto semantics, Oracle QR endpoints unless a route mismatch is proven, XRPL/Wallet/Send XRP, seed policy, auth lifecycle, encryption/decryption, or transfer/re-encryption.

## Current Findings
- `OracleLoginModal.tsx` invokes `start_vaulted_qr_login` and `poll_vaulted_qr_login`, matching registered Tauri command names in `crates/desktop-client/src/main.rs`.
- `start_vaulted_qr_login` takes only Tauri `State`, so the UI no-arg invoke is structurally valid.
- `poll_vaulted_qr_login` expects `login_request_id`, exposed as `loginRequestId` by `#[tauri::command(rename_all = "camelCase")]`; the UI argument shape is structurally valid.
- `QrCode` rendering happens only after `start_vaulted_qr_login` returns a payload, so QR rendering cannot be the cause of a failure before Oracle `/auth/qr/start`.
- The locked Auth screen action currently opens the modal; it does not itself invoke Tauri. The actual invoke is bound to the modal’s inner `Sign in with QR code` button.
- The visible message `Cannot connect to the vault server` can be produced by `formatError` for `Oracle API error`, `HTTP error`, `error sending request`, or `localhost:3000`. It may hide whether the failure was a Tauri invoke error, a desktop-to-Oracle HTTP error, or an endpoint URL/config issue.
- The Rust QR commands currently have no explicit command-boundary logs, so “no desktop logs” is not yet proof that Tauri was not invoked.

## Likely Failure Classes To Distinguish
- **UX/event path:** user clicks the Auth screen QR action but not the modal’s inner start button; no Tauri command should run in that case.
- **Frontend invoke path:** the modal calls the wrong command or Tauri cannot dispatch it; expected error would be command-not-found/IPC-related, not an Oracle route hit.
- **Desktop command path:** Tauri command runs, but `OracleClient` fails before Oracle receives `/api/v1/auth/qr/start` due URL/config/transport.
- **Error masking:** `formatError` maps the raw error into generic vault-server copy, hiding the actionable failure class.

## Tasks

- [x] 1. Add safe frontend step diagnostics around QR login start/poll
  - Files likely to change:
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
  - Deliverable: make the UI prove whether the modal start button was clicked and whether it reached the `invoke()` call, without logging payload contents.
  - Expected behavior: visible safe status or sanitized `console.debug`/`console.warn` entries show `ui_step=start_clicked`, `ui_step=invoke_start_begin`, `ui_step=invoke_start_ok|invoke_start_error`, and for poll `ui_step=poll_begin|poll_result|poll_error` with only request id/status/error class.
  - Logging requirements: no QR payload JSON, no challenge, no tokens, no signatures. If console logging is used, log only command name, phase, request id after start succeeds, status enum, and sanitized error class/message.
  - Dependency notes: keep the existing modal UX intact unless Task 2 changes the start behavior.

- [x] 2. Decide whether Auth QR action should start immediately or only open the modal
  - Files likely to change:
    - [crates/desktop-client/ui/src/screens/AuthScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/AuthScreen.tsx)
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
  - Deliverable: remove ambiguity from the locked Auth flow.
  - Expected behavior: either the Auth screen action remains “open modal” but copy clearly indicates the second click is required, or the modal gets a minimal `startOnOpen` prop so the Auth screen action starts `start_vaulted_qr_login` immediately after opening.
  - Logging requirements: if `startOnOpen` is added, log safe `ui_step=modal_open_autostart` only; do not log payload contents.
  - Dependency notes: do not alter the unlocked App-level Oracle login modal behavior unless the same prop can remain backward-compatible.

- [x] 3. Add safe Rust command-boundary logs for QR login commands
  - Files likely to change:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
  - Deliverable: prove whether `start_vaulted_qr_login`, `poll_vaulted_qr_login`, and `confirm_vaulted_qr_login` are invoked and where they fail.
  - Expected behavior:
    - `start_vaulted_qr_login` logs `command=start_vaulted_qr_login`, `phase=begin`, `phase=oracle_request`, then `phase=success` with QR request id only after Oracle returns.
    - `poll_vaulted_qr_login` logs command, phase, QR request id, and returned status enum.
    - `confirm_vaulted_qr_login` logs command, phase, QR request id, and approved/status boolean only; no signature.
    - On failure, logs safe error class/status, not request payloads or tokens.
  - Logging requirements: no QR payload, no challenge, no approval signature, no tokens, no seed/private material.
  - Dependency notes: use existing `tracing` patterns; no new dependencies.

- [x] 4. Preserve or expose actionable QR login error detail without leaking secrets
  - Files likely to change:
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](</home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx>)
    - [crates/desktop-client/ui/src/utils/formatError.ts](/home/riggle/vaulted/crates/desktop-client/ui/src/utils/formatError.ts) only if a shared helper is cleaner
  - Deliverable: prevent `Cannot connect to the vault server` from hiding command-dispatch or QR-specific failures.
  - Expected behavior: QR login errors distinguish at least `Tauri command failed`, `Oracle request failed`, `request timed out`, `expired`, and `replay/consumed` when the raw error makes that possible.
  - Logging requirements: show only sanitized user-facing text and safe error class/status; do not display raw payloads, tokens, signatures, or challenges.
  - Dependency notes: keep global `formatError` mappings unchanged unless needed; prefer a local QR-login formatter to avoid changing unrelated flows.

- [x] 5. Verify command registration and invocation wiring remains exact
  - Files likely to inspect/change:
    - [crates/desktop-client/src/main.rs](/home/riggle/vaulted/crates/desktop-client/src/main.rs)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
  - Deliverable: confirm no command rename, case mismatch, or argument mismatch exists after changes.
  - Expected behavior: no changes to Tauri registration unless a mismatch is found; if unchanged, document that `start_vaulted_qr_login` is no-arg and `poll_vaulted_qr_login` uses `{ loginRequestId }`.
  - Logging requirements: none beyond Task 3.
  - Dependency notes: do not touch Oracle route definitions unless runtime logs prove desktop reaches Oracle with a mismatched path.

- [x] 6. Run focused checks and runtime proof
  - Files likely to change:
    - none beyond the files above
  - Deliverable: automated checks plus a runtime QR login trace that identifies the exact failing boundary.
  - Expected behavior: after clicking through the intended QR login path, either Oracle logs show `/api/v1/auth/qr/start` or desktop logs show the command failed before/while making that request with a safe error class.
  - Logging requirements: inspect logs for forbidden values before committing.
  - Dependency notes: do not reset runtime state, log out, clear wallets, or modify `.env`.

## Verification Commands

Run Rust checks if `commands.rs` changes:

```bash
cargo fmt --all --check
cargo check -p xrpl-vault-desktop
cargo test -p xrpl-vault-desktop
```

Run UI checks if frontend changes:

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

## Runtime Verification Steps
- Start Oracle and desktop exactly as in the existing dev workflow; do not reset or log out unless explicitly authorized.
- On the locked Auth screen, click `Sign in with QR code`.
- If Task 2 keeps the two-step flow, click the modal’s inner `Sign in with QR code` button; if `startOnOpen` is implemented, confirm the command starts when the modal opens.
- Watch desktop logs for:
  - `command=start_vaulted_qr_login phase=begin`
  - `phase=oracle_request`
  - either `phase=success qr_request_id=<id>` or a safe error class/status.
- Watch Oracle logs for `/api/v1/auth/qr/start`.
- If Oracle sees no request but desktop logs show `oracle_request`, inspect the configured Oracle base URL and transport error class without logging tokens or payloads.
- If desktop logs show no command begin, inspect modal event binding and Tauri WebView console for a frontend click/invoke failure.
- After a successful start, confirm QR renders and `poll_vaulted_qr_login` logs request id and status enum only.

## Out Of Scope
- QR approval crypto semantics.
- Oracle QR endpoint behavior unless a route mismatch is proven by runtime logs.
- XRPL mint/signing/serialization.
- Wallet tab and Send XRP command.
- Seed policy and auth restart/logout lifecycle.
- File encryption/decryption and transfer/re-encryption.
- Runtime reset/logout, clearing local data, or `.env` changes.

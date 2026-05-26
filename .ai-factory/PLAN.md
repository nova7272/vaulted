# Plan: Make QR Login Polling Rate-Limit Safe
Created: 2026-05-26
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, include focused UI lint/type/build checks and desktop Rust checks only if the Tauri poll response/error shape changes.
- **Logging:** keep existing safe QR diagnostics and add only rate-limit-safe fields: command name, UI step, request phase, QR request id, status enum, endpoint status, error class, and `rate_limited` boolean. Do not log QR payload, challenge, approval signatures, tokens, seed phrases, private keys, JWTs, AES keys, `tx_blob`, plaintext, decrypted content, or recovery phrase.
- **Docs:** no docs changes.
- **Scope:** minimal QR login polling fix. Do not change QR approval crypto semantics, Oracle QR endpoint behavior unless absolutely required, XRPL/Wallet/Send XRP, seed policy, auth lifecycle, encryption/decryption, transfer/re-encryption, or runtime reset/logout.

## Runtime Finding
- QR login frontend-to-Tauri boundary is working:
  - desktop logs show `start_vaulted_qr_login` begin/request/success and `poll_vaulted_qr_login` status polling;
  - Oracle receives `/api/v1/auth/qr/start` and repeated `/api/v1/auth/qr/status/{id}`.
- Failure is now caused by auth rate limiting:
  - Oracle auth routes use `auth_rate_limit_middleware`;
  - default `AUTH_RATE_LIMIT_RPM` is 10 requests/minute;
  - current UI poll interval is 1.5s, about 40 status requests/minute plus start request.
- Therefore the minimal fix should be primarily in the QR login modal polling loop, not Oracle routes.

## Current Integration Points
- QR login modal and poll loop:
  - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
- Desktop poll command and safe command-boundary logging:
  - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
- Shared error formatter, only if a local QR classifier is insufficient:
  - [crates/desktop-client/ui/src/utils/formatError.ts](/home/riggle/vaulted/crates/desktop-client/ui/src/utils/formatError.ts)
- Oracle rate-limit context for inspection only:
  - [crates/oracle/src/middleware.rs](/home/riggle/vaulted/crates/oracle/src/middleware.rs)
  - [crates/oracle/src/config.rs](/home/riggle/vaulted/crates/oracle/src/config.rs)
  - [crates/oracle/src/api/mod.rs](/home/riggle/vaulted/crates/oracle/src/api/mod.rs)

## Recommended Approach
- Use a rate-limit-safe base poll interval of at least 7 seconds, not 5 seconds, because default auth limit is 10 req/min and QR start consumes one auth request. A 7-second interval keeps status polling under the default bucket while preserving a usable demo cadence.
- Stop using a fixed 120-iteration loop as the main bound. Poll until QR expiration plus a small grace window, so a longer interval does not extend the flow beyond its actual validity.
- Treat a single 429/rate-limit response as recoverable:
  - keep the modal in waiting state;
  - show “Waiting before retrying QR status...” or similar safe status text;
  - wait with backoff before retrying;
  - do not fail the login unless the QR expires, the user cancels, or repeated non-rate-limit errors occur.
- Prefer frontend-only rate-limit detection first via existing error text (`HTTP 429`, `Rate limit`, `Too many requests`). Add desktop structured `rateLimited`/`endpointStatus` only if needed to distinguish 429 reliably.

## Tasks

- [x] 1. Tune QR polling interval and expiry-bound loop
  - Files likely to change:
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
  - Deliverable: replace the 1.5s fixed delay and 120-count loop with an expiry-aware polling loop using a safe base interval, preferably `7000ms`.
  - Expected behavior: QR status polling remains below the default Oracle auth rate limit while the expiration timer stays visible and accurate.
  - Logging requirements: keep `poll_begin` and `poll_result`; no payload, challenge, token, or signature fields.
  - Dependency notes: do not alter QR start, approval, or session semantics.

- [x] 2. Handle 429/rate-limit as recoverable backoff
  - Files likely to change:
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs) only if frontend cannot reliably identify 429 from current errors
  - Deliverable: update `classifyQrError` and the poll loop so rate-limit errors produce a backoff delay instead of setting terminal `error` state.
  - Expected behavior: a single 429 shows a safe waiting message, logs `rate_limited=true`, waits longer, and resumes polling until approval/expiry/cancel.
  - Logging requirements: log only `ui_step=poll_error`, QR request id, `error_class=rate_limited`, `rate_limited=true`, and optionally endpoint status `429`; no response body or secret-bearing values.
  - Dependency notes: if `commands.rs` is changed, preserve existing safe command-boundary logs and avoid changing Oracle client routes.

- [x] 3. Add user-facing waiting status without hiding terminal errors
  - Files likely to change:
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
  - Deliverable: add a small safe status line for rate-limit backoff, such as “Waiting before retrying QR status...”.
  - Expected behavior: users can tell the QR login is still active during backoff; expired/rejected/timeout still show clear terminal errors.
  - Logging requirements: no extra logging unless state changes; if logged, use `ui_step=rate_limit_backoff` with request id and delay milliseconds only.
  - Dependency notes: keep the QR expiration timer visible and keep retry/cancel controls available.

- [x] 4. Keep QR retry/cancel behavior correct under backoff
  - Files likely to change:
    - [crates/desktop-client/ui/src/components/OracleLoginModal.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/OracleLoginModal.tsx)
  - Deliverable: ensure `Retry` cancels the old poll token and starts a new QR request, and `Cancel` stops any pending backoff wait.
  - Expected behavior: no stale poll resumes after retry/cancel; no duplicate poll loops run for a single modal session.
  - Logging requirements: existing `start_clicked`, `invoke_start_begin`, `poll_begin`, and `poll_result` are enough; add no payload logs.
  - Dependency notes: preserve `startOnOpen` behavior for the locked Auth screen and default false behavior for the App-level modal.

- [x] 5. Run focused verification
  - Files likely to change:
    - none beyond implementation files above
  - Deliverable: run local checks and a runtime QR login poll verification.
  - Expected behavior: status polling no longer trips the default auth rate limit during the 2-minute QR lifetime; if an old bucket is already rate-limited, the UI backs off instead of failing immediately.
  - Logging requirements: inspect UI console and desktop logs for forbidden values.
  - Dependency notes: do not reset runtime state, log out, clear wallets, or modify `.env`.

## Tests And Checks

Frontend checks:

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
cd ../../..
```

Rust checks, only if `crates/desktop-client/src/commands.rs` changes:

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

Optional targeted UI logic test, only if a pure helper is extracted:
- rate-limit classifier returns `rate_limited` for `HTTP 429`, `Rate limit`, and `Too many requests`;
- non-rate-limit Oracle errors remain terminal.

## Runtime Verification Steps
- Start Oracle and desktop using the existing dev workflow; do not reset runtime state.
- Open locked Auth screen and start QR login.
- Confirm desktop logs show:
  - `start_vaulted_qr_login phase=success qr_request_id=...`
  - `poll_vaulted_qr_login phase=status_result status=pending`
- Confirm Oracle status requests occur at the new safe cadence, not every 1.5 seconds.
- Leave QR login pending for at least 60 seconds and confirm Oracle does not emit `Auth rate limit exceeded`.
- If the auth bucket is already exhausted, confirm the modal remains in waiting state and shows the safe backoff message instead of failing immediately.
- Approve from an unlocked trusted session and confirm polling still observes approval before expiration.
- Let a QR request expire and confirm expiration still becomes a terminal safe error with retry available.
- Review UI console and desktop logs for forbidden values: no QR payload, challenge, approval signature, token/JWT, seed/private material, AES key, `tx_blob`, plaintext, decrypted content, or recovery phrase.

## Out Of Scope
- Oracle rate-limit configuration or middleware behavior.
- QR approval crypto semantics.
- Oracle QR endpoint routes or DB behavior.
- XRPL mint/signing/serialization, Wallet tab, and Send XRP command.
- Seed policy and auth restart/logout lifecycle.
- File encryption/decryption and transfer/re-encryption.
- Runtime reset/logout, clearing data, or `.env` changes.

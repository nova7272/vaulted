# Plan: Diagnose Desktop Window Launch
Created: 2026-05-25
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, focused desktop/UI launch checks only
- **Logging:** safe startup diagnostics only: app phase, window label/count, window visibility/focus result, frontend asset presence boolean, Tauri setup/run phase, display backend env key presence; do not log secrets or raw environment dumps
- **Docs:** no docs work unless launch command guidance in README/QUICKSTART is already wrong and directly blocks runtime checks
- **Security:** never log seed phrase, mnemonic entropy, private keys, derived keys, AES keys, JWTs, plaintext files, `tx_blob`, signatures, decrypted content, recovery phrase, or raw restore input

## Scope
- Diagnose why `cargo run -p xrpl-vault-desktop` starts and stays alive but no visible WSLg/Tauri window appears.
- Keep the fix minimal and localized to desktop launch/window configuration.
- Do not modify wallet feature logic unless a startup-breaking import/build error is proven.
- Do not touch XRPL mint/signing, Oracle finalization/linking, seed policy, auth lifecycle, encryption, transfer, QR login, or reset/logout behavior.

## Runtime Evidence
- `DISPLAY=:0`
- `WAYLAND_DISPLAY=wayland-0`
- `cargo run -p xrpl-vault-desktop` prints:
  - `Starting XRPL Vault Desktop...`
  - `Loaded device fingerprint: ...`
- No further logs appear.
- Process remains alive until stopped.
- No visible window appears.
- Recent commit `c5e19d9 Add read only wallet tab` added UI imports and two Tauri commands, but Rust/UI checks passed at commit time.

## Findings
- [crates/desktop-client/src/main.rs](/home/riggle/vaulted/crates/desktop-client/src/main.rs) logs before `AppState::new`, then immediately builds/runs Tauri with no `.setup(...)` hook and no logs before/after plugin registration, context generation, setup, window lookup, or app run.
- [crates/desktop-client/tauri.conf.json](/home/riggle/vaulted/crates/desktop-client/tauri.conf.json) defines one window but leaves `title` empty and does not explicitly set a `label` or `visible`.
- [crates/desktop-client/capabilities/default.json](/home/riggle/vaulted/crates/desktop-client/capabilities/default.json) scopes permissions to window label `main`; Tauri likely defaults the first window to `main`, but the config does not make that explicit.
- `frontendDist` is `./ui/dist`, and `crates/desktop-client/ui/dist` exists with `index.html`, JS, CSS, and assets.
- `ui/package.json` has no Tauri dev script; `cargo run -p xrpl-vault-desktop` uses the built `ui/dist` path and does not rebuild the frontend.
- Recent `App.tsx` and `WalletScreen.tsx` imports are valid enough for `npm run lint`, `tsc`, and `npm run build` from the prior commit; a frontend runtime error would usually still show a window, possibly blank, so it is not the first suspect.

## Questions Answered
- **Is this likely wallet backend logic?** No. Runtime stops producing logs before any wallet command can be invoked, and the app is unauthenticated at startup.
- **Is this likely XRPL/Oracle/seed/auth logic?** No. The process reaches Tauri run setup after loading local app state; no runtime evidence points to those completed areas.
- **Could stale/missing frontend dist be the cause?** `ui/dist` exists, but the correct runtime command should still rebuild it before launch during diagnostics to remove stale artifact ambiguity.
- **What is the smallest safe diagnostic?** Add a Tauri `.setup(...)` hook that logs safe setup phases, enumerates webview window labels/counts, checks/forces the `main` window visible/focused, and reports failure as safe status text.
- **What is the likely minimal fix if setup proves the window is missing/hidden/unfocused?** Make the configured window explicit with `label: "main"`, non-empty title, `visible: true`, and possibly call `show()`/`set_focus()` in setup after startup logs.

## Exact Launch Commands

Use the packaged-dist path first, because current config has no dev URL:

```bash
cd /home/riggle/vaulted/crates/desktop-client/ui
npm run build
```

```bash
cd /home/riggle/vaulted
DISPLAY=:0 WAYLAND_DISPLAY=wayland-0 RUST_LOG=xrpl_vault_desktop=debug,tauri=trace,wry=trace cargo run -p xrpl-vault-desktop
```

If WebKit/WSLg compositing is suspect, retry with a WSLg-safe rendering toggle:

```bash
cd /home/riggle/vaulted
DISPLAY=:0 WAYLAND_DISPLAY=wayland-0 WEBKIT_DISABLE_COMPOSITING_MODE=1 RUST_LOG=xrpl_vault_desktop=debug,tauri=trace,wry=trace cargo run -p xrpl-vault-desktop
```

If `cargo-tauri` is already installed locally, optional dev-mode comparison:

```bash
cd /home/riggle/vaulted/crates/desktop-client
cargo tauri dev
```

Do not install new tooling or fetch dependencies for this diagnostic unless explicitly approved.

## Tasks

- [x] 1. Add safe Tauri startup/window diagnostics
  - Files likely to change:
    - [crates/desktop-client/src/main.rs](/home/riggle/vaulted/crates/desktop-client/src/main.rs)
  - Deliverable: add logs around Tauri builder construction, plugin registration boundary, setup start, setup completion, window lookup, and run start.
  - Expected behavior: runtime logs clearly show whether Tauri setup ran, how many webview windows exist, whether `main` was found, and whether `show()`/`set_focus()` succeeded.
  - Logging requirements: allowed fields only: phase/status enum, window label, window count, boolean result, display env presence booleans. Do not log full env values or secret-bearing config.
  - Dependency notes: do not change command handlers or wallet backend logic.

- [x] 2. Make the main window explicit and visible if diagnostics support it
  - Files likely to change:
    - [crates/desktop-client/tauri.conf.json](/home/riggle/vaulted/crates/desktop-client/tauri.conf.json)
    - [crates/desktop-client/src/main.rs](/home/riggle/vaulted/crates/desktop-client/src/main.rs) only for setup `show()`/`set_focus()`
  - Deliverable: set explicit window `label: "main"`, non-empty title, and `visible: true`; optionally call `window.show()` and `window.set_focus()` in setup with safe logs.
  - Expected behavior: the Tauri window opens visibly under WSLg and can be identified by title.
  - Logging requirements: log only `window_label=main`, `phase=show|focus`, `status=ok|failed`, and safe error class/message if needed.
  - Dependency notes: preserve size/resizable/theme unless runtime evidence shows dimensions are the blocker; avoid unrelated UI polish.

- [x] 3. Confirm frontend startup artifacts are not the blocker
  - Files likely to inspect/change:
    - [crates/desktop-client/ui/src/App.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/App.tsx)
    - [crates/desktop-client/ui/src/screens/WalletScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/WalletScreen.tsx)
    - [crates/desktop-client/tauri.conf.json](/home/riggle/vaulted/crates/desktop-client/tauri.conf.json)
  - Deliverable: verify `npm run build` succeeds and `ui/dist/index.html` exists before launch; inspect recent imports only if build fails or a visible blank window appears with frontend console errors.
  - Expected behavior: no wallet UI rollback or backend changes unless a startup-breaking import/runtime exception is proven.
  - Logging requirements: no `console.log`; if a temporary frontend error boundary is needed, show safe user-facing text only.
  - Dependency notes: do not touch wallet backend read-only commands.

- [x] 4. Run focused verification
  - Files likely to change:
    - none beyond diagnostics/config files above
  - Deliverable: compile/build checks plus runtime launch evidence that the window appears.
  - Expected behavior: Tauri logs include setup/window phases; WSLg displays the app window; process exits cleanly when window is closed.
  - Logging requirements: review logs for secrets before commit; no raw env dumps or sensitive data.
  - Dependency notes: no live XRPL/Oracle checks needed for window visibility.

## Verification Commands

Run commands separately:

```bash
cargo fmt --all --check
cargo check -p xrpl-vault-desktop
cargo test -p xrpl-vault-desktop
```

Run UI checks if frontend files are touched or to refresh dist before launch:

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

Runtime launch check:

```bash
cd /home/riggle/vaulted
DISPLAY=:0 WAYLAND_DISPLAY=wayland-0 RUST_LOG=xrpl_vault_desktop=debug,tauri=trace,wry=trace cargo run -p xrpl-vault-desktop
```

Expected safe log milestones:

```text
Starting XRPL Vault Desktop...
tauri_setup_started
tauri_window_lookup window_label=main status=found
tauri_window_show window_label=main status=ok
tauri_window_focus window_label=main status=ok
tauri_run_started
```

## Runtime Checks
- Confirm WSLg variables exist: `DISPLAY` and/or `WAYLAND_DISPLAY`.
- Confirm `ui/dist/index.html` exists after `npm run build`.
- Start desktop with trace logging.
- Confirm a visible window appears.
- Confirm the title is visible/non-empty.
- Close the window and confirm the process exits normally.
- If no visible window appears, use logs to classify:
  - setup never reached
  - no `main` window
  - `show()` failed
  - `focus()` failed
  - webview/frontend loads blank after a visible window exists

## Out Of Scope
- XRPL signing/serialization.
- Oracle post-mint linking/finalization.
- Pending mint recovery.
- Oracle XRPL HTTP RPC config.
- 12-word seed policy.
- Auth restart/logout lifecycle.
- Wallet backend read-only logic unless a startup issue is proven.
- File encryption/decryption.
- Transfer/re-encryption.
- QR login implementation.
- Runtime reset/logout behavior.
- Send XRP / Payment signing and submission.

## Expected Successful State
- Desktop launch logs prove Tauri setup and window creation/show/focus.
- `cargo run -p xrpl-vault-desktop` opens a visible Tauri window under WSLg after `ui/dist` is built.
- No secret-bearing values are logged.

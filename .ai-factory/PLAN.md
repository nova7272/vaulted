# Plan: Non-Blocking Release Hardening Follow-Ups

Branch: main
Created: 2026-05-28
Mode: fast, plan only

## Settings
- Testing: yes. Each follow-up has targeted checks plus final safety checks.
- Logging: standard. Do not add runtime logging unless an implementation step explicitly needs safe diagnostics.
- Docs: yes. README/runtime docs may change for demo polish and retest instructions.
- Roadmap Linkage: none. These are post-MVP hardening follow-ups after final verification passed.

## Current Context
- Final MVP verification passed and was recorded in `docs/RUNTIME_VERIFICATION.md`.
- Handoff says no production blocker remains after storage proxy log redaction and retest.
- Known follow-ups:
  - remove duplicate `XRPL_NODE_URL` in local `.env` when safe
  - investigate/update yanked Rust `aes 0.9.0` through `zip 8.6.0`
  - investigate/update npm moderate `brace-expansion` advisory through `@typescript-eslint/typescript-estree`
  - optionally retest QR approval with a second device/session
  - identify minimal UI/README polish for an external demo

## Security Boundary
Do not print, copy, log, document, or commit:
- seed phrase, mnemonic entropy, recovery phrase
- private keys, derived keys, AES keys
- JWTs, storage tokens, tokenized URLs, raw storage keys
- `tx_blob`, signatures, QR payloads, QR approval signatures
- plaintext/decrypted file contents or raw encrypted key material
- full `.env` contents

Allowed:
- dependency names and versions
- commit hashes
- advisory names
- env key names without values
- safe command pass/fail output
- endpoint statuses and safe phase names

## Risk Classification

| Item | Risk | Why | Implementation posture |
| --- | --- | --- | --- |
| Duplicate local `XRPL_NODE_URL` in `.env` | Low local config risk | Duplicate keys can make runtime behavior depend on parser/source order; `.env` is local and must not be committed. | Inspect safely, edit locally only with owner approval, do not commit `.env`. |
| Yanked Rust `aes 0.9.0` via `zip 8.6.0` | Medium dependency hygiene risk | Final audit completed with an allowed yanked dependency; upgrade may alter archive behavior or lockfile resolution. | Investigate first, update `zip` only if available compatible version removes yanked path, run desktop/workspace checks. |
| npm moderate `brace-expansion` advisory | Low-to-medium dev tooling risk | Path is dev tooling (`eslint` / `typescript-eslint`), but it affects release audit cleanliness. | Inspect advisory, prefer lockfile/package update over force fixes, run UI checks. |
| QR approval retest with second device/session | Low runtime evidence gap | QR approval lifecycle has previous evidence; fresh final pass lacked second device/session. | Prepare runbook, retest only when second device/session is available; no code changes unless regression is found. |
| Minimal UI/README polish | Low demo quality risk | External demo benefits from crisp wording and reduced ambiguity, but MVP is already passed. | Keep edits copy/docs-level unless a small UI text adjustment is clearly needed; avoid crypto/runtime flow changes. |

## Exact Safe Inspection Commands

### Duplicate `.env` Keys Without Printing Values

Run only from repo root. These commands print key names, line numbers, and counts only.

```bash
test -f .env
```

```bash
git check-ignore -v .env
```

```bash
awk -F= '/^[[:space:]]*XRPL_NODE_URL[[:space:]]*=/{count++} END{print "XRPL_NODE_URL entries:", count+0}' .env
```

```bash
awk -F= '/^[[:space:]]*XRPL_NODE_URL[[:space:]]*=/{print FILENAME ":" NR ": XRPL_NODE_URL=<redacted>"}' .env
```

If cleanup is approved, edit `.env` manually to keep one intended `XRPL_NODE_URL` value. Do not print the value, and do not stage or commit `.env`.

### Rust Dependency Tree

Run from repo root.

```bash
cargo tree -i aes@0.9.0
```

```bash
cargo tree -i zip@8.6.0
```

```bash
cargo tree -p xrpl-vault-desktop -e normal
```

```bash
cargo audit
```

Optional update probe only after deciding to implement, not during planning:

```bash
cargo update -p zip --dry-run
```

If `--dry-run` is unavailable in the installed Cargo version, use `cargo update -p zip --precise <candidate-version>` only after selecting a candidate version and be ready to revert if checks fail.

### npm Advisory

Run from `crates/desktop-client/ui`.

```bash
npm ls brace-expansion @typescript-eslint/typescript-estree --depth=6
```

```bash
npm audit --audit-level=moderate
```

```bash
npm audit --json
```

```bash
npm explain brace-expansion
```

Do not run `npm audit fix` until the advisory path and likely lockfile/package changes are understood.

## Recommended Implementation Order

1. Local `.env` duplicate inspection and cleanup decision.
   - Lowest blast radius and should be resolved before future runtime retests.
   - Leave `.env` uncommitted.
2. Rust dependency investigation/update for `zip`/`aes`.
   - More likely to affect desktop archive behavior, lockfile, and Rust checks.
   - Commit separately if a safe update is found.
3. npm advisory investigation/update.
   - Dev-tooling scope; likely package-lock or devDependency update.
   - Commit separately from Rust dependency work.
4. QR approval retest preparation.
   - Depends on having a second device/session.
   - Prefer a runbook/docs update before any code changes.
5. Minimal UI/README polish for external demo.
   - Last, after dependency and config hygiene, to avoid mixing demo copy with dependency churn.

## Files Likely To Change

Local only, not committed:
- `.env`
  - Remove duplicate `XRPL_NODE_URL` only after confirming the intended value.

Rust dependency hardening:
- `crates/desktop-client/Cargo.toml`
  - Current direct dependency: `zip = "8.5.1"`; lock resolves to `zip 8.6.0`.
- `Cargo.lock`
  - Expected if `zip` or transitive dependencies are updated.

npm advisory hardening:
- `crates/desktop-client/ui/package.json`
  - Only if a devDependency range change is needed.
- `crates/desktop-client/ui/package-lock.json`
  - Expected for npm dependency resolution changes.

QR retest and demo polish:
- `docs/RUNTIME_VERIFICATION.md`
  - Add optional QR approval retest evidence if performed.
- `README.md`
  - Tighten external demo flow, QR limitation language, validation commands, or release notes.
- `QUICKSTART.md`
  - Update only if it contradicts the final demo flow.
- Possible UI copy-only files under `crates/desktop-client/ui/src/`
  - Only if external demo polish clearly requires text/state wording changes.
  - Do not change QR crypto, wallet derivation, transfer/re-encryption, mint/finalize, owner decrypt, storage token semantics, or Oracle routes.

## What Should Be Committed

Commit:
- `Cargo.toml` / `Cargo.lock` dependency updates that pass checks.
- `package.json` / `package-lock.json` npm dependency updates that pass checks.
- README/Quickstart/runtime verification documentation updates.
- Minimal UI text polish if intentionally implemented and verified.

Do not commit:
- `.env` or any local secret/config file.
- runtime logs
- screenshots containing secrets or payloads
- generated build output
- dependency cache directories
- local wallet/app state

## Tasks

### Phase 1: Local Config Hygiene
- [ ] Task 1: Safely inspect duplicate `XRPL_NODE_URL` entries in local `.env` without printing values.

  Deliverable:
  - Count and line-number summary of `XRPL_NODE_URL` entries with values redacted.
  - Confirmation whether `.env` is ignored.
  - Owner-approved local cleanup instructions if duplicates exist.

  Files:
  - `.env` local only, not committed.

  Logging requirements:
  - Print only key names, counts, and line numbers.
  - Do not print `.env` values or surrounding lines.

  Checks:
  - `git status --short` must not show `.env` staged or tracked.
  - If local cleanup is performed, restart/retest only when explicitly requested.

### Phase 2: Rust Dependency Hardening
- [ ] Task 2: Investigate the yanked Rust dependency path `aes 0.9.0 -> zip 8.6.0 -> xrpl-vault-desktop`.

  Deliverable:
  - Confirm current tree with `cargo tree`.
  - Identify whether a compatible `zip` update removes yanked `aes`.
  - Recommend one of:
    - update `zip` and `Cargo.lock`
    - pin/adjust features if safe
    - defer with documented rationale if no safe compatible update exists

  Files:
  - `crates/desktop-client/Cargo.toml`
  - `Cargo.lock`

  Logging requirements:
  - Record package names/versions only.
  - Do not include unrelated environment output.

  Checks:
  - `cargo fmt --all --check`
  - `cargo check -p xrpl-vault-desktop`
  - `cargo test -p xrpl-vault-desktop`
  - `cargo check --workspace`
  - `cargo test --workspace`
  - `cargo audit`
  - `./scripts/check-sensitive-logs.sh`
  - `git diff --check`

### Phase 3: npm Advisory Hardening
- [ ] Task 3: Investigate and update the npm `brace-expansion` advisory path through `@typescript-eslint/typescript-estree` if a safe update exists.

  Deliverable:
  - Confirm current advisory path with `npm ls` and `npm audit`.
  - Prefer targeted devDependency/package-lock update.
  - Do not run `npm audit fix --force`.
  - Recommend defer only if the advisory remains in upstream tooling with no safe compatible update.

  Files:
  - `crates/desktop-client/ui/package.json`
  - `crates/desktop-client/ui/package-lock.json`

  Logging requirements:
  - Record package names, versions, and advisory name only.
  - Do not include environment variables or local paths beyond repo-relative paths.

  Checks:
  - `npm run lint`
  - `npx tsc --noEmit --project tsconfig.json`
  - `npm run build`
  - `npm audit --audit-level=moderate`
  - `./scripts/check-sensitive-logs.sh`
  - `git diff --check`

### Phase 4: Optional QR Approval Retest Prep
- [ ] Task 4: Prepare an optional second-device/session QR approval retest runbook.

  Deliverable:
  - A concise checklist for a fresh QR approval retest.
  - Preconditions for the second device/session.
  - Safe evidence to capture: status names, endpoint statuses, no raw QR payloads or signatures.
  - Stop conditions if secrets, manual reset, or unavailable second session blocks the run.

  Files:
  - `docs/RUNTIME_VERIFICATION.md`
  - `README.md` only if external demo documentation should mention the optional QR retest limitation.

  Logging requirements:
  - Capture only safe phase names and statuses.
  - Do not capture QR payloads, approval signatures, wallet recovery material, or tokens.

  Checks:
  - `./scripts/check-sensitive-logs.sh`
  - `git diff --check`
  - If runtime retest is performed: Oracle/storage health checks and QR status evidence only.

### Phase 5: Minimal External Demo Polish
- [ ] Task 5: Identify and implement minimal README/UI polish for an external demo.

  Deliverable:
  - Short list of demo friction points after final verification.
  - Minimal README/Quickstart wording updates, and UI text-only changes only if necessary.
  - No crypto, wallet derivation, transfer, mint/finalize, owner decrypt, storage token, or Oracle route changes.

  Files:
  - `README.md`
  - `QUICKSTART.md`
  - `docs/RUNTIME_VERIFICATION.md`
  - possible UI copy-only files under `crates/desktop-client/ui/src/`

  Logging requirements:
  - No new runtime logging expected.
  - If UI text is changed, ensure no secret-bearing values are rendered or copied.

  Checks:
  - For docs-only changes: `./scripts/check-sensitive-logs.sh`, `git diff --check`.
  - If UI files change:
    - `cd crates/desktop-client/ui`
    - `npm run lint`
    - `npx tsc --noEmit --project tsconfig.json`
    - `npm run build`
    - `cd ../../..`
    - `./scripts/check-sensitive-logs.sh`
    - `git diff --check`

## Commit Plan

Use separate commits to keep release hardening reversible:

- Commit 1, local config: no commit for `.env`; report local cleanup only.
- Commit 2, Rust dependencies: `Update desktop archive dependency`
- Commit 3, npm dependencies: `Update frontend lint dependencies`
- Commit 4, QR/docs: `Document optional QR approval retest`
- Commit 5, demo polish: `Polish external demo docs`

If UI text changes are needed, keep them in the demo polish commit only if they are small and directly tied to the README/demo wording. Otherwise split them into a separate UI polish commit.

## Out Of Scope

- Runtime source changes during this planning turn.
- Committing `.env` or printing `.env` values.
- Resetting runtime state, logging out, clearing wallets, deleting app data, or editing `.env` without explicit approval.
- Running `npm audit fix` or `cargo update` during planning.
- QR crypto changes.
- Wallet derivation changes.
- Transfer/re-encryption changes.
- Mint/finalize changes.
- Owner decrypt changes.
- Storage token semantics changes.
- Oracle route changes.
- Dependency updates that require broad runtime refactors.

## Next Step

To implement this plan, run:

```text
$aif-implement
```

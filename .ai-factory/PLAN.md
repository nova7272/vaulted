# Plan: Full MVP Security And Code-Quality Audit

Branch: main
Created: 2026-05-28
Mode: fast, plan only

## Settings
- Testing: yes. Audit findings and any cleanup must be verified with full Rust/frontend/security gates.
- Logging: standard. Do not add new runtime logs unless a proven security fix needs safe diagnostic context.
- Docs: yes. Document audit findings, accepted risks, and final verification evidence.
- Roadmap Linkage: none. MVP verification passed; this is post-MVP audit and hardening.

## Goal
Perform a full MVP security and code-quality audit, then plan safe cleanup and low-risk optimization without changing runtime behavior during planning. Preserve all runtime-tested MVP flows:
- Wallet/Send XRP
- QR login/approval semantics
- upload/mint/finalize
- owner download/decrypt
- transfer/re-encryption
- recipient decrypt
- storage token access
- Oracle auth/session flows

## Hard Boundaries
Do not:
- reset runtime state, log out, clear wallets, delete app data, or edit `.env`
- change QR crypto, wallet derivation, transfer/re-encryption, mint/finalize, owner decrypt, storage token semantics, or Oracle routes unless a security bug is proven and a separate fix plan is approved
- commit runtime logs, local wallet/app state, `.env`, screenshots with secrets, generated build output, or dependency caches
- print or include seed phrases, mnemonic entropy, private keys, derived keys, AES keys, JWTs, storage tokens, `tx_blob`, signatures, plaintext/decrypted content, recovery phrases, QR payloads, QR approval signatures, raw encrypted key material, tokenized URLs, raw storage keys, or full `.env` contents

Allowed evidence:
- safe file paths
- dependency names/versions
- advisory names
- command pass/fail summaries
- safe phase names
- commit hashes
- non-secret code snippets only when needed for review

## Audit Risk Classification

| Area | Risk | Notes |
| --- | --- | --- |
| Secret logging/redaction | Critical | Previous final-pass blocker was a tokenized URL leak; all logging paths need re-audit. |
| Wallet seed/key lifecycle | Critical | Client-side secret boundary is core security property; review storage, zeroization, UI exposure, and logs. |
| QR payload handling | High | QR payloads and approvals are signature-bearing trust transitions; avoid raw payload render/copy/logging. |
| Storage token handling | High | Signed storage URLs/tokens must never leak; validate operation/key/expiry boundaries. |
| Oracle auth/session/rate limits | High | JWT/session/device flows gate registry and access metadata. |
| XRPL signing/tx_blob handling | High | Signing is local; tx blobs/signatures must not be exposed in logs/UI/docs. |
| File encryption/decryption boundaries | High | Plaintext and file keys must stay client-side. |
| Transfer/re-encryption/access control | High | Owner/recipient permissions must match DB and XRPL evidence. |
| CORS/security headers/rate limits | Medium-high | Production assumptions differ from local dev defaults. |
| Dependency audit state | Medium | Existing non-blocking yanked Rust and npm advisory follow-ups must be rechecked. |
| Docker/local runtime assumptions | Medium | Local defaults may be unsafe for production if not clearly documented. |
| Dead/debug/stale/duplicated code | Low-to-medium | Cleanup can improve maintainability but can regress MVP if too broad. |
| Russian comments/strings in source | Low-to-medium | Developer-facing source comments should be English; user-facing docs can be handled separately if desired. |
| Low-risk optimization | Low | Only accept changes with obvious benefit and strong tests. |

## Files And Directories To Inspect

Security-sensitive Rust:
- `crates/crypto-core/src/`
- `crates/desktop-client/src/`
- `crates/oracle/src/`
- `crates/storage-node/src/`
- `crates/oracle/tests/`
- `migrations/`

Frontend and UI security:
- `crates/desktop-client/ui/src/`
- `crates/desktop-client/ui/package.json`
- `crates/desktop-client/ui/package-lock.json`
- `crates/desktop-client/capabilities/`
- `crates/desktop-client/tauri.conf.json`

Runtime and audit automation:
- `scripts/`
- `Makefile`
- `docker-compose.yml`
- `Cargo.toml`
- `Cargo.lock`
- `crates/*/Cargo.toml`

Docs and policy:
- `README.md`
- `QUICKSTART.md`
- `SECURITY.md`
- `docs/RUNTIME_VERIFICATION.md`
- `AGENTS.md`
- `.ai-factory/HANDOFF_CURRENT.md`

Manual-review candidates already observed:
- `crates/desktop-client/buildй.rs`
- `crates/desktop-client/build1й.rs`
- Russian developer-facing text in `Makefile` and `QUICKSTART.md`

## Exact Audit Commands

Run commands from repo root unless a `cd` is shown. Prefer `rg`; fallback commands are included for environments without ripgrep.

### Baseline Git And File Inventory

```bash
git status --short
git log --oneline -12
rg --files crates scripts migrations docs README.md QUICKSTART.md SECURITY.md Cargo.toml Cargo.lock docker-compose.yml Makefile
rg --files | rg '[^[:ascii:]]'
```

Fallback:

```bash
find crates scripts migrations docs -type f
find . -path './target' -prune -o -path './crates/desktop-client/ui/node_modules' -prune -o -print | LC_ALL=C grep -n '[^ -~]'
```

### Russian/Cyrillic Comments And Strings

Target source/config/docs where developer-facing text should be English:

```bash
rg -n --pcre2 '[\p{Cyrillic}]' crates scripts migrations Makefile Cargo.toml docker-compose.yml README.md QUICKSTART.md SECURITY.md docs
```

To narrow to Rust/TS/JS/source comments and strings:

```bash
rg -n --pcre2 '[\p{Cyrillic}]' crates scripts migrations -g '*.rs' -g '*.ts' -g '*.tsx' -g '*.js' -g '*.jsx' -g '*.sql' -g '*.toml' -g '*.json' -g '*.sh'
```

Fallback:

```bash
grep -RInP '[\p{Cyrillic}]' crates scripts migrations Makefile README.md QUICKSTART.md SECURITY.md docs 2>/dev/null || true
```

Manual review rule:
- Translate comments and developer-facing strings to English.
- Do not rewrite user-facing product copy unless it is clearly developer/demo-facing.
- Do not change behavior while translating comments.

### TODO/FIXME/HACK/XXX/Stale Markers

```bash
rg -n '\b(TODO|FIXME|HACK|XXX|TEMP|WIP|placeholder|stub|legacy|deprecated|remove before|debug only)\b' crates scripts migrations README.md QUICKSTART.md SECURITY.md docs Makefile
```

Fallback:

```bash
grep -RInE '\b(TODO|FIXME|HACK|XXX|TEMP|WIP|placeholder|stub|legacy|deprecated|remove before|debug only)\b' crates scripts migrations README.md QUICKSTART.md SECURITY.md docs Makefile 2>/dev/null || true
```

### Console Logging, Debugger, dbg, println

```bash
rg -n '(console\.(log|debug|info|warn|error)|debugger\b)' crates/desktop-client/ui/src
rg -n '(dbg!|println!|eprintln!)' crates scripts
rg -n 'tracing::(trace|debug|info|warn|error)!|log::(trace|debug|info|warn|error)!' crates
```

Fallback:

```bash
grep -RInE '(console\.(log|debug|info|warn|error)|debugger\b)' crates/desktop-client/ui/src 2>/dev/null || true
grep -RInE '(dbg!|println!|eprintln!)' crates scripts 2>/dev/null || true
```

### Raw Secret Terms And Sensitive Data Sinks

Use these scans only to identify review targets; do not paste secret values.

```bash
./scripts/check-sensitive-logs.sh
```

```bash
rg -n -i '(seed phrase|mnemonic|private[_ -]?key|secret|password|passphrase|jwt|bearer|storage[_ -]?token|token=|tx_blob|signature|aes[_ -]?key|file[_ -]?key|plaintext|plain[_ -]?text|decrypted|recovery phrase|qr payload|raw storage key)' crates scripts migrations README.md QUICKSTART.md SECURITY.md docs
```

Fallback:

```bash
grep -RInEi '(seed phrase|mnemonic|private[_ -]?key|secret|password|passphrase|jwt|bearer|storage[_ -]?token|token=|tx_blob|signature|aes[_ -]?key|file[_ -]?key|plaintext|plain[_ -]?text|decrypted|recovery phrase|qr payload|raw storage key)' crates scripts migrations README.md QUICKSTART.md SECURITY.md docs 2>/dev/null || true
```

### Security-Specific Code Paths

```bash
rg -n 'Authorization|Bearer|jwt|token|StorageToken|sign_storage_token|verify_token|CORS|rate_limit|RateLimit|Origin|headers|Set-Cookie|cookie|session|device|qr|QRCode|tx_blob|sign|decrypt|encrypt|KeyEnvelope|owner|recipient|transfer|grant|file_replicas' crates
```

Manual review focus:
- route authorization before handler logic
- owner/recipient checks before download/decrypt/access metadata
- storage token operation/key/expiry verification
- no signed tokenized URLs in logs/errors
- QR payload canonicalization and signature verification
- local-only wallet/seed/private key handling
- XRPL tx blob treatment

### Dead Code, Unused Exports, Duplicates

```bash
cargo check --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

If `-D warnings` is too noisy, re-run for report-only:

```bash
cargo clippy --workspace --all-targets --all-features
```

Search likely stale duplicate files:

```bash
rg --files | rg '(^|/)(test_|old_|backup_|copy_|tmp_|temp_|.*[0-9]+[^/]*\.(rs|ts|tsx|js|jsx)$|.*[^[:ascii:]].*)'
```

Optional duplicate-code tooling only if already installed; do not install during audit without approval:

```bash
which cargo-udeps
which cargo-machete
which jscpd
```

Fallback manual duplicate helper scan:

```bash
rg -n 'fn safe_|fn validate_|fn verify_|fn normalize_|fn sanitize_|fn redact_|function (safe|validate|verify|normalize|sanitize|redact)' crates
```

### Rust Formatting, Build, Tests, Audit

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Dependency audit:

```bash
cargo audit
```

Project strict audit:

```bash
make security-audit-strict
```

If `cargo-audit` is not installed:

```bash
make security-audit
```

Record the missing-tool limitation rather than installing without approval.

### Frontend Lint, Typecheck, Build, Audit

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
npm audit --audit-level=high
cd ../../..
```

For full advisory inventory:

```bash
cd crates/desktop-client/ui
npm audit --audit-level=moderate
npm audit --json
cd ../../..
```

Do not run `npm audit fix` during audit unless a separate dependency-fix task is approved.

### Docker And Runtime Assumptions

```bash
rg -n '(password|dev_password|ports:|0.0.0.0|localhost|REQUIRE_AUTH|ORACLE_PUBLIC_KEY|CORS|ENVIRONMENT|healthcheck|volumes:|privileged|cap_add|network_mode)' docker-compose.yml Makefile SECURITY.md README.md QUICKSTART.md crates/oracle/src crates/storage-node/src
```

Manual review focus:
- dev credentials clearly marked local-only
- production requires `REQUIRE_AUTH=true`, `ORACLE_PUBLIC_KEY`, restricted CORS, HTTPS/reverse proxy
- Docker profiles do not imply production hardening

## What Can Be Safely Auto-Cleaned

Only after audit confirms no behavior change:
- translate comments to English
- translate developer-facing Makefile/help text to English if commands remain identical
- remove duplicate obsolete build files if they are not referenced by Cargo, Tauri, scripts, docs, or CI
- delete unused imports flagged by compiler/clippy
- remove `console.log`, `debugger`, `dbg!`, and accidental `println!` debug statements when not part of CLI/dev tooling
- rename comments/docs headings for clarity
- consolidate duplicate pure helper functions only when call sites and tests make behavior equivalence obvious
- tighten overly broad log messages by replacing raw values with safe classifications/redaction

## What Requires Manual Review

- any code touching auth/session validity, QR payloads, signatures, grants, storage token generation/verification, wallet seed/key lifecycle, transfer/re-encryption, mint/finalize, owner decrypt, or Oracle route registration
- any SQL query consolidation or access-control helper extraction
- any dependency update that changes public API or lockfile significantly
- any CORS/rate-limit/security-header behavior change
- any UI copy that might change user trust decisions or recovery guidance
- any old runtime artifact whose purpose is unclear
- any migration cleanup; migrations should generally not be deleted or rewritten

## What Must Not Be Touched Without Separate Approval

- `.env`
- runtime state, wallet state, local app data, stored seeds/keys
- QR crypto/canonical payload/signature semantics
- wallet derivation and seed policy
- transfer/re-encryption semantics
- mint/finalize flow
- owner download/decrypt logic
- storage token generation/verification semantics
- Oracle route structure or auth boundary behavior
- schema/migrations beyond read-only review
- production-impacting Docker/runtime assumptions without a separate hardening plan

## Phased Implementation Plan

### Phase 1: Audit Baseline And Evidence Discipline
- [ ] Task 1: Establish clean audit baseline and safe evidence rules.

  Deliverable:
  - Current branch/status and recent commits.
  - Confirm audit ignores in `.ai-factory/SECURITY.md` if present.
  - Confirm no `.env` values are printed or staged.

  Files to inspect:
  - `.ai-factory/SECURITY.md`
  - `SECURITY.md`
  - `.gitignore`
  - `scripts/check-sensitive-logs.sh`
  - `scripts/security-audit.sh`

  Logging requirements:
  - Record only safe command summaries and file paths.
  - Do not paste raw logs that may include secrets.

  Checks:
  - `git status --short`
  - `./scripts/check-sensitive-logs.sh`

### Phase 2: Automated Security Gates
- [ ] Task 2: Run and triage automated security checks.

  Deliverable:
  - Categorized findings from sensitive log scan, Rust audit, npm audit, strict audit, and clippy.
  - Mark each finding as blocker, non-blocking hardening, false positive, or requires manual review.

  Files to inspect:
  - `Cargo.toml`, `Cargo.lock`, `crates/*/Cargo.toml`
  - `crates/desktop-client/ui/package.json`
  - `crates/desktop-client/ui/package-lock.json`
  - `scripts/`

  Logging requirements:
  - Include advisory names and dependency paths only.
  - Do not include environment values or runtime secrets.

  Checks:
  - `cargo fmt --all --check`
  - `cargo check --workspace`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `make security-audit-strict`
  - frontend lint/typecheck/build/audit commands listed above

### Phase 3: Manual Security Review By Trust Boundary
- [ ] Task 3: Review security-sensitive boundaries preserving MVP behavior.

  Deliverable:
  - Findings and proposed fixes for:
    - secret logging/redaction
    - QR payload handling
    - storage token handling
    - Oracle auth/session handling
    - wallet seed/key lifecycle
    - XRPL signing and tx blob handling
    - file encryption/decryption boundaries
    - transfer/re-encryption
    - owner/recipient download access control
    - CORS/security headers/rate limits
    - error messages and user-facing errors
    - Docker/local runtime assumptions
    - security-sensitive helper test coverage

  Files to inspect:
  - `crates/crypto-core/src/`
  - `crates/desktop-client/src/`
  - `crates/oracle/src/`
  - `crates/storage-node/src/`
  - `crates/desktop-client/ui/src/`
  - `docker-compose.yml`
  - `SECURITY.md`

  Logging requirements:
  - Use safe file/line references and paraphrased issue descriptions.
  - Do not paste secret-bearing request/response examples.

  Checks:
  - Existing unit/integration tests relevant to any proposed fix.
  - Add tests only in later implementation tasks where a fix changes security-sensitive helpers.

### Phase 4: Code Quality, Dead/Stale/Debug Audit
- [ ] Task 4: Identify garbage/dead/debug/stale/duplicated code and classify cleanup risk.

  Deliverable:
  - Inventory of safe cleanup candidates.
  - Manual-review list for risky cleanup.
  - Explicit decision on suspicious files with non-ASCII names:
    - `crates/desktop-client/buildй.rs`
    - `crates/desktop-client/build1й.rs`

  Files to inspect:
  - all `crates/**`
  - `scripts/`
  - `migrations/`
  - `Makefile`
  - docs listed above

  Logging requirements:
  - File paths and reasons only.
  - Do not include runtime data or local state.

  Checks:
  - `cargo check --workspace`
  - `cargo clippy --workspace --all-targets --all-features`
  - frontend lint/typecheck/build if UI cleanup is proposed

### Phase 5: English Source Comments And Developer Strings
- [ ] Task 5: Remove Russian comments and Russian developer-facing source strings.

  Deliverable:
  - List of Cyrillic occurrences.
  - Translate comments/developer-facing command text to English.
  - Keep behavior unchanged.

  Files likely to change:
  - `Makefile`
  - `QUICKSTART.md`
  - `Cargo.toml`
  - Rust/TS/SQL files found by the Cyrillic scan

  Logging requirements:
  - Report changed file paths and categories only.
  - Do not include secrets or `.env` values.

  Checks:
  - Cyrillic scan returns no source-code Russian comments/strings except explicitly accepted user-facing docs if any.
  - `cargo fmt --all --check`
  - `cargo check --workspace`
  - frontend checks if UI source changes
  - `git diff --check`

### Phase 6: Low-Risk Cleanup And Optimization
- [ ] Task 6: Apply only low-risk cleanup/optimization with tight verification.

  Deliverable:
  - Small, reversible patches grouped by risk area.
  - No runtime behavior changes unless a proven bug fix has a separate approved plan.

  Allowed examples:
  - remove unreferenced stale files
  - remove debug-only statements
  - simplify obviously duplicated pure helper code
  - narrow logs to safe structured fields
  - clean unused imports or dead private functions flagged by compiler/clippy

  Disallowed examples:
  - changing crypto semantics
  - changing route/auth behavior
  - changing transfer/re-encryption, mint/finalize, owner decrypt, or storage token behavior
  - broad SQL refactors

  Checks:
  - targeted package checks for touched areas
  - full final verification checklist below

### Phase 7: Audit Report And Final Verification
- [ ] Task 7: Produce final audit summary and run full verification.

  Deliverable:
  - Security/code-quality audit summary in an existing doc or a new `docs/SECURITY_AUDIT.md` if approved.
  - Finding table with severity, affected files, status, and next action.
  - Final verification evidence.

  Files likely to change:
  - `SECURITY.md`
  - `docs/RUNTIME_VERIFICATION.md`
  - optional `docs/SECURITY_AUDIT.md`
  - README only if commands/status need update

  Logging requirements:
  - Findings must avoid secret values and raw payloads.
  - Use safe phase names and command statuses.

  Checks:
  - all final verification commands below

## Proposed Commit Boundaries

Keep commits small and reversible:

1. `Audit security posture`
   - documentation-only audit findings, no runtime source changes.
2. `Remove stale debug artifacts`
   - dead/debug/stale cleanup with no behavior change.
3. `Translate developer comments to English`
   - comment and developer-facing text only.
4. `Harden safe logging and errors`
   - only if audit finds non-blocking log/error issues; no secret values.
5. `Improve security helper coverage`
   - tests for redaction/token/auth helpers without behavior changes.
6. `Apply low-risk quality cleanup`
   - small clippy/dead-code/duplication cleanups.
7. `Document MVP security audit`
   - final report and verification evidence.

If a blocker or behavior-changing security bug is found, stop and create a separate fix plan before editing runtime-sensitive code.

## Final Verification Checklist

Run after any implementation arising from this audit:

```bash
git status --short
git diff --stat
git diff --check
```

```bash
./scripts/check-sensitive-logs.sh
```

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

```bash
make security-audit-strict
```

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
npm audit --audit-level=high
cd ../../..
```

If dependency-advisory cleanup is part of the implementation:

```bash
cargo audit
```

```bash
cd crates/desktop-client/ui
npm audit --audit-level=moderate
cd ../../..
```

If runtime-sensitive code changes are approved later, rerun the safe MVP smoke checklist from `docs/RUNTIME_VERIFICATION.md` without resetting state:
- Oracle `/health`
- storage-node `/health`
- owner download/decrypt safe phases
- transfer/re-encryption safe phases if transfer code changed
- no tokenized URLs or raw keys in fresh logs

## Next Step

To execute this plan after review:

```text
$aif-implement
```

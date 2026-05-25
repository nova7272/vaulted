# Plan: Enforce 12-Word Seed Only
Created: 2026-05-25
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, focused crypto-core, desktop command, and UI checks
- **Logging:** no secret diagnostics; allowed fields only are `word_count`, `validation_status`, command name, UI step, and error code/status
- **Docs:** update only seed-policy docs or user-facing copy directly affected by removing 24-word support
- **Security:** do not log or print seed phrases, mnemonic entropy, private keys, derived keys, AES keys, JWTs, plaintext files, `tx_blob`, signatures, or decrypted content

## Roadmap Linkage
- **Milestone:** `VAULTED_AGENT_INSTRUCTIONS.md` task 5, "Enforce 12-word seed only"
- **Rationale:** XRPL mint / Oracle finalize / by-NFT linkage blocker is complete, and the instruction file marks 12-word seed enforcement as the next production MVP task.

## Scope
- Enforce the production MVP policy that Vaulted seed phrases are exactly 12 words.
- Create wallet must generate exactly 12 words.
- Restore and validation commands must reject 6, 18, and 24 words before key derivation.
- Auth UI must contain no 24-word option, no Advanced 24-word mode, and no copy that says 12 or 24 words.
- Keep the intended backup ceremony, including one-time display, copy warning, and "I saved this seed phrase offline" gate.
- Do not touch XRPL mint/signing/serialization, Oracle finalize/linking, file encryption/decryption, transfer/re-encryption, QR login, Wallet tab, or runtime reset/logout.

## Findings
- [crates/desktop-client/ui/src/screens/AuthScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/AuthScreen.tsx:52) stores `advancedSeed` UI state.
- [crates/desktop-client/ui/src/screens/AuthScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/AuthScreen.tsx:68) chooses `wordCount = advancedSeed ? 24 : 12`.
- [crates/desktop-client/ui/src/screens/AuthScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/AuthScreen.tsx:126) tells users restore supports "12 or 24 word phrase".
- [crates/desktop-client/ui/src/screens/AuthScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/AuthScreen.tsx:130) exposes the Advanced 24-word checkbox.
- [crates/desktop-client/ui/src/screens/AuthScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/AuthScreen.tsx:177) restore placeholder says "12 or 24 word".
- [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs:56) accepts an optional `word_count` in `create_vaulted_wallet` and passes it through to `SeedManager::generate_mnemonic`.
- [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs:86) restore relies on `SeedManager::validate_mnemonic`, so restore currently accepts 24 words.
- [crates/crypto-core/src/seed.rs](/home/riggle/vaulted/crates/crypto-core/src/seed.rs:13) defines `DEFAULT_MNEMONIC_WORDS = 12`.
- [crates/crypto-core/src/seed.rs](/home/riggle/vaulted/crates/crypto-core/src/seed.rs:15) defines `ADVANCED_MNEMONIC_WORDS = 24`.
- [crates/crypto-core/src/seed.rs](/home/riggle/vaulted/crates/crypto-core/src/seed.rs:24) generates 12 words from 16 bytes of OS CSPRNG entropy and 24 words from 32 bytes.
- [crates/crypto-core/src/seed.rs](/home/riggle/vaulted/crates/crypto-core/src/seed.rs:44) validates either 12 or 24 words.
- [crates/crypto-core/src/seed.rs](/home/riggle/vaulted/crates/crypto-core/src/seed.rs:76) has a test proving 24-word support, which must be inverted/removed.
- No React test files were found under `crates/desktop-client/ui/src`; UI coverage should come from lint, TypeScript, build, and runtime checks unless a test framework is introduced in a separate task.

## Questions Answered
- **Where is 24-word generation currently exposed?** In `AuthScreen.tsx` via `advancedSeed`, `wordCount = advancedSeed ? 24 : 12`, and the `<details className="v-advanced-toggle">` checkbox.
- **Does backend accept `wordCount=24` or arbitrary word counts?** It accepts the `word_count` parameter and delegates to `SeedManager::generate_mnemonic`; current crypto-core accepts 12 and 24, rejects other counts.
- **Does restore accept 24-word mnemonic today?** Yes. `restore_vaulted_wallet` calls `SeedManager::validate_mnemonic`, which currently accepts 12 or 24 words.
- **Is seed generated through BIP-39 + OS CSPRNG with 128-bit entropy for 12 words?** Yes. `SeedManager::generate_mnemonic(12)` fills 16 bytes with `OsRng`, builds a BIP-39 English mnemonic with `Mnemonic::from_entropy_in`, then zeroizes the entropy buffer.
- **What exact files need minimal changes?** `crates/crypto-core/src/seed.rs`, `crates/crypto-core/src/lib.rs`, `crates/desktop-client/src/commands.rs`, `crates/desktop-client/ui/src/screens/AuthScreen.tsx`, and directly affected docs such as `README.md`, `QUICKSTART.md`, or `SECURITY.md` only if they mention 12/24-word support.
- **What tests should be added or updated?** Update crypto-core seed tests to prove 12-word generation and reject 6/18/24-word validation/generation. Add desktop command-level tests only if existing command test scaffolding can do so without constructing full Tauri state; otherwise rely on crypto-core plus UI/static checks for this narrow policy.

## Tasks

- [x] 1. Enforce strict 12-word policy in crypto-core
  - Files likely to change:
    - [crates/crypto-core/src/seed.rs](/home/riggle/vaulted/crates/crypto-core/src/seed.rs)
    - [crates/crypto-core/src/lib.rs](/home/riggle/vaulted/crates/crypto-core/src/lib.rs)
  - Deliverable: `SeedManager::generate_mnemonic` accepts only `DEFAULT_MNEMONIC_WORDS`, and `SeedManager::validate_mnemonic` accepts only 12 words before parsing/seed derivation.
  - Expected behavior: 12-word generation still uses BIP-39 with 16 bytes from `OsRng`; 6, 18, 24, and arbitrary counts fail with a safe policy error that does not echo mnemonic words.
  - Logging requirements: add no logs; errors may mention only required `word_count` policy, not provided words.
  - Dependency notes: preserve `mnemonic_to_seed` flow and only tighten validation; do not change derivation paths or wallet/key derivation.

- [x] 2. Ignore/remove create-wallet word count override in desktop command boundary
  - Files likely to change:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
  - Deliverable: `create_vaulted_wallet` always generates `DEFAULT_MNEMONIC_WORDS` and no longer honors a caller-supplied 24-word request.
  - Expected behavior: even if an old UI or manual invoke passes `wordCount: 24`, the command returns a 12-word mnemonic or rejects non-12 input with a safe error; choose the smaller code path consistent with the final `SeedManager` API.
  - Logging requirements: add no seed logs; if diagnostics are needed, log only command name, `word_count`, and validation status.
  - Dependency notes: keep response shape unchanged so the backup UI still receives `mnemonic` only during creation.

- [x] 3. Remove 24-word option and copy from Auth UI
  - Files likely to change:
    - [crates/desktop-client/ui/src/screens/AuthScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/AuthScreen.tsx)
    - [crates/desktop-client/ui/src/index.css](/home/riggle/vaulted/crates/desktop-client/ui/src/index.css) only if unused advanced-toggle styles are removed
  - Deliverable: Auth UI has no `advancedSeed` state, no Advanced 24-word checkbox, no 24-word text, and create calls `create_vaulted_wallet` without a selectable word count or with fixed `wordCount: 12`.
  - Expected behavior: create flow status says 12-word recovery phrase; restore copy and placeholder say 12 words; restore button can remain disabled until at least/exactly 12 entered, with command validation as the source of truth.
  - Logging requirements: no console logs or seed diagnostics; UI errors must not include mnemonic words.
  - Dependency notes: keep backup ceremony unchanged and do not touch QR login, Wallet tab, logout/reset, mint, upload, or file screens.

- [x] 4. Update focused tests for strict seed policy
  - Files likely to change:
    - [crates/crypto-core/src/seed.rs](/home/riggle/vaulted/crates/crypto-core/src/seed.rs)
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs) only if practical command-boundary tests can be added without broad Tauri state setup
  - Deliverable: tests prove generation produces 12 words and strict restore validation rejects 6, 18, and 24 words.
  - Expected behavior: replace the current `supports_24_word_advanced_mnemonic_policy` test with rejection coverage; include a valid 12-word generated mnemonic validation test without printing the phrase.
  - Logging requirements: tests must not print mnemonic words, entropy, private keys, or derived secrets.
  - Dependency notes: do not introduce a frontend test framework in this task; use existing Rust and UI build checks.

- [x] 5. Update directly affected docs and run verification
  - Files likely to change:
    - [README.md](/home/riggle/vaulted/README.md)
    - [QUICKSTART.md](/home/riggle/vaulted/QUICKSTART.md)
    - [SECURITY.md](/home/riggle/vaulted/SECURITY.md)
    - historical reports only if they contain active current guidance, not archival notes
  - Deliverable: any current docs that mention seed length describe exactly 12 words and do not mention 24-word mode.
  - Expected behavior: docs remain concise and do not include example seed phrases.
  - Logging requirements: no runtime logging changes.
  - Dependency notes: skip archival/historical docs unless their wording is presented as current product behavior.

## Verification Commands

Run commands separately:

```bash
cargo fmt --all --check
cargo check -p xrpl-vault-crypto-core
cargo test -p xrpl-vault-crypto-core
cargo check -p xrpl-vault-desktop
cargo test -p xrpl-vault-desktop
```

Run UI checks because `AuthScreen.tsx` changes:

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

Optional broader check if time permits:

```bash
cargo test --workspace
```

## Runtime UI Checks
- Start the desktop UI in the normal dev flow.
- On the initial Auth screen, verify there is no Advanced section and no 24-word option.
- Click `Create wallet`; verify the backup ceremony shows exactly 12 numbered words.
- Verify `Continue to Vaulted` stays disabled until `I saved this seed phrase offline` is checked.
- Verify restore placeholder and helper text mention only 12 words.
- Attempt restore with 6, 18, and 24 words; verify each fails with a safe generic policy error that does not display or log the entered phrase.
- Restore with a valid 12-word Vaulted phrase only in a safe local test session; do not print or save the phrase outside the intended backup ceremony.

## Expected Successful State
- `SeedManager::generate_mnemonic(DEFAULT_MNEMONIC_WORDS)` generates exactly 12 BIP-39 words using 128 bits of OS CSPRNG entropy.
- `SeedManager::generate_mnemonic(24)` and restore validation for 24 words fail under the strict MVP policy.
- Auth UI has no 24-word option, advanced 24-word mode, or 12/24 wording.
- No seed phrase, mnemonic entropy, private key, or derived secret is logged or displayed outside the intended backup ceremony.

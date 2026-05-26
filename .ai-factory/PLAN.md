# Plan: Verify And Harden Owner Download/Decrypt
Created: 2026-05-26
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, include focused Rust tests for any changed parsing/error/logging helpers and UI lint/type/build for any frontend change.
- **Logging:** safe diagnostics only. Allowed fields: command name, request phase, NFT token id, vault object id, storage node id, storage key hash/truncated non-secret identifier, byte counts, endpoint status, status enum. Do not log seed phrase, mnemonic entropy, private keys, derived keys, AES keys, JWTs, storage tokens, `tx_blob`, signatures, plaintext files, decrypted content, recovery phrase, QR payloads, QR approval signatures, or raw encrypted key material.
- **Docs:** no docs changes for implementation; runtime evidence can be added later through the runtime verification document when a broader milestone is verified.
- **Scope:** minimal production-MVP follow-up for “Download/decrypt works as owner” from the XRPL Grants MVP checklist.

## Next Roadmap Item
- **Next item:** Owner download/decrypt for minted vault files.
- **Why it is next:** The completed and runtime-tested items cover wallet, QR login, upload/encrypted payload, metadata URL, mint, account NFTs, and Oracle finalization. In the `VAULTED_AGENT_INSTRUCTIONS.md` MVP checklist, the next unfinished item after “Vault object finalizes in Oracle” is “Download/decrypt works as owner.” Transfer NFT/file access and recipient decrypt depend on a reliable owner read path, so owner download/decrypt should be validated and hardened first.

## Current Code Surface
- Desktop command already exists:
  - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - `download_file`
    - `request_file_access`
    - filename/content-key unwrap helpers
- Files UI already exposes owner download:
  - [crates/desktop-client/ui/src/screens/FilesScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/FilesScreen.tsx)
- Oracle protected access/download routes already exist:
  - [crates/oracle/src/api/files.rs](/home/riggle/vaulted/crates/oracle/src/api/files.rs)
  - [crates/oracle/src/api/file_proxy.rs](/home/riggle/vaulted/crates/oracle/src/api/file_proxy.rs)
  - [crates/oracle/src/api/mod.rs](/home/riggle/vaulted/crates/oracle/src/api/mod.rs)
- Storage-node fragment serving exists:
  - [crates/storage-node/src/main.rs](/home/riggle/vaulted/crates/storage-node/src/main.rs)

## Key Risks To Inspect
- Owner download may fail at one of four boundaries: Oracle access metadata, Oracle proxy download, storage-node fragment retrieval, or local content-key/file decrypt.
- Existing Oracle file proxy debug logging appears to include a full signed storage URL. If enabled at debug level, that can expose a storage token. The implementation should remove or redact that before runtime testing.
- Desktop `download_file` must not log decrypted filenames if those could reveal sensitive user file names. Prefer byte counts, phase, NFT id, and status only.
- Error handling should preserve actionable user messages without exposing response bodies that may include tokenized URLs or secret-bearing payloads.
- The runtime should save decrypted bytes only to the user-selected output path and never log or display file contents.

## Tasks

- [x] 1. Inspect owner download/decrypt path end to end
  - Files likely to inspect:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/src/oracle/api.rs](/home/riggle/vaulted/crates/desktop-client/src/oracle/api.rs)
    - [crates/desktop-client/ui/src/screens/FilesScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/FilesScreen.tsx)
    - [crates/oracle/src/api/files.rs](/home/riggle/vaulted/crates/oracle/src/api/files.rs)
    - [crates/oracle/src/api/file_proxy.rs](/home/riggle/vaulted/crates/oracle/src/api/file_proxy.rs)
    - [crates/storage-node/src/main.rs](/home/riggle/vaulted/crates/storage-node/src/main.rs)
  - Deliverable: confirm the exact owner download flow: UI save dialog -> Tauri `download_file` -> Oracle `/files/{nft}/access` -> Oracle `/files/{nft}/download` -> storage-node `/fragments/{key}` -> local decrypt -> write selected output path.
  - Expected behavior: no changes yet unless an obvious security violation is found in the inspected path.
  - Logging requirements: no new logs in this task; record only safe findings in implementation notes/final response.
  - Dependency notes: do not inspect or modify transfer/re-encryption beyond understanding shared helper dependencies.

- [x] 2. Remove or redact token-bearing download diagnostics
  - Files likely to change:
    - [crates/oracle/src/api/file_proxy.rs](/home/riggle/vaulted/crates/oracle/src/api/file_proxy.rs)
    - [crates/storage-node/src/main.rs](/home/riggle/vaulted/crates/storage-node/src/main.rs) only if storage-node logs expose token-bearing URLs or headers
  - Deliverable: ensure Oracle/storage logs do not include signed storage tokens or full tokenized URLs during owner download.
  - Expected behavior: logs still show safe phase, NFT token id, storage node id, endpoint status, and byte counts where useful.
  - Logging requirements: do not log query strings, `token=...`, JWTs, storage tokens, encrypted keys, plaintext, decrypted content, or user-selected output path if avoidable.
  - Dependency notes: preserve Oracle proxy behavior and storage token verification semantics.

- [x] 3. Harden desktop owner download error handling and diagnostics
  - Files likely to change:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs)
    - [crates/desktop-client/ui/src/utils/formatError.ts](/home/riggle/vaulted/crates/desktop-client/ui/src/utils/formatError.ts) only if user-facing mapping is too generic
    - [crates/desktop-client/ui/src/screens/FilesScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/FilesScreen.tsx) only if the UI needs a minimal safer message/state
  - Deliverable: keep `download_file` user-safe and diagnostic enough: phase logs, NFT id, byte counts, status enum/status code, no file contents, no AES/encrypted key material, no storage token, no raw Oracle response body if it may contain sensitive content.
  - Expected behavior: failures distinguish unavailable storage, ownership/authorization failure, and decrypt failure where practical; owner success returns the selected output path to the UI.
  - Logging requirements: allowed diagnostics only; do not log decrypted filename/content or key material.
  - Dependency notes: preserve existing owner download command signature unless a narrow response shape is clearly needed.

- [x] 4. Add/update focused tests for changed helpers
  - Files likely to change:
    - [crates/desktop-client/src/commands.rs](/home/riggle/vaulted/crates/desktop-client/src/commands.rs) tests module, if helper logic changes
    - [crates/oracle/src/api/file_proxy.rs](/home/riggle/vaulted/crates/oracle/src/api/file_proxy.rs) tests, if URL/log sanitization helper is extracted
    - [crates/desktop-client/ui/src/utils/formatError.ts](/home/riggle/vaulted/crates/desktop-client/ui/src/utils/formatError.ts) only if a tested pure formatter exists or is added
  - Deliverable: add narrow tests only for new pure helper logic, such as tokenized URL redaction or HTTP status/error classification.
  - Expected behavior: tests prove storage tokens are not retained by sanitizer helpers and owner-download error categories remain stable.
  - Logging requirements: tests must not print storage tokens, encrypted keys, decrypted content, or file contents.
  - Dependency notes: do not add broad runtime/integration tests that require live Oracle/storage unless the existing test harness already supports it.

- [x] 5. Run verification and runtime owner download checklist
  - Files likely to change:
    - none beyond implementation files above
  - Deliverable: run local checks and perform a runtime download/decrypt test against an already minted active vault object.
  - Expected behavior: decrypted owner file is saved to a user-selected path; logs contain no forbidden values; Oracle/storage/desktop health remains good.
  - Logging requirements: inspect logs for forbidden values before commit.
  - Dependency notes: do not reset runtime state, log out, clear wallets, delete data, modify `.env`, or change completed wallet/QR/mint areas.

## Verification Commands

Frontend checks if UI changes:

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
cd ../../..
```

Rust checks:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
./scripts/check-sensitive-logs.sh
git diff --check
```

If only Oracle Rust changes are made during implementation, the implementer may run the narrow package checks first:

```bash
cargo check -p xrpl-vault-oracle
cargo test -p xrpl-vault-oracle
```

## Runtime Checks
- Start Oracle, storage-node, and desktop using the existing dev workflow; do not reset runtime state.
- Use an already active minted vault object from the Files/Vaults screen.
- Click owner `Download`, choose a temporary output path, and confirm the command completes.
- Confirm desktop progress reaches download/decrypt/save/complete.
- Confirm the saved file byte size/content matches the original test file when the original is available.
- Confirm Oracle logs show owner access/download success without signed storage URLs or storage tokens.
- Confirm storage-node logs show fragment serving without token values.
- Confirm failure cases are safe if tested: stopped storage-node shows a storage-unavailable message; wrong owner/expired session shows authorization/session message.
- Run `./scripts/check-sensitive-logs.sh` after the runtime test if logs are in the scanned paths, and manually inspect `/tmp/vaulted-*.log` if runtime logs were tee’d there.

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
- NFT transfer, recipient grant acceptance, and re-encryption.
- Mobile app implementation.
- Runtime reset/logout, clearing local app data, or `.env` changes.

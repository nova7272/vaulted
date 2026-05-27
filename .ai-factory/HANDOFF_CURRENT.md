# Vaulted current handoff checkpoint

Date: 2026-05-27

## Status

Production-MVP transfer/re-encryption is now through the runtime checkpoint. The current working milestone is no longer XRPL mint, wallet send, QR login, owner decrypt, or transfer acceptance plumbing. The next work should start from the remaining roadmap items after transfer/re-encryption unless runtime evidence shows a regression.

Security reminder: do not log or paste seed phrases, mnemonic entropy, private keys, derived keys, AES keys, JWTs, storage tokens, `tx_blob`, signatures, plaintext file contents, decrypted content, recovery phrases, QR payloads, QR approval signatures, raw encrypted key material, tokenized URLs, or raw storage keys.

## Completed

- XRPL mint serialization.
- XRPL mint / Oracle finalize / by-NFT linkage.
- No-remint pending mint recovery.
- Oracle XRPL HTTP RPC verification endpoint.
- 12-word seed-only policy.
- Auth restart/logout lifecycle.
- Desktop window launch fallback.
- Read-only Wallet tab.
- Send XRP / Payment command.
- QR login demo-safe flow.
- QR polling rate-limit fix.
- QR approval lifecycle fix.
- Owner download/decrypt hardening.
- Owner download/decrypt runtime success.
- Local XRPL NFT transfer flow:
  - `NFTokenCreateOffer` signing/submission.
  - Oracle confirm-signed payload compatibility.
  - Incoming transfer visibility.
  - Accept UI crash fix.
  - `claim_nft` Tauri command registration.
  - `NFTokenAcceptOffer` signing/submission.
  - Oracle `complete_transfer`.
  - Recipient decrypt after re-encryption.

## Runtime-Tested Evidence

Owner download/decrypt runtime phases completed:

```text
access_metadata_ok
proxy_download_ok
unwrap_owner_key
content_key_unwrapped
payload_decrypted
complete
```

Transfer/re-encryption runtime completed:

```text
NFTokenCreateOffer -> tesSUCCESS
confirm-signed -> 200 OK
incoming offer visible
NFTokenAcceptOffer -> tesSUCCESS
Oracle completed locally accepted NFT transfer
unwrap_transferred_key
payload_decrypted
complete
```

Sensitive logging check passed after the owner decrypt and transfer checkpoints.

## Latest Relevant Commits

```text
50547f4 Update transfer runtime checkpoint plan
772b68b Register local NFT claim command
5903186 Fix incoming transfer accept UI crash
2b12dbf Fix transfer confirm signed payload
0668f67 Implement local XRPL NFT transfer flow
41e7df2 Harden owner download decrypt path
1d8414a Keep QR login polling alive through approval
258265e Make QR login polling rate limit safe
56e3ae7 Trace QR login command boundary
5f6deb0 Add demo safe QR login flow
9eae2d0 Add testnet XRP send from wallet
b7f1b30 Make desktop window launch visible
c5e19d9 Add read only wallet tab
d53aca4 Add green checkpoint handoff
bf61f7b Verify auth restart lifecycle
51b9749 Enforce 12 word seed policy
ce0f58a Configure Oracle XRPL HTTP RPC endpoint
0a47421 Recover restarted pending mint finalization
e7248df Recover pending mint finalization after submit
d92c579 Link vault objects after local mint finalization
25c48cc Fix post-mint NFTokenID finalization
7d54a89 Fix NFT file status mapping after mint
865fb68 Use xrpl-mithril codec for XRPL transaction serialization
```

## Remaining Roadmap

From `.ai-factory/VAULTED_AGENT_INSTRUCTIONS.md`, immediate tasks 1-8 are complete or have runtime checkpoint evidence. Remaining explicit roadmap items:

1. Polish UI for XRPL Grants demo.
2. Update runtime verification and README.

Final MVP acceptance gates still need a fresh, end-to-end confirmation pass before declaring production-ready MVP:

- Docker compose starts Postgres/Redis.
- Oracle starts and `/health` responds.
- Storage-node starts and `/health` responds.
- Desktop starts.
- Fresh create-wallet and restore-by-seed flow.
- QR login works or demo-safe QR is clearly presented.
- Wallet balance, receive QR, Send XRP, and transaction history behavior.
- Upload, encrypted payload upload, public metadata URL, mint, account NFT visibility, Oracle finalize.
- Owner download/decrypt.
- Transfer NFT/file access to another user.
- Recipient decrypt after re-encryption.
- `make security-audit-strict`.
- `cargo test --workspace`.
- Frontend lint/typecheck/build.
- README/demo script updated.

Items needing roadmap confirmation because this checkpoint does not prove final polish state:

- Whether a dedicated `Transfers` navigation view is required beyond the current Files/Activity transfer surfaces.
- Whether Wallet MVP is considered complete for receive QR, transaction history, XRPL connection status, and testnet/mainnet badge.
- Whether `docs/RUNTIME_VERIFICATION.md` should be created now or together with README/demo script updates.
- Whether final `make security-audit-strict` should run before UI polish or only at final release gate.

## Known Issues / Follow-Ups

- `.ai-factory/PLAN.md` was updated by the transfer runtime checkpoint plan commit and should be treated as historical context, not the next implementation target.
- Activity screen previously had a placeholder incoming-offer accept path; Files screen is the runtime-tested accept path. Confirm whether Activity should be wired to the same `claim_nft` command during UI polish.
- Final MVP still needs a clean all-up verification pass in a fresh runtime session.
- Do not reset runtime state, log out, clear wallets, or delete app data without explicit owner approval.

## How To Continue Safely

Recommended next planning prompt:

```text
$aif-plan Read AGENTS.md, .ai-factory/VAULTED_AGENT_INSTRUCTIONS.md, .ai-factory/HANDOFF_2026-05-25.md, and .ai-factory/HANDOFF_CURRENT.md first.

Create a plan only. Do not implement yet.

Transfer/re-encryption has runtime checkpoint evidence through recipient decrypt. Identify the next minimal production-MVP task from the remaining roadmap after transfer/re-encryption.

Do not touch completed XRPL mint, pending recovery, Oracle XRPL RPC, seed policy, auth lifecycle, desktop launch, Wallet/Send XRP, QR login, owner decrypt, or transfer/re-encryption code unless inspection is required.

Include exact files likely to inspect/change, tests, verification commands, runtime checks, and out-of-scope list.
```

Safe verification baseline before any push/review:

```bash
git status --short
git log --oneline -30
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
cd ../../..
./scripts/check-sensitive-logs.sh
git diff --check
```

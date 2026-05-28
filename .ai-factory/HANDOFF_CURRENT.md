# Vaulted current handoff checkpoint

Date: 2026-05-28

## Status

Final production-MVP verification passed. The fresh pass covered service health, Wallet/Send XRP, upload/mint/finalize, owner decrypt, transfer/re-encryption, recipient decrypt, sensitive logging retest, Rust gates, frontend gates, and final security audit.

QR login has one documented fresh-pass limitation: the QR UI/security surface passed, raw payload/copy was removed, Oracle-only wording was clarified, and the approval lifecycle had previous runtime evidence, but fresh approval was skipped because no second device/session was available.

No production blocker remains after the storage proxy failed-replica logging fix and retest.

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
- QR UI/security final-pass verification.
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
- Storage proxy failed-replica log redaction.
- Final MVP verification report update.

## Runtime-Tested Evidence

Service health:

```text
Oracle /health -> 200 OK
storage-node /health -> 200 OK
Postgres accepting connections
Redis healthy
```

Wallet / Send XRP:

```text
send_xrp_payment validation_status=input_valid
spendable_balance_valid
engine_result=tesSUCCESS
tx_hash=7358EBD2206746DB741CB97C722D5F92B09A29A149658BC62E207E358ADC480F
```

Fresh mint/finalize:

```text
NFTokenMint -> tesSUCCESS
tx_hash=CDCBBC5C415748A970DDAEF6630E9CB8C973B98CCCD03D4CEB9FB62B6436D3A9
nft_token_id=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FDC806A59010D42BE
by-NFT lookup -> 200 OK
status=active
```

Owner download/decrypt:

```text
access_metadata_ok
proxy_download_ok
unwrap_owner_key
content_key_unwrapped
payload_decrypted
complete
```

Transfer/re-encryption:

```text
transfer_id=cc31996f-d50f-4266-8afc-ab70369ab88e
offer_index=73279F7F968205554AC8810A5D2CE9822CAA6169810EB64F9B556A1CE581B858
NFTokenCreateOffer -> tesSUCCESS
create_offer_tx_hash=788B5514302452EE1A7594B271B7D071A97CC139D5E83B46E9EB3400BBBFC113
confirm-signed -> 200 OK
incoming offer visible
NFTokenAcceptOffer -> tesSUCCESS
accept_tx_hash=086E8C092A0935A85094E6A4E201229D6F17B067D0D1CE8314B5515E3ECCB40D
Oracle completed locally accepted NFT transfer
unwrap_transferred_key
content_key_unwrapped
payload_decrypted
complete
```

Sensitive logging:

```text
tokenized storage URL leak found during final pass
fixed in commit 29d4938
fresh failed upload line uses safe structured fields with error_class="connect"
no tokenized URL or fragment URL path in fresh failed upload line
./scripts/check-sensitive-logs.sh passed
```

Automated gates:

```text
cargo fmt --all --check passed
cargo check --workspace passed
cargo test --workspace passed
npm run lint passed
npx tsc --noEmit --project tsconfig.json passed
npm run build passed
git diff --check passed
make security-audit-strict completed
```

## Latest Relevant Commits

```text
29d4938 Redact storage proxy error logs
22e9514 Clarify QR login Oracle session UX
64a3e8f Plan final MVP verification pass
bc69b1a Update runtime verification docs
8bfda0a Polish demo UI safety surfaces
842737b Add current project handoff
50547f4 Update transfer runtime checkpoint plan
772b68b Register local NFT claim command
5903186 Fix incoming transfer accept UI crash
2b12dbf Fix transfer confirm signed payload
0668f67 Implement local XRPL NFT transfer flow
41e7df2 Harden owner download decrypt path
```

## Remaining Roadmap

Final MVP acceptance gates have fresh pass evidence or documented acceptable limitation:

- Docker compose starts Postgres/Redis.
- Oracle starts and `/health` responds.
- Storage-node starts and `/health` responds.
- Desktop starts.
- Fresh wallet/auth flow remains covered by current auth/runtime evidence.
- QR login UI/security works; fresh approval retest is optional with a second device/session.
- Wallet balance, receive surface, Send XRP, and transaction behavior.
- Upload, encrypted payload upload, public metadata URL, mint, account NFT visibility, Oracle finalize.
- Owner download/decrypt.
- Transfer NFT/file access to another user.
- Recipient decrypt after re-encryption.
- `make security-audit-strict`.
- `cargo test --workspace`.
- Frontend lint/typecheck/build.
- README/demo script and runtime verification docs updated.

## Known Issues / Follow-Ups

- Remove duplicate `XRPL_NODE_URL` in `.env` when safe.
- Consider dependency updates for yanked `aes 0.9.0` through `zip 8.6.0`.
- Consider dependency updates for the npm `brace-expansion` advisory through `@typescript-eslint/typescript-estree`.
- Optional full QR approval retest with a second device/session.
- Do not reset runtime state, log out, clear wallets, delete app data, or edit `.env` without explicit owner approval.

## How To Continue Safely

Recommended next prompt:

```text
Review the final MVP verification artifacts and identify only non-blocking release hardening follow-ups. Do not touch runtime state, wallet state, .env, or production source code unless explicitly approved.
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

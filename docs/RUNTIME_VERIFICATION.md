# Runtime Verification

Date: 2026-05-27

## Environment

- Postgres/Redis: local Docker Compose services.
- Oracle: local Axum service, health endpoint `http://127.0.0.1:3000/health`.
- Storage node: local storage service, health endpoint `http://127.0.0.1:9001/health`.
- Desktop: local Tauri desktop client.
- XRPL network: testnet.
- XRPL WebSocket role: desktop XRPL transaction and account flows.
- XRPL HTTP RPC role: Oracle ledger verification.

Do not paste secret runtime material into this document. Keep wallet recovery words, private material, local file keys, tokenized storage URLs, raw storage keys, raw approval payloads, transaction blobs, and decrypted file contents out of docs and logs.

## Runtime Checkpoint Evidence

The current production-MVP checkpoint has evidence for these completed areas:

- XRPL mint serialization works.
- XRPL mint finalization works with Oracle by-NFT linkage.
- Pending mint recovery prevents no-remint restart loss.
- Oracle XRPL ledger verification uses the HTTP RPC endpoint.
- 12-word wallet recovery policy is enforced.
- Auth restart/logout lifecycle is verified.
- Desktop launch/window fallback is verified.
- Wallet tab is present in read-only runtime mode.
- Send XRP / Payment command is implemented and runtime-tested.
- QR login has a demo-safe flow, polling rate-limit fix, and approval lifecycle fix.
- Owner download/decrypt is hardened and runtime-tested.
- Local XRPL NFT transfer and re-encryption are runtime-tested through recipient decrypt.
- XRPL Grants demo UI safety polish is complete.

Owner download/decrypt completed with these safe phases:

```text
access_metadata_ok
proxy_download_ok
unwrap_owner_key
content_key_unwrapped
payload_decrypted
complete
```

Transfer/re-encryption completed with these safe phases:

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

Recipient decrypt after re-encryption completed with:

```text
unwrap_transferred_key
payload_decrypted
complete
```

Sensitive logging checks passed after the owner download/decrypt and transfer/re-encryption checkpoints.

## MVP Checklist

| Check | Status | Evidence |
| --- | --- | --- |
| Docker Compose starts Postgres/Redis | Needs fresh final pass | Included in final rehearsal commands. |
| Oracle starts and `/health` responds | Needs fresh final pass | Health command documented below. |
| Storage-node starts and `/health` responds | Needs fresh final pass | Health command documented below. |
| Desktop starts | Complete | Desktop launch/window fallback verified. |
| Create wallet generates secure 12-word recovery words | Complete | 12-word policy enforced. |
| Restore by recovery words works | Complete | Auth restart/restore lifecycle verified. |
| QR login works or demo-safe QR is clearly implemented | Complete | Demo-safe QR login flow, polling, and approval lifecycle fixes complete. |
| Wallet tab shows XRP balance | Complete | Read-only Wallet tab works in runtime. |
| Receive QR works | Needs fresh final pass | Wallet receive display should be included in final rehearsal. |
| Send XRP works on testnet | Complete | Send XRP / Payment command runtime-tested. |
| Upload encrypts file locally | Complete | Existing file vault flow and owner decrypt checkpoint require local encryption boundary. |
| Encrypted payload uploads | Complete | Owner proxy download and decrypt checkpoint completed. |
| Public metadata URL returns `200` | Complete | XRPL mint / Oracle finalize / by-NFT linkage checkpoint completed. |
| Mint NFT succeeds | Complete | XRPL mint serialization and runtime mint finalization completed. |
| NFT appears in account NFTs | Complete | Mint checkpoint verified account NFT visibility. |
| Vault object finalizes in Oracle | Complete | Oracle finalize and by-NFT linkage completed. |
| Download/decrypt works as owner | Complete | Owner decrypt phases completed. |
| Transfer NFT/file access to another user works | Complete | Transfer/re-encryption phases completed. |
| Recipient decrypts after re-encryption | Complete | Recipient decrypt phases completed. |
| `make security-audit-strict` passes | Needs fresh final pass | Run before release-ready declaration. |
| `cargo test --workspace` passes | Needs fresh final pass | Run before release-ready declaration. |
| Frontend lint/typecheck/build passes | Needs fresh final pass | Run before release-ready declaration. |
| README/demo script updated | Complete after this docs change | See `README.md`. |

## Verification Commands

Start local infrastructure:

```bash
docker compose up -d postgres redis
docker compose ps
docker exec xrpl-vault-postgres pg_isready -U xrpl_vault -d xrpl_vault
```

Start Oracle:

```bash
set -a
source .env
set +a
cargo run -p xrpl-vault-oracle --bin oracle
```

Check Oracle health:

```bash
curl -i http://127.0.0.1:3000/health
```

Start storage-node:

```bash
set -a
source .env
set +a
REQUIRE_AUTH=false cargo run -p xrpl-vault-storage-node --bin storage-node
```

Check storage-node health:

```bash
curl -i http://127.0.0.1:9001/health
```

Launch desktop:

```bash
set -a
source .env
set +a
cargo run -p xrpl-vault-desktop
```

Run Rust verification:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

Run frontend verification:

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
cd ../../..
```

Run safety checks:

```bash
./scripts/check-sensitive-logs.sh
git diff --check
```

Run final release security gate when requested:

```bash
make security-audit-strict
```

## Demo Flow For Final Pass

1. Start Postgres/Redis with Docker Compose.
2. Start Oracle and confirm `/health`.
3. Start storage-node and confirm `/health`.
4. Launch desktop.
5. Create or restore a 12-word Vaulted wallet.
6. Confirm Wallet balance and receive address/QR.
7. Send testnet XRP.
8. Upload a file and confirm local encryption before upload.
9. Mint ownership NFT locally.
10. Confirm Oracle finalization and by-NFT lookup.
11. Download/decrypt as owner.
12. Transfer NFT/file access to a recipient.
13. Confirm recipient incoming offer visibility.
14. Accept the incoming offer with local `NFTokenAcceptOffer`.
15. Confirm Oracle completes the accepted transfer.
16. Confirm recipient decrypt after re-encryption.

## Known Issues And Follow-Ups

- A fresh all-up final pass is still required before declaring production-ready MVP.
- Dedicated Transfers navigation remains a roadmap confirmation item if the current Files/Activity transfer surfaces are not sufficient for the demo.
- Wallet MVP completeness for receive QR, transaction history, XRPL connection status, and testnet/mainnet badge still needs owner confirmation if those are treated as release blockers.
- Do not reset runtime state, log out, clear wallets, delete app data, or edit `.env` without explicit owner approval.

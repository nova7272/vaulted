# Runtime Verification

Date: 2026-05-28

## Environment

- Postgres/Redis: local Docker Compose services.
- Oracle: local Axum service, health endpoint `http://127.0.0.1:3000/health`.
- Storage node: local storage service, health endpoint `http://127.0.0.1:9001/health`.
- Desktop: local Tauri desktop client.
- XRPL network: testnet.
- XRPL WebSocket role: desktop XRPL transaction and account flows.
- XRPL HTTP RPC role: Oracle ledger verification.

Do not paste secret runtime material into this document. Keep wallet recovery words, private material, local file keys, tokenized storage URLs, raw storage keys, raw approval payloads, transaction blobs, and decrypted file contents out of docs and logs.

## Final Fresh Pass - 2026-05-28

Final MVP verification passed with one documented QR limitation: QR UI/security was verified in the fresh pass, and the approval lifecycle had previous runtime evidence, but fresh QR approval was skipped because no second device/session was available.

No production blocker remains after the storage proxy log redaction retest.

### Service Health

- Postgres accepted connections.
- Redis was healthy.
- Oracle `/health` returned `200 OK`.
- Storage-node `/health` returned `200 OK`.

### Wallet And Send XRP

```text
send_xrp_payment validation_status=input_valid
spendable_balance_valid
engine_result=tesSUCCESS
tx_hash=7358EBD2206746DB741CB97C722D5F92B09A29A149658BC62E207E358ADC480F
```

### QR Login

- QR renders.
- Raw payload/copy was removed.
- Oracle-only wording was clarified.
- Approval lifecycle was previously runtime-tested.
- Fresh approval was skipped because no second device/session was available for this final pass.

### Fresh Mint And Finalize

```text
NFTokenMint -> tesSUCCESS
tx_hash=CDCBBC5C415748A970DDAEF6630E9CB8C973B98CCCD03D4CEB9FB62B6436D3A9
nft_token_id=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FDC806A59010D42BE
by-NFT lookup -> 200 OK
status=active
```

### Owner Download And Decrypt

```text
access_metadata_ok
proxy_download_ok
unwrap_owner_key
content_key_unwrapped
payload_decrypted
complete
```

### Transfer And Re-Encryption

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

### Sensitive Logging

- A tokenized storage URL leak was found during final verification in an Oracle failed replica upload warning.
- The leak was fixed in commit `29d4938 Redact storage proxy error logs`.
- Fresh retest shows safe structured failure logging:

```text
Upload to storage node failed operation="upload" error_class="connect"
```

- Fresh failed upload logging contained no `token=` value and no fragment URL path.
- `./scripts/check-sensitive-logs.sh` passed.

### Automated Gates

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

Non-blocking audit notes:

- `cargo audit` reports allowed yanked `aes 0.9.0` through `zip 8.6.0`.
- `npm audit` reports one moderate `brace-expansion` advisory through `@typescript-eslint/typescript-estree`.

## Runtime Checkpoint Evidence

The production-MVP checkpoint has evidence for these completed areas:

- XRPL mint serialization works.
- XRPL mint finalization works with Oracle by-NFT linkage.
- Pending mint recovery prevents no-remint restart loss.
- Oracle XRPL ledger verification uses the HTTP RPC endpoint.
- 12-word wallet recovery policy is enforced.
- Auth restart/logout lifecycle is verified.
- Desktop launch/window fallback is verified.
- Wallet tab is present and Send XRP is runtime-tested.
- QR login has a demo-safe flow, polling rate-limit fix, approval lifecycle fix, and final-pass UI/security verification.
- Owner download/decrypt is hardened and runtime-tested.
- Local XRPL NFT transfer and re-encryption are runtime-tested through recipient decrypt.
- XRPL Grants demo UI safety polish is complete.
- Storage proxy failed-replica logging no longer exposes tokenized URLs after commit `29d4938`.

## MVP Checklist

| Check | Status | Evidence |
| --- | --- | --- |
| Docker Compose starts Postgres/Redis | Complete | Postgres accepted connections; Redis healthy. |
| Oracle starts and `/health` responds | Complete | `/health` returned `200 OK`. |
| Storage-node starts and `/health` responds | Complete | `/health` returned `200 OK`. |
| Desktop starts | Complete | Desktop launch/window fallback verified. |
| Create wallet generates secure 12-word recovery words | Complete | 12-word policy enforced. |
| Restore by recovery words works | Complete | Auth restart/restore lifecycle verified. |
| QR login works or demo-safe QR is clearly implemented | Complete with limitation | QR renders, raw payload/copy removed, Oracle-only wording clarified; fresh approval skipped due to no second device/session, with previous approval lifecycle runtime evidence. |
| Wallet tab shows XRP balance | Complete | Wallet runtime checks completed. |
| Receive QR works | Complete | Wallet receive surface included in final pass. |
| Send XRP works on testnet | Complete | `engine_result=tesSUCCESS`, tx hash recorded above. |
| Upload encrypts file locally | Complete | Upload/mint/owner decrypt flow completed without plaintext evidence exposure. |
| Encrypted payload uploads | Complete | Owner proxy download and decrypt checkpoint completed. |
| Public metadata URL returns `200` | Complete | Fresh mint/finalize by-NFT lookup returned `200 OK`. |
| Mint NFT succeeds | Complete | Fresh `NFTokenMint -> tesSUCCESS`. |
| NFT appears in account NFTs | Complete | Fresh mint/finalize evidence captured. |
| Vault object finalizes in Oracle | Complete | Fresh by-NFT lookup returned `status=active`. |
| Download/decrypt works as owner | Complete | Owner decrypt phases completed. |
| Transfer NFT/file access to another user works | Complete | Create offer, confirm-signed, incoming offer, accept offer, and Oracle completion succeeded. |
| Recipient decrypts after re-encryption | Complete | Recipient decrypt phases completed after transfer. |
| `make security-audit-strict` passes | Complete with non-blocking notes | Completed; see audit notes. |
| `cargo test --workspace` passes | Complete | Passed in final automated gates. |
| Frontend lint/typecheck/build passes | Complete | `npm run lint`, `npx tsc`, and `npm run build` passed. |
| README/demo script updated | Complete | README/demo documentation was updated before this final report. |

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

Run final release security gate:

```bash
make security-audit-strict
```

## Demo Flow

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

- Remove duplicate `XRPL_NODE_URL` in `.env` when safe.
- Consider dependency updates for yanked `aes` through `zip` and the npm `brace-expansion` advisory.
- Optionally run a full QR approval retest with a second device/session.
- Do not reset runtime state, log out, clear wallets, delete app data, or edit `.env` without explicit owner approval.

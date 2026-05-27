# Plan: Final Fresh All-Up Production MVP Verification
Created: 2026-05-27
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes. This is a verification pass; run full automated gates and the documented runtime checks.
- **Logging:** standard runtime logging only. Capture safe phase names, endpoint statuses, `engine_result`, transaction hashes, transfer ids, offer indexes, and non-secret identifiers only.
- **Docs:** yes. After a pass, update `docs/RUNTIME_VERIFICATION.md` and `.ai-factory/HANDOFF_CURRENT.md` with final evidence. If blockers are found, update them as blockers/follow-ups instead of marking MVP ready.
- **Roadmap linkage:** `VAULTED_AGENT_INSTRUCTIONS.md` section 14 final XRPL Grants MVP acceptance checklist and section 19 final production-ready MVP definition.

## Goal
Execute a fresh all-up production-ready MVP verification pass from the documented runtime flow, identify blocker regressions, and produce final evidence. Do not implement code fixes during this pass. If a blocker is discovered, stop the runtime proof, document the exact safe failure evidence, and create a follow-up fix plan.

## Security Boundaries
Do not log, paste, screenshot, or commit:
- seed phrase, mnemonic entropy, recovery phrase
- private keys, derived keys, AES keys
- JWTs, storage tokens, tokenized storage URLs, raw storage keys
- `tx_blob`, signatures, QR payloads, QR approval signatures
- plaintext file contents, decrypted content, raw encrypted key material

Allowed evidence:
- command names and pass/fail status
- endpoint statuses
- safe phase names
- `engine_result` and safe engine message
- transaction hash
- NFT token id
- offer index
- transfer id
- classic address only when needed to identify non-secret wallet/account state
- screenshots with all secret-bearing fields cropped or obscured

## Files To Inspect Or Update
- `docs/RUNTIME_VERIFICATION.md`
  - Update checklist statuses from "needs fresh final pass" to complete only when freshly verified.
  - Add date/time of final pass, safe evidence, and blocker notes if any.
- `.ai-factory/HANDOFF_CURRENT.md`
  - Update current checkpoint after the pass, latest commit list if docs are committed, and how to continue safely.
- `README.md`
  - Inspect only; update only if the final pass proves the demo flow or validation commands need correction.
- `QUICKSTART.md`
  - Inspect only; update only if it contradicts final-pass behavior.
- Optional generated artifact:
  - `docs/RUNTIME_VERIFICATION.md` may serve as the final verification report. Do not create a second report file unless the owner explicitly asks for a separate artifact.

## Preflight Commands
Run from repo root. Do not print `.env` values.

```bash
git status --short
git log --oneline -12
```

Confirm required `.env` keys are present without printing values:

```bash
test -f .env
for key in DATABASE_URL REDIS_URL XRPL_NODE_URL XRPL_RPC_URL ORACLE_URL; do
  if grep -q "^${key}=" .env; then
    echo "${key}=set"
  else
    echo "${key}=missing"
  fi
done
```

Confirm XRPL endpoint roles without printing hosts:

```bash
awk -F= '
  /^XRPL_NODE_URL=/ { print ($2 ~ /^wss:\/\// ? "XRPL_NODE_URL=websocket" : "XRPL_NODE_URL=check-scheme") }
  /^XRPL_RPC_URL=/ { print ($2 ~ /^https:\/\// ? "XRPL_RPC_URL=https-json-rpc" : "XRPL_RPC_URL=check-scheme") }
' .env
```

Confirm Docker/Postgres/Redis state:

```bash
docker compose up -d postgres redis
docker compose ps
docker exec xrpl-vault-postgres pg_isready -U xrpl_vault -d xrpl_vault
```

Pass:
- Git state is understood before verification starts.
- Required env keys are present.
- `XRPL_NODE_URL` is a WebSocket endpoint and `XRPL_RPC_URL` is an HTTPS JSON-RPC endpoint.
- Postgres and Redis containers are running; Postgres readiness succeeds.

Fail:
- Missing required endpoint keys.
- Postgres/Redis cannot start.
- Worktree has unexpected source-code changes that could invalidate the pass.

## Service Startup Commands
Use separate terminals or managed sessions. Do not paste full logs into the report.

Start Oracle:

```bash
set -a
source .env
set +a
RUST_LOG=info cargo run -p xrpl-vault-oracle --bin oracle
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
REQUIRE_AUTH=false RUST_LOG=info cargo run -p xrpl-vault-storage-node --bin storage-node
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
RUST_LOG=info cargo run -p xrpl-vault-desktop
```

Pass:
- Oracle starts without migration/config failures and `/health` returns success.
- Storage-node starts and `/health` returns success.
- Desktop window launches to the expected auth or unlocked state.

Fail:
- Any service exits before runtime flow begins.
- Health check fails or hangs.
- Desktop does not render a usable window.

## Runtime Flow
Perform this in the desktop UI against the live local services. Do not reset runtime state unless the owner explicitly approves.

### 1. Wallet/Auth
Steps:
- Create or restore a 12-word Vaulted wallet using the approved current runtime path.
- Confirm restore flow works if using an existing wallet.
- Confirm wallet state loads without exposing recovery words after onboarding.

Capture:
- Screenshot of Auth success/unlocked app with recovery words fully absent.
- Note: `create_wallet_12_words=pass` or `restore_12_words=pass`.

Pass:
- 12-word policy is enforced.
- App unlocks and registers/loads identity.
- No recovery words appear after backup/onboarding.

Fail:
- Non-12-word flow is available or accepted.
- Unlock/register fails without a clear recoverable reason.

### 2. Wallet Tab
Steps:
- Open Wallet.
- Confirm balance display.
- Confirm receive address/QR display.
- Send XRP on testnet using a safe recipient account and low amount.
- Confirm transaction history reflects the payment or refreshes to include it.

Capture:
- Screenshot of Wallet balance and receive QR with no secret fields.
- Safe log/result line: `Payment -> <engine_result>` and transaction hash if available.
- Screenshot/history row with hash visible if safe.

Pass:
- Balance loads.
- Receive QR/address is available.
- Send XRP returns successful or accepted XRPL result.
- History shows the payment or clearly refreshes from account history.

Fail:
- Wallet tab cannot load.
- Send flow fails with a blocker result unrelated to funding/reserve/user input.
- History is broken if it is required for MVP acceptance.

### 3. QR Login Demo-Safe Flow
Steps:
- Start QR login from Auth or the relevant QR login surface.
- Confirm QR request renders.
- Confirm polling remains alive through approval.
- Confirm demo-safe approval lifecycle completes or the demo-safe state is clearly presented.

Capture:
- Screenshot of QR login status with raw QR payload not visible as JSON.
- Safe phase/status: `qr_login_pending`, `qr_login_approved`, or documented demo-safe equivalent.

Pass:
- QR login flow does not expose raw QR payload/signatures.
- Polling does not rate-limit itself into failure.
- Approval lifecycle completes or demo-safe UX is explicit.

Fail:
- Raw QR payload or approval signature is rendered.
- Polling dies before approval.
- QR login blocks the runtime demo.

### 4. Upload And Mint
Steps:
- Upload a non-sensitive test file created for the demo.
- Confirm encrypted payload upload.
- Mint ownership NFT locally.
- Confirm public metadata URL returns `200`.
- Confirm Oracle finalizes vault object and by-NFT lookup works.
- Confirm NFT appears in account NFTs if checked through XRPL.

Suggested safe commands after mint:

```bash
curl -I 'http://127.0.0.1:3000/nft/sha256:<HASH>/metadata.json'
curl -i 'http://127.0.0.1:3000/api/v1/vault-objects/by-nft/<NFT_TOKEN_ID>'
```

Capture:
- UI screenshot of file/vault status after mint.
- Endpoint statuses only.
- `NFTokenMint -> <engine_result>` and transaction hash.
- NFT token id.

Pass:
- File upload completes with encrypted storage path.
- Metadata endpoint returns `200`.
- Mint succeeds locally.
- Oracle finalization succeeds.
- By-NFT lookup returns `200`.

Fail:
- Plaintext content is exposed to service logs/UI evidence.
- Mint fails with a non-transient XRPL result.
- Oracle cannot finalize or link by NFT.

### 5. Owner Download/Decrypt
Steps:
- Download/decrypt the minted vault object as owner.
- Save output to a local test destination.
- Confirm decrypted file opens locally without exposing contents in report.

Capture safe phases only:

```text
access_metadata_ok
proxy_download_ok
unwrap_owner_key
content_key_unwrapped
payload_decrypted
complete
```

Pass:
- Owner access metadata and proxy download succeed.
- Owner key unwrap succeeds.
- Payload decrypt succeeds.
- Output file is saved locally.

Fail:
- Any phase fails without a documented expected user-action cause.
- Logs expose tokenized URLs, storage keys, keys, or plaintext.

### 6. Transfer/Re-Encryption
Steps:
- Owner creates and submits local `NFTokenCreateOffer` for recipient.
- Extract/record safe offer index.
- Confirm Oracle transfer initiate and confirm-signed/finalize path.
- Recipient sees incoming offer.
- Recipient accepts with local `NFTokenAcceptOffer`.
- Confirm Oracle completes accepted transfer.
- Recipient downloads/decrypts after re-encryption.

Capture safe transfer evidence:

```text
NFTokenCreateOffer -> tesSUCCESS
confirm-signed -> 200 OK
incoming offer visible
NFTokenAcceptOffer -> tesSUCCESS
Oracle completed locally accepted NFT transfer
unwrap_transferred_key
content_key_unwrapped
payload_decrypted
complete
```

Allowed identifiers:
- NFT token id
- offer index
- transfer id
- transaction hashes
- endpoint statuses

Pass:
- Owner offer succeeds and offer index is captured.
- Oracle confirm-signed returns success.
- Incoming recipient offer is visible and verified.
- Recipient accept succeeds locally.
- Oracle transfer completion succeeds.
- Recipient decrypt completes after re-encryption.

Fail:
- Offer/accept local XRPL signing fails.
- Oracle confirm/complete transfer fails.
- Recipient decrypt cannot unwrap transferred key.
- Any raw secret-bearing payload appears in UI/logs/report.

## Final Automated Gates
Run after the runtime flow, unless a blocker requires stopping early.

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

```bash
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
cd ../../..
```

```bash
./scripts/check-sensitive-logs.sh
git diff --check
```

Run security audit if available and safe in the current environment:

```bash
make security-audit-strict
```

Pass:
- All automated gates exit `0`.
- If `make security-audit-strict` is unavailable due to missing local tool or network/DNS, record the exact blocker and do not mark the audit complete.

Fail:
- Any automated gate fails.
- Sensitive-log audit reports a real exposure.

## Evidence Capture Rules
Screenshots to capture:
- Service health responses or terminal health status.
- Desktop launched/unlocked state with no recovery words visible.
- Wallet balance/receive QR/Send XRP result with no secrets.
- QR login status with raw QR JSON/signatures not visible.
- File/vault minted status.
- Owner decrypt success state without file contents visible.
- Incoming recipient offer.
- Recipient transfer accept/decrypt success state without file contents visible.

Log snippets to capture:
- Service started lines without config values.
- Health endpoint status codes.
- XRPL `engine_result` and transaction hash only.
- Safe phase names listed above.
- Endpoint status lines for Oracle transfer/finalize/download access.

Do not capture:
- Full `.env`.
- Raw JSON containing tokens, QR payloads, approval signatures, storage URLs, or keys.
- Recovery words or seed backup screen.
- Plaintext/decrypted file previews.
- Full request/response bodies unless manually verified as non-secret.

## Report Update Plan
After a clean pass:
- Update `docs/RUNTIME_VERIFICATION.md`:
  - Set fresh final pass date/time.
  - Mark all completed MVP checklist rows as `Complete`.
  - Add safe runtime evidence block with phase names, endpoint statuses, engine results, transaction hashes, NFT token id, transfer id, and offer index.
  - Record final gates and `make security-audit-strict` result.
- Update `.ai-factory/HANDOFF_CURRENT.md`:
  - State final all-up verification pass result.
  - Add latest relevant commits.
  - List any remaining non-blocking follow-ups.

If blockers are found:
- Do not mark MVP ready.
- Update `docs/RUNTIME_VERIFICATION.md` with a blocker section containing:
  - failed step
  - safe command/status
  - safe error class or `engine_result`
  - next diagnostic action
- Update `.ai-factory/HANDOFF_CURRENT.md` with blocker status and a recommended `$aif-plan` prompt for the fix.
- Create a separate fix plan before changing runtime code.

## Tasks

- [ ] 1. Preflight repository and environment
  - Deliverable: preflight notes with git status/log, env-key presence, XRPL endpoint roles, and Docker/Postgres/Redis state.
  - Files to update after pass: `docs/RUNTIME_VERIFICATION.md`, `.ai-factory/HANDOFF_CURRENT.md`.
  - Logging requirements: no env values, tokens, URLs with credentials, or secrets; record only `set/missing`, endpoint role, service status.
  - Dependency notes: must pass before service startup.

- [ ] 2. Start local services and desktop
  - Deliverable: Oracle, storage-node, and desktop are running with health checks captured.
  - Files to update after pass: `docs/RUNTIME_VERIFICATION.md`, `.ai-factory/HANDOFF_CURRENT.md`.
  - Logging requirements: capture endpoint statuses and service-ready lines only; do not paste full logs.
  - Dependency notes: blocked by task 1.

- [ ] 3. Verify wallet, QR login, and XRP payment surfaces
  - Deliverable: wallet create/restore, balance, receive QR, Send XRP, history, and QR login demo-safe flow verified or blockers recorded.
  - Files to update after pass: `docs/RUNTIME_VERIFICATION.md`, `.ai-factory/HANDOFF_CURRENT.md`.
  - Logging requirements: allowed `engine_result`, transaction hash, safe UI status; no recovery words, QR payloads, signatures, or private material.
  - Dependency notes: blocked by task 2.

- [ ] 4. Verify upload, mint, Oracle finalize, and owner decrypt
  - Deliverable: encrypted upload, local NFT mint, metadata `200`, by-NFT lookup, and owner download/decrypt verified.
  - Files to update after pass: `docs/RUNTIME_VERIFICATION.md`, `.ai-factory/HANDOFF_CURRENT.md`.
  - Logging requirements: capture safe phase names, endpoint statuses, transaction hash, NFT token id; no file contents, keys, tokenized URLs, or storage keys.
  - Dependency notes: blocked by task 3.

- [ ] 5. Verify transfer, recipient accept, and recipient decrypt
  - Deliverable: `NFTokenCreateOffer`, Oracle confirm-signed, incoming offer, `NFTokenAcceptOffer`, Oracle complete transfer, and recipient decrypt verified.
  - Files to update after pass: `docs/RUNTIME_VERIFICATION.md`, `.ai-factory/HANDOFF_CURRENT.md`.
  - Logging requirements: capture safe transfer phases, offer index, transfer id, transaction hashes, endpoint statuses; no signatures, `tx_blob`, QR payloads, keys, or plaintext.
  - Dependency notes: blocked by task 4.

- [ ] 6. Run final automated gates
  - Deliverable: full command results for Rust, frontend, sensitive-log, diff, and security-audit gates.
  - Files to update after pass: `docs/RUNTIME_VERIFICATION.md`, `.ai-factory/HANDOFF_CURRENT.md`.
  - Logging requirements: record pass/fail and short safe error summaries only; no raw secret-bearing output.
  - Dependency notes: blocked by task 5 unless a blocker stops runtime verification early.

- [ ] 7. Update final verification report artifacts
  - Deliverable: `docs/RUNTIME_VERIFICATION.md` and `.ai-factory/HANDOFF_CURRENT.md` reflect the final pass or blocker state.
  - Files likely to change: `docs/RUNTIME_VERIFICATION.md`, `.ai-factory/HANDOFF_CURRENT.md`; `README.md`/`QUICKSTART.md` only if documented commands are proven stale.
  - Logging requirements: write only safe evidence and checklist status; no secrets or raw payloads.
  - Dependency notes: blocked by tasks 1-6 or by documented blocker evidence.

## Out Of Scope
- Runtime code changes.
- Rust, TypeScript, Tauri, Oracle, storage, crypto, migration, or schema edits.
- Resetting runtime state, logging out, deleting app data, clearing wallets, or editing `.env` without explicit owner approval.
- Pushing commits.
- Fixing discovered blockers in the same pass.
- Adding new diagnostic logging unless a separate fix plan is approved.
- Capturing or publishing raw logs that may contain sensitive material.

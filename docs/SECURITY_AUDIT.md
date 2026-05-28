# Vaulted MVP Security Audit

## Scope

This audit covers the XRPL Grants MVP release surface:

- desktop client, including Tauri commands, local secret handling, UI flows, and wallet actions;
- Oracle, including authentication, registry, manifest, grant, transfer, QR, storage-token, and XRPL verification paths;
- storage node, including encrypted fragment storage and signed storage-token verification;
- crypto-core, including Vaulted seed identity, file encryption, manifests, QR payloads, `KeyEnvelope`, legacy PRE compatibility, and XRPL wallet helpers;
- XRPL integration, including local signing, Send XRP, NFT mint/finalize, transfer offers, and accept-offer flow;
- QR login and QR approval surfaces;
- transfer/re-encryption and recipient decrypt;
- owner decrypt;
- wallet balance, receive surface, and Send XRP.

## Audit Date

Current audit cycle: 2026-05-28.

## Verification Performed

Completed runtime evidence for the MVP release:

- Oracle health endpoint returned `200 OK`.
- Storage-node health endpoint returned `200 OK`.
- Postgres accepted connections.
- Redis reported healthy.
- Send XRP completed with `tesSUCCESS`.
- NFT mint and Oracle finalize completed with `tesSUCCESS` and active by-NFT lookup.
- Owner decrypt completed successfully.
- Transfer and re-encryption completed successfully.
- Recipient decrypt after re-encryption completed successfully.
- Sensitive logging verification passed after redaction retest.
- Security audit checks completed, including Rust gates, frontend gates, sensitive-log scan, diff check, and strict security audit.

No raw transaction blobs, tokenized URLs, QR payloads, signatures, private material, file keys, or decrypted content are stored in this audit document.

## Completed Findings

- Sensitive log redaction: storage proxy failed-replica logging was changed to safe structured fields without tokenized URLs or fragment URL paths.
- QR payload removal: raw QR payload/copy exposure was removed from the final UI/security surface.
- QR wording cleanup: Oracle session wording was clarified for the QR login flow.
- Console logging cleanup: production UI console logging was removed from `crates/desktop-client/ui/src`.
- Clippy cleanup: workspace clippy findings were fixed and `cargo clippy --workspace --all-targets --all-features -- -D warnings` passed.
- Dependency cleanup: frontend dependency cleanup addressed the `brace-expansion` advisory path; current npm audit result for the audit cycle is 0 vulnerabilities.
- Cyrillic/source cleanup: developer-facing comments, docs, SQL comments, and remaining human-readable SQL metadata were translated to English.
- Duplicate build script removal: duplicate desktop build scripts with non-ASCII filenames were removed.

## Remaining Accepted Risks

### XRPL verification gaps

`crates/oracle/src/api/files.rs` still contains a note that real XRPL verification should be used for file registration ownership validation. The current path validates token shape and Oracle database state, but the explicit ledger-backed ownership check remains a hardening follow-up.

`crates/oracle/src/api/nfts.rs` still contains a note that the ownership verification endpoint should also verify through XRPL. The current path compares against Oracle database ownership state.

Status: Deferred after MVP.

### Legacy PRE compatibility paths

The codebase still contains compatibility paths for legacy key envelopes using the `legacy-pre-aes-key` algorithm marker. These appear in grant, QR file-grant, migration, and desktop compatibility paths so older records can continue to be read during migration.

The codebase also keeps a legacy transferred-data compatibility path where old `ReEncryptedData` without a sender verifying key can still be decrypted. This preserves access to existing migrated data, but should be retired only after a dedicated migration plan confirms all records carry sender verifying-key material.

Status: Required for migration compatibility.

### is_re_encrypted metadata correctness

`crates/oracle/src/api/nfts.rs` still hardcodes `is_re_encrypted: false` in one metadata response path even though the database has an `is_re_encrypted` column and other file-access paths read the real value.

Status: Correctness issue, not active exploit.

## Dependency Notes

- `brace-expansion` advisory path was fixed during frontend dependency cleanup.
- `npm audit` result for the current audit cycle is 0 vulnerabilities.
- Rust audit still has a deferred note for yanked `aes` through the `zip` dependency.
- Do not move to a `zip` prerelease before release; keep the deferred dependency update as a separate post-MVP dependency plan.

## Deferred Testing

Fresh QR approval retest requires a second trusted device/session. The QR UI/security surface was verified during the final pass, and the approval lifecycle had previous runtime evidence, but the fresh final approval retest was deferred due to unavailable second-session runtime conditions.

## Final Verification Commands

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
cargo clippy --workspace --all-targets --all-features -- -D warnings
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

## Final Assessment

Suitable for MVP release with documented deferred items.

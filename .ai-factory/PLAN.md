# Plan: Oracle XRPL HTTP RPC Verification Endpoint
Created: 2026-05-25
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes, focused Oracle config/XRPL verification checks
- **Logging:** diagnostic allow-list only
- **Docs:** update env examples/docs only where endpoint config is documented
- **Security:** preserve ledger verification; do not remint or bypass XRPL validation

## Scope
- Fix Oracle `finalize_vault_mint` XRPL ledger verification so it uses a valid HTTP JSON-RPC endpoint.
- Keep desktop WebSocket XRPL flows working.
- Do not remint.
- Do not touch XRPL transaction signing/serialization, stale-sequence or `tefPAST_SEQ` retry logic, encryption/decryption, wallet/key derivation, plaintext handling, runtime reset, or logout.
- Do not bypass ledger verification.

## Runtime Evidence
- Recovery UI and `recover_pending_vault_mint` work.
- Oracle `GET /api/v1/vault/b524fe14-4976-448f-a3c6-1f43c249a5ff/mint-recovery` returns 200.
- Desktop extracted the correct `NFTokenID`:
  - `NFTokenID=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC`
  - `tx_hash=2E084681288AEC19132D70F2B970AE78089D6A66B27E25EC95683F5BF7ECBB7F`
- Oracle `POST /api/v1/vault/finalize-mint` is reached.
- Oracle fails during XRPL tx verification:
  - `XRPL error: HTTP error: builder error for url (wss://s.altnet.rippletest.net:51233/)`
- Oracle returns 502.
- DB remains `pending_claim`; `vault_objects` is still missing.

## Code Findings
- Oracle XRPL verification uses [crates/oracle/src/xrpl.rs](/home/riggle/vaulted/crates/oracle/src/xrpl.rs), which stores `XrplConfig.node_url` as a JSON-RPC URL and sends JSON-RPC requests with `reqwest::Client.post(&self.config.node_url)`.
- `verify_local_nft_mint` calls `self.rpc("tx", ...)` and `account_nfts`, so it requires an HTTP(S) JSON-RPC endpoint.
- Oracle config currently has only `Config.xrpl_node_url`, loaded from `XRPL_NODE_URL` in [crates/oracle/src/config.rs](/home/riggle/vaulted/crates/oracle/src/config.rs).
- [crates/oracle/src/services/app_state.rs](/home/riggle/vaulted/crates/oracle/src/services/app_state.rs) passes `config.xrpl_node_url` directly into `XrplConfig.node_url`.
- `XrplConfig::default()` already defaults to `https://s.altnet.rippletest.net:51234`, but that default is bypassed when `XRPL_NODE_URL=wss://s.altnet.rippletest.net:51233` is set.
- `.env.example`, `README.md`, and `QUICKSTART.md` document `XRPL_NODE_URL` as a WebSocket URL (`wss://s.altnet.rippletest.net:51233`).
- The desktop XRPL client is WebSocket-based and should keep using `XRPL_NODE_URL` as a WebSocket endpoint.

## Questions Answered
- **Which env/config value supplies Oracle XRPL verification URL?** `XRPL_NODE_URL` currently supplies it through `Config.xrpl_node_url` into `XrplService`.
- **Is Oracle using `XRPL_NODE_URL=wss://s.altnet.rippletest.net:51233/` with an HTTP client?** Yes, runtime evidence plus `reqwest::Client.post(&self.config.node_url)` confirms the mismatch.
- **Does the code already support a separate HTTP JSON-RPC URL?** No. There is only `xrpl_node_url` in Oracle config, although `XrplConfig` expects JSON-RPC.
- **Should Oracle derive `https://...:51234` from `wss://...:51233`, or require explicit `XRPL_HTTP_URL` / `XRPL_RPC_URL`?** Prefer an explicit Oracle HTTP JSON-RPC env var, with a small compatibility conversion for standard `ws://`/`wss://` values to avoid breaking existing dev configs.
- **What is the smallest safe fix?** Add `XRPL_RPC_URL` / `XRPL_HTTP_URL` config for Oracle verification, validate that the final URL scheme is `http` or `https`, and fall back by converting `wss` to `https` and `ws` to `http` only when no explicit HTTP URL is set.

## Preferred Design
- Add `Config.xrpl_rpc_url: Option<String>` for Oracle HTTP JSON-RPC.
- Load from env in this precedence:
  1. `XRPL_RPC_URL`
  2. `XRPL_HTTP_URL`
  3. derived from `XRPL_NODE_URL` if it is `ws://` or `wss://`
  4. existing `XRPL_NODE_URL` if it is already `http://` or `https://`
  5. default `https://s.altnet.rippletest.net:51234`
- For the public XRPL testnet default, convert:
  - `wss://s.altnet.rippletest.net:51233` -> `https://s.altnet.rippletest.net:51234`
  - `ws://...:51233` -> `http://...:51234`
- For other WebSocket URLs, convert only the scheme unless a port-specific public-testnet rule is clearly applicable. Do not hardcode testnet-only behavior as the only path.
- Reject unsupported schemes with a clear config error before runtime verification, logging only `XRPL endpoint scheme`.
- Keep `XRPL_NODE_URL` available for desktop/WebSocket flows and compatibility docs.

## Tasks

- [x] 1. Add Oracle HTTP RPC endpoint config resolution
  - Files likely to change:
    - [crates/oracle/src/config.rs](/home/riggle/vaulted/crates/oracle/src/config.rs)
    - [crates/oracle/src/services/app_state.rs](/home/riggle/vaulted/crates/oracle/src/services/app_state.rs)
  - Deliverable: Oracle resolves a validated HTTP JSON-RPC endpoint separately from the WebSocket-style `XRPL_NODE_URL`.
  - Expected behavior: `XRPL_RPC_URL=https://s.altnet.rippletest.net:51234/` is used directly; if only `XRPL_NODE_URL=wss://s.altnet.rippletest.net:51233/` is set, Oracle derives `https://s.altnet.rippletest.net:51234/`.
  - Logging requirements: log only endpoint scheme, request phase, and status enum; do not log full URLs.
  - Dependency notes: do not alter desktop config or XRPL signing/submission code.

- [x] 2. Validate XRPL JSON-RPC URL scheme before verification
  - Files likely to change:
    - [crates/oracle/src/config.rs](/home/riggle/vaulted/crates/oracle/src/config.rs)
    - [crates/oracle/src/xrpl.rs](/home/riggle/vaulted/crates/oracle/src/xrpl.rs)
  - Deliverable: unsupported schemes such as `wss` reaching the HTTP RPC client produce an actionable config error instead of a `reqwest` builder error.
  - Expected behavior: Oracle startup or `XrplService` construction rejects non-HTTP final RPC URLs with a safe message like `XRPL JSON-RPC URL must use http or https`.
  - Logging requirements: allowed diagnostic is `XRPL endpoint scheme only`; do not log full endpoint strings.
  - Dependency notes: ledger verification remains mandatory and fail-closed.

- [x] 3. Wire finalize verification to the resolved HTTP RPC endpoint
  - Files likely to change:
    - [crates/oracle/src/services/app_state.rs](/home/riggle/vaulted/crates/oracle/src/services/app_state.rs)
    - [crates/oracle/src/xrpl.rs](/home/riggle/vaulted/crates/oracle/src/xrpl.rs)
    - [crates/oracle/src/api/vault.rs](/home/riggle/vaulted/crates/oracle/src/api/vault.rs) only if safer diagnostics are needed around `verify_local_nft_mint`.
  - Deliverable: `finalize_vault_mint` verification uses the HTTP JSON-RPC endpoint for `tx` and `account_nfts`.
  - Expected behavior: recovery retry reaches XRPL verification without `builder error for url (wss://...)`.
  - Logging requirements: if adding diagnostics, only log `NFTokenID`, `tx_hash`, `metadata_hash`, metadata URI length, `vault_id`, status enum, request phase, HTTP status code, and endpoint scheme.
  - Dependency notes: do not bypass or weaken `validated`, `tesSUCCESS`, `NFTokenMint`, Account, NFTokenID, URI, or ownership checks.

- [x] 4. Update env examples and docs for split endpoints
  - Files likely to change:
    - [.env.example](/home/riggle/vaulted/.env.example)
    - [README.md](/home/riggle/vaulted/README.md)
    - [QUICKSTART.md](/home/riggle/vaulted/QUICKSTART.md)
  - Deliverable: docs distinguish WebSocket `XRPL_NODE_URL` from Oracle HTTP JSON-RPC `XRPL_RPC_URL` / `XRPL_HTTP_URL`.
  - Expected behavior: local dev config clearly includes `XRPL_NODE_URL=wss://s.altnet.rippletest.net:51233` and `XRPL_RPC_URL=https://s.altnet.rippletest.net:51234`.
  - Logging requirements: no runtime logging changes in docs.
  - Dependency notes: do not document secrets or wallet seed values.

- [x] 5. Add focused tests
  - Files likely to change:
    - [crates/oracle/src/config.rs](/home/riggle/vaulted/crates/oracle/src/config.rs)
    - [crates/oracle/src/xrpl.rs](/home/riggle/vaulted/crates/oracle/src/xrpl.rs)
  - Deliverable: unit tests for URL resolution and scheme validation.
  - Required test cases:
    - explicit `XRPL_RPC_URL=https://...` wins over `XRPL_NODE_URL=wss://...`
    - `wss://s.altnet.rippletest.net:51233` converts to `https://s.altnet.rippletest.net:51234`
    - `https://...` remains unchanged
    - unsupported schemes fail with a safe error that does not include secrets
  - Logging requirements: tests must not print full secret-bearing URLs; use benign example hosts only.

## Env / Config Update Needed
- Add to `.env` for the current runtime:

```bash
XRPL_RPC_URL=https://s.altnet.rippletest.net:51234/
```

- Keep existing desktop/WebSocket setting if needed:

```bash
XRPL_NODE_URL=wss://s.altnet.rippletest.net:51233/
```

## Verification Commands After Code Changes

Run commands separately:

```bash
cargo fmt --all --check
cargo check -p xrpl-vault-oracle
cargo test -p xrpl-vault-oracle
./scripts/check-sensitive-logs.sh
git diff --check
```

If docs or desktop config surfaces are touched unexpectedly, also run:

```bash
cargo check -p xrpl-vault-desktop
cargo test -p xrpl-vault-desktop
cd crates/desktop-client/ui
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
```

## Runtime Recovery Retry Command

After restarting Oracle with the fixed HTTP RPC config, retry the existing no-remint recovery from the desktop Upload screen with:

```text
vault_id=b524fe14-4976-448f-a3c6-1f43c249a5ff
tx_hash=2E084681288AEC19132D70F2B970AE78089D6A66B27E25EC95683F5BF7ECBB7F
```

Do not press `Mint vault NFT`.

## Runtime Verification Commands

Check Oracle health:

```bash
curl -i http://127.0.0.1:3000/health
```

Check DB state after recovery:

```bash
docker compose exec -T postgres psql -U xrpl_vault -d xrpl_vault -c "SELECT nm.id AS vault_id, nm.nft_token_id AS metadata_nft_token_id, nm.status AS metadata_status, nm.metadata_hash, nm.manifest #>> '{xrpl_tx_hash}' AS xrpl_tx_hash, vo.id AS vault_object_id, vo.nft_token_id AS vault_object_nft_token_id, vo.status AS vault_object_status FROM nft_metadata nm LEFT JOIN vault_objects vo ON vo.id = nm.id::text WHERE nm.id = 'b524fe14-4976-448f-a3c6-1f43c249a5ff';"
```

Verify by-NFT lookup through the authenticated app path, or use raw curl only if it does not require printing tokens:

```bash
curl -i http://127.0.0.1:3000/api/v1/vault-objects/by-nft/00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC
```

## Expected Successful State
- Oracle verification uses `https://s.altnet.rippletest.net:51234/` or another explicit HTTP JSON-RPC endpoint.
- `finalize_vault_mint` still verifies the XRPL ledger and then finalizes:
  - `nft_metadata.status=active`
  - `nft_metadata.nft_token_id=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC`
  - `vault_objects.nft_token_id=00080000DB73821505A0B4F90B6DFF9CBAA1014B60FEDB4FAEB4C857010D42BC`
- `/api/v1/vault-objects/by-nft/{NFTokenID}` returns 200 through the authenticated app path.
- Re-running recovery remains idempotent and does not create conflicting rows.

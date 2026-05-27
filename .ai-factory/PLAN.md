# Plan: Fix Incoming Transfer Accept UI Crash
Created: 2026-05-27
Mode: fast
Branch: current branch, no branch changes planned

## Settings
- **Testing:** yes. This is a frontend-only crash fix; run UI lint, TypeScript, build, sensitive-log scan, and diff checks.
- **Logging:** no new runtime logging expected. If diagnostics are added, only UI step, offer index, transfer id, and safe error class are allowed.
- **Docs:** no docs changes.
- **Roadmap linkage:** `VAULTED_AGENT_INSTRUCTIONS.md` section 12, transfer/recipient flow, specifically step 13: recipient accepts transfer.

## Runtime Evidence
- Owner transfer offer works.
- Recipient incoming offer is visible:
  - `Found 1 incoming offers for rMrMMCarMB4j38ToQc1r3s9ZUbtrvFH4mB (1 verified on XRPL)`
- After clicking Accept/Claim, the desktop UI becomes blank/black.
- DevTools shows:
  - `TypeError: undefined is not an object (evaluating 'i.bg')`
- Desktop logs do not show `claim_nft`, `NFTokenAcceptOffer`, or `complete_transfer` after the click, so the crash is in frontend rendering/state before the local XRPL claim flow reaches Tauri.

## Finding
- The exact crash point is the Toast renderer in [Toast.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/Toast.tsx:38):
  - `const c = colors[toast.type]`
  - render then reads `c.bg` at [Toast.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/Toast.tsx:54).
- `ToastData.type` is typed as only `success | info | error`, and the `colors` map only contains those three keys.
- The UI already has live `warning` toast call sites, including:
  - [FilesScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/FilesScreen.tsx:444)
  - [FilesScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/FilesScreen.tsx:470)
  - [ActivityScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/ActivityScreen.tsx:149)
- A `warning` toast therefore makes `colors[toast.type]` undefined and crashes on `c.bg`.
- The current FilesScreen claim handler itself calls `invoke('claim_nft')` before success/error toast work in [FilesScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/FilesScreen.tsx:450), so the reported no-invoke symptom most directly matches a warning-toast path such as the Activity incoming-offer Accept placeholder. The same Toast defect can still blank the UI from FilesScreen warning paths and should be fixed globally.
- Activity type/status maps already include `transfer_received`, and the Activity renderer has fallbacks for unknown activity type/status values, so `transfer_received` is not the immediate `i.bg` source.

## Minimal Files To Change
- [crates/desktop-client/ui/src/components/Toast.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/components/Toast.tsx)
  - Add `warning` to the `ToastData.type` union.
  - Add a `warning` color config.
  - Add a safe fallback such as `const c = colors[toast.type] ?? colors.info` so future unknown toast types cannot blank the whole UI.
  - Keep icon handling minimal; warning may reuse the info icon or a simple alert icon.
- [crates/desktop-client/ui/src/screens/FilesScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/FilesScreen.tsx)
  - Inspect only during implementation to confirm the FilesScreen claim path remains wired to `invoke('claim_nft', { offerIndex })`.
  - No expected change unless TypeScript reveals an immediate type mismatch after `warning` is added.
- [crates/desktop-client/ui/src/screens/ActivityScreen.tsx](/home/riggle/vaulted/crates/desktop-client/ui/src/screens/ActivityScreen.tsx)
  - Inspect only for this plan’s crash diagnosis. Do not rework the Activity transfer accept flow unless the user explicitly expands scope beyond FilesScreen.

## Tasks

- [x] 1. Harden toast style resolution
  - Add `warning` to `ToastData.type`.
  - Add `warning` to the Toast color map.
  - Add an info-style fallback for any unexpected toast type before reading `.bg`, `.border`, `.ibg`, or `.ico`.
  - Keep the change in `Toast.tsx` only unless the compiler requires small adjacent type updates.

- [x] 2. Confirm FilesScreen claim path remains unchanged
  - Verify `claimOffer` still sets `claimingOffer`, invokes `claim_nft` with only `offerIndex`, then adds `transfer_received` only after a successful result.
  - Do not alter XRPL signing, Oracle transfer completion, QR/auth, owner download/decrypt, Wallet, Send XRP, mint/finalize, or storage code.

- [x] 3. Check activity/style maps for safe fallback behavior
  - Confirm `ActivityScreen` continues to resolve `TYPE_META[entry.type] || TYPE_META.info`.
  - Confirm `STATUS_COLORS[entry.status] || STATUS_COLORS.success` remains in place.
  - No ActivityScreen behavior change unless a missing fallback is proven during implementation.

## Tests And Checks
Run from the UI package:

```bash
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
```

Run from the repository root:

```bash
./scripts/check-sensitive-logs.sh
git diff --check
```

Optional broader check if implementation unexpectedly touches Rust/Tauri command types:

```bash
cargo check -p xrpl-vault-desktop
```

## Runtime Retest Steps
1. Start the existing desktop runtime without resetting wallet/session state.
2. Navigate to Files.
3. Confirm the incoming offer is visible for the recipient account.
4. Click FilesScreen Accept on the incoming offer.
5. Expected immediate UI behavior:
   - UI does not blank/black.
   - Accept button moves to the claiming state.
   - No `undefined ... bg` error appears in DevTools.
6. Expected backend/Tauri behavior:
   - desktop logs show the `claim_nft` command boundary after the click.
   - local `NFTokenAcceptOffer` submit begins.
   - Oracle `complete_transfer`/finalize path is reached if XRPL submit succeeds.
7. If the user also clicks Accept from the Activity screen, confirm the warning toast no longer crashes the UI; do not treat Activity’s placeholder accept behavior as fixed unless it is separately scoped.

## Out Of Scope
- `NFTokenCreateOffer` signing/serialization.
- `NFTokenAcceptOffer` signing/serialization.
- Oracle confirm-signed or complete-transfer backend changes.
- QR/auth.
- Wallet tab or Send XRP.
- Owner download/decrypt path.
- Seed policy.
- Mint/finalize.
- Storage.
- Broad UI redesign or visual polish.
- Transfer history redesign.
- Advanced retry/recovery UX.
- Runtime reset/logout.

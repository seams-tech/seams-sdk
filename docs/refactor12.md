# Refactor 12: Unified Chain-Scoped Key Export (NEAR + EVM + Tempo)

Status: Completed  
Severity: Medium-High (user-facing capability gap + duplicate export API surface)  
Last updated: 2026-02-22

## 1. Problem Statement

Today export flows expose scheme-oriented/multi-key semantics (`exportPrivateKeysWithUI`, `schemes`) while the product needs:

- one canonical key-export API surface,
- chain-oriented caller input,
- single-key export UI per action (for now).

Current issues:

1. Primary entrypoint (`AccountMenuButton`) is NEAR-only.
2. Duplicate API/protocol surfaces (`exportNearKeypairWithUI`, `PM_EXPORT_NEAR_KEYPAIR_UI`) remain.
3. Export call shape is schemes-first, not chain-first.
4. Multi-key export semantics push UI complexity we do not want yet.

## 2. Scope and Decisions

1. Keep one canonical export API: `exportKeypairWithUI(...)` (single-key export per call).
2. Canonical input is chain-scoped:
   - `chain: 'near' | 'evm' | 'tempo'`.
3. Chain to exported key mapping:
   - `near` -> Ed25519 keypair (NEAR).
   - `evm` -> secp256k1 keypair entry.
   - `tempo` -> secp256k1 keypair entry.
4. `evm` and `tempo` currently map to the same underlying secp256k1 export key material; they differ only in caller intent/copy.
5. Remove `exportNearKeypairWithUI(...)` and `PM_EXPORT_NEAR_KEYPAIR_UI` completely (breaking change accepted; no aliases/deprecation shims).
6. No legacy fallback/feature-flag path; switch behavior directly.

## 3. Invariants

- Export flow remains worker-owned (`EXPORT_PRIVATE_KEYS_WITH_UI` path).
- Main thread does not handle secret material beyond UI display payload.
- No chain-specific duplicate private keys for Tempo/EVM when both map to the same secp256k1 material.
- Wallet iframe and direct mode produce identical export payload semantics.
- Only one export UI entrypoint/API is supported across SDK + iframe protocol.
- Each export action shows one key card (no multi-key drawer requirement in this refactor).

## 4. Target UX

When user initiates key export from the default menu:

1. Export call is chain-scoped (`chain` argument).
2. Viewer shows exactly one key card for that chain intent.
3. Security warning remains unchanged and prominent.

## 5. Implementation Plan

## Phase 0: Canonical API Contract

- [x] Introduce canonical API: `exportKeypairWithUI(nearAccountId, { chain, variant, theme })`.
- [x] Remove scheme-based public API contract from key export capability.
- [x] Define runtime mapping from chain to underlying export scheme/label in one place.

Files:

- `client/src/core/TatchiPasskey/interfaces.ts`
- `client/src/core/TatchiPasskey/index.ts`

## Phase 1: Delete Legacy Export Surfaces

- [x] Remove `exportNearKeypairWithUI` from `KeyExportCapability`.
- [x] Remove `exportNearKeypairWithUIDomain` helper and NEAR-only wrappers.
- [x] Remove `PM_EXPORT_NEAR_KEYPAIR_UI` payload/envelope and handler branch.
- [x] Remove NEAR-only export helper functions from recovery API module.

Files:

- `client/src/core/TatchiPasskey/interfaces.ts`
- `client/src/core/TatchiPasskey/index.ts`
- `client/src/core/WalletIframe/TatchiPasskeyIframe.ts`
- `client/src/core/WalletIframe/client/router.ts`
- `client/src/core/WalletIframe/shared/messages.ts`
- `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`
- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts`

## Phase 2: Entry-Point Switch (Default UX)

- [x] Update AccountMenuButton to call canonical `exportKeypairWithUI(..., { chain: 'near' })` for now.
- [x] Keep existing error handling/alerts.
- [x] Keep menu copy stable unless product explicitly changes it.

Files:

- `client/src/react/components/AccountMenuButton/index.tsx`

## Phase 3: Worker/Viewer Semantics (Single-Key)

- [x] Update export worker path to receive chain intent (or chain-derived scheme) and return one key entry.
- [x] Keep secp label chain-aware but concise (`EVM secp256k1` for `evm`, `Tempo secp256k1` for `tempo`) while preserving shared-key note in docs/copy.
- [x] Keep viewer single-card behavior as-is; do not add multi-key UX requirements.
- [x] Keep response payload secret-safe (`ok/cancelled/exportedSchemes` only).

Files:

- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts`
- `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
- `client/src/core/signingEngine/touchConfirm/ui/lit-components/ExportPrivateKey/viewer.ts`
- `client/src/core/signingEngine/touchConfirm/shared/confirmTypes.ts` (if chain intent is added to payload contracts)

## Phase 4: Wallet-Iframe Parity + Tests

- [x] Unit: AccountMenuButton calls canonical chain-scoped export API.
- [x] Unit: passkey-confirm export flow resolves correct single key by chain.
- [x] Unit: evm + tempo chain intents both export secp256k1 and label correctly.
- [x] Unit: wallet iframe host pass-through preserves `chain` payload.
- [x] Integration: wallet-iframe export flow closes overlay correctly for chain-scoped export.
- [x] Integration: router overlay intent/sticky tests reference only canonical export message type.
- [x] Add grep-based guard preventing reintroduction of deleted symbols (`exportNearKeypairWithUI`, `PM_EXPORT_NEAR_KEYPAIR_UI`).

Suggested tests/files:

- `tests/unit/passkeyConfirm.exportFlow.unit.test.ts`
- `tests/unit/walletIframeHost.exportUi.unit.test.ts`
- `tests/wallet-iframe/export.flow.integration.test.ts`
- `tests/wallet-iframe/router.computeOverlayIntent.test.ts`
- `tests/wallet-iframe/router.behavior.sticky.test.ts`
- `tests/playwright.lite.config.ts`
- `tests/unit/accountMenuButton.*.test.ts` (new if missing)

## 6. Risks and Mitigations

1. Breaking changes for downstream callers using `exportNearKeypairWithUI` or scheme-based public options.  
   Mitigation: none required for current prototype phase; breaking cleanup is intentional.

2. Misinterpretation that EVM and Tempo should have distinct exported private keys.  
   Mitigation: docs/copy explicitly state both chain intents map to shared secp256k1 export key material in the current signer model.

3. Partial key material availability on older accounts/devices.  
   Mitigation: keep current fail-closed errors and user-friendly guidance; do not silently omit requested schemes.

4. Future request for multi-key export from one click could reintroduce UI complexity.  
   Mitigation: defer multi-key drawer work; this refactor intentionally remains single-key per call.

## 7. Done Criteria

- [x] Canonical chain-scoped export API exists and is the only supported export entrypoint.
- [x] "Export Keys" from AccountMenuButton routes through canonical API.
- [x] Export viewer remains single-key per export action.
- [x] Wallet-iframe and non-iframe behavior are parity-tested.
- [x] No `exportNearKeypairWithUI` symbol remains in SDK runtime codepaths.
- [x] No `PM_EXPORT_NEAR_KEYPAIR_UI` symbol remains in iframe protocol/runtime codepaths.
- [x] Existing export hardening invariants (worker-owned flow, no secret leakage in API responses) remain intact.

## 8. Validation Snapshot (2026-02-22)

- `pnpm -C sdk build` passes.
- Chain-scoped export suites pass (`24/24`) across unit + wallet-iframe integration:
  - `tests/unit/keyExport.noLegacySurface.guard.unit.test.ts`
  - `tests/unit/privateKeyExportRecovery.binding.unit.test.ts`
  - `tests/unit/privateKeyExportRecovery.hardening.unit.test.ts`
  - `tests/unit/passkeyConfirm.exportFlow.unit.test.ts`
  - `tests/unit/walletIframeHost.exportUi.unit.test.ts`
  - `tests/unit/touchConfirm.workerRouter.unit.test.ts`
  - `tests/wallet-iframe/export.flow.integration.test.ts`
  - `tests/wallet-iframe/router.computeOverlayIntent.test.ts`
  - `tests/wallet-iframe/router.behavior.sticky.test.ts`
- Repository-wide `pnpm -s lint` / `pnpm -s type-check` are currently red from unrelated in-flight changes outside this refactor scope.

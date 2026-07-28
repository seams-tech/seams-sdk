# Auto Audit Log

Last updated: `2026-07-27T01:30:26Z`

## Latest Entry

- Timestamp: `2026-07-27T01:30:26Z`
- Target file: `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts`
- Flow: `Wallet SDK NEAR Ed25519 shared auth planning for delegate and NEP-413 signing, exact account/session selection, warm-session status normalization, and step-up handoff`
- Report: [`/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-07-27T01-30-26Z-sdk-web-signing-session-auth-mode.md`](/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-07-27T01-30-26Z-sdk-web-signing-session-auth-mode.md)
- Findings:
  - Security: `1`
  - Refactor/slimming: `2`
- Highest severity: `medium`
- Highest-severity items:
  - Already-expired active warm-session status can still be normalized to `ready`, delaying reauth failure until later signing checks.
  - NEAR transaction and ad hoc flows maintain separate readiness planners with divergent expiry behavior.
- Next audit candidates:
  - `packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts`
  - `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/statusReader.ts`
  - `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`
  - `packages/sdk-web/src/core/signingEngine/assembly/ports/near.ts`

## Audited Files

- `packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts`
- `packages/shared-ts/src/utils/routerAbEcdsaDerivation.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`
- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts`

## Audited Flows

- `Router A/B ECDSA derivation registration, export, recovery, refresh, and normal-signing boundary`
- `Wallet SDK Router A/B ECDSA derivation wire parser, JWT rehydration, request digest binding, and active-session identity`
- `Wallet SDK Router A/B Ed25519 normal-signing prepare/finalize RPC, presign-pool refill, and budget-bound response binding`
- `Wallet SDK Router A/B Ed25519 wallet-session authority parsing, persisted-state classification, runtime worker-material validation, and NEAR readiness gating`
- `Wallet SDK NEAR Ed25519 lane selection, readiness planning, passkey or Email OTP reauth, confirmation funding, and transaction/delegate/NEP-413 signing entrypoints`
- `Wallet SDK NEAR Ed25519 shared auth planning for delegate and NEP-413 signing, exact account/session selection, warm-session status normalization, and step-up handoff`

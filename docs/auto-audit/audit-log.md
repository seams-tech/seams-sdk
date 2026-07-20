# Auto Audit Log

Last updated: `2026-07-13T00:05:03Z`

## Latest Entry

- Timestamp: `2026-07-13T00:05:03Z`
- Target file: `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`
- Flow: `Wallet SDK NEAR Ed25519 lane selection, readiness planning, passkey or Email OTP reauth, confirmation funding, and transaction/delegate/NEP-413 signing entrypoints`
- Report: [`/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-07-13T00-05-03Z-sdk-web-sign-near-readiness.md`](/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-07-13T00-05-03Z-sdk-web-sign-near-readiness.md)
- Findings:
  - Security: `2`
  - Refactor/slimming: `2`
- Highest severity: `medium`
- Highest-severity items:
  - Runtime-validated NEAR transaction lanes ignore live warm-session status and can still plan stale sessions as ready.
  - Passkey reauth still sends the pre-reauth wallet-session JWT into implicit-account funding during confirmation.
- Next audit candidates:
  - `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts`
  - `packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts`
  - `packages/sdk-web/src/core/signingEngine/assembly/ports/near.ts`
  - `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/statusReader.ts`

## Audited Files

- `packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts`
- `packages/shared-ts/src/utils/routerAbEcdsaDerivation.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`
- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`

## Audited Flows

- `Router A/B ECDSA derivation registration, export, recovery, refresh, and normal-signing boundary`
- `Wallet SDK Router A/B ECDSA derivation wire parser, JWT rehydration, request digest binding, and active-session identity`
- `Wallet SDK Router A/B Ed25519 normal-signing prepare/finalize RPC, presign-pool refill, and budget-bound response binding`
- `Wallet SDK Router A/B Ed25519 wallet-session authority parsing, persisted-state classification, runtime worker-material validation, and NEAR readiness gating`
- `Wallet SDK NEAR Ed25519 lane selection, readiness planning, passkey or Email OTP reauth, confirmation funding, and transaction/delegate/NEP-413 signing entrypoints`

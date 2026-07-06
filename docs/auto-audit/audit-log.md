# Auto Audit Log

Last updated: `2026-07-06T00:04:08Z`

## Latest Entry

- Timestamp: `2026-07-06T00:04:08Z`
- Target file: `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
- Flow: `Wallet SDK Router A/B Ed25519 wallet-session authority parsing, persisted-state classification, runtime worker-material validation, and NEAR readiness gating`
- Report: [`/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-07-06T00-04-08Z-sdk-web-router-ab-wallet-session-state.md`](/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-07-06T00-04-08Z-sdk-web-router-ab-wallet-session-state.md)
- Findings:
  - Security: `1`
  - Refactor/slimming: `3`
- Highest severity: `medium`
- Highest-severity items:
  - Expired Ed25519 wallet sessions still parse as signable and can survive as `runtime_validated` ready state.
- Next audit candidates:
  - `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
  - `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`

## Audited Files

- `crates/router-ab-core/src/protocol/ecdsa_hss.rs`
- `packages/shared-ts/src/utils/routerAbEcdsaHss.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`
- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`

## Audited Flows

- `Router A/B ECDSA-HSS registration, export, recovery, refresh, and normal-signing boundary`
- `Wallet SDK Router A/B ECDSA-HSS wire parser, JWT rehydration, request digest binding, and active-session identity`
- `Wallet SDK Router A/B Ed25519 normal-signing prepare/finalize RPC, presign-pool refill, and budget-bound response binding`
- `Wallet SDK Router A/B Ed25519 wallet-session authority parsing, persisted-state classification, runtime worker-material validation, and NEAR readiness gating`

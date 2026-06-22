# Auto Audit Log

Last updated: `2026-06-22T00:04:22Z`

## Latest Entry

- Timestamp: `2026-06-22T00:04:22Z`
- Target file: `packages/shared-ts/src/utils/routerAbEcdsaHss.ts`
- Flow: `Wallet SDK Router A/B ECDSA-HSS wire parser, JWT rehydration, request digest binding, and active-session identity`
- Report: [`/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-06-22T00-04-22Z-shared-ts-router-ab-ecdsa-hss.md`](/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-06-22T00-04-22Z-shared-ts-router-ab-ecdsa-hss.md)
- Findings:
  - Security: `3`
  - Refactor/slimming: `2`
  - Highest severity: `high`
- Highest-severity items:
  - Finalize request digests omit `budget_reservation_id` and `budget_operation_id`.
  - Active-state session ids are collision-prone because they join unconstrained fields with `:`.
- Next audit candidates:
  - `packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`
  - `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
  - `crates/router-ab-cloudflare/src/lib.rs`

## Audited Files

- `crates/router-ab-core/src/protocol/ecdsa_hss.rs`
- `packages/shared-ts/src/utils/routerAbEcdsaHss.ts`

## Audited Flows

- `Router A/B ECDSA-HSS registration, export, recovery, refresh, and normal-signing boundary`
- `Wallet SDK Router A/B ECDSA-HSS wire parser, JWT rehydration, request digest binding, and active-session identity`

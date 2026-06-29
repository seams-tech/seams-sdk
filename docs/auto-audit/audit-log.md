# Auto Audit Log

Last updated: `2026-06-29T00:03:49Z`

## Latest Entry

- Timestamp: `2026-06-29T00:03:49Z`
- Target file: `packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`
- Flow: `Wallet SDK Router A/B Ed25519 normal-signing prepare/finalize RPC, presign-pool refill, and budget-bound response binding`
- Report: [`/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-06-29T00-03-49Z-sdk-web-router-ab-normal-signing.md`](/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-06-29T00-03-49Z-sdk-web-router-ab-normal-signing.md)
- Findings:
  - Security: `2`
  - Refactor/slimming: `2`
- Highest severity: `high`
- Highest-severity items:
  - Ed25519 prepare responses are not request-bound before the SDK uses `server_verifying_share_b64u`, `server_commitments`, and budget metadata.
- Next audit candidates:
  - `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
  - `crates/router-ab-cloudflare/src/signing_worker/mod.rs`
  - `crates/router-ab-cloudflare/src/lib.rs`

## Audited Files

- `crates/router-ab-core/src/protocol/ecdsa_hss.rs`
- `packages/shared-ts/src/utils/routerAbEcdsaHss.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`

## Audited Flows

- `Router A/B ECDSA-HSS registration, export, recovery, refresh, and normal-signing boundary`
- `Wallet SDK Router A/B ECDSA-HSS wire parser, JWT rehydration, request digest binding, and active-session identity`
- `Wallet SDK Router A/B Ed25519 normal-signing prepare/finalize RPC, presign-pool refill, and budget-bound response binding`

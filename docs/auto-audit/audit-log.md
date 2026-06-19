# Auto Audit Log

Last updated: `2026-06-18T08:05:26Z`

## Latest Entry

- Timestamp: `2026-06-18T08:05:26Z`
- Target file: `crates/router-ab-core/src/protocol/ecdsa_hss.rs`
- Flow: `Router A/B ECDSA-HSS registration, export, recovery, refresh, and normal-signing boundary`
- Report: [`/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-06-18T08-05-26Z-router-ab-core-protocol-ecdsa-hss.md`](/Users/pta/Dev/rust/seams-sdk/docs/auto-audit/2026-06-18T08-05-26Z-router-ab-core-protocol-ecdsa-hss.md)
- Findings:
  - Security: `3`
  - Refactor/slimming: `2`
  - Highest severity: `high`
- Highest-severity items:
  - Registration/export request validators do not enforce route-specific `lifecycle.work_kind`.
  - Active-state session ids are collision-prone because they join unconstrained fields with `:`.
- Next audit candidates:
  - `packages/shared-ts/src/utils/routerAbEcdsaHss.ts`
  - `crates/router-ab-cloudflare/src/lib.rs`
  - `crates/router-ab-cloudflare/src/durable_object.rs`

## Audited Files

- `crates/router-ab-core/src/protocol/ecdsa_hss.rs`

## Audited Flows

- `Router A/B ECDSA-HSS registration, export, recovery, refresh, and normal-signing boundary`

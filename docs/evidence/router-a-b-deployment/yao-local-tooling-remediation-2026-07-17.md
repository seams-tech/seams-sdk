# Yao Local Tooling Remediation

Date: 2026-07-17

Scope: post-review remediation of the two local evidence-integrity failures recorded by `independent-separation-review-2026-07-17.md`. This receipt does not supply deployed account or operator separation evidence.

## Changes

- Regenerated `crates/router-ab-dev/target/phase9c-yaos-ab-local-evidence-v1.json` through the canonical `pnpm validate:yaos-ab-local` gate.
- Rebound the Phase 13A local evidence fixture to the resulting 2,349-file source tree: 34,293,845 bytes, SHA-256 `6f02b1e3c1093ffa5c2c634fa4b01fd3d9574bc0ffff0f69c6d99d091a528818`.
- Refreshed the pinned digests for the changed Yao source guard and crate manifest.

The canonical local evaluator reports `deployment-required`, `phase13a_decision=unavailable`, and `production_eligible=false`. The four deployed-evidence requirements remain unavailable: cross-account benchmark, Workers analytics, measured cost, and operational topology acceptance.

## Validation

| Command | Result |
| --- | --- |
| `pnpm validate:yaos-ab-local` | Pass; 14 named gates completed, including 240/242 SDK Router browser cases with two explicitly skipped and 7/7 public local-product cases |
| `pnpm -C crates/ed25519-yao-cloudflare-bench test:deployment-tooling` | Pass |
| `pnpm -C crates/ed25519-yao-cloudflare-bench test:phase13a-local-preflight` | Pass, including evidence-mutation rejection fixtures |
| `pnpm -C crates/ed25519-yao-cloudflare-bench phase13a:local-preflight` | Pass as local evidence; final status `deployment-required` |

The independent review's production conclusion is unchanged. Same-account staging is locally substantiated; independent A/B accounts, principals, approvers, storage, logs, backups, deployed traces, and cross-account measurements still require external receipts.

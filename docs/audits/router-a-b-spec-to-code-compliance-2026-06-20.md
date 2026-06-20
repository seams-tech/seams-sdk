# Router A/B Spec-To-Code Compliance Audit

Date: June 20, 2026  
Scope: local Router A/B cleanup closeout after explicit supersession of
deployment setup and cross-refactor follow-up work.

## Executive Summary

Result: PASS for the local Router A/B cleanup scope.

No Critical, High, or security-relevant Medium findings remain for this plan.
Deployment setup, deployed Cloudflare browser/runtime evidence, and upload
workflow hardening are excluded by request and must be handled in a future
deployment plan. Remaining no-HSS and raw-material deletion work is owned by
Refactor 74/75; server-authoritative budget and step-up work is owned by
Refactor 70.

Confidence: 0.82. This is a scoped documentation-to-code audit, not a fresh full
test-suite run.

## Spec-IR

```yaml
spec_requirements:
  - id: router_ab_only_signing
    text: "Router A/B is the only SDK/server signing architecture for Ed25519 and ECDSA."
    evidence: "docs/router-a-b-cleanup.md:24-41"
    priority: critical
  - id: local_scope_closed
    text: "The local cleanup scope is closed and deployment setup is removed."
    evidence: "docs/router-a-b-cleanup.md:5-15"
    priority: high
  - id: supersession_ledger
    text: "No-HSS/material work, server budget work, hygiene, and deployment are owned by separate plans."
    evidence: "docs/router-a-b-cleanup.md:54-68"
    priority: high
  - id: no_old_public_signing_routes
    text: "Old public threshold signing routes are confined to cleanup/guard contexts."
    evidence: "docs/router-a-b-cleanup.md:45-52"
    priority: critical
  - id: worker_owned_material_boundary
    text: "TypeScript may route handles/public facts; signer-core/WASM owns crypto-secret material."
    evidence: "docs/refactor-68-wallet-session-v2.md:105-118"
    priority: critical
  - id: phase_15_9_closed
    text: "Active signing paths moved to worker-handle-backed material for local cleanup."
    evidence: "docs/router-a-b-cleanup.md:3117-3122"
    priority: high
  - id: phase_15_10_closed
    text: "Stale-record gating required by this cleanup landed for active Router A/B signing."
    evidence: "docs/router-a-b-cleanup.md:3676-3680"
    priority: high
  - id: phase_15_11_closed
    text: "Strict signable-state work blocks legacy-shaped Router A/B signing state."
    evidence: "docs/router-a-b-cleanup.md:3830-3835"
    priority: high
  - id: phase_15_12_superseded
    text: "Broad raw-material deletion moved to Refactor 74/75."
    evidence: "docs/router-a-b-cleanup.md:4208-4214"
    priority: medium
  - id: server_budget_authority
    text: "Server budget is authoritative; SDK projection is not policy authority."
    evidence: "docs/refactor-70-server-budget.md:136-146"
    priority: critical
  - id: budget_reserve_commit_release
    text: "Router A/B routes reserve before private worker, release on private failure, commit exactly once before returning a signature."
    evidence: "docs/refactor-70-server-budget.md:177-193"
    priority: critical
  - id: budget_error_semantics
    text: "Valid auth with mismatched or inactive backend grant state returns wallet_budget_forbidden."
    evidence: "docs/refactor-70-server-budget.md:251-263"
    priority: high
  - id: runtime_handle_validation_followup
    text: "Persisted material handles are hints; validation must ask the worker."
    evidence: "docs/refactor-74-login-no-hss.md:277-281"
    priority: medium
```

## Code-IR

```yaml
code_observations:
  - id: strict_signable_ed25519_shape
    file: packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts
    evidence: "lines 20-38 require wallet-session auth, threshold session id, signing grant id, material ref, runtime scope, signing root, and Router A/B state"
    alignment: worker_owned_material_boundary
  - id: strict_signable_ecdsa_shape
    file: packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts
    evidence: "lines 40-52 require Router A/B ECDSA-HSS state and reject raw client verifier/share fields with never fields"
    alignment: worker_owned_material_boundary
  - id: runtime_ed25519_material_validation_key
    file: packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts
    evidence: "lines 150-187 track runtime validation by threshold session, signing grant, JWT, handle, binding digest, verifier, signing root, and SigningWorker"
    alignment: runtime_handle_validation_followup
  - id: ecdsa_signable_parser_rejects_missing_state
    file: packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts
    evidence: "lines 340-399 reject cookie sessions, missing JWT, missing grant, missing runtime scope, missing Router A/B state, verifier mismatch, signing-root mismatch, and invalid budget"
    alignment: worker_owned_material_boundary
  - id: budget_service_methods_shared
    file: packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts
    evidence: "lines 114-130 define shared reserve, validate, commit, and release methods"
    alignment: server_budget_authority
  - id: budget_digest_helper
    file: packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts
    evidence: "lines 392-412 implement canonical length-prefixed field hashing"
    alignment: budget_reserve_commit_release
  - id: forward_then_commit_budget
    file: packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts
    evidence: "lines 577-606 release on private worker failure, commit after private success, and return no signature when commit fails"
    alignment: budget_reserve_commit_release
  - id: ed25519_budget_reservation
    file: packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts
    evidence: "lines 885-908 reserve Ed25519 prepare budget and return reservation metadata"
    alignment: budget_reserve_commit_release
  - id: ed25519_finalize_budget_validation
    file: packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts
    evidence: "lines 989-1015 validate finalize reservation, release mismatches, then forward and commit"
    alignment: budget_reserve_commit_release
  - id: ecdsa_budget_reservation
    file: packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts
    evidence: "lines 1427-1450 reserve ECDSA-HSS prepare budget and return reservation metadata"
    alignment: budget_reserve_commit_release
  - id: ecdsa_finalize_budget_validation
    file: packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts
    evidence: "lines 1500-1528 validate ECDSA-HSS finalize reservation, release mismatches, then forward and commit"
    alignment: budget_reserve_commit_release
  - id: budget_status_fail_closed
    file: packages/sdk-server-ts/src/router/signingBudgetStatus.ts
    evidence: "lines 246-292 reject expired/incomplete JWT as unauthorized and missing/expired/mismatched backend budget as wallet_budget_forbidden"
    alignment: budget_error_semantics
  - id: budget_evidence_hard_assertions
    file: tests/e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts
    evidence: "lines 211-246 assert remainingUses 3 -> 2 -> 1 -> 0 and require a new signingGrantId after exhaustion"
    alignment: server_budget_authority
```

## Alignment Matrix

| Area | Spec Evidence | Code Evidence | Status |
| --- | --- | --- | --- |
| Router A/B-only product signing | `docs/router-a-b-cleanup.md:24-52` | Source guard and completion criteria remain tracked in `docs/router-a-b-cleanup.md:5106-5113` | Aligned |
| Worker-owned client material | `docs/refactor-68-wallet-session-v2.md:105-118` | `routerAbSigningWalletSession.ts:20-52`, `150-187`, `340-399` | Aligned for cleanup scope; deeper no-HSS deletion is Refactor 74/75 |
| Server budget authority | `docs/refactor-70-server-budget.md:136-146` | `routerAbPrivateSigningWorker.ts:114-130`, `577-606` | Aligned |
| Reserve/commit/release lifecycle | `docs/refactor-70-server-budget.md:177-193` | `routerAbPrivateSigningWorker.ts:885-908`, `989-1015`, `1427-1450`, `1500-1528` | Aligned |
| Budget status failures | `docs/refactor-70-server-budget.md:251-263` | `signingBudgetStatus.ts:246-292` | Aligned |
| Shared budget evidence | `docs/refactor-70-server-budget.md:37-40` | `routerAb.serverBudgetEvidence.walletIframe.test.ts:211-246` | Aligned |
| Deployment work | `docs/router-a-b-cleanup.md:5-15`, `54-68` | No deployment phase remains in this plan | Excluded by request |

## Divergence Findings

No unresolved Critical, High, or security-relevant Medium findings were found
within the local cleanup scope.

Low/Deferred Notes:

- Deployment setup and deployed runtime evidence are intentionally excluded from
  this plan. This is not a local cleanup finding.
- Refactor 74/75 still own the deeper no-HSS and raw-material deletion model.
  This is explicitly superseded by `docs/router-a-b-cleanup.md:58-60` and is not
  a blocker for this plan.
- Refactor 70 owns server-authoritative budget and step-up behavior. That plan
  is referenced as complete for the local evidence slice at
  `docs/refactor-70-server-budget.md:21-40`.

## Phase 15.19 Disposition

Phase 15.19 may remain closed. There are no findings to copy into it for the
local Router A/B cleanup scope.

## Validation Performed

- Read `spec-to-code-compliance` skill instructions and output/checklist
  resources.
- Reconciled `docs/router-a-b-cleanup.md` Phase 15.9 through 15.12, Phase 15.17,
  Phase 15.18, and Phase 15.19 against the current owner plans and code
  evidence.
- Verified the cleanup plan has no remaining unchecked checklist items after
  marking stale tasks as superseded.
- Verified deployment setup was removed from the cleanup plan.

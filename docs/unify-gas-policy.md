# Unify Gas Sponsorship Policy With Transaction Policy

## Goal

Unify gas sponsorship and transaction policies around one policy identity and lifecycle:

- one policy record model
- one versioning model
- one approval and publish flow
- one audit vocabulary

Do this with minimal behavior change. Breaking changes are acceptable. Legacy compatibility branches are not.

## First-Cut Constraints

This refactor should stay narrow.

Do:

- unify policy identity
- unify draft and publish lifecycle
- unify approval handling
- unify audit and API naming around real `policyId`

Do not do in the first cut:

- do not invent a generic mega-rule engine
- do not introduce `entries[]` or `policyEntryId`
- do not force gas scopes into the existing transaction-policy assignment model
- do not rewrite the relay hot path to consume a generic policy payload directly
- do not require the dashboard gas page to be deleted in the same backend refactor

## Minimal Target Model

### Shared policy envelope

Both kinds should use one top-level policy record shape:

- `id`
- `kind` (`TRANSACTION` | `GAS_SPONSORSHIP`)
- `name`
- `status` (`DRAFT` | `PUBLISHED` | `ARCHIVED`)
- `version`
- `createdAt`
- `updatedAt`
- `publishedAt`
- `rules`

### Kind-specific rules

Use a discriminated union for `rules`:

- `TransactionPolicyRules`
- `GasSponsorshipPolicyRules`

`TransactionPolicyRules` should remain behaviorally unchanged.

`GasSponsorshipPolicyRules` should preserve the current gas sponsorship config semantics one-to-one:

- `scopeType` (`ORG` | `PROJECT` | `ENVIRONMENT` | `POLICY` | `WALLET_SEGMENT`)
- `projectId`
- `environmentId`
- `scopePolicyId`
- `walletSegmentId`
- `enabled`
- `templateId`
- `networkClass`
- `allowedChainIds`
- `callMode`
- `allowedCalls`
- `spendCap`

Notes:

- `scopePolicyId` replaces the old overloaded gas field named `policyId`.
- `policyId` should refer only to the actual policy record id.
- Telemetry is not policy definition data. Keep it derived/runtime-side, not versioned policy rules.

### Why this is the minimal model

Each existing gas sponsorship config becomes one `GAS_SPONSORSHIP` policy record.

That means:

- no grouping multiple gas configs into one parent policy
- no second identity layer for gas entries
- no need for `policyEntryId`
- no need to redesign spend-cap accounting around sub-entries

## Scope Semantics

Do not unify scope semantics in the first cut.

Transaction policies currently use the policy assignment model.
Gas sponsorship currently has its own scope vocabulary, including `POLICY` and `WALLET_SEGMENT`.

For a minimal refactor:

- keep transaction policy assignment behavior as-is
- keep gas sponsorship scope behavior as-is
- unify only the top-level policy envelope and lifecycle

If scope models should be merged later, that should be a separate refactor after the backend model is stable.

## Approval and Publish

Reuse the existing policy publish approval flow.

Rules:

- keep `POLICY_PUBLISH` as the approval operation type
- do not create a separate gas-specific approval operation type
- include `policyKind` in approval metadata and audit payloads
- default gas policy publish approvals to `requiredApprovals = 1`
- default the required mutation role to `admin` or the existing admin-equivalent role set

This keeps approval taxonomy small while still making gas policy approvals visible in audit and UI.

## Storage and Migration

### Policy storage

Add `kind` support to the policy tables and version rows so both transaction and gas sponsorship policies live in the same policy store.

### Migration strategy

Migrate existing gas sponsorship configs one-to-one:

- one gas sponsorship config becomes one `GAS_SPONSORSHIP` policy
- carry over the existing config `name`
- carry over the existing scope fields into `GasSponsorshipPolicyRules`
- carry over the current enabled/rule/spend-cap settings
- create a published policy version when the source config is currently live

### Downstream references

Migrate downstream sponsorship data from config identity to unified policy identity:

- sponsored call ledger rows should reference `policyId`
- spend-cap windows and reservations should reference `policyId`

Do not add `policyEntryId` in this migration.

The one-to-one mapping is the reason this stays simple.

## API and Runtime Refactor

### API surface

Policy APIs should become the source of truth for both kinds.

Required changes:

- add `kind` filtering to policy list/read endpoints
- support create/update/publish for `GAS_SPONSORSHIP` policies
- expose `policyKind` in responses where relevant

Transition rule:

- the dedicated gas dashboard page may remain temporarily as a thin client adapter over `/console/policies`
- do not keep a dedicated backend `/console/gas-sponsorship` CRUD surface
- do not keep a second source of truth

### Runtime payloads

Do not force the relay to consume a generic policy document directly.

Instead:

- keep a dedicated gas execution projection in runtime snapshots
- derive that projection from published `GAS_SPONSORSHIP` policies
- keep relay matching logic focused on gas execution data, not authoring-format policy objects

This preserves hot-path clarity and avoids coupling execution to policy authoring shape.

### Naming contract

Use these names consistently:

- `policyId`: actual policy record id
- `policyKind`: `TRANSACTION` or `GAS_SPONSORSHIP`
- `scopePolicyId`: gas sponsorship rule field for policy-scoped targeting

Do not keep or reintroduce:

- `sponsorshipConfigId`
- `sponsorshipConfigNameAtEvent`
- gas-owned `policyId` fields that are not actual policy ids

## Dashboard Plan

Keep the UI plan narrow.

Phase 1:

- backend unification first
- existing gas sponsorship page can call the unified backend through an adapter if that reduces churn

Phase 2:

- keep the dedicated gas page unless folding it into policy engine clearly removes code and duplicated UX

If policy engine convergence happens later:

- add `kind` filters or tabs
- reuse the shared publish and approval UI shell
- keep `?policyId=...` selection behavior

But do not block the backend refactor on the UI merge.

## Testing Plan

Required test coverage:

- gas config to policy migration correctness
- publish flow for `GAS_SPONSORSHIP` policies
- approval defaults for gas policy publish
- runtime projection derived from published gas policies
- sponsored call matching against unified gas policy projection
- spend-cap accounting using migrated `policyId`
- audit payloads including `policyId` and `policyKind`

Avoid expanding test scope into unrelated UI redesign work in the first cut.

## Phased TODO List

### Immediate next steps

- [x] remove remaining standalone gas sponsorship service/adaptor exports
- [x] decide that the gas dashboard remains a thin policy-backed surface for now
- [x] delete the remaining `/console/gas-sponsorship` backend route adapter and switch the remaining route tests to `/console/policies`
- [x] retire or rewrite older planning docs that still describe the removed gas route
- [x] keep the thin gas dashboard adapter for now; only merge into policy engine if doing so clearly removes code
- [x] remove the old gas CRUD helper surface from shared router adaptor exports
- [x] rename remaining gas config-shaped symbols to policy projection terminology

### Phase 1: Shared Policy Envelope

- [x] Add `kind` to policy records and policy versions.
- [x] Add `GasSponsorshipPolicyRules` as a policy rules union member.
- [x] Preserve existing gas scope semantics inside gas rules.
- [x] Rename gas rule field `policyId` to `scopePolicyId`.
- [x] Keep transaction policy rules unchanged.

Phase 1 exit criteria:

- The policy store can persist both transaction and gas sponsorship policies without changing gas behavior.

### Phase 2: Shared Publish and Approval Flow

- [x] Reuse the existing `POLICY_PUBLISH` approval flow for gas policies.
- [x] Include `policyKind` in approval metadata.
- [x] Include `policyKind` in publish audit metadata.
- [x] Set default gas publish approvals to one admin approver.
- [x] Add router and service support for listing and mutating policies by `kind`.

Phase 2 exit criteria:

- Gas policies are real policy records with the same draft, approval, and publish lifecycle as transaction policies.

### Phase 3: Migration and Downstream Reference Cutover

- [x] Migrate each gas sponsorship config to one `GAS_SPONSORSHIP` policy.
- [x] Rename remaining gas sponsorship API/UI scope fields from `policyId` to `scopePolicyId`.
- [x] Migrate sponsored call rows from config id references to `policyId`.
- [x] Migrate spend-cap rows from config id references to `policyId`.
- [x] Remove remaining overloaded config identity usage from production code.

Phase 3 exit criteria:

- Runtime writes and reads no longer depend on gas sponsorship config ids.

### Phase 4: Runtime Projection Cleanup

- [x] Keep a dedicated runtime gas execution projection.
- [x] Change that projection to be derived from published gas policies.
- [x] Keep relay matching code focused on gas execution data.
- [x] Update audit and insights payloads to expose `policyId` and `policyKind` explicitly.

Phase 4 exit criteria:

- Sponsorship execution runs on unified policy data without turning the relay into a generic policy interpreter.

### Phase 5: UI Convergence Decision

- [x] Decide whether the dedicated gas page should remain as a policy-backed surface or be merged into policy engine.
- [ ] If merging, implement `kind`-aware policy engine UI.
- [x] If not merging yet, keep the gas page as a thin adapter only.

Phase 5 exit criteria:

- There is only one backend source of truth regardless of whether one or two UI surfaces remain temporarily.

## Definition of Done

- Gas sponsorship is stored as `GAS_SPONSORSHIP` policy records.
- `policyId` always means a real policy record id.
- Gas publish uses the shared policy approval and publish flow.
- Sponsored execution and spend-cap accounting read unified policy identities.
- No production code depends on legacy gas sponsorship config identity.

## Legacy Removal (Mandatory Final Cleanup)

Remove legacy paths as soon as the unified backend cutover is complete. Do not keep dead compatibility branches.

Mandatory backend removals:

- old gas sponsorship config tables
- old gas sponsorship config ids in ledger and spend-cap tables
- old backend structs that model gas sponsorship as a separate top-level resource
- old runtime fields that expose config identity instead of policy identity

Mandatory naming removals:

- `sponsorshipConfigId`
- `sponsorshipConfigNameAtEvent`
- gas-owned overloaded `policyId` fields that are not true policy ids

Backend files/modules expected to be deleted or replaced after cutover:

- `server/src/console/gasSponsorship/types.ts`
- `server/src/console/gasSponsorship/requests.ts`
- `server/src/console/gasSponsorship/onboarding.ts`
- `server/src/console/gasSponsorship/index.ts`

Runtime and accounting modules expected to be simplified after cutover:

- `server/src/router/runtimeSnapshotPayload.ts`
- `server/src/sponsorship/evm.ts`
- `server/src/sponsorship/evmRelay.ts`
- `server/src/console/sponsoredCalls/*`
- `server/src/console/sponsorshipSpendCaps/*`

UI removals are conditional:

- remove the dedicated gas sponsorship page and API only if policy engine fully replaces it
- otherwise keep them as thin adapters and remove only the old backend model beneath them

Final verification gate:

- `rg` searches for `sponsorshipConfigId` and legacy gas config identity terms return no production code hits
- gas publish, runtime sponsorship, spend-cap, audit, and dashboard tests pass on unified policy-backed behavior

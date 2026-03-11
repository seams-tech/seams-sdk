# Unify Gas Sponsorship Policy With Transaction Policy

## Goal

Unify gas sponsorship policy and transaction policy under one policy model so both use the same lifecycle (draft, approval, publish), assignment semantics, and auditability.

Breaking changes are acceptable. Legacy compatibility paths should not be retained.

## Scope

- In scope:
  - Shared policy struct types and storage model for both policy kinds.
  - Shared approval and publish flow.
  - Runtime projection and relay matching updated to unified payloads.
  - Dashboard policy-engine UX updated to manage both kinds.
  - Full migration from gas sponsorship configs to policy records.
- Out of scope:
  - Backward-compatible dual-write/read paths.
  - Long-lived feature flags for old gas sponsorship config routes.

## Canonical Model

### 1) Shared envelope type

Define a single policy envelope:

- `id`
- `kind` (`TRANSACTION` | `GAS_SPONSORSHIP`)
- `name`
- `status` (`DRAFT` | `PUBLISHED` | `ARCHIVED`)
- `version`
- `createdAt`
- `updatedAt`
- `publishedAt`
- `rules` (kind-discriminated payload)

### 2) Kind-specific rules

Keep one discriminated union:

- `TransactionPolicyRules`
- `GasSponsorshipPolicyRules`

`GasSponsorshipPolicyRules` should contain `entries[]`, where each entry has:

- `entryId` (stable id for accounting and matching)
- `enabled`
- `scope constraints` (project/environment/wallet-segment constraints if needed)
- `networkClass`
- `allowedChainIds`
- `callMode`
- `allowedCalls`
- `spendCap`

### 3) Shared assignment semantics

Use one assignment model and precedence rules across both kinds:

- `ORG`
- `PROJECT`
- `ENVIRONMENT`
- `WALLET`

Resolution should be per scope and per `kind`.

## Approval and Publish

Use one approval pipeline for publish across both policy kinds.

Default approval config for gas sponsorship:

- `operationType`: policy publish operation for `GAS_SPONSORSHIP` kind
- `requiredApprovals`: `1`
- required role: `admin` (or existing admin-equivalent role set)

Approval/audit metadata must include policy `kind` and `policyId`.

## Data Migration Plan (Single Breaking Cutover)

### 1) Schema changes

- Add `kind` and rules union support in policy tables/version rows.
- Add any missing columns/indexes required for gas-rule entry resolution.
- Add new references for sponsorship accounting:
  - `policyId`
  - `policyEntryId` (for gas rule entry identity)

### 2) Backfill gas configs to policies

For each org:

- Read all gas sponsorship configs.
- Group into target gas policies by scope strategy (deterministic).
- Create `GAS_SPONSORSHIP` policy records + policy versions.
- Create assignments for effective scopes.
- Generate stable `policyEntryId` per former config.

### 3) Migrate downstream references

Migrate sponsorship-related records from config identity to policy identity:

- sponsored call ledger rows
- spend cap windows/reservations
- runtime projection dependencies

Persist mapping only for migration execution; remove mapping artifacts after verification.

### 4) Deletion

After successful migration:

- remove old gas sponsorship config tables
- remove old gas sponsorship service interfaces/routes
- remove old sponsorship-config-centric payload fields

No legacy fallback branches should remain.

## API and Runtime Refactor

### 1) API surface

- Policy endpoints become the source of truth for both kinds.
- Gas sponsorship CRUD endpoints are removed.
- Policy APIs support filtering by `kind`.

### 2) Runtime payloads

- Runtime snapshots expose unified `policies` grouped or filterable by `kind`.
- Remove dedicated `sponsoredCallConfigs` projection.
- Relay matcher resolves applicable `GAS_SPONSORSHIP` policy and selects matching `entryId`.

### 3) Naming contracts

- `policyId` always means real policy record id.
- For gas entry-level references, use `policyEntryId`.
- Do not reintroduce overloaded fields like `sponsorshipConfigId`.

## Dashboard Changes

### 1) Policy Engine as single surface

- Add policy kind filters/tabs:
  - Transaction
  - Gas Sponsorship
- Reuse shared lifecycle controls:
  - Edit draft
  - Request approval
  - Approve/reject
  - Publish

### 2) Gas editor in policy engine

- Gas-specific form for `GasSponsorshipPolicyRules`.
- Show publish timeline and approvals like transaction policies.
- Keep URL behavior:
  - `?policyId=...` selects and expands the policy row for both kinds.

## Testing Plan

### 1) Migration tests

- Config-to-policy conversion correctness.
- Assignment precedence preserved after migration.
- Referential integrity for sponsorship ledger/spend-cap rows.

### 2) Service/router tests

- Policy CRUD and publish by kind.
- Approval defaults for gas policies (`requiredApprovals=1`).
- `policy_not_found` behavior for all references.

### 3) End-to-end tests

- Create gas policy draft, request approval, approve, publish.
- Sponsored call matching on published gas policy entries.
- Spend-cap reservation/settle/release using `policyId + policyEntryId`.

## Phased TODO List

### Phase 1: Canonical Types and Schema

- [ ] Add `PolicyKind` support everywhere policy records are modeled and decoded.
- [ ] Add `GasSponsorshipPolicyRules` union member with stable `entryId` support.
- [ ] Add DB support for `kind` in policy records/versions.
- [ ] Add DB support for sponsorship execution references: `policyId` + `policyEntryId`.
- [ ] Add indexes for `policyId` + `policyEntryId` lookup on sponsorship accounting tables.
- [ ] Remove any remaining overloaded naming in new code paths.

Phase 1 exit criteria:

- All compile-time policy types can represent transaction and gas policies in one envelope.
- New schema can store and query gas policy rules without using gas sponsorship config tables.

### Phase 2: Policy Service + Publish/Approval Unification

- [ ] Extend policy service CRUD/list/version APIs to support `kind=GAS_SPONSORSHIP`.
- [ ] Implement gas policy publish with shared approval path.
- [ ] Set gas publish approval defaults to one admin approver.
- [ ] Ensure audit events always include `policyId` and `kind`.
- [ ] Remove any gas-specific publish bypass route.

Phase 2 exit criteria:

- Gas policies can be created, edited, approved, and published through the policy service only.

### Phase 3: Runtime + Relay Cutover

- [ ] Replace runtime payload use of `sponsoredCallConfigs` with unified policy payload.
- [ ] Update sponsorship matcher to resolve effective gas policy and matched `policyEntryId`.
- [ ] Update sponsored call ledger writes to persist `policyId` + `policyEntryId`.
- [ ] Update spend-cap reservation/settle/release paths to key by `policyId` + `policyEntryId`.

Phase 3 exit criteria:

- Sponsored execution path runs entirely on unified gas policy data.

### Phase 4: Dashboard Policy Engine Unification

- [ ] Add policy kind filters/tabs in policy engine (`TRANSACTION`, `GAS_SPONSORSHIP`).
- [ ] Implement gas rules editor under policy engine using shared draft/publish shell.
- [ ] Move approvals UI to single policy approval timeline for both kinds.
- [ ] Keep deep-link behavior: `?policyId=...` selects and expands row for both kinds.
- [ ] Remove dashboard dependency on dedicated gas sponsorship page/API for config management.

Phase 4 exit criteria:

- Users can fully manage gas policies from policy engine without separate config UI.

### Phase 5: Data Migration + Hard Cutover

- [ ] Migrate existing gas sponsorship configs into `GAS_SPONSORSHIP` policy records/versions.
- [ ] Migrate sponsorship ledger/spend-cap rows from config ids to `policyId` + `policyEntryId`.
- [ ] Verify assignment precedence and runtime behavior match pre-cutover behavior.
- [ ] Run fixture/e2e sweeps and update all assumptions about old gas config identity.
- [ ] Remove migration helpers and temporary mapping artifacts after validation.

Phase 5 exit criteria:

- No runtime reads depend on old gas sponsorship config storage or identifiers.

## Definition of Done

- Gas sponsorship is represented only as `GAS_SPONSORSHIP` policy records.
- `policyId` is globally consistent and always points to a real policy record.
- Sponsorship execution, spend-cap accounting, audit, and insights use unified policy identities.
- No legacy gas sponsorship config APIs/types/tables remain.

## Legacy Removal (Mandatory Final Cleanup)

After Phase 5, remove all legacy gas sponsorship config surfaces in the same cleanup window. Do not leave compatibility branches.

API and route paths to remove:

- `/console/gas-sponsorship` list/create/update handlers.
- Any router helpers that parse or project gas sponsorship config DTOs directly.

Legacy structs and fields to remove or rename:

- `ConsoleGasSponsorshipConfig` as a top-level managed resource.
- `CreateConsoleGasSponsorshipRequest` and `UpdateConsoleGasSponsorshipRequest`.
- `ResolvedSponsoredCallConfig` payload shape derived from gas config resources.
- `sponsorshipConfigId` and `sponsorshipConfigNameAtEvent` in runtime/ledger payloads.
- Any remaining `sponsoredCallConfigs` payload contracts.

Legacy files/modules to delete or replace:

- `server/src/console/gasSponsorship/types.ts`
- `server/src/console/gasSponsorship/requests.ts`
- `server/src/console/gasSponsorship/service.ts`
- `server/src/console/gasSponsorship/postgres.ts`
- `server/src/console/gasSponsorship/onboarding.ts`
- `server/src/console/gasSponsorship/index.ts`
- `examples/tatchi-site/src/pages/dashboard/routes/gas-sponsorship/consoleGasSponsorshipApi.ts`
- `examples/tatchi-site/src/pages/dashboard/routes/gas-sponsorship/page.tsx`

Legacy schema/storage to remove after data migration validation:

- `console_gas_sponsorship_configs` table and dependent indexes/constraints.
- Any sponsorship tables/columns keyed by gas sponsorship config identity instead of policy identity.

Final verification gate before merge:

- `rg` searches for `sponsorshipConfigId`, `sponsoredCallConfigs`, and `/console/gas-sponsorship` return no production code hits.
- All sponsorship execution, accounting, audit, and dashboard tests pass on policy-only paths.

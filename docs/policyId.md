# Policy ID Consistency Plan

Date updated: March 11, 2026

## Objective

Make `policyId` semantics consistent across console backend, dashboard APIs, runtime payloads, persisted records, and user-facing views.

The target rule is simple:

- `policyId` is the canonical, opaque, server-generated identifier for a console policy record.
- `policyId` always points to `console_policies.id`.
- New policies always receive generated `policy_...` IDs. Clients do not choose policy IDs.
- `policyName` is the mutable human-readable name of that canonical console policy.
- If another subsystem has its own config identity, it must use subsystem-specific fields such as `configId`, `configName`, or `sponsorshipConfigId`.

`policyId` should be globally unique within a namespace, even if tenant isolation and foreign keys still include `org_id`.

## Current Problems

### 1. Policy creation still accepts caller-supplied IDs

Today, policy creation still accepts `id` from the request body and persists it directly. That means `policyId` is not yet a fully opaque server-owned identifier.

Affected areas:

- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/policies/types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/policies/requests.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/policies/service.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/policies/postgres.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/policy-engine/consolePoliciesApi.ts`

### 2. Policy storage uniqueness and migration are only partially refactored

The system default policy no longer relies on `orgId:policy:default`, but the broader system still permits ad hoc policy IDs and still uses composite storage keys keyed by `(namespace, org_id, id)`.

We need a stronger invariant:

- canonical `policyId` is globally unique within a namespace
- all existing canonical policy records are normalized to generated `policy_...` IDs
- all persisted references are rewritten to the normalized ID

Affected areas:

- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/policies/postgres.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/console-router.test.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/console-tenant-isolation.postgres.test.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/examples/relay-server/src/index.ts`

### 3. `policyId` is overloaded in gas sponsorship and sponsored-call flows

Today, gas sponsorship uses `policyId` in two different ways:

- as the canonical console policy foreign key when `scopeType === 'POLICY'`
- as the resolved gas-sponsorship config identity in runtime and sponsored-call paths

This is the main source of ambiguity after canonical policy creation itself.

Affected areas:

- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/gasSponsorship/types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/gasSponsorship/onboarding.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/evm.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/service.ts`

### 4. Policy-scoped config modules do not enforce referential integrity

Smart-wallet and gas-sponsorship config services currently only validate that a `policyId` is present for `scopeType === 'POLICY'`. They do not verify that the policy actually exists in the same org.

Affected areas:

- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/smartWallets/service.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/smartWallets/postgres.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/gasSponsorship/service.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/gasSponsorship/postgres.ts`

### 5. User-facing read models and audit/history views still leak or infer policy identity

Some dashboard screens and read models still surface raw IDs where a human-readable policy name should be projected. Audit and approval flows also still need inference from generic `resourceType` and `resourceId` in places where policy identity should be explicit.

Affected areas:

- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/consoleInsights.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/consoleInsightsApi.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/wallets/types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/wallets/consoleWalletApi.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/wallets-list/page.tsx`
- `/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/audit/page.tsx`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/createConsoleRouter.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/createCloudflareConsoleRouter.ts`

### 6. Historical and runtime outputs need explicit naming rules

History-like outputs may need to snapshot a display name, but that should be explicit and immutable. We should not use ambiguous fields like bare `policyName` on records that are not canonical console policies.

Affected areas:

- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/runtimeSnapshots/types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/runtimeSnapshotPayload.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/types.ts`

## Locked Naming Rules

Use these rules everywhere going forward:

- Canonical console policy entity:
  - `policyId`
  - `policyName`
- `policyId` is opaque:
  - do not derive org, scope, or behavior from its string form
  - do not reconstruct special policy IDs from `orgId`
- Policy creation:
  - create requests do not accept `id`
  - the server generates `policy_...`
- Foreign keys pointing to `console_policies.id`:
  - `policyId`
- Display projections of canonical policy:
  - include both `policyId` and `policyName` when humans see them
- Generic resource envelopes:
  - `resourceType` and `resourceId` may still exist
  - if `resourceType === 'POLICY'`, include explicit `policyId`
- Subsystem-owned config identity:
  - use subsystem-specific names, for example:
    - `sponsorshipConfigId`
    - `sponsorshipConfigName`
    - `smartWalletConfigId`
- Immutable history and event labels:
  - use explicit suffixes such as:
    - `policyNameAtEvent`
    - `sponsorshipConfigNameAtEvent`

Do not introduce new generic `policyId` fields unless they point to `console_policies.id`.

## Phased TODO List

### Phase 1: Lock canonical policy creation contract

- [ ] Remove `id` from `CreateConsolePolicyRequest`.
- [ ] Update request parsing so client-supplied `id` on policy create is rejected instead of tolerated.
- [ ] Update in-memory and Postgres policy creation to always generate `policy_...`.
- [ ] Update dashboard policy-create APIs so they do not send policy IDs.
- [ ] Update tests and fixtures to capture created IDs from responses instead of hard-coding caller-owned IDs where creation is under test.
- [ ] Delete any remaining code paths that treat policy ID as client-controlled input.

Expected error contract:

- `POST /console/policies` with body `id` should return `invalid_body`
- policy creation returns a server-generated canonical `policyId`

### Phase 2: Make canonical policy IDs globally unique and migrate existing data

- [ ] Add a uniqueness guarantee on canonical policy IDs at the storage layer, at minimum on `(namespace, id)`.
- [ ] Keep tenant isolation and RLS intact while adding the stronger uniqueness invariant.
- [ ] Extend the current migration beyond the legacy default policy to all non-canonical existing policy IDs.
- [ ] Rewrite every persisted foreign-key-like reference to migrated policy IDs, including:
  - `console_policy_versions`
  - `console_policy_assignments`
  - `console_wallet_index`
  - `console_smart_wallet_configs`
  - `console_gas_sponsorship_configs`
  - `console_approvals`
  - `console_audit_events`
  - `console_sponsorship_spend_cap_windows`
  - `console_sponsorship_spend_cap_reservations`
  - `console_sponsored_call_records`
- [ ] Normalize seed data, demo data, and tests so canonical policy rows no longer use org-derived or ad hoc IDs.
- [ ] Delete remaining org-derived policy ID assumptions after migration coverage is in place.

Expected outcome:

- every canonical persisted policy row uses a generated `policy_...` ID
- canonical `policyId` is unique within a namespace
- migration logic is isolated to one cleanup path instead of scattered legacy checks

### Phase 3: Remove overloaded `policyId` usage in downstream subsystems

- [ ] Rename gas-sponsorship config display field from `policyName` to `name` or `configName`.
- [ ] Rename resolved gas-sponsorship runtime payload fields away from `policyId` and `policyName` when they actually refer to gas-sponsorship config identity.
- [ ] Rename sponsored-call ledger fields away from generic `policyId` if they store gas-sponsorship config identity rather than canonical console policy identity.
- [ ] Update API adapters, router payload builders, and tests so the renamed fields are used everywhere.
- [ ] Delete any legacy aliases instead of carrying dual names.

Recommended target:

- gas sponsorship config entity:
  - `id`
  - `name`
- resolved sponsored-call payload:
  - `sponsorshipConfigId`
  - `sponsorshipConfigName`
- sponsored-call record:
  - `sponsorshipConfigId`
  - optional `sponsorshipConfigNameAtEvent`

### Phase 4: Enforce canonical policy referential integrity

- [ ] Inject or compose policy lookup into smart-wallet config create and update flows.
- [ ] Inject or compose policy lookup into gas-sponsorship config create and update flows.
- [ ] Reject `scopeType === 'POLICY'` when the referenced policy does not exist in the same org.
- [ ] Reject stray canonical `policyId` values for shapes that should not carry them, instead of silently preserving invalid scope combinations.
- [ ] Add parity coverage for Express, Cloudflare, in-memory, and Postgres implementations.

Expected error contract:

- missing referenced policy should return `policy_not_found`
- invalid scope shape should continue returning `invalid_scope`

### Phase 5: Fix user-facing projections and linking

- [ ] Add `policyName` to wallet read models used by dashboard pages.
- [ ] Add `policyName` to policy coverage and insights projections.
- [ ] Update dashboard wallet tables, wallet detail views, and insights pages to display `policyName ?? policyId`.
- [ ] Keep filtering, linking, and routing based on `policyId`, but stop using raw IDs as the primary visible label.
- [ ] Reuse a shared policy-directory lookup helper rather than open-coding lookup maps per page where practical.
- [ ] Ensure audit and approval views receive explicit `policyId` for policy resources instead of relying on `resourceType` plus `resourceId` inference.
- [ ] Ensure policy links in audit and approval UX target canonical policy viewers using `policyId`.

Expected outcome:

- users see human-readable names
- IDs remain available for links, filters, titles, and diagnostics
- audit and approval views stop guessing policy identity from generic resource fields

### Phase 6: Make runtime and history semantics explicit

- [ ] Audit runtime snapshot policy payloads and decide which fields are canonical policy references versus resolved display metadata.
- [ ] Tighten `ConsoleRuntimeSnapshotPayload.policy` typing so it is not just `Record<string, unknown>` where we already know the shape.
- [ ] For generic resource envelopes that represent policy resources, include explicit `policyId`.
- [ ] For immutable records or event logs that need labels, store explicit `...NameAtEvent` fields instead of ambiguous live-display names.
- [ ] Ensure published snapshot tests, audit tests, and event tests assert the intended ID semantics, not just string presence.

This phase is about reducing future reintroduction of ambiguity.

## Suggested Order

1. Lock policy creation so canonical policy IDs become server-owned.
2. Add uniqueness guarantees and migrate all canonical policy rows and references.
3. Remove overloaded `policyId` usage in gas sponsorship and sponsored calls.
4. Enforce referential integrity for policy-scoped config modules.
5. Update dashboard and API projections to include names and explicit links.
6. Tighten runtime snapshot and historical naming and typing.

This order minimizes churn because it stabilizes what `policyId` means before we rename downstream config identities or enrich user-facing projections.

## Acceptance Criteria

- `POST /console/policies` does not accept client-supplied IDs.
- Every newly created canonical policy has a server-generated `policy_...` ID.
- Canonical `policyId` is globally unique within a namespace.
- Existing canonical policy rows and persisted references have been migrated off org-derived or ad hoc IDs.
- Everywhere `policyId` appears in console APIs, it points to `console_policies.id`.
- Non-canonical subsystems use subsystem-specific IDs and names.
- Policy-scoped smart-wallet and gas-sponsorship configs cannot reference missing policies.
- User-facing tables, detail panels, and audit and approval flows prefer policy names over raw IDs.
- Runtime snapshots and history records use explicit naming that makes the source and mutability of labels obvious.
- No code reconstructs or compares org-derived policy IDs.
- No compatibility aliases remain after the rename.

## Non-Goals

- Do not denormalize policy names into every persisted table just for convenience.
- Do not keep compatibility aliases indefinitely after the rename.
- Do not treat generic string IDs as acceptable if the system already knows the canonical policy entity.
- Do not rely on the string form of `policyId` for semantics beyond it being a canonical opaque identifier.
- Do not require dropping `org_id` from every policy foreign key in the first pass if uniqueness is enforced separately.

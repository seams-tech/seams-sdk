# Policy Engine Implementation Plan

Last updated: 2026-03-10
Status: in progress

## Goal

Ship the full policy engine experience for console-managed signing guardrails and sponsorship authorization.

In the finished product, a policy should define:

- which wallet operations are allowed or denied
- which chains are allowed or denied
- which contracts and methods may be called
- which amount and velocity limits apply
- whether key export is blocked
- whether a transaction or delegate request is sponsorable
- which sponsorship executor and spend limits apply
- how policies inherit across org, project, environment, and wallet scopes
- how draft, review, approval, publish, and audit all fit together

This work should replace the current thin CSV editor. It should not add a second parallel policy system.

## Target product shape

The full experience should include:

- typed policy kinds and rules instead of `Record<string, unknown>` as the primary product contract
- scope-aware assignment with precedence: `WALLET` > `ENVIRONMENT` > `PROJECT` > `ORG`
- policy coverage and unassigned-wallet insights powered by wallet data
- draft, simulate, diff, approval, publish, and audit flow
- runtime-consumable published policy snapshots
- resolved sponsorship artifacts published through runtime snapshots
- one shared evaluator used by simulate, publish checks, runtime enforcement, and observability
- policy engine ownership of authorization decisions, with signing and sponsorship execution remaining outside the policy engine

## Sponsorship alignment

This plan now assumes the same product boundary as [sponsorship-policy.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/sponsorship-policy.md):

- sponsorship authorization is a first-class policy-engine feature
- sponsorship execution, finalized spend recording, and billing attribution remain runtime concerns
- runtime routes consume resolved sponsorship policy artifacts from runtime snapshots, not raw dashboard config
- there should not be a second long-term gas-sponsorship policy surface parallel to the policy engine

This document is the product and console-surface plan. The detailed runtime, route, and ledger migration work for sponsorship remains tracked in [sponsorship-policy.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/sponsorship-policy.md).

## Current state

Implemented today:

- backend CRUD, publish, simulate, and assignment APIs for policies
- Postgres storage for policies, versions, and assignments
- default org policy bootstrap
- a shared typed policy-rules module now normalizes the currently enforced rule family set
- request-time rule validation now rejects unknown rule keys instead of silently storing them
- in-memory and Postgres policy services now share one evaluator and reason-generation path
- simulation results now include typed deny reason codes plus normalized action and chain identifiers
- policy publish approval enforcement when an approvals service is mounted
- policy coverage API contract
- attached drafts now auto-attach to the current context or selected wallet without a separate dashboard assign step
- wallet policy resolution and runtime snapshot payloads now treat published policy state as the live boundary instead of mutable draft rules
- example relay wiring for policies, wallets, and approvals in the local stack
- demo seed data for wallets, policies, assignments, and publish approvals in the example relay
- dashboard policy workspace with current-context policy tables, auto-attached draft creation, inline create/edit/simulate flows, and scheduled live policy changes through approvals
- a separate gas sponsorship config module exists for current EVM sponsorship flows
- runtime snapshots already publish resolved EVM `sponsoredCallPolicies`

Not yet at the desired product shape:

- the current dashboard builder only exposes the rule families the backend enforces today: blocked actions, allowed chains, max amount, and contract-call allowlists
- version history and published-version diff UX are still missing
- contract-call target and function allowlists are now implemented, but broader typed action families are still incomplete
- velocity limits are still planned and should not be reintroduced in UI until enforced
- sponsorship authorization still lives in a separate gas-sponsorship config surface instead of the policy engine
- sponsorship resolution is still EVM-shaped and not yet generalized across `evm_call` and `near_delegate`
- docs and tests still carry stale assumptions from earlier policy-engine designs

## Policy kinds and rule families to implement

Phase 1 of the typed model should support these policy kinds and rule families:

- signing policy
  - action rules
    - `transfer`
    - `contract_call`
    - `deploy_contract`
    - `add_key`
    - `delete_key`
    - `sign_message`
    - `export_key`
  - chain rules
    - allowlist and denylist by normalized chain id or chain family
  - contract target rules
    - allowlist and denylist by chain plus contract address
  - method rules
    - allowlist and denylist by chain plus contract plus selector or method name
  - value rules
    - max amount per transaction
    - optional per-asset limits
  - velocity rules
    - max transactions per window
    - minimum seconds between transactions
  - publish governance rules
    - publish requires approval when approvals are configured

- sponsorship policy
  - policy kinds
    - `evm_call`
    - `near_delegate`
  - sponsorship authorization rules
    - allowed chain family and network
    - allowed contracts or receivers
    - allowed selectors or methods
    - max gas, value, or attached deposit
    - executor mode
    - fail-closed or unsponsored-fallback semantics

Execution stays outside the policy engine. The policy engine decides whether a request is allowed or sponsorable and publishes the resolved policy artifacts consumed by runtime routes.

The first typed schema should be versioned. Do not keep unbounded free-form rule keys as the primary interface.

## UX to build

The policy page should become a proper policy workspace, not a single form.

Required UX features:

- policy registry
  - list drafts and published versions
  - distinguish policy kind clearly
  - status, scope usage, last updated, last published
  - duplicate from existing policy or template
- scope assignment explorer
  - org, project, environment, wallet scopes
  - effective policy preview for the selected scope
  - inheritance and override visualization
- coverage panel
  - policy assignment coverage by wallet count
  - active versus archived wallet breakdown
  - unassigned wallet sample
  - bulk assignment entry points
- structured rule builder
  - policy kind chooser where applicable
  - action toggles and deny rules
  - chain chips and selectors
  - contract and method rows
  - amount and velocity limit inputs
  - key export restriction controls
  - sponsorship builder for chain family, contract or receiver, selector or method, gas or deposit limits, executor mode, and fail-closed behavior
- simulation panel
  - test a representative signing request against the current draft
  - test a representative sponsorship request against the current draft when editing sponsorship policy
  - show resolved policy version and machine-readable deny reasons
- publish flow
  - draft versus published diff summary
  - approval status if approvals are configured
  - publish audit summary
- templates
  - project default signing policy
  - wallet override policy
  - export-disabled wallet
  - contract-limited app wallet
  - testnet onboarding sponsorship template
  - generic EVM sponsorship template
  - future NEAR delegate sponsorship template

UX rules:

- normal `Create policy` inherits the current org, project, and environment context from the top navbar
- normal draft creation should not ask for scope; the draft auto-attaches to the current topbar context
- wallet picker UI only appears in an explicit `Create wallet override` flow
- wallet override creation auto-attaches the draft to the selected wallet
- the main dashboard flow should not expose a separate `Assign` step; `Go live` is the explicit activation step
- precedence should be stated plainly anywhere scope is shown: a wallet-specific override wins over inherited defaults, including environment policies
- the structured rule builder is the main UX
- a raw JSON view may exist as an advanced read-only or import-export tool
- do not keep the CSV editor once the structured builder lands
- do not keep a free-text `approvalId` field as the long-term UX once approval queue integration exists

## Phased todo list

## Current high-impact todo list

### 1. Finalize backend contract-call policy model and validation

- [x] Replace the current `contractCallAllowlistEnabled` UI-only mode split with one explicit typed backend rule shape.
- [x] Keep contract-call rules policy-wide rather than chain-aware per rule; chain applicability already comes from the policy's allowed-chain setting.
- [x] Validate contract addresses strictly instead of accepting arbitrary strings.
- [x] Validate function selectors and method signatures strictly instead of storing free-form values without checks.
- [x] Reject empty allowlist entries, duplicate contracts, and duplicate selectors at request-parse time.
- [x] Normalize contract addresses and selectors into one canonical stored form.
- [x] Emit stable deny codes for contract mismatch versus function mismatch.
- [x] Align the dashboard create or edit modal so it only exposes fields that are truly enforced by the backend.
- [x] Default new policies to all chains by leaving `allowedChains` unset unless the user narrows them.

### 2. Make `Go live` show a real change and impact summary

- [x] Compare the selected draft against the current published version before scheduling approvals.
- [x] Show field-level diffs for actions, chains, contract-call rules, and amount limits.
- [x] Show the target assignment scope affected by the live change.
- [x] Show impact summary for the selected policy, including wallet usage count.
- [x] Make the modal clearly distinguish between scheduling approvals and actually publishing live.

### 3. Add minimal live-version visibility

- [x] Show current published version, last published timestamp, and draft versus published status in the row-driven view flow.
- [x] Reuse the same version metadata in the `Go live` diff flow so live review is grounded in the actual published state.

### 4. Expand focused tests for the new modal flows

- [x] Add relayer tests for invalid contract addresses, invalid selectors, duplicate allowlist entries, and normalized storage behavior.
- [x] Add relayer tests for contract mismatch versus function mismatch deny reasons.
- [x] Add dashboard tests for creating a policy with contract-call allowlist rules.
- [x] Add dashboard tests for modal validation failures and save blocking.
- [x] Add dashboard tests for row-driven simulate flow.
- [x] Add dashboard tests for `Go live` diff and impact summary rendering.
- [x] Add dashboard tests for minimal live-version visibility after publish.

### Phase 0: Audit, cleanup, and contract freeze

- [ ] Inventory every policy-engine touchpoint across dashboard, router, services, tests, docs, and example relay wiring.
- [ ] Define the first typed policy schema and its versioning plan.
- [ ] Decide which current flat rule keys migrate directly and which are removed.
- [x] Remove stale docs that claim the dashboard already consumes coverage or lifecycle views when it does not.
- [ ] Remove stale test expectations that refer to UI sections or flows no longer present.
- [x] Delete the CSV editor and stop adding new rule fields to the legacy policy page.
- [x] Lock sponsorship as a first-class policy-engine feature and remove ambiguity about separate long-term policy surfaces.
- [x] Align this plan with [sponsorship-policy.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/sponsorship-policy.md) on where policy ends and runtime execution begins.

### Phase 1: Backend parity in the example stack

- [x] Wire `ConsoleWalletService` into the example relay so `/console/policy/coverage` works locally.
- [x] Wire `ConsoleApprovalService` into the example relay so publish can require approval locally.
- [x] Seed demo wallets, policies, assignments, and approval requests for end-to-end local testing.
- [x] `GET /console/policies`
- [x] `GET /console/policies/assignments`
- [x] `GET /console/policy/coverage`
- [x] `GET /console/approvals`
- [x] Keep the example relay using the same Postgres namespace split already used by other console modules.

### Phase 2: Typed policy model and shared evaluator

- [x] Introduce a typed policy-rules module shared by in-memory and Postgres services.
- [ ] Introduce explicit policy kinds for signing and sponsorship authorization.
- [x] Move rule validation into shared codecs instead of ad hoc `Record<string, unknown>` access.
- [x] Move policy evaluation into one shared evaluator used by both service implementations.
- [ ] Implement all currently exposed rule families, including the missing velocity checks.
- [ ] Add sponsorship authorization schema for `evm_call` and `near_delegate`.
- [x] Add typed deny reason codes instead of a single generic deny message.
- [ ] Normalize action, chain, contract, and method identifiers.
- [x] Add schema-level tests for invalid rules, unknown keys, and migration behavior.

### Phase 3: Coverage, assignments, and policy lifecycle

- [x] Support full scope assignment UX and API usage for `ORG`, `PROJECT`, `ENVIRONMENT`, and `WALLET`.
- [x] Expose effective-policy resolution as a first-class dashboard concept.
- [ ] Add version history and published-version diff support.
- [ ] Add archive or retire behavior for obsolete policies.
- [ ] Add policy decision logs storage and query APIs.
- [x] Ensure runtime snapshot payloads include resolved published policy metadata and assignments for the target environment.
- [ ] Publish resolved sponsorship policy artifacts in runtime snapshots for policy-owned sponsorship flows.

### Phase 4: Dashboard UX overhaul

- [x] Replace the current CSV form with a policy registry plus detail workspace.
- [x] Add coverage summary cards and the unassigned-wallet table.
- [x] Add an inheritance panel showing which scope wins and why.
- [ ] Add structured rule-builder components for signing rules and sponsorship rules.
- [x] Add a simulator section for representative request testing.
- [ ] Add publish diff review with version bump preview.
- [ ] Add policy templates and duplicate-from-template actions.
- [x] Add read-only and edit modes based on the current console role gates.
- [ ] Keep the page usable on both desktop and laptop viewport sizes without relying on dense tables alone.

### Phase 5: Approval-driven publish flow

- [x] Replace manual approval-id entry with approval queue integration.
- [x] Allow users to create or select a `POLICY_PUBLISH` approval request from the policy page.
- [x] Show approval status inline before publish.
- [x] Require approved requests before publish when approvals are configured.
- [ ] Record audit events with policy diff, approver identity, and published version.
- [ ] Add clear fallback behavior for environments where approvals are not configured.

### Phase 6: Sponsorship policy integration

- [ ] Migrate current EVM sponsorship authorization into the policy engine as a normal policy kind.
- [ ] Replace the separate gas-sponsorship policy editing surface with policy-engine-owned sponsorship editing.
- [ ] Keep sponsorship execution, spend recording, and billing attribution outside the policy engine.
- [ ] Ensure the detailed runtime and ledger migration remains aligned with [sponsorship-policy.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/sponsorship-policy.md).
- [ ] Treat Tempo onboarding sponsorship as seeded policy data, not a special policy product path.

### Phase 7: Runtime enforcement and observability

- [ ] Use the shared evaluator in actual signing enforcement paths, not only the simulate endpoint.
- [x] Ensure runtime consumers read published policy versions, not mutable drafts.
- [ ] Emit structured observability events for allow and deny decisions.
- [ ] Link decision logs back to policy id, policy version, wallet id, environment id, and request type.
- [ ] Emit equivalent allow and deny observability for sponsorship authorization decisions once sponsorship is policy-owned.
- [ ] Add dashboards or queries for top deny reasons and unassigned-wallet risk.

### Phase 8: Delete transitional code and stale context

- [x] Delete the CSV editor and its parsing helpers once the structured builder ships.
- [ ] Delete temporary flat-rule compatibility logic after migration is complete.
- [ ] Delete duplicate evaluator or default-bootstrap logic left behind in service implementations.
- [ ] Delete the separate gas-sponsorship policy surface once sponsorship editing lands in the policy engine.
- [ ] Delete stale test fixtures and mocks that only exist for the old policy lifecycle UI.
- [ ] Collapse duplicated docs into this plan plus the final product docs once implementation lands.

## Legacy code and redundant bloat to eliminate

These are current cleanup targets. They should be removed during the refactor, not preserved behind compatibility flags.

- `examples/tatchi-site/src/pages/dashboard/routes/gas-smart-wallets/page.tsx`
  - currently keeps sponsorship authorization in a separate dashboard surface
  - long term, policy-owned sponsorship editing should move into the policy engine workspace
- `examples/tatchi-site/src/pages/dashboard/routes/policy-engine/consolePoliciesApi.ts`
  - client contract is still generic and mirrors free-form `rules`
  - should move to typed request and response shapes once the schema is defined
- `server/src/console/policies/service.ts`
  - still contains default-policy bootstrap logic that should eventually move into shared policy bootstrap helpers
- `server/src/console/policies/postgres.ts`
  - still repeats default bootstrap concerns already present in the in-memory service
  - both services should keep converging on shared bootstrap and persistence helpers
- `server/src/console/gasSponsorship/service.ts`
  - current sponsorship authorization lives behind a separate config boundary
  - treat this as transitional until sponsorship authorization is absorbed into the policy engine
- `server/src/console/gasSponsorship/postgres.ts`
  - current Postgres shape is still part of the separate sponsorship-config path
  - avoid preserving it as a permanent parallel policy product boundary
- EVM-only resolved sponsorship snapshot fields
  - current runtime snapshot sponsorship output is still EVM-shaped
  - it should converge on the generalized sponsorship policy artifacts described in [sponsorship-policy.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/sponsorship-policy.md)
- `docs/saas/dashboard-backend-implementation-plan.md`
  - contains claims about policy-engine dashboard behavior that no longer match the shipped page
  - should be trimmed once this focused plan becomes the source of truth
- flat `rules: Record<string, unknown>` access throughout client and server
  - this is the main schema-drift source
  - it should be replaced by a typed rule model with explicit versioning

## Guardrails for the refactor

- Do not keep both old and new policy editors alive once the structured builder is ready.
- Do not expose a rule field in UI unless the backend evaluator enforces it.
- Do not add more free-form rule keys without updating the typed schema.
- Do not keep a separate long-term gas-sponsorship policy editor once sponsorship authorization is policy-engine-owned.
- Do not keep duplicate evaluator code paths for memory versus Postgres services.
- Do not keep stale tests and docs that describe UI that no longer exists.
- Do not move execution, spend recording, or billing attribution into the policy engine.
- Prefer breaking cleanup over compatibility shims when the old path only adds policy-engine confusion.

## Exit criteria

The policy engine is complete when all of the following are true:

- the example relay supports policies, wallets, and approvals end to end
- the dashboard shows policy coverage, effective inheritance, lifecycle state, and approval-aware publish
- sponsorship authorization is configured and resolved through the policy engine
- policy rules are typed and versioned
- the same evaluator powers simulate and runtime enforcement
- runtime snapshots publish resolved sponsorship policy artifacts for policy-owned sponsorship flows
- velocity and contract or method restrictions are enforced, not merely stored
- stale CSV-editor code, stale docs, and stale tests have been removed

# Gas Sponsorship Spend Cap Plan

Last updated: 2026-03-10

## Status

Implemented so far:

- gas sponsorship console config now stores `spendCap` instead of `chainBudgets[]`
- `quotaTransactions` has been removed from the gas sponsorship config, API, UI, and persistence codepaths
- runtime snapshot policy payloads now include resolved `spendCap`
- the dashboard modal now shows one environment-selected network surface and a per-chain spend-cap table
- a dedicated backend reservation service now exists for spend-cap reserve, settle, and release flows

Still missing:

- billable spend pricing still uses native fee units in sponsored-call records; there is no finalized `estimatedSpendMinor` / `finalSpendMinor` path yet
- the sponsorship runtime still matches only allowed chains and calls; it does not call the spend-cap reservation service before execution
- reserve/settle/release events are not yet emitted into observability or admin views

## Goal

Replace the current budget guardrail with one explicit spend-cap feature that supports exactly one mode per gas sponsorship policy:

1. `Per chain total`
2. `Per wallet, per chain`

For each selected chain in the current environment network:

- show the chain as a row
- let the operator enter a spend cap amount
- apply the cap on a `WEEKLY` or `MONTHLY` window

The selected topbar environment continues to decide the network surface:

- `prod` => mainnet
- all other current environment keys => testnet

## Non-goals

- keep the old `chainBudgets` + `quotaTransactions` shape around as legacy config
- add mixed cap modes inside one policy
- add a second parallel budget system outside sponsorship policy data
- implement raw transaction sponsorship or paymaster redesign as part of this work

## Product shape

Each gas sponsorship policy gets one spend-cap section:

- `mode`: `NONE | CHAIN_TOTAL | WALLET_CHAIN_TOTAL`
- `period`: `WEEKLY | MONTHLY`
- `capsByChain`: one optional cap per selected chain

Semantics:

- `CHAIN_TOTAL`: one shared cap per chain for the whole policy/environment
- `WALLET_CHAIN_TOTAL`: one separate cap per initiating wallet per chain
- blank chain amount means no cap for that chain
- the cap is enforced against billable sponsorship spend in minor currency units

`quotaTransactions` should be deleted from this feature. If count-based limits are still needed later, they should come back as a separate rule type, not be bundled into spend caps.

## Proposed config model

Replace the current legacy budget shape with this:

```ts
export type ConsoleGasSponsorshipSpendCapMode =
  | 'NONE'
  | 'CHAIN_TOTAL'
  | 'WALLET_CHAIN_TOTAL';

export type ConsoleGasSponsorshipSpendCapPeriod = 'WEEKLY' | 'MONTHLY';

export interface ConsoleGasSponsorshipSpendCap {
  mode: ConsoleGasSponsorshipSpendCapMode;
  period: ConsoleGasSponsorshipSpendCapPeriod;
  capsByChain: Array<{
    chainId: number;
    capMinor: number;
  }>;
}
```

Then update `ConsoleGasSponsorshipConfig` to store:

- `spendCap: ConsoleGasSponsorshipSpendCap`

Delete:

- `chainBudgets`
- `ConsoleGasSponsorshipChainBudget`
- `quotaTransactions`
- freeform chain-name budget rows

Use `chainId` as the canonical budget key. UI labels should always be derived from the current chain registry, not stored as freeform strings.

## Runtime model

Resolved runtime sponsorship policy should carry spend-cap data directly:

```ts
type ResolvedSponsoredCallSpendCap = {
  mode: 'NONE' | 'CHAIN_TOTAL' | 'WALLET_CHAIN_TOTAL';
  period: 'WEEKLY' | 'MONTHLY';
  capsByChain: Array<{
    chainId: number;
    capMinor: number;
  }>;
};
```

Each resolved sponsored-call policy should include:

- `spendCap`

The runtime should not infer budgets from dashboard-only strings or labels.

## Enforcement model

Spend caps need real backend enforcement, not just config storage.

Enforcement requirements:

- compute an estimated billable spend before execution
- reserve that amount against the correct budget bucket
- reject the request if the bucket would exceed the configured cap
- reconcile the reservation to actual finalized spend after execution
- release unused reserved amount on revert, broadcast failure, or RPC rejection

Budget buckets:

- `CHAIN_TOTAL`: `policyId + environmentId + chainId + periodWindow`
- `WALLET_CHAIN_TOTAL`: `policyId + environmentId + accountRef + chainId + periodWindow`

Use `accountRef` as the canonical wallet identity for per-wallet caps so the runtime uses the same normalized identifier it already persists in sponsored-call records.

## Pricing requirement

The current ledger stores native fee units like `wei`, not billable minor units.

To enforce spend caps in dashboard currency, backend work must add:

- `estimatedSpendMinor` before execution
- `finalSpendMinor` after finalization
- a stable pricing/version marker used for reconciliation

Fail closed if billable spend cannot be computed.

## Data model additions

Add a dedicated budget-accounting store instead of trying to infer caps only from raw sponsored-call rows.

Implemented tables:

1. `console_sponsorship_spend_cap_reservations`
2. `console_sponsorship_spend_cap_windows`

Reservation fields:

- `org_id`
- `environment_id`
- `policy_id`
- `account_ref` nullable for `CHAIN_TOTAL`
- `chain_id`
- `mode`
- `period`
- `window_start_at`
- `window_end_at`
- `reserved_minor`
- `settled_minor`
- `status`
- `source_event_id`

This avoids race conditions from concurrent sponsorship requests.

## Dashboard UI shape

Replace the current single budget input block with:

1. a cap mode selector
   - `No spend cap`
   - `Per chain total`
   - `Per wallet, per chain`
2. a period selector
   - `Weekly`
   - `Monthly`
3. a chain table for the currently selected environment network only
   - one row per selected chain
   - chain label
   - spend-cap input in minor units
   - blank means no cap

UI rules:

- only show chains that are currently enabled in the policy
- when a chain is toggled off, remove its cap row from form state
- when switching environments between development and production, remap the visible chain rows to that environment network
- view mode should summarize caps as:
  - `Tempo Testnet weekly cap $500 total`
  - `Tempo Testnet monthly cap $25 per wallet`

## Phased todo list

## Phase 0: Lock product semantics

- [x] Confirm the feature replaces the existing budget UI instead of extending it
- [x] Confirm only one cap mode is allowed per policy
- [x] Confirm `WEEKLY | MONTHLY` are the only supported windows for this feature
- [x] Confirm `prod => mainnet` and all other current environment keys => testnet for gas sponsorship
- [x] Confirm spend caps apply to billable spend in minor currency units
- [x] Confirm `quotaTransactions` is removed from this feature

## Phase 1: Replace console config schema

- [x] Add `ConsoleGasSponsorshipSpendCapMode`
- [x] Add `ConsoleGasSponsorshipSpendCapPeriod`
- [x] Add `ConsoleGasSponsorshipSpendCap`
- [x] Replace `chainBudgets` with `spendCap` in gas sponsorship config types
- [x] Update request parsing for create and update routes
- [x] Update in-memory gas sponsorship service normalization and validation
- [x] Update Postgres schema and persistence to store `spend_cap JSONB`
- [x] Drop legacy `chain_budgets` writes and remove read-time fallback once migration is complete
- [x] Update console router tests for the new request and response shape

## Phase 2: Publish resolved spend caps in runtime snapshots

- [x] Extend resolved sponsored-call policy payloads to include `spendCap`
- [x] Remove any snapshot dependence on legacy chain-name budget rows
- [ ] Update runtime snapshot tests to assert the new resolved cap shape
- [x] Keep chain identifiers canonical as `chainId`

## Phase 3: Add sponsorship pricing primitives

- [ ] Define how estimated spend minor is computed for sponsorship authorization
- [ ] Define how finalized spend minor is reconciled after execution
- [ ] Add price-version metadata so reservations and settlements are auditable
- [ ] Extend sponsored-call records or adjacent accounting records to retain billable spend minor
- [ ] Fail closed when pricing is unavailable or invalid

## Phase 4: Add budget accounting and reservations

- [x] Create a budget reservation service with atomic reserve/settle/release operations
- [x] Add Postgres tables for reservations and window usage
- [x] Key reservations by policy, environment, chain, period window, and optionally account
- [x] Prevent concurrent overspend with transactionally safe reservation logic
- [x] Add idempotent replay handling keyed by `sourceEventId`
- [x] Add tests for concurrent requests against the same budget bucket

## Phase 5: Enforce spend caps in sponsorship runtime

- [ ] Check spend-cap policy before sponsored execution starts
- [ ] Reserve estimated spend for the matching chain bucket
- [ ] Reject over-cap requests with a distinct error code such as `spend_cap_exceeded`
- [ ] Settle to finalized spend on success
- [ ] Release reservation on revert, broadcast failure, or RPC rejection
- [ ] Include spend-cap rejection context in audit logs and API responses
- [ ] Add relayer tests for:
  - chain-total cap success and rejection
  - wallet-chain cap success and rejection
  - concurrent reservation behavior
  - reconciliation after lower-than-estimated final spend

## Phase 6: Replace the dashboard budget UI

- [x] Remove the legacy budget amount + transaction quota form block
- [x] Add the spend-cap mode selector
- [x] Add the weekly/monthly selector
- [x] Render one cap input row per currently selected chain
- [x] Ensure the modal only shows chains for the current environment network
- [x] Persist draft state for spend-cap mode, period, and per-chain cap inputs
- [x] Update view summaries and card summaries to describe total vs per-wallet caps clearly
- [x] Add dashboard e2e coverage for development/testnet and production/mainnet modes

## Phase 7: Cleanup, observability, and rollout

- [x] Remove legacy `chainBudgets` codepaths and tests
- [x] Remove `quotaTransactions` from gas sponsorship docs, UI, API types, and persistence
- [ ] Add observability for reserve, settle, release, and reject paths
- [ ] Add admin/debug visibility for current budget usage per policy and per chain
- [ ] Add migration notes for existing seeded sponsorship policies
- [x] Verify Tempo onboarding policy still works with the new spend-cap model when no cap is configured

## Exit criteria

- gas sponsorship policies can configure either chain-total spend caps or per-wallet-per-chain spend caps
- the dashboard UI matches the selected environment network
- the backend rejects requests that would exceed the configured cap
- reservations prevent concurrent overspend
- no legacy `chainBudgets` or `quotaTransactions` remain in the gas sponsorship codepath

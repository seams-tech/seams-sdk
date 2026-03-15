# Sponsored Tempo Onboarding Sponsorship Plan

Last updated: 2026-03-09

## Goal

Get the `Drip Fee Tokens` button working for a freshly registered Tempo threshold signer that has zero native Tempo gas, while moving away from a hardcoded faucet route toward a policy-driven sponsorship system.

The smallest durable product shape is:

- a default onboarding sponsorship policy exists for testnet environments
- that policy is visible in the policy engine and enabled by default
- the relay executes a generic sponsored single-call flow based on resolved policy, not hardcoded route logic
- exact finalized spend is recorded against the API key that initiated the request

## Product direction

This should not stay a special-case faucet endpoint.

The next version should treat Tempo onboarding sponsorship as a normal policy-backed feature:

- policy scope: environment
- environment class: testnet only
- default seeded policy: tutorial onboarding sponsorship
- initial allowed call:
  - chain `42431`
  - contract = Tempo faucet contract
  - selector = `drip(address[])`
  - `value = 0`
  - bounded gas limit
- execution backend: relay-owned EOA for now
- accounting:
  - exact spend ledger row keyed by `apiKeyId`
  - usage/billing event recorded alongside the finalized sponsorship

This keeps the current MVP narrow while matching the longer-term model where developers can constrain sponsorship by contract address and function selector.

## Current state

The current implementation now matches the policy-backed direction:

- route: `POST /sponsorships/evm/call`
- policy source: runtime snapshot `gasSponsorship.sponsoredCallPolicies`
- route ownership: shared server sponsorship modules, not example-local relay code
- default seeded policy: `Tempo Testnet Onboarding`
- initial allowed call:
  - chain `42431`
  - contract = Tempo faucet contract
  - selector = `drip(address[])`
  - `value = 0`
  - bounded gas limit
- execution backend: relay-owned EOA
- accounting:
  - exact spend ledger row keyed by `apiKeyId`
  - explicit caller-provided `idempotencyKey` per intent
  - `policyId` persisted with each sponsorship record
  - billing usage event recorded for the org
- demo integration:
  - `Drip Fee Tokens` uses the generic sponsored-call route
  - browser coverage proves register/login can reach the sponsored drip path for a zero-gas signer

The old hardcoded faucet route has been removed.

MVP status:

- complete for the original goal of making `Drip Fee Tokens` work for a fresh zero-gas signer with spend tracked against the initiating API key

## MVP scope

In scope:

- one policy-backed sponsorship type for EVM single-call relay-paid transactions
- one default onboarding policy seeded for new testnet environments
- one initial allowed call: Tempo faucet `drip(address[])`
- one generic relay execution path that consumes resolved policy
- one exact finalized spend ledger used for usage and billing attribution

Out of scope:

- mainnet sponsorship
- arbitrary transaction blobs
- multicall sponsorship
- generic Tempo fee-payer transactions
- client `prepare -> sign -> submit` placeholder-fee-payer flow
- sponsorship for `setUserToken(address)` in this phase
- runtime budget enforcement beyond exact spend recording
- sponsorship reporting UX in console or invoices

## Target architecture

### 1. Policy layer

The policy engine should own what is sponsorable.

For MVP, the resolved policy shape should answer:

- is sponsorship enabled for this environment
- which backend executes the call
- which exact calls are sponsorable
- what gas and value bounds apply

Minimum resolved shape:

```ts
type ResolvedSponsoredCallPolicy = {
  id: string;
  enabled: boolean;
  environmentId: string;
  networkClass: "testnet";
  chainId: number;
  executor: "relay_eoa";
  allowedCalls: Array<{
    to: `0x${string}`;
    selector: `0x${string}`;
    maxGasLimit: bigint;
    maxValueWei: bigint;
  }>;
};
```

### 2. Runtime resolution

The relay should not evaluate raw console config directly.

Instead, the runtime snapshot should publish a resolved sponsorship artifact for the environment. The relay consumes that artifact and performs exact matching on:

- `chainId`
- target contract address
- 4-byte selector
- gas limit
- call value

### 3. Execution layer

The route should be generic for a single sponsored EVM call.

It should:

- authenticate the publishable key
- verify origin and environment binding
- load resolved sponsorship policy from the runtime snapshot
- parse the requested call
- match it against policy
- execute through the configured backend
- persist finalized exact spend and billing attribution

The first backend is `relay_eoa`. Later backends can be added without changing the route contract.

### 4. Accounting layer

The sponsorship ledger remains the billing source of truth.

Each finalized record should include:

- `orgId`
- `environmentId`
- `apiKeyId`
- `policyId`
- `walletAddress`
- requested call identity
- `txHash`
- `gasUsed`
- `effectiveGasPrice`
- `spendWei`
- finalized receipt status

## Phased todo list

## Phase 0: Freeze the target model

Objective:

- stop expanding the hardcoded bridge and align on the policy-backed replacement

Todo:

- [x] Prove the product need with a working sponsored Tempo drip flow
- [x] Add exact finalized spend recording keyed by `apiKeyId`
- [x] Record billing usage alongside the sponsorship record
- [x] Switch `Drip Fee Tokens` to the sponsored relay flow
- [x] Treat `POST /tempo/sponsorships/drip` as a temporary bridge only
- [x] Do not add new hardcoded sponsorable routes or selectors
- [x] Replace the document direction from “hardcoded faucet path” to “default onboarding policy”

Exit criteria:

- there is one clear target architecture
- the current route is explicitly temporary

## Phase 1: Add a default onboarding sponsorship policy

Objective:

- make onboarding sponsorship a normal policy-engine concept

Todo:

- [x] Add a first-class sponsorship policy type or extend the existing sponsorship config model cleanly for resolved single-call sponsorship
- [x] Define one built-in policy template: `Tempo Testnet Onboarding`
- [x] Restrict the built-in template to testnet environments only
- [x] Seed the onboarding policy by default for newly created testnet environments
- [x] Allow the same policy template to be added manually in the policy engine for testnet testing
- [x] Make the policy visible in the policy engine as a normal environment-scoped policy
- [x] Model the initial allowed call as:
  - Tempo chain `42431`
  - faucet contract address
  - selector `drip(address[])`
  - `value = 0`
  - bounded gas limit
- [x] Store a stable `policyId` that can flow through runtime snapshots and spend records

Exit criteria:

- a new testnet environment receives a default onboarding sponsorship policy
- the rule is data-driven and visible in product surfaces

## Phase 2: Publish resolved sponsorship policy to runtime

Objective:

- make the relay consume resolved policy instead of hardcoded config

Todo:

- [x] Extend the runtime snapshot payload to publish resolved sponsorship policy artifacts
- [x] Publish only the resolved environment-effective policy, not raw ambiguous config state
- [x] Include the fields needed for exact runtime matching:
  - `policyId`
  - `enabled`
  - `chainId`
  - `executor`
  - allowed `to`
  - allowed `selector`
  - `maxGasLimit`
  - `maxValueWei`
- [x] Add a pure matcher for:
  - `chainId`
  - contract address
  - selector
  - gas limit
  - call value
- [x] Plumb snapshot and `policyId` references through sponsorship execution and persistence

Exit criteria:

- the relay can decide sponsorship from resolved runtime policy alone
- there is no route-level hardcoded faucet rule left in the decision path

## Phase 3: Replace the hardcoded route with a generic sponsored-call route

Objective:

- use one generic execution path for sponsored single-call EVM transactions

Todo:

- [x] Replace `POST /tempo/sponsorships/drip` with a generic sponsored-call route
- [x] Keep the request shape narrow:
  - one chain
  - one call
  - one gas limit
  - one value
- [x] Validate:
  - publishable key bearer token exists
  - key authenticates for the request origin
  - key matches the requested environment
  - requested call matches resolved sponsorship policy
- [x] Execute through a generic backend interface instead of faucet-specific route logic
- [x] Use the existing relay-owned EOA backend as the first executor
- [x] Persist exact finalized spend with `policyId` and `apiKeyId`
- [x] Record usage/billing events from the generic path
- [x] Delete the hardcoded faucet route after cutover

Exit criteria:

- the relay no longer contains a special-case faucet execution path
- `drip(address[])` succeeds because policy allows it, not because code hardcodes it

## Phase 4: Reconnect the demo to the policy-backed route

Objective:

- keep the product outcome intact while removing the bridge implementation

Todo:

- [x] Switch `Drip Fee Tokens` from the bridge route to the generic sponsored-call route
- [x] Keep the button behavior unchanged from the user’s perspective
- [x] Ensure a fresh zero-gas registration still succeeds
- [x] Add an end-to-end demo test for:
  - register
  - login to a fresh zero-gas signer session
  - click `Drip Fee Tokens`
  - confirm the demo hits the generic sponsored-call route with the managed-registration API key and environment binding
- [x] Keep exact spend-record attribution to the correct `apiKeyId` covered by relay integration tests
- [x] Remove any remaining bridge-only client code once the generic path is live

Exit criteria:

- onboarding still works
- the product now uses the durable policy-backed implementation

## Legacy fallback cleanup checklist

Objective:

- remove the temporary bridge and any compatibility paths once the policy-backed route is live

Todo:

- [x] Delete `POST /tempo/sponsorships/drip` after the generic sponsored-call route is in production use
- [x] Remove bridge-only route registration and server wiring from the example relay
- [x] Remove bridge-only request and response types once the generic route contract replaces them
- [x] Remove bridge-only environment variables and README setup instructions
- [x] Remove any faucet-specific validation logic duplicated by the generic policy matcher
- [x] Remove any client-side fetch helpers that exist only for the bridge route
- [x] Remove any fallback from sponsored onboarding back to the old self-funded drip path
- [x] Rename storage and services so the ledger surface matches the generic sponsored-call model
- [x] Delete bridge-specific tests after equivalent generic-route coverage exists
- [x] Remove documentation that describes the bridge route as a supported implementation
- [x] Verify the cutover fails closed:
  - no policy match means reject
  - no route-level fallback
  - no implicit unsponsored retry

Exit criteria:

- there is one supported sponsorship path
- the codebase no longer contains legacy bridge or fallback behavior

## Phase 5: Expand carefully after the replacement lands

Objective:

- support developer-configurable sponsorship without reopening hardcoded behavior

Todo:

- [ ] Let developers author sponsorship constraints by contract address and function selector
- [ ] Support exact allowed calls beyond the built-in onboarding policy
- [ ] Add quotas or budget enforcement on top of the exact spend ledger
- [ ] Surface sponsorship spend in console reporting and billing views
- [ ] Decide whether later flows need Tempo sender-signed sponsorship instead of relay-owned execution
- [ ] Extend beyond `drip(address[])` only after the generic policy-backed route is stable

Exit criteria:

- sponsorship expands through policy data, not special-case route code

## Phase 6: Generalize the sponsorship engine across chain families

Objective:

- keep one shared sponsorship core for auth, policy resolution, idempotency, spend recording, and billing
- add chain-specific intent types instead of forcing all chains through the same request shape

Todo:

- [ ] Define one resolved sponsorship policy union in runtime snapshots with explicit intent kinds:
  - `evm_call`
  - `near_delegate`
- [ ] Keep one shared sponsorship engine for:
  - API key auth
  - origin and environment binding
  - runtime snapshot lookup
  - idempotency
  - exact spend recording
  - billing usage attribution
- [x] Generalize the sponsored-call ledger schema so it is not EVM-shaped:
  - add chain-family and intent-kind fields
  - replace EVM-only identity fields with generic target and details fields
  - keep exact fee amount and fee unit for billing
- [x] Rename the current Tempo route into a generic EVM sponsorship route:
  - `POST /sponsorships/evm/call`
- [ ] Replace Tempo-specific EVM executor config with a per-chain executor registry keyed by `chainId`
- [ ] Keep the EVM request shape narrow:
  - one chain
  - one call
  - one gas limit
  - one value
- [x] Make additional EVM sponsorship data-driven:
  - policy decides allowed contract address
  - policy decides allowed selector
  - policy decides gas and value bounds
  - no new route logic per EVM chain
- [ ] Add a NEAR delegate sponsorship route:
  - `POST /sponsorships/near/delegate`
- [ ] Resolve NEAR sponsorship policy from runtime snapshots instead of static router config
- [ ] Reuse the existing delegate-action execution primitives for NEAR relaying
- [ ] Keep initial NEAR sponsorship narrow:
  - function-call delegate actions only
  - no `Transfer`
  - no attached deposit beyond a small explicit policy limit
  - receiver and method allowlists enforced by policy
- [ ] Add NEAR replay protection for sponsored delegate submission keyed by delegate signer identity and nonce
- [ ] Record exact NEAR relayer spend from execution outcomes using burned-token accounting
- [ ] Add integration coverage for:
  - one non-Tempo EVM sponsored call
  - one NEAR sponsored delegate action
  - spend attribution and idempotency on both paths

Exit criteria:

- one sponsorship engine supports multiple chain families through explicit intent kinds
- adding another EVM chain is a policy and executor configuration change, not a new route implementation
- NEAR delegate sponsorship reuses the same auth, accounting, and billing core as EVM sponsorship
- chain-specific execution stays isolated to executor modules and policy matchers

## Post-MVP next steps

- expose the new sponsorship policy fields in the dashboard UI, not just the console API/runtime snapshot

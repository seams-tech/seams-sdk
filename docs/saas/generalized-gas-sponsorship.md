# Generalized Gas Sponsorship Plan

Last updated: 2026-03-17

## Current implementation status

Backend implementation is complete for the generalized MVP.

Completed so far:

- EVM sponsorship no longer uses the old single-chain flat env model in active code
- EVM sponsorship now uses a multichain executor registry keyed by `chainId`
- the gas sponsorship policy model is now a tagged union with:
  - `kind: "evm_call"`
  - `kind: "near_delegate"`
- EVM `allowedCalls` now carry:
  - `functionSignature`
  - derived `selector`
  - `maxGasLimit`
  - `maxValueWei`
- the EVM runtime matcher now treats `functionSignature` as canonical and derives the selector at match time instead of trusting snapshot selector drift
- runtime snapshots now publish one unified `gasSponsorship.resolvedPolicies` artifact
- Tempo onboarding is represented as seeded EVM sponsorship policy data, not route-specific policy storage
- the EVM relay route matches against the new resolved policy model
- the NEAR relay route now resolves sponsorship from runtime snapshots instead of a route-local receiver policy
- EVM and NEAR routes now share a sponsorship runtime helper for:
  - publishable-key route failure normalization
  - principal narrowing
  - runtime snapshot loading
- EVM and NEAR routes now share a sponsorship replay/match helper for:
  - idempotency-key replay lookup
  - matched-policy resolution
  - early policy-miss response shaping
- EVM and NEAR routes now share a sponsorship execution lifecycle helper for:
  - executor invocation wrapping
  - normalized assessment handoff
  - terminal success/failure response orchestration
- EVM and NEAR backend execution now runs through a shared sponsorship adapter contract in:
  - [server/src/sponsorship/engine.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/engine.ts)
- the shared sponsored-call ledger now persists:
  - `policyId`
  - `templateId`
  - `executorKind`
- the EVM executor registry now derives sponsor addresses from `sponsorPrivateKeyHex`
- sponsor address derivation now runs through the existing signer-core / `eth_signer` Rust+WASM boundary instead of Node crypto helpers
- EVM and NEAR routes now share:
  - a normalized sponsorship execution assessment envelope
  - a shared sponsored execution persistence helper over the common ledger/billing path
- EVM and NEAR sponsorship routes now both replay idempotently from the shared sponsored-call ledger
- the EVM executor registry parser now rejects unsupported executor kinds and duplicate normalized chain entries
- the EVM executor registry parser now fails closed for malformed entries such as:
  - missing `sponsorPrivateKeyHex`
  - missing `rpcUrl` on non-default chains
  - invalid explicit fee-floor values
- the SDK/exported relay type surface is now refreshed to match the generalized sponsorship router options and executor registry shape
- the dashboard EVM gas sponsorship authoring flow now:
  - authors `kind: "evm_call"`
  - authors top-level `executionMode: "evm_eoa"`
  - writes richer `allowedCalls` entries with `functionSignature`, `maxGasLimit`, and `maxValueWei`
  - no longer depends on legacy `allowedChainIds` / `callMode` form payload fields
- `/dashboard/gas-sponsorship` now also authors and previews NEAR sponsorship policies with:
  - `kind: "near_delegate"`
  - top-level `executionMode: "near_delegate"`
  - explicit `allowedDelegateActions`
- sponsorship routes now share backend-agnostic spend-cap reservation and settlement plumbing through:
  - a shared sponsorship pricing adapter contract
  - the existing shared sponsorship spend-cap reservation service
  - fail-closed behavior when capped policies are active but pricing is unavailable
- the example relay now supports a shared explicit static pricing adapter via:
  - `SPONSORED_EXECUTION_STATIC_PRICING_JSON`
  - one shared spend-cap service wired through the root sponsorship router options
  - consistent reserve/finalize conversion of fee units into billable `spendMinor`
- sponsorship routes now emit shared structured spend-cap observability events for:
  - reservation success
  - cap rejection
  - settlement completion
- the shared sponsorship pricing path now supports:
  - operator-configured static pricing via `SPONSORED_EXECUTION_STATIC_PRICING_JSON`
  - optional CoinGecko-backed real pricing via `SPONSORED_EXECUTION_REAL_PRICING_JSON`
  - precedence of real pricing over static pricing when both are configured
- NEAR `near_delegate` policies can now enforce spend caps through the same shared budgeting path using:
  - explicit internal NEAR spend-cap target ids per network
  - shared static pricing support
  - shared CoinGecko-backed real pricing support
  - gas-only settlement based on finalized `tokens_burnt`
- sponsored execution details now retain spend-cap reconciliation metadata such as:
  - reservation source event id
  - estimated billable spend minor
  - settled billable spend minor
  - pricing version
  - whether settlement had to fall back to the reserved estimate
- relayer coverage now proves the generalized MVP on:
  - Tempo onboarding as one seeded EVM template
  - a second non-Tempo EVM template using `transfer(address,uint256)`
  - the unified NEAR delegate path through the shared sponsorship engine
- EVM sponsorship policy misses now return distinct route diagnostics for:
  - selector mismatch
  - gas-limit bound exceeded
  - value bound exceeded

Still outstanding:

- optional future work only:
  - richer pricing sources beyond the current CoinGecko-backed real pricing adapter
  - operator UX / diagnostics refinements around capped sponsorship behavior

## Goal

Replace the current narrow EVM sponsorship implementation with a generalized product shape that:

- supports multiple EVM chains through one executor registry
- unifies EVM and NEAR sponsorship under one sponsorship architecture
- removes Tempo-onboarding-specific route logic from the core sponsorship path
- extends the existing gas sponsorship policy model only as far as needed for a minimal multichain MVP
- keeps exact finalized spend, idempotency, and policy-driven runtime matching

Breaking changes are acceptable. The old single-chain EVM env model and Tempo-only route assumptions should be deleted as part of the refactor, not left behind as compatibility clutter.

## Use the existing gas sponsorship policy architecture

This plan should extend the existing gas sponsorship policy system exposed in the dashboard at `/dashboard/gas-sponsorship`, not create a second sponsorship-policy product.

Current policy ownership already exists in:

- [server/src/console/gasSponsorship/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/gasSponsorship/types.ts)
- [server/src/console/policies/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/policies/types.ts)
- [examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/page.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/page.tsx)

The refactor should therefore be:

- extend the existing `GAS_SPONSORSHIP` policy kind
- evolve the existing `allowedCalls` policy surface into a richer call-template surface
- keep runtime snapshots as the bridge from dashboard policy to relay execution
- keep sponsor credentials and executor secrets server-side only

It should not be:

- a second policy table
- a second dashboard page
- a hidden relay-only config model that bypasses the policy engine

## Locked MVP decisions

These decisions are now part of the implementation plan:

- keep using the existing `/dashboard/gas-sponsorship` product surface
- keep the existing `GAS_SPONSORSHIP` policy kind
- keep the current `allowedCalls` concept and evolve it in place
- unify EVM and NEAR under one sponsorship runtime architecture from the start
- extend the EVM `allowedCalls` shape only with:
  - `functionSignature`
  - `maxGasLimit`
  - `maxValueWei`
- do not add argument constraints in the MVP
- do not add a generic decoded-argument policy engine in the MVP
- use a multichain EVM executor registry for relay-owned EOA sponsorship
- keep sponsor credentials and executor secrets server-side only
- use a tagged-union gas sponsorship policy kind
- give NEAR its own explicit rule shape instead of forcing it into `allowedCalls`
- use one unified versioned runtime snapshot artifact for sponsorship
- use one shared internal sponsorship engine with typed per-chain routes
- keep `executionMode` top-level on the policy branch for MVP simplicity

Practical consequence:

- the MVP generalized sponsorship surface is contract/function allowlisting plus gas/value bounds, with top-level execution mode per policy branch
- it is not a recipient-aware policy engine
- the architecture is shared across EVM and NEAR even if the first concrete schema extension is EVM-shaped

## Architectural choices locked in

These are now fixed for implementation:

### 1. Unified runtime snapshot artifact

Decision:

- publish one versioned sponsorship artifact in the runtime snapshot
- use that same artifact for both EVM and NEAR sponsorship resolution

Why:

- cleaner relay architecture
- one policy-to-runtime contract
- avoids permanent EVM-vs-NEAR snapshot drift

Tradeoff accepted:

- larger migration step now
- less incremental wiggle room

### 2. One shared internal sponsorship engine

Decision:

- use one shared internal sponsorship engine
- keep public routes typed per chain family

Public routes remain:

- `POST /sponsorships/evm/call`
- `POST /sponsorships/near/delegate`

Why:

- one place for auth, idempotency, policy loading, executor dispatch, and spend recording
- better EVM/NEAR parity
- less duplicated orchestration logic

Tradeoff accepted:

- more abstraction work upfront
- requires cleaner internal interfaces immediately

### 3. Top-level `executionMode`

Decision:

- keep `executionMode` top-level on each tagged-union policy branch for MVP simplicity

Why:

- simpler dashboard authoring
- simpler runtime matching
- enough for the current MVP, where one policy branch maps to one executor kind

Tradeoff accepted:

- if one branch later needs mixed executor strategies, a follow-up refactor will be needed

## What "unified runtime snapshot artifact" means

This refers to the resolved sponsorship payload that the relay reads from the published runtime snapshot.

Do this:

- publish one versioned sponsorship artifact in the runtime snapshot
- let that artifact carry both:
  - `evm_call` resolved policy entries
  - `near_delegate` resolved policy entries
- make both EVM and NEAR relay routes load the same artifact shape

Do not do this:

- keep `gasSponsorship.sponsoredCallPolicies` for EVM
- then add a second unrelated NEAR sponsorship payload beside it
- then make the relay understand two different sponsorship snapshot contracts forever

The clean target is one resolved sponsorship snapshot contract with a tagged union inside it.

## Current shortcomings

### 1. EVM executor config is single-chain

Today [server/src/sponsorship/evmRelay.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/evmRelay.ts) models one `SponsoredEvmCallExecutorConfig`:

- one `chainId`
- one `rpcUrl`
- one sponsor key
- one sponsor address

That is enough for Tempo testnet, but it is not a real multichain sponsorship model.

### 2. Policy matching is too shallow for a durable MVP

Today [server/src/sponsorship/evm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/evm.ts) matches only:

- `chainId`
- `call.to`
- function selector

That is enough for coarse allowlisting, but not enough for a durable multichain contract-call product. At minimum, the policy should also own:

- the intended function signature
- the gas/value bounds
- the execution mode

This is enough for an MVP where sponsorship is based on allowlisted functions on specific contracts.

### 2.5. The current `allowedCalls` model is a coarse template, not a full one

Today the dashboard policy model already has `allowedCalls`, but each entry is only:

- `chainId`
- `to`
- `selector`

That is effectively a v0 call template. It answers only:

- which contract
- which function selector

It does not answer:

- what ABI the function is expected to have
- what gas envelope belongs to that allowed call
- what value envelope belongs to that allowed call
- which top-level executor kind should execute the sponsorship

This plan keeps the MVP intentionally narrow. It does not add generic decoded argument constraints in the first pass.

So this plan is not introducing a second concept parallel to `allowedCalls`. It is enriching the existing policy surface just enough to support a durable multichain MVP.

### 3. The current working flow is still product-specific

The current Tempo onboarding flow is valid, but it is still specialized:

- `Drip Fee Tokens` targets one known faucet contract
- the demo client knows the contract ABI and gas limit
- the relay still assumes this product-specific flow in places

That should become one seeded policy template implemented through the same `allowedCalls` model as every other sponsorable contract call.

### 4. The config surface is legacy-shaped

The current env shape:

- `SPONSORED_EVM_CALL_ENABLED`
- `SPONSORED_EVM_CALL_RPC_URL`
- `SPONSORED_EVM_CALL_CHAIN_ID`
- `SPONSORED_EVM_CALL_SPONSOR_ADDRESS`
- `SPONSORED_EVM_CALL_SPONSOR_PRIVATE_KEY_HEX`

does not scale to multiple chains and duplicates data that can be derived.

### 5. EVM and NEAR still feel like two adjacent systems

Today the codebase has:

- EVM sponsorship centered around [server/src/sponsorship/evm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/evm.ts) and [server/src/sponsorship/evmRelay.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/evmRelay.ts)
- NEAR sponsored execution behavior centered around [server/src/router/relaySignedDelegate.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySignedDelegate.ts)

Both already share some high-level concerns:

- publishable-key auth
- environment binding
- metering
- sponsored spend recording
- exact finalized execution assessment

But the architecture is still split by implementation history rather than by a single sponsorship model.

## Target product shape

### 1. One sponsorship system, multiple execution backends

Sponsorship should be modeled as:

- policy resolution
- request validation
- backend selection
- execution
- spend accounting

Backends should be pluggable by chain family and funding model.

Initial backend set:

- `evm_eoa`
- `near_delegate`

Future backend examples can exist later, but they are not part of the MVP:

- `evm_paymaster`
- `tempo_fee_payer`
- `erc4337_paymaster`

The request path should stay stable while backend selection evolves.

For the MVP, the policy layer should declare the execution mode, while the relay config provides the actual server-side executor credentials for that mode.

Examples:

- policy says `executionMode = evm_eoa`
- relay registry provides the per-chain EOA sponsor key
- policy says `executionMode = near_delegate`
- relay uses the configured NEAR relayer account

Architectural rule:

- there should be one sponsorship orchestration model for both EVM and NEAR
- chain-specific execution should plug into that model through executor interfaces
- route typing can remain chain-family specific

### 1.5. Use a tagged-union policy model

The unified architecture should not force EVM and NEAR into one fake shared rule vocabulary.

Chosen direction:

- one shared `GAS_SPONSORSHIP` policy family
- tagged union by sponsorship kind
- explicit EVM rule shape
- explicit NEAR rule shape

Recommended authored shape:

```ts
type ConsoleGasSponsorshipRules =
  | {
      kind: "evm_call";
      executionMode: "evm_eoa";
      allowedCalls: Array<{
        chainId: number;
        to: string;
        selector?: string;
        functionSignature: string;
        maxGasLimit: string;
        maxValueWei: string;
      }>;
      spendCap: ConsoleGasSponsorshipSpendCap;
    }
  | {
      kind: "near_delegate";
      executionMode: "near_delegate";
      allowedDelegateActions: Array<{
        receiverId: string;
        methods: string[];
        maxDepositYocto: string;
        allowTransfers: boolean;
      }>;
      spendCap: ConsoleGasSponsorshipSpendCap;
    };
```

Notes:

- `selector` may still exist as a stored or resolved optimization, but `functionSignature` is canonical
- NEAR should not be forced into `allowedCalls`
- if we ever want one common field name later, `allowedOperations` is the only acceptable alternative
- for the MVP, explicit separate field names are clearer than premature unification
- `executionMode` is top-level per policy branch for MVP simplicity
- this still leaves room for `kind: "evm_call"` to support a different executor kind later

### 2. One multichain EVM executor registry

The relay should load a registry of EVM sponsor executors keyed by `chainId`, not one flat executor.

Target shape:

```ts
type SponsoredEvmExecutorRegistry = Record<
  number,
  {
    kind: "evm_eoa";
    privateKeyHex: `0x${string}`;
    rpcUrl?: string;
    maxPriorityFeePerGasFloor?: bigint;
    maxFeePerGasFloor?: bigint;
  }
>;
```

Rules:

- derive sponsor address from `privateKeyHex`
- use the chain registry or existing network config for RPC defaults where possible
- treat a non-empty registry as "enabled"
- delete the old single-chain env vars once the registry lands

Recommended env:

```env
SPONSORED_EVM_EXECUTORS_JSON={"42431":{"kind":"evm_eoa","privateKeyHex":"0x..."}, "11155111":{"kind":"evm_eoa","privateKeyHex":"0x..."}}
```

Optional overrides may stay if they are global and backend-agnostic:

- `SPONSORED_EVM_MAX_PRIORITY_FEE_PER_GAS`
- `SPONSORED_EVM_MAX_FEE_PER_GAS`

### 3. Policy-owned call templates for the MVP

The policy layer should not stop at `to + selector`.

Concretely, this should evolve the existing `allowedCalls` entries in the gas sponsorship policy model. Today they are coarse allowlist rows. The target is for those rows to become real call templates.

Each allowed call should be a template with:

- target contract
- function signature
- gas/value bounds

Current shape:

```ts
type ConsoleGasSponsorshipPolicyAllowedCall = {
  chainId: number;
  to: string;
  selector: string;
};
```

Target direction on the same policy surface:

```ts
type ConsoleGasSponsorshipPolicyAllowedCall = {
  chainId: number;
  to: string;
  selector: string;
  functionSignature: string;
  maxGasLimit: string;
  maxValueWei: string;
};
```

If we decide the existing `allowedCalls` field name is misleading once it becomes ABI-aware, we can rename it to `allowedCallTemplates` as a breaking cleanup. But the important point is that this is an evolution of the current gas sponsorship policy surface, not a second feature.

Explicit MVP non-goal:

- no generic argument-constraint DSL
- no recipient-binding rules in policy
- no decoded calldata validation beyond selector/function-signature compatibility

Target resolved shape:

```ts
type ResolvedSponsoredCallTemplate = {
  templateId: string;
  chainId: number;
  to: `0x${string}`;
  functionSignature: string;
  maxGasLimit: bigint;
  maxValueWei: bigint;
};
```

This lets the current Tempo onboarding flow become data:

- contract = faucet
- function = `dripTo(address,address[])`
- policy execution mode = `evm_eoa`

The policy still will not inspect decoded arguments in the MVP. If a product flow needs recipient-awareness, that should come from the contract design itself or remain a deliberately scoped follow-up.

### 3.5. NEAR gets its own explicit delegate rule shape

NEAR rules should be modeled directly in NEAR terms.

Recommended shape:

```ts
type ConsoleGasSponsorshipNearAllowedDelegate = {
  receiverId: string;
  methods: string[];
  maxDepositYocto: string;
  allowTransfers: boolean;
};
```

Recommended field name:

- `allowedDelegateActions`

Why:

- `receiverId` is not an EVM contract address
- `methods` are not EVM function selectors
- attached deposit is not `valueWei`
- forcing NEAR into `allowedCalls` would make the policy model harder to reason about
- `allowedDelegates` sounds like a list of delegates rather than allowlisted delegate-action rules

The architecture is unified at the engine, ledger, snapshot, and policy-family level, not by pretending EVM and NEAR share the same low-level rule shape.

### 4. Request identity should stay generic

The current request shape is already close:

```ts
type SponsoredEvmCallRequest = {
  environmentId: string;
  nearAccountId: string;
  walletAddress: `0x${string}`;
  chainId: number;
  call: SponsoredEvmCall;
  idempotencyKey: string;
};
```

Keep that narrow shape unless a new use case requires more subject data.

Policy constraints should bind to canonical request fields like:

- `walletAddress`
- `nearAccountId`
- environment/project scope

Do not create a second Tempo-only request type.

For the unified architecture:

- keep `POST /sponsorships/evm/call` for EVM requests
- add or preserve `POST /sponsorships/near/delegate` for NEAR requests
- keep one shared internal sponsorship engine behind both route families

### 5. Seeded product templates should be data, not route logic

The product can still ship built-in templates such as:

- `tempo_testnet_onboarding_drip`
- `erc20_transfer`
- `testnet_faucet_claim`

But they should be seeded through the gas sponsorship policy system and resolved into generic call templates.

## Non-goals

- arbitrary raw transaction sponsorship without decoding
- legacy compatibility for the old single-chain env vars
- duplicating the `signedDelegate` flow inside sponsorship
- forcing initial registration to deploy smart accounts
- generic argument-constraint rules in the first pass
- solving general pricing, spend-cap enforcement, and refunds in this document
  Those stay in the adjacent sponsorship accounting docs.

NEAR is not out of scope. What is out of scope is inventing a second independent sponsorship architecture for NEAR.

## Remaining constraints to keep explicit during implementation

### 1. Recipient binding is intentionally out of MVP

Without argument constraints, a policy that allowlists:

- one contract
- one function signature

does not bind the call to `request.walletAddress`.

That means a function like `dripTo(address,address[])` is sponsorable for any recipient as long as the contract/function pair is allowed.

Recommended resolution:

- accept that limitation for the MVP
- treat the generalized MVP as contract/function sponsorship, not recipient-aware sponsorship
- keep recipient-aware enforcement out of scope until there is a concrete product requirement that justifies the extra policy complexity

Consequence:

- the Tempo onboarding flow can still work under the generalized MVP
- but it will not be a generic "only sponsor calls to the request wallet" product until a later phase

### 2. `functionSignature` should be the source of truth

We should avoid letting `selector` and `functionSignature` drift independently.

Recommended resolution:

- keep `selector` in runtime-resolved artifacts if it helps fast matching
- derive it from `functionSignature`
- do not treat user-supplied `selector` as an independent source of truth once the richer model lands

### 3. Existing policies need an explicit migration decision

The current published gas sponsorship policies and runtime snapshots only know about:

- `chainId`
- `to`
- `selector`

Recommended resolution:

- use a one-time normalization or migration that backfills:
  - `functionSignature` where known
  - `maxGasLimit`
  - `maxValueWei`
  - `executionMode = evm_eoa`
- reseed and republish the built-in onboarding template if a policy cannot be upgraded cleanly

Because this repo is in development, deleting or rewriting invalid legacy policy state is acceptable.

### 4. Keep the `allowedCalls` field name for the EVM side of the MVP

Renaming to `allowedCallTemplates` may be more precise, but it is not required for the first implementation.

Recommended resolution:

- keep `allowedCalls` as the EVM field name for the MVP
- use an explicit NEAR field `allowedDelegateActions`
- make each side's value shape richer
- revisit the name only if it becomes materially confusing during implementation

## Phased todo list

## Phase 0: Freeze the model

Objective:

- stop adding parallel shapes while the generalized model is built

Rules:

- do not add new `SPONSORED_EVM_CALL_*` fields
- do not add new route-local recipient checks
- do not add new Tempo-only sponsorship request shapes
- do not add a second sponsorship policy surface outside `/dashboard/gas-sponsorship`
- do not add a generic argument-constraint DSL in the MVP
- do not build a separate NEAR sponsorship architecture in parallel
- do not preserve compatibility wrappers once the new registry lands

Exit criteria:

- this document is the source of truth for the next sponsorship refactor
- status: complete

## Phase 1: Define the unified sponsorship core

Objective:

- lock in the shared internal architecture before chain-specific implementation branches grow

Primary targets:

- [server/src/router/relaySponsoredEvmCall.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySponsoredEvmCall.ts)
- [server/src/router/relaySignedDelegate.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySignedDelegate.ts)
- [server/src/console/sponsoredCalls/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/types.ts)
- shared route metering helpers
- runtime snapshot payload code

Todo:

- [x] Define one internal sponsorship orchestration contract shared by EVM and NEAR
- [x] Split route concerns into:
  - request parsing
  - auth/environment binding
  - policy resolution
  - executor dispatch
  - spend persistence
- [x] Define one shared sponsored execution result envelope for both EVM and NEAR
- [x] Define one unified versioned sponsorship runtime snapshot artifact
- [x] Ensure the sponsored-call ledger remains chain-family aware but not EVM-centric
- [x] Keep public routes typed by chain family even though the internal engine is shared

Exit criteria:

- EVM and NEAR sponsorship routes are two typed entrypoints into one internal sponsorship architecture
- the relay reads one sponsorship artifact shape from the runtime snapshot
- status: complete for the MVP shared sponsorship architecture

## Phase 2: Replace flat EVM env config with a multichain registry

Primary targets:

- [server/src/sponsorship/evmRelay.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/evmRelay.ts)
- [examples/relay-server/src/index.ts](/Users/pta/Dev/rust/simple-threshold-signer/examples/relay-server/src/index.ts)
- relay env examples and docs

Todo:

- [x] Introduce `SponsoredEvmExecutorRegistry`
- [x] Parse `SPONSORED_EVM_EXECUTORS_JSON`
- [x] Derive sponsor address from the private key instead of configuring it
- [x] Remove `SPONSORED_EVM_CALL_ENABLED`
- [x] Remove `SPONSORED_EVM_CALL_RPC_URL`
- [x] Remove `SPONSORED_EVM_CALL_CHAIN_ID`
- [x] Remove `SPONSORED_EVM_CALL_SPONSOR_ADDRESS`
- [x] Remove `SPONSORED_EVM_CALL_SPONSOR_PRIVATE_KEY_HEX`
- [x] Make fee floors optional per executor or global overrides
- [x] Log the loaded executor set on startup by chain
- [x] Add parser tests for invalid JSON, duplicate chain ids, and unsupported kinds
- [x] Add parser tests for malformed missing-key and malformed explicit floor-value cases
Exit criteria:

- EVM sponsorship can execute on more than one chain in the same relay process
- there is no legacy single-chain EVM sponsor config left in active code
- status: complete for the MVP registry shape

## Phase 3: Generalize the policy model and runtime snapshot

Primary targets:

- [server/src/console/gasSponsorship/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/gasSponsorship/types.ts)
- [server/src/console/policies/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/policies/types.ts)
- [examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/page.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/page.tsx)
- [server/src/sponsorship/evm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/evm.ts)
- [server/src/console/gasSponsorship/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/gasSponsorship/types.ts)
- [server/src/console/gasSponsorship/service.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/gasSponsorship/service.ts)
- [server/src/console/runtimeSnapshots](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/runtimeSnapshots)

Todo:

- [x] Extend the existing dashboard gas sponsorship policy schema instead of adding a parallel sponsorship config model
- [x] Implement `GAS_SPONSORSHIP` as a tagged union policy kind
- [x] Evolve current `allowedCalls` rows into ABI-aware call templates with gas/value bounds
- [x] Add top-level `executionMode` to each policy branch
- [x] Extend the resolved sponsorship policy model from `to + selector` to call templates with function signature, gas/value bounds, and execution mode
- [x] Add explicit NEAR delegate sponsorship rules under `allowedDelegateActions`, not as `allowedCalls`
- [x] Publish `functionSignature` or equivalent ABI fragment in runtime snapshots
- [x] Derive `selector` from `functionSignature` in the richer model
- [x] Add enough calldata decoding to verify selector and function-signature pairing when needed
- [x] Validate gas limit and value bounds as part of template matching
- [x] Keep exact `policyId` and `templateId` on the sponsored-call record

Exit criteria:

- route matching is generic enough to support both EVM and NEAR under one policy family without chain-specific ad hoc policy storage
- one unified versioned sponsorship artifact is published in runtime snapshots
- status: complete for the MVP policy/runtime shape

## Phase 4: Implement executor dispatch and route integration

Primary targets:

- [server/src/sponsorship/index.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/index.ts)
- [server/src/sponsorship/evmRelay.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/evmRelay.ts)
- [server/src/router/relaySponsoredEvmCall.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySponsoredEvmCall.ts)

Todo:

- [x] Separate policy matching from backend execution
- [x] Add a resolver from `chainId + policy/backend kind` to an executor implementation
- [x] Keep `evm_eoa` as the first EVM executor kind
- [x] Add `near_delegate` as a first-class executor kind in the same internal engine
- [x] Extract shared idempotency replay lookup and matched-policy resolution for both routes
- [x] Extract shared terminal execution lifecycle and response shaping for both routes
- [x] Normalize execution result shape across backends:
  - tx hash
  - finalized spend units
  - receipt status
  - backend kind
- [x] Move backend-specific executor invocation behind one explicit shared sponsorship-engine contract
- [x] Ensure replay/idempotency remains backend-agnostic

Exit criteria:

- sponsorship routing no longer assumes one EVM executor config, one chain family, or one special-case NEAR path
- status: complete for the current backend execution path

## Phase 5: Migrate built-in policies and Tempo onboarding

Primary targets:

- [server/src/console/gasSponsorship/onboarding.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/gasSponsorship/onboarding.ts)
- [server/src/router/relaySponsoredEvmCall.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySponsoredEvmCall.ts)
- [examples/seams-site/src/flows/demo](/Users/pta/Dev/rust/simple-threshold-signer/examples/seams-site/src/flows/demo)

Todo:

- [x] Represent the Tempo onboarding faucet as a seeded template, not route code
- [x] Represent it inside the existing gas sponsorship policy model shown in `/dashboard/gas-sponsorship`
- [x] Encode the current policy execution mode as `executionMode = evm_eoa`
- [x] Remove Tempo-onboarding-specific route assumptions that are replaced by the generic call-template model
- [x] Keep the demo client responsible only for building the call and idempotency key
- [x] Move any remaining Tempo-only assumptions into the seeded policy template or demo helper

Note:

- the MVP does not bind the drip recipient to `request.walletAddress`
- if that becomes unacceptable, that is the point where argument constraints should be reconsidered explicitly instead of being smuggled in ad hoc

Exit criteria:

- the generic route can sponsor the Tempo onboarding drip without knowing anything Tempo-specific
- status: complete

## Phase 6: EVM-first dashboard authoring

Primary targets:

- [examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/page.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/page.tsx)
- gas sponsorship API codecs used by the dashboard

Todo:

- [x] Update `/dashboard/gas-sponsorship` create/edit/view flows for richer EVM `allowedCalls`
- [x] Surface top-level `executionMode` for EVM sponsorship policies
- [x] Keep NEAR editing out of the dashboard in this pass
- [x] Ensure the UI does not imply recipient-bound sponsorship

Exit criteria:

- the dashboard can author the EVM side of the unified sponsorship architecture without adding NEAR editing scope
- status: complete for the EVM-first dashboard scope

## Phase 7: Tighten accounting and observability

Primary targets:

- [server/src/console/sponsoredCalls](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls)
- [server/src/router/relaySponsoredEvmCall.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySponsoredEvmCall.ts)
- existing spend-cap and billing services

Todo:

- [x] Persist `executorKind` and `templateId` with each record
- [x] Keep `idempotencyKey` replay behavior unchanged across all backends
- [x] Ensure multichain records remain queryable by `chainId`
- [x] Ensure NEAR executions are queryable and reportable under the same sponsored-call ledger model
- [x] Reconcile this work with spend-cap reservation logic so budget checks remain backend-agnostic

Exit criteria:

- product and ops surfaces can explain why a sponsorship matched, failed policy, or failed execution
- status: complete for the current generalized accounting path

## Phase 8: Prove the generalized MVP

Objective:

- prove the architecture on both chain families and on more than one EVM contract shape

Todo:

- [x] Add at least one non-Tempo-specific allowlisted EVM contract/function template
- [x] Confirm the minimal `allowedCalls` extension is sufficient for more than one real contract shape
- [x] Confirm the unified NEAR path works through the same internal engine
- [x] Reject any request to add a generic argument-constraint engine unless a concrete product requirement forces it

Exit criteria:

- the generalized sponsorship MVP is a real reusable product surface, not just a renamed Tempo faucet rule
- status: complete

## Phase 9: Expand dashboard authoring beyond EVM-first

Objective:

- let `/dashboard/gas-sponsorship` author the NEAR side of the unified sponsorship architecture instead of treating it as seeded/backend-only policy data

Primary targets:

- [examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/page.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/page.tsx)
- [examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/consoleGasSponsorshipApi.ts](/Users/pta/Dev/rust/simple-threshold-signer/examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/consoleGasSponsorshipApi.ts)
- gas sponsorship policy request/response codecs used by the dashboard

Todo:

- [x] Add first-class NEAR authoring for `kind: "near_delegate"`
- [x] Author explicit `allowedDelegateActions` rows with:
  - `receiverId`
  - `methods`
  - `maxDepositYocto`
  - `allowTransfers`
- [x] Surface top-level `executionMode: "near_delegate"` in create/edit/view flows
- [x] Keep the tagged-union policy UX explicit so operators can tell EVM and NEAR sponsorship apart
- [x] Extend dashboard validation and preview rendering for NEAR rules without regressing the existing EVM flows
- [x] Add dashboard API wiring coverage for NEAR gas sponsorship authoring

Exit criteria:

- `/dashboard/gas-sponsorship` can create, edit, and view both EVM and NEAR sponsorship policies through the unified policy model
- status: complete

## Phase 10: Add an optional real pricing source

Objective:

- make capped sponsorship enforcement capable of using a real pricing source for billable USD minor accounting instead of relying only on the explicit static conversion config

Primary targets:

- [server/src/sponsorship/spendCaps.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/spendCaps.ts)
- [server/src/sponsorship/pricing.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/pricing.ts)
- [examples/relay-server/src/index.ts](/Users/pta/Dev/rust/simple-threshold-signer/examples/relay-server/src/index.ts)
- relay env examples and sponsorship docs

Todo:

- [x] Define how sponsored executions map to billable USD minor units for each capped chain family
- [x] Introduce a real pricing adapter contract alongside the existing static adapter
- [x] Keep the real pricing source optional so operators can still use `SPONSORED_EXECUTION_STATIC_PRICING_JSON`
- [x] Wire the real pricing adapter through the shared root sponsorship router options, not route-local config
- [x] Preserve fail-closed behavior when capped policies are active and neither static nor real pricing is configured
- [x] Record pricing-source/version metadata so spend-cap reservations and settlements remain auditable
- [x] Add focused tests for estimate/finalize behavior, fallback rules, and pricing-source selection precedence

Exit criteria:

- shared spend-cap enforcement can use either a static operator-configured conversion or an optional real pricing source without changing the sponsorship route architecture
- status: complete

## Phase 11: Add NEAR spend-cap support

Objective:

- expand capped sponsorship beyond the current EVM-focused path so NEAR `near_delegate` policies can enforce spend caps through the same shared budgeting and billing architecture

Primary targets:

- [server/src/console/policies/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/policies/types.ts)
- [server/src/console/policies/rules.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/policies/rules.ts)
- [server/src/console/gasSponsorship/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/gasSponsorship/types.ts)
- [server/src/sponsorship/near.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/near.ts)
- [server/src/sponsorship/spendCaps.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/spendCaps.ts)
- [server/src/sponsorship/pricing.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/pricing.ts)
- [examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/page.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/seams-site/src/pages/dashboard/routes/gas-sponsorship/page.tsx)
- NEAR sponsorship relayer coverage and dashboard API wiring coverage

Architecture changes:

- keep the tagged-union `GAS_SPONSORSHIP` model, but make spend caps first-class for `near_delegate` instead of silently treating them as EVM-only
- preserve one shared `spendCap` shape at the policy level, while defining how NEAR policies map spend caps to billable USD minor units
- keep `allowedDelegateActions` as the NEAR rule surface; do not force NEAR back into `allowedCalls`
- keep spend-cap reservation and settlement in the shared sponsorship path, but make NEAR pricing/finalization produce honest billable `spendMinor` instead of using the current implicit “unsupported” branch

Current implementation choice:

- the current NEAR spend-cap model is gas-only
- billable NEAR spend is derived from finalized `tokens_burnt`
- reservation uses an operator-configured `estimateFeeAmountYocto`
- attached deposit is user-paid and is not part of sponsorship pricing, caps, or billing
- refund semantics for attached deposit are out of scope because attached deposit is not sponsored

Todo:

- [x] Remove the MVP validation block in [server/src/console/policies/rules.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/policies/rules.ts) that rejects `near_delegate` spend caps
- [x] Lock the first NEAR billable-unit model to gas-only relayer spend:
  - finalized `tokens_burnt`
  - attached deposit is user-paid and excluded from sponsorship spend
  - no attached-deposit refund accounting is needed because attached deposit is not sponsored
- [x] Extend the shared pricing contract in [server/src/sponsorship/pricing.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/pricing.ts) so NEAR can estimate and finalize spend using the same `SponsorshipSpendPricingService`
- [x] Use CoinGecko `near` USD pricing as the first real NEAR pricing source and keep static pricing as an optional fallback
- [x] Expand [server/src/sponsorship/spendCaps.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/spendCaps.ts) / the NEAR route integration so NEAR reservations no longer fail closed simply because `chainId` is null
- [x] Add an explicit NEAR spend-cap target key that does not depend on EVM `chainId`
- [x] Update shared sponsored execution details so NEAR records retain auditable pricing metadata for gas-only settlement:
  - gas burnt
  - tokens burnt
  - pricing source/version
- [x] Update `/dashboard/gas-sponsorship` so NEAR create/edit/view flows can configure spend caps instead of forcing `mode: "NONE"`
- [x] Keep the dashboard UX explicit that the current NEAR spend cap is capping gas-only spend
- [x] Add relayer coverage for:
  - NEAR capped reservation success
  - NEAR settlement with real/static finalized spend
  - replay behavior with an existing capped NEAR record
- [x] Add dashboard API wiring coverage for NEAR spend-cap authoring and validation
- [ ] Optional future hardening:
  - clearer operator-facing diagnostics for NEAR capped rejection / settlement details
  - richer pricing providers if CoinGecko + static config stop being sufficient

Exit criteria:

- `near_delegate` sponsorship policies can configure and enforce spend caps through the same shared sponsorship spend-cap path as EVM
- dashboard NEAR authoring no longer forces `spendCap.mode = "NONE"`
- NEAR sponsored-call records settle auditable gas-only billed `spendMinor` with pricing-source metadata
- attached deposit remains user-paid and outside sponsorship accounting
- status: complete for gas-only NEAR spend caps

## Verification matrix

Lower-level coverage:

- [x] executor registry parsing and normalization
- [x] sponsor address derivation
- [x] multichain executor selection
- [x] call template parsing
- [x] selector/function-signature compatibility
- [x] allowlist and numeric bound checks
- [x] shared sponsorship-engine result normalization across EVM and NEAR
- [x] replay behavior with explicit `idempotencyKey`

Relayer coverage:

- [x] one chain succeeds while another chain uses a different executor
- [x] request rejected when no executor exists for the matched chain
- [x] request rejected when gas/value bounds fail even though selector matches
- [x] replayed success returns the original success body
- [x] replayed failure returns the original failure class
- [x] NEAR delegate sponsorship uses the same replay and persistence model

Demo or integration coverage:

- [x] Tempo onboarding drip still works end to end
- [x] a second non-Tempo EVM template works end to end through relayer coverage
- [x] NEAR delegate sponsorship works end to end through the unified engine in relayer coverage
- [x] `Set Tempo Fee Token` and later normal Tempo signing still work after the sponsored drip

## Recommended implementation order

1. Phase 1: define the unified sponsorship core.
2. Phase 2: ship the multichain EVM executor registry.
3. Phase 3: generalize the policy model and runtime snapshot.
4. Phase 4: implement executor dispatch and typed route integration.
5. Phase 5: migrate built-in policies and Tempo onboarding.
6. Phase 6: ship EVM-first dashboard authoring.
7. Phase 7: tighten accounting and observability.
8. Phase 8: prove the generalized MVP across EVM and NEAR.
9. Phase 9: expand dashboard authoring beyond the EVM-first scope.
10. Phase 10: add an optional real pricing source.
11. Phase 11: add NEAR spend-cap support.
12. Only after that, reconsider richer pricing providers, argument constraints, or additional executor kinds.

## Final desired state

When this plan is complete:

- the relay can sponsor EVM calls on multiple chains in one process
- NEAR sponsorship uses the same internal sponsorship architecture
- the EVM executor config is keyed by chain, not by one global flat env block
- sponsorship policies can express allowlisted contract/function templates with gas/value bounds and top-level execution mode
- Tempo onboarding is just one seeded policy template in that model
- the EVM and NEAR runtime routes are thin typed entrypoints over one sponsorship engine
- `/dashboard/gas-sponsorship` can author both EVM and NEAR sponsorship policies under the same tagged-union model
- the generic sponsorship system does not need Tempo-specific policy storage or env assumptions
- idempotency, spend tracking, and policy attribution remain intact
- capped sponsorship can use either static configured pricing or an optional real pricing source without changing the core route architecture
- capped sponsorship can enforce both EVM and NEAR sponsorship policies through the same shared budgeting model
- NEAR sponsorship caps and billing only cover relayer-paid gas, not user-paid attached deposit

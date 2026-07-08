# Sponsorship Policy Engine Plan

Last updated: 2026-06-29

## Goal

Introduce a policy-engine mediated transaction sponsorship flow that:

- uses one policy surface to decide what can be sponsored
- supports multiple chain families without hardcoded route rules
- keeps execution chain-specific
- records exact finalized spend for usage and billing

The target product shape is:

- sponsorship is configured as a normal policy
- runtime snapshots publish resolved sponsorship policies
- relay routes load resolved policy and match incoming requests against it
- chain-specific executors perform the actual sponsored submission
- the billing ledger records exact spend keyed to the initiating API key and policy

## Scope

In scope:

- policy-mediated sponsorship for EVM single-call transactions
- policy-mediated sponsorship for NEAR delegate-action submission
- one shared sponsorship core for auth, idempotency, policy loading, spend recording, and billing attribution
- runtime snapshot publication of resolved sponsorship policies
- migration away from route-level hardcoded sponsorship rules

Out of scope for this plan:

- arbitrary raw transaction sponsorship
- multicall or multi-intent sponsorship
- invoice/reporting UX beyond exact spend capture

## Design principles

1. The policy engine decides whether a request is sponsorable.
2. The sponsorship runtime decides how the request is executed and how spend is recorded.
3. Runtime routes consume resolved policy artifacts, not raw console config.
4. The request contract stays narrow and typed per chain family.
5. No legacy fallback paths: a request either matches policy and executes, or it is rejected.

## Current state

What already exists:

- EVM sponsorship config exists in [packages/console-server-ts/src/gasSponsorship/types.ts](../packages/console-server-ts/src/gasSponsorship/types.ts)
- runtime snapshots already publish resolved EVM `sponsoredCallPolicies` in [packages/sdk-server-ts/src/router/runtimeSnapshotPayload.ts](../packages/sdk-server-ts/src/router/runtimeSnapshotPayload.ts)
- the shared server package now owns the EVM sponsorship route and execution path in [packages/console-server-ts/src/sponsorship/evmRelay.ts](../packages/console-server-ts/src/sponsorship/evmRelay.ts) and [packages/sdk-server-ts/src/router/express/routes/sponsoredEvmCall.ts](../packages/sdk-server-ts/src/router/express/routes/sponsoredEvmCall.ts)
- shared onboarding seeding now lives in [packages/console-server-ts/src/gasSponsorship/seeding.ts](../packages/console-server-ts/src/gasSponsorship/seeding.ts)
- shared EVM sponsorship parsing and matching primitives exist in [packages/console-server-ts/src/sponsorship/evm.ts](../packages/console-server-ts/src/sponsorship/evm.ts)
- exact sponsored spend is stored through a chain-aware ledger model in [packages/console-server-ts/src/sponsoredCalls/types.ts](../packages/console-server-ts/src/sponsoredCalls/types.ts)
- NEAR delegate validation and relaying primitives already exist in [packages/sdk-server-ts/src/delegateAction/index.ts](../packages/sdk-server-ts/src/delegateAction/index.ts)

What is still missing:

- one first-class sponsorship policy model spanning both EVM and NEAR
- one resolved runtime sponsorship artifact covering both chain families
- one shared sponsorship engine abstraction above chain-specific executors
- a policy-backed NEAR sponsorship route

## Target architecture

### 1. Policy engine

The policy engine should own sponsorship authorization.

It should answer:

- which chain family is sponsorable
- which networks are sponsorable
- which contracts or receivers are sponsorable
- which functions or methods are sponsorable
- which gas, value, or deposit limits apply
- which execution backend should be used
- whether unsponsored fallback is forbidden

Target resolved policy union:

```ts
type ResolvedSponsorshipPolicy =
  | {
      kind: 'evm_call';
      policyId: string;
      environmentId: string;
      enabled: boolean;
      executor: 'evm_relay_eoa';
      allowedCalls: Array<{
        chainId: number;
        to: `0x${string}`;
        selector: `0x${string}`;
        maxGasLimit: string;
        maxValueWei: string;
      }>;
    }
  | {
      kind: 'near_delegate';
      policyId: string;
      environmentId: string;
      enabled: boolean;
      executor: 'near_relayer';
      allowedReceivers: string[];
      allowedMethods: string[];
      maxTotalDepositYocto: string;
      allowTransfers: boolean;
    };
```

### 2. Runtime snapshot

The runtime snapshot should publish only resolved sponsorship artifacts.

The relay should not need to understand:

- scope precedence
- template inheritance
- dashboard-only config structure

It should receive one normalized resolved policy set for the active environment and match requests against it directly.

### 3. Sponsorship runtime

The runtime should be split into:

- shared request authentication and environment binding
- policy lookup and matching
- idempotency and replay protection
- executor dispatch
- finalized spend persistence
- billing usage emission

That shared engine should dispatch to typed executors:

- EVM single-call executor
- NEAR delegate-action executor

### 4. Chain-specific execution

EVM:

- input is one chain, one target, one calldata blob, one gas limit, one value
- match on `chainId + to + selector + gasLimit + value`
- execute through relay-owned signer first

NEAR:

- input is one signed delegate plus request metadata
- match on receiver, allowed function-call methods, and attached deposit limit
- reject non-function-call transfer-like actions unless explicitly permitted
- reuse existing delegate validation and relayer submission primitives

### 5. Sponsored spend ledger

The ledger should become chain-agnostic.

Required billing identity:

- `orgId`
- `environmentId`
- `apiKeyId`
- `policyId`
- `route`
- `chainFamily`
- `intentKind`
- `accountRef`
- `targetRef`
- `sponsorRef`
- `txOrExecutionRef`
- `receiptStatus`
- exact spend unit and amount
- chain-specific details as JSON

Do not preserve EVM-only columns as the primary model once NEAR is added.

## API shape

Public runtime routes should stay chain-specific:

- `POST /sponsorships/evm/call`
- `POST /sponsorships/near/delegate`

Internal engine should be shared.

Do not expose one generic untyped blob route for all chains.

## Phased todo list

## Phase 0: Lock the architecture

Objective:

- align on the split between policy engine, sponsorship runtime, and chain executors

Todo:

- [ ] Confirm sponsorship becomes a first-class policy-engine feature, not a relay-only feature
- [ ] Confirm execution stays outside the policy engine
- [ ] Confirm there will be no unsponsored fallback path in the new flow
- [ ] Confirm the runtime contract remains typed per chain family, not raw tx blobs
- [ ] Confirm the first supported intent kinds are:
  - `evm_call`
  - `near_delegate`
- [ ] Declare the current Tempo onboarding flow the first EVM policy instance, not a special system path

Exit criteria:

- one approved target architecture
- no ambiguity about where policy ends and execution begins

## Phase 1: Promote sponsorship into the policy engine

Objective:

- make sponsorship configuration a normal policy-engine concept

Todo:

- [ ] Define a first-class sponsorship policy type in the policy engine
- [ ] Decide whether the current `gasSponsorship` config becomes:
  - the implementation of that policy type, or
  - a temporary storage layer to be migrated
- [ ] Model policy kinds explicitly:
  - `evm_call`
  - `near_delegate`
- [ ] Add executor mode to the policy model
- [ ] Add fail-closed semantics to policy resolution
- [ ] Define scope and precedence rules for sponsorship policy resolution
- [ ] Ensure policy records carry stable `policyId` values through snapshots and billing records

Exit criteria:

- sponsorship is owned by the policy layer
- the current EVM policy can be represented without route-level special cases

## Phase 2: Publish resolved sponsorship policy in runtime snapshots

Objective:

- make the relay consume one resolved sponsorship artifact

Todo:

- [ ] Replace EVM-only resolved snapshot output with a sponsorship policy union
- [ ] Keep the snapshot payload normalized and runtime-oriented
- [ ] Publish only effective resolved policies for the environment
- [ ] Preserve current EVM onboarding policy in the new resolved format
- [ ] Add resolved NEAR delegate sponsorship policy shape to the snapshot
- [ ] Version the snapshot contract cleanly so old route consumers are not silently misreading new data
- [ ] Add unit tests for resolved snapshot generation across:
  - EVM-only policy
  - NEAR-only policy
  - mixed policy sets
  - disabled policy cases

Exit criteria:

- runtime routes can decide sponsorship from snapshot data alone
- the snapshot format is no longer EVM-specific

## Phase 3: Build the shared sponsorship engine

Objective:

- centralize the cross-chain parts of sponsorship execution

Todo:

- [ ] Introduce a shared sponsorship engine module for:
  - API key auth
  - environment binding
  - policy lookup
  - idempotency
  - finalized spend recording
  - billing usage emission
- [x] Add a typed matcher layer per policy kind
- [ ] Add a typed executor dispatch interface
- [ ] Add shared request and response error codes
- [x] Add a shared request correlation or source event model
- [ ] Remove duplicate route-local policy parsing and billing logic

Exit criteria:

- chain-specific routes are thin
- policy matching and spend accounting are no longer duplicated

## Phase 4: Generalize the ledger and billing model

Objective:

- make sponsored-spend persistence truly chain-agnostic

Todo:

- [x] Replace EVM-shaped record fields with chain-agnostic identity fields
- [x] Move EVM-specific execution details into structured details payloads
- [x] Add `chainFamily` and `intentKind` to the canonical record model
- [ ] Add support for NEAR execution references and receipt status mapping
- [x] Define exact spend units per chain family:
  - `wei` for EVM
  - `yoctoNEAR` for NEAR
- [x] Ensure billing attribution remains keyed to the initiating API key and policy
- [ ] Migrate existing EVM sponsored-call persistence without leaving legacy duplicate modules behind

Exit criteria:

- one ledger model can represent both EVM and NEAR sponsorship cleanly

## Phase 5: Move EVM sponsorship onto the shared engine

Objective:

- make current EVM sponsorship the first consumer of the generalized system

Todo:

- [x] Rename the example route contract from Tempo-specific branding to generic EVM sponsorship
- [x] Add `POST /sponsorships/evm/call`
- [x] Move route ownership from the example relay into shared server routing and sponsorship modules
- [x] Move onboarding policy seeding out of the example relay and into shared gas-sponsorship helpers
- [ ] Route it through the shared sponsorship engine
- [x] Keep the request shape narrow:
  - `chainId`
  - `to`
  - `data`
  - `gasLimit`
  - `value`
  - `idempotencyKey`
- [x] Keep selector extraction and matching in the EVM matcher
- [x] Preserve exact spend measurement and billing attribution
- [x] Remove remaining Tempo-specific route logic and naming from the generic path
- [x] Keep the Tempo onboarding policy as seeded data only

Exit criteria:

- EVM sponsorship is productized as a generic policy-backed flow
- the Tempo onboarding case is just one policy instance
- developers configure sponsorship; they do not implement route-local sponsorship logic

## Phase 6: Add NEAR delegate sponsorship

Objective:

- add policy-backed sponsorship for NEAR delegate-action relay submission

Todo:

- [ ] Add `POST /sponsorships/near/delegate`
- [ ] Validate API key and environment binding through the shared engine
- [ ] Resolve the applicable `near_delegate` policy from the runtime snapshot
- [ ] Reuse `validateDelegateExpiryAndNonce` from [packages/sdk-server-ts/src/delegateAction/index.ts](../packages/sdk-server-ts/src/delegateAction/index.ts)
- [ ] Reuse `enforceDelegatePolicy` from [packages/sdk-server-ts/src/delegateAction/index.ts](../packages/sdk-server-ts/src/delegateAction/index.ts)
- [ ] Reuse `executeSignedDelegateWithRelayer` from [packages/sdk-server-ts/src/delegateAction/index.ts](../packages/sdk-server-ts/src/delegateAction/index.ts)
- [ ] Add replay protection keyed to delegate signer identity and nonce
- [ ] Reject transfer-like value movement unless the policy explicitly allows it
- [ ] Record finalized NEAR relayer spend in the generic ledger
- [ ] Emit billing usage keyed to `apiKeyId` and `policyId`

Exit criteria:

- NEAR delegate sponsorship uses the same policy and billing core as EVM sponsorship
- NEAR execution remains chain-specific and typed

## Phase 7: Product surface and cleanup

Objective:

- finish the migration and remove the old boundaries

Todo:

- [ ] Expose sponsorship policy editing in the dashboard or console UI
- [ ] Show chain family, contract or receiver, and function or method constraints clearly
- [ ] Show executor mode and enabled state clearly
- [ ] Remove any remaining route-local hardcoded sponsorship constraints
- [ ] Remove temporary compatibility helpers introduced during migration
- [ ] Remove stale Tempo-branded naming from generic sponsorship modules
- [ ] Remove legacy EVM-only snapshot fields once all consumers use the generalized contract
- [ ] Add integration coverage for:
  - EVM allowed call
  - EVM rejected selector
  - NEAR allowed delegate
  - NEAR rejected receiver or method
  - replay rejection
  - finalized spend attribution

Exit criteria:

- policy-mediated sponsorship is the only active implementation path
- no legacy fallback or duplicate sponsorship paths remain

## Initial success criteria

The plan is complete when all of the following are true:

- sponsorship policy is configured and resolved through the policy engine
- the relay reads one resolved sponsorship artifact from runtime snapshots
- EVM sponsorship runs through a generic `evm_call` path
- NEAR sponsorship runs through a generic `near_delegate` path
- exact spend is recorded for both chain families and attributed to the initiating API key
- the Tempo onboarding case exists only as seeded policy data
- no hardcoded route-level sponsorship exceptions remain

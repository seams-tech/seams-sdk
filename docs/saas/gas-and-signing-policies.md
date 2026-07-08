# Gas and Signing Policies

Date updated: June 29, 2026

## Overview

The console policy system has one shared policy model and two policy kinds:

- `TRANSACTION`: signing and transaction authorization policy
- `GAS_SPONSORSHIP`: gas sponsorship policy

Both kinds are stored as real policy records in the shared policy store and use the same draft, publish, version, approval, audit, and runtime snapshot pipeline.

The main distinction is in `rules`:

- transaction policies use `ConsoleTransactionPolicyRules`
- gas policies use `ConsoleGasSponsorshipPolicyRules`

Code references:

- [packages/console-server-ts/src/policies/types.ts](../../packages/console-server-ts/src/policies/types.ts)
- [packages/console-server-ts/src/policies/service.ts](../../packages/console-server-ts/src/policies/service.ts)
- [packages/console-server-ts/src/policies/rules.ts](../../packages/console-server-ts/src/policies/rules.ts)

## Main Structs And Services

### Shared policy model

`ConsolePolicy`

- top-level policy record
- fields include `id`, `kind`, `name`, `status`, `version`, `rules`, `publishedAt`

`ConsolePolicyVersion`

- immutable version row for a policy
- stores the versioned `rules`, `status`, `publishedAt`, and actor metadata

`ConsolePolicyAssignment`

- assignment record for transaction policies
- binds a `policyId` to an `ORG`, `PROJECT`, `ENVIRONMENT`, or `WALLET` scope

`ConsolePolicyService`

- main authoring service
- owns list/get/create/update/publish/delete/simulate operations
- also owns transaction-policy assignments and wallet resolution

Code references:

- [packages/console-server-ts/src/policies/types.ts](../../packages/console-server-ts/src/policies/types.ts)
- [packages/console-server-ts/src/policies/service.ts](../../packages/console-server-ts/src/policies/service.ts)

### Transaction policy rules

`ConsoleTransactionPolicyRules`

- signer/transaction rule set
- fields include `blockedActions`, `allowedChains`, `maxAmountMinor`, `allowedContractCalls`

`SimulateConsolePolicyRequest`

- request shape for policy simulation
- used to test whether a transaction policy would allow or deny an action

`SimulateConsolePolicyResult`

- simulation result with `decision`, `denyReasons`, normalized request, and evaluated version

Code references:

- [packages/console-server-ts/src/policies/types.ts](../../packages/console-server-ts/src/policies/types.ts)
- [packages/console-server-ts/src/policies/rules.ts](../../packages/console-server-ts/src/policies/rules.ts)

### Gas sponsorship policy rules

`ConsoleGasSponsorshipPolicyRules`

- authoring format for gas sponsorship policies
- fields include `scopeType`, `projectId`, `environmentId`, `scopePolicyId`, `walletSegmentId`, `enabled`, `templateId`, `networkClass`, `allowedChainIds`, `callMode`, `allowedCalls`, `spendCap`

Important naming rule:

- `policyId` always means the real policy record id
- `scopePolicyId` is only the gas rule field used when a gas policy targets another policy scope

`ConsoleGasSponsorshipPolicyProjection`

- gas-focused projection derived from a published `GAS_SPONSORSHIP` policy
- adds projection-friendly fields like `scopePolicyName` and telemetry
- this is the shape used by runtime snapshot assembly and dashboard presentation

`ResolvedSponsoredCallPolicy`

- relayer-ready execution shape derived from gas policy projections
- strips the model down to the fields needed to match and enforce a sponsored call

Code references:

- [packages/console-server-ts/src/policies/types.ts](../../packages/console-server-ts/src/policies/types.ts)
- [packages/console-server-ts/src/gasSponsorship/types.ts](../../packages/console-server-ts/src/gasSponsorship/types.ts)
- [packages/console-server-ts/src/gasSponsorship/service.ts](../../packages/console-server-ts/src/gasSponsorship/service.ts)
- [packages/console-server-ts/src/gasSponsorship/onboarding.ts](../../packages/console-server-ts/src/gasSponsorship/onboarding.ts)

### Runtime snapshot model

`ConsoleRuntimeSnapshotPayload`

- published runtime bundle for one environment and optional project
- contains:
  - `policy`: published transaction policies plus assignments for the runtime scope
  - `gasSponsorship`: published gas policies plus relayer-ready sponsored call policy projections

`resolveConsoleRuntimeSnapshotPayload`

- assembles the current runtime payload from live policy state
- this is the bridge from authoring-time policy records to execution-time payloads

Code references:

- [packages/console-server-ts/src/runtimeSnapshots/types.ts](../../packages/console-server-ts/src/runtimeSnapshots/types.ts)
- [packages/sdk-server-ts/src/router/runtimeSnapshotPayload.ts](../../packages/sdk-server-ts/src/router/runtimeSnapshotPayload.ts)

## Entry Points

### Authoring and policy management

Express router:

- `GET /console/policies`
- `GET /console/policies/:id/versions`
- `GET /console/policies/assignments`
- `POST /console/policies`
- `PATCH /console/policies/:id`
- `DELETE /console/policies/:id`
- `PUT /console/policies/assignments`
- `DELETE /console/policies/assignments/:id`
- `POST /console/policies/:id/publish`
- `POST /console/policies/:id/simulate`

Cloudflare router exposes the same policy surface.

Code references:

- [packages/sdk-server-ts/src/router/express/createConsoleRouter.ts](../../packages/sdk-server-ts/src/router/express/createConsoleRouter.ts)
- [packages/sdk-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts](../../packages/sdk-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts)

### Approval flow

Publish approvals use the shared approvals system.

Main entry points:

- `GET /console/approvals`
- `GET /console/approvals/:id`
- `POST /console/approvals`
- `POST /console/approvals/:id/approve`
- `POST /console/approvals/:id/reject`

For policy publish, the approval operation type is `POLICY_PUBLISH`. Approval payloads and audit rows carry `policyId`, `policyName`, and `policyKind`.

Code references:

- [packages/sdk-server-ts/src/router/express/createConsoleRouter.ts](../../packages/sdk-server-ts/src/router/express/createConsoleRouter.ts)
- [packages/sdk-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts](../../packages/sdk-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts)

### Runtime publication

Main entry point:

- `POST /console/runtime-snapshots/publish-current`

This reads current live policy state, resolves the effective payload for an environment and optional project, and publishes a runtime snapshot.

Code references:

- [packages/sdk-server-ts/src/router/runtimeSnapshotPayload.ts](../../packages/sdk-server-ts/src/router/runtimeSnapshotPayload.ts)
- [packages/sdk-server-ts/src/router/express/createConsoleRouter.ts](../../packages/sdk-server-ts/src/router/express/createConsoleRouter.ts)
- [packages/sdk-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts](../../packages/sdk-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts)

### Sponsored call execution

Main relayer entry point:

- `POST /sponsorships/evm/call`

This is the runtime execution path for gas sponsorship.

Code reference:

- [packages/console-server-ts/src/sponsorship/evmRelay.ts](../../packages/console-server-ts/src/sponsorship/evmRelay.ts)

## Flows

### 1. Signing policy authoring and publish flow

1. A client creates or updates a `TRANSACTION` policy through `/console/policies`.
2. `ConsolePolicyService` parses and normalizes rules through `parseConsolePolicyRulesInput`.
3. Transaction policy assignments are managed separately through `/console/policies/assignments`.
4. When the policy is ready, the client publishes it directly or requests approval through `/console/approvals`.
5. `publishPolicy` creates a published version row and updates the live `ConsolePolicy`.
6. Audit and approval payloads expose the published `policyId`, `policyName`, and `policyKind`.

Relevant code:

- [packages/console-server-ts/src/policies/service.ts](../../packages/console-server-ts/src/policies/service.ts)
- [packages/console-server-ts/src/policies/rules.ts](../../packages/console-server-ts/src/policies/rules.ts)

### 2. Signing policy simulation flow

1. A client calls `/console/policies/:id/simulate`.
2. `ConsolePolicyService.simulatePolicy` loads the policy and evaluates it with `evaluateConsolePolicyRules`.
3. The response returns `ALLOW` or `DENY`, plus normalized inputs and deny reasons.

This flow exists only for transaction policies.

Relevant code:

- [packages/console-server-ts/src/policies/service.ts](../../packages/console-server-ts/src/policies/service.ts)
- [packages/console-server-ts/src/policies/rules.ts](../../packages/console-server-ts/src/policies/rules.ts)

### 3. Gas policy authoring and publish flow

1. A client creates or updates a `GAS_SPONSORSHIP` policy through `/console/policies`.
2. `ConsolePolicyService` parses gas rules with the same top-level policy pipeline.
3. On publish, gas rules are validated for publish-time requirements such as scope integrity and allowed-call shape.
4. The published policy becomes the live gas policy record for that policy id.
5. Gas-specific views are derived later from the published policy; there is no separate gas CRUD resource.

Relevant code:

- [packages/console-server-ts/src/policies/service.ts](../../packages/console-server-ts/src/policies/service.ts)
- [packages/console-server-ts/src/policies/rules.ts](../../packages/console-server-ts/src/policies/rules.ts)
- [packages/console-server-ts/src/gasSponsorship/service.ts](../../packages/console-server-ts/src/gasSponsorship/service.ts)

### 4. Runtime snapshot publish flow

1. A client calls `/console/runtime-snapshots/publish-current`.
2. `resolveConsoleRuntimeSnapshotPayload` loads:
   - published transaction policies and assignments for the requested scope
   - published `GAS_SPONSORSHIP` policies for the requested scope
3. Gas policies are projected through `projectConsoleGasSponsorshipPolicyProjection`.
4. Projections are converted into relayer-ready `sponsoredCallPolicies` with `resolveSponsoredCallPoliciesFromProjections`.
5. The assembled `ConsoleRuntimeSnapshotPayload` is published as the next runtime snapshot.

Relevant code:

- [packages/sdk-server-ts/src/router/runtimeSnapshotPayload.ts](../../packages/sdk-server-ts/src/router/runtimeSnapshotPayload.ts)
- [packages/console-server-ts/src/gasSponsorship/service.ts](../../packages/console-server-ts/src/gasSponsorship/service.ts)
- [packages/console-server-ts/src/gasSponsorship/onboarding.ts](../../packages/console-server-ts/src/gasSponsorship/onboarding.ts)

### 5. Sponsored EVM call execution flow

1. The relayer receives `POST /sponsorships/evm/call`.
2. It loads the latest published runtime snapshot for the environment and project.
3. It reads `payload.gasSponsorship.sponsoredCallPolicies`.
4. It parses those policies into runtime matcher input and selects the matching sponsored call policy.
5. The relayer enforces allowed chains, allowed calls, and spend-cap rules.
6. If the request is accepted, the relayer executes the sponsored transaction and records history against the matched `policyId`.

Relevant code:

- [packages/console-server-ts/src/sponsorship/evmRelay.ts](../../packages/console-server-ts/src/sponsorship/evmRelay.ts)
- [packages/console-server-ts/src/gasSponsorship/onboarding.ts](../../packages/console-server-ts/src/gasSponsorship/onboarding.ts)

### 6. Tempo onboarding gas policy flow

This is the main built-in gas policy bootstrap path.

1. `ensureTempoTestnetOnboardingPolicyForEnvironment` looks for an existing onboarding gas policy projection.
2. If none exists, it creates a `GAS_SPONSORSHIP` policy with `buildTempoTestnetOnboardingGasPolicyRules`.
3. It immediately publishes that policy.
4. The published policy then participates in normal runtime snapshot publication and sponsored-call matching.

Relevant code:

- [packages/console-server-ts/src/gasSponsorship/onboarding.ts](../../packages/console-server-ts/src/gasSponsorship/onboarding.ts)

## Mental Model

The cleanest way to think about the system is:

- one policy store
- two policy kinds
- shared draft, version, publish, approval, audit, and runtime publication flow
- separate rule schemas for signing vs gas sponsorship
- gas execution runs on a derived runtime projection, not directly on the authoring document

That split keeps authoring uniform without forcing the relayer hot path to consume the full policy authoring model.

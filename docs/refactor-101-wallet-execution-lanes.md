# Wallet Key And Execution Lane Foundation

Date created: June 15, 2026

Reconciled: August 13, 2026

Status: active foundation plan, rewritten for four-agent parallel delivery.
Curve-specific key identity, participant bindings, local capability material,
and exact Wallet Session admission already exist as groundwork. R101 now ends
at a working owner-lane resolution and admission boundary. Lane creation and
refresh remain R102 work; device linking remains R103 work; delegated spending
remains R104 work.

Implementation checklist: 7/8 complete (87.5%). The remaining item is the
full intended-behavior, source-guard, and wallet-iframe integration gate; the
focused owner projection, hydration, preflight, admission, and type-boundary
contracts pass.

## Authority And Dependencies

This plan owns stable wallet-key identity and share-bearing execution lanes.
It does not own agent identity, delegated-spend authorization, device-linking
transport, or user-facing policy.

It consumes:

- [refactor-90-modular-auth-capabilities-plan.md](./refactor-90-modular-auth-capabilities-plan.md)
  for canonical capability hydration, the landed curve-specific ECDSA
  capability manifest, exact `MpcMaterialActivationRef` identities, idempotent
  activation commits, authorization resources, atomic authorized-operation
  admission, and exact operation execution;
- [router-ab/ed25519-yao/implementation-plan.md](./router-ab/ed25519-yao/implementation-plan.md)
  for Ed25519 key identity, Client and SigningWorker lifecycle, recovery,
  recipient provisioning, refresh, and export;
- `crates/router-ab-ecdsa-derivation` for secp256k1 role-local additive shares,
  threshold sessions, signing, and export;
- [refactor-100-passkey-account-refactor.md](./refactor-100-passkey-account-refactor.md)
  for wrapped owner and linked-device custody.

It supplies the execution model consumed by:

- [refactor-102-rotatable-signing-lanes.md](./refactor-102-rotatable-signing-lanes.md) for lane
  provisioning, refresh, activation, and revocation;
- [refactor-103-device-linking.md](./refactor-103-device-linking.md) for physical
  linked-device enrollment;
- [refactor-104-agent-id-spending.md](./refactor-104-agent-id-spending.md) for an
  optional authorization-bound delegated execution lane after agent identity
  and owner authorization have verified.

## Goal

Represent each persistent wallet public identity and each independently
revocable cryptographic execution path with precise domain objects.

```text
Wallet
  -> WalletKey: one stable public key or address
       -> ExecutionLane: one holder/server participant pair
            -> active capability and exact signing sessions
```

Agent authority is a separate axis:

```text
AgentIdentityKey
  -> owner-signed DelegatedSpendAuthorization
       -> agent-signed SpendRequest
            -> admitted WalletExecution
```

An agent identity key never becomes a `WalletKey`. A delegated authorization
never becomes a lane policy. An execution lane never proves who authored a
request.

Terminology is deliberately split. A persistent `SigningLane` is durable
share-bearing material for one wallet key, holder participant, and server
participant. Refactor 90's `ExactEcdsaOperationLane` is an operation-local,
prepared signing descriptor. It carries the selected persistent lane and exact
material activation into admission, then expires with that operation; it is not
a second durable lane and cannot be used to infer lane ownership.

## Required Invariants

1. A `WalletKey` is the only persistent cryptographic identity that produces
   wallet or blockchain signatures.
2. An `AgentIdentityKey` is independent from every `WalletKey` and signs only
   agent-authored authorization requests or protocol-specific agent objects.
3. A `SigningLane` is share-bearing execution material for one wallet key. It
   cannot contain a delegated mandate, agent display profile, or raw request.
4. Authorization admission completes before root, share, presignature, Client,
   SigningWorker, or relayer work begins.
5. Every execution resolves one exact wallet key, lane, share epoch,
   revocation epoch, participant binding, and operation identity.
6. Revoking one lane leaves the wallet key and unrelated lanes unchanged.
7. Adding a credential to an existing principal does not create a wallet key
   or lane.
8. Export requires an owner/export authorization branch. Device and delegated
   execution lanes cannot satisfy it.
9. Raw request, persistence, and worker shapes are parsed once at their
   boundaries. Core execution receives precise active records.
10. Obsolete `delegated_agent` lane and lane-owned mandate types are deleted
    when this model lands. No compatibility union enters core logic.

## Wallet Key

A wallet key is stable across credential replacement, share refresh, new
execution lanes, and recovery.

```ts
type WalletKeyRecord = Ed25519WalletKeyRecord | EvmFamilyWalletKeyRecord;

type Ed25519WalletKeyRecord = {
  kind: 'wallet_key_record_v1';
  keyFamily: 'ed25519';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  walletKeyVersion: WalletKeyVersion;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  keyCreationSignerSlot: KeyCreationSignerSlot;
  registeredPublicKeyB64u: string;
  lifecycle: WalletKeyLifecycle;
  evmFamilySigningKeySlotId?: never;
  thresholdPublicKey33B64u?: never;
  evmAddress?: never;
};

type EvmFamilyWalletKeyRecord = {
  kind: 'wallet_key_record_v1';
  keyFamily: 'ecdsa_secp256k1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  walletKeyVersion: WalletKeyVersion;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  thresholdPublicKey33B64u: string;
  evmAddress: string;
  lifecycle: WalletKeyLifecycle;
  nearEd25519SigningKeyId?: never;
  keyCreationSignerSlot?: never;
  registeredPublicKeyB64u?: never;
};
```

`WalletKeyLifecycle` is an exhaustive union of `active`, `retired`, and
`compromised`. Only `active` keys may admit new signing operations.

Tempo, Arc, Ethereum, and future EVM-family targets reuse one EVM-family wallet
key when they share the same key slot. Chain-specific sessions, nonce lanes,
and transaction formats are operational bindings under that key.

## Execution Lane Taxonomy

An execution lane binds one wallet key to one holder participant and one server
participant. The core taxonomy is:

```ts
type SigningLaneKind =
  | 'owner_passkey'
  | 'owner_email_otp'
  | 'linked_device'
  | 'delegated_execution'
  | 'recovery'
  | 'break_glass';

type SigningLaneReference = {
  kind: 'signing_lane_reference_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneKind: SigningLaneKind;
  laneShareEpoch: LaneShareEpoch;
  participantBindingDigestB64u: string;
};

type ActiveSigningLaneReference = SigningLaneReference & {
  lifecycle: Extract<SigningLaneLifecycle, { state: 'active' }>;
  materialActivation: MpcMaterialActivationRef;
};
```

Only an active lane may expose `ActiveSigningLaneReference`. Provisioning and
pending records carry their protocol correlation and activation candidate but
cannot satisfy an execution reference until the curve-specific activation
receipt is verified. A lane refresh creates a fresh activation reference for
the next share epoch; it never mutates the prior active reference in place.

`delegated_execution` describes an optional MPC execution topology used after
Refactor 104 authorization. Its holder material may be sealed to an agent
runtime so the agent and Seams policy participant must both cooperate. The
agent's independent identity key remains the request author and authorization
subject.

The canonical record union is:

```ts
type SigningLaneRecord =
  | OwnerPasskeySigningLaneRecord
  | OwnerEmailOtpSigningLaneRecord
  | LinkedDeviceSigningLaneRecord
  | DelegatedExecutionLaneRecord
  | RecoverySigningLaneRecord
  | BreakGlassSigningLaneRecord;
```

Owner branches bind the exact durable signer identity, participant tuple,
SigningWorker identity, custody-manifest digest, and current public capability
digest already present in canonical signer records. Linked-device and delegated
branches require the independently provisioned holder and server HPKE participant
records owned by later refactors. Branches use `never` fields to reject identities
and policies owned by another branch.

### Delegated execution lane

The delegated branch carries execution references only:

```ts
type DelegatedExecutionLaneRecord = SigningLaneReference & {
  laneKind: 'delegated_execution';
  authorizationId: DelegatedSpendAuthorizationId;
  agentIdentityKeyId: AgentIdentityKeyId;
  custodyBindingId: AgentCustodyBindingId;
  authorizationBindingDigestB64u: string;
  holderParticipant: DelegatedExecutionHolderParticipant;
  serverParticipant: DelegatedExecutionServerParticipant;
  lifecycle: SigningLaneLifecycle;
  mandate?: never;
  mandatePolicy?: never;
  agentProfile?: never;
};
```

Refactor 104 owns the referenced authorization, agent key, custody binding, and
policy. This lane can execute only after Refactor 104 returns a committed
admission claim for the exact request and authorization epoch. The lane's
activation remains an independent `MpcMaterialActivationRef` selected by the
curve-specific capability adapter.

Deployments that use a chain-native smart account or credential-provider
payment rail may omit `delegated_execution` entirely. The agent key or released
credential is then the execution mechanism defined by that adapter.

## Lane Lifecycle

Cryptographic material lifecycle and authorization availability are separate.
Wallet Session expiry, quota exhaustion, delegated-authorization expiry, and
step-up denial block admission while preserving the active lane's sealed
material and `MpcMaterialActivationRef`. They never retire a lane. Product
pause or risk decisions are admission projections owned by the relevant
authorization plan; they are not cryptographic lane states.

The cryptographic lifecycle and revocation form one exhaustive union:

```ts
type SigningLaneLifecycle =
  | {
      state: 'provisioning';
      revocationEpoch: number;
      startedAtMs: number;
    }
  | {
      state: 'pending_receipt';
      revocationEpoch: number;
      startedAtMs: number;
      deliveryDigestB64u: string;
    }
  | {
      state: 'active';
      revocationEpoch: number;
      activatedAtMs: number;
      activationReceiptDigestB64u: string;
    }
  | {
      state: 'revoked';
      revocationEpoch: number;
      revokedAtMs: number;
      revokeReason: 'user_revoked' | 'device_compromise' | 'agent_compromise' | 'rotation';
    };
```

Only `active` lanes sign. Admission rejects every other branch before secret
material or server participation.

## Key, Lane, Credential, And Authorization Operations

| Operation                   | Wallet key | Lane                         | Authorization identity                  |
| --------------------------- | ---------- | ---------------------------- | --------------------------------------- |
| Create owner wallet key     | new        | new owner lane               | owner authentication                    |
| Add passkey credential      | same       | same                         | owner authentication                    |
| Recover credential          | same       | same or refreshed            | recovery authorization                  |
| Link physical device        | same       | new linked-device lane       | owner-approved device enrollment        |
| Authorize independent agent | same       | none required                | owner-signed delegated authorization    |
| Add delegated MPC execution | same       | new delegated-execution lane | existing active delegated authorization |
| Refresh lane shares         | same       | same lane, next epoch        | branch-specific refresh authorization   |
| Refill ECDSA presignatures  | same       | same                         | existing active execution admission     |
| Rekey wallet                | new        | new                          | owner rekey authorization               |

Creating an agent authorization is never itself a wallet-key or lane-creation
operation.

## Enrollment Boundaries

Physical linked devices commonly require one child lane for every wallet key.
Refactor 103 owns their aggregate enrollment, ordered key manifest, delivery
receipts, and atomic activation.

A Refactor 104 authorization can cover one or more wallet keys without creating
lanes. When a direct threshold-wallet adapter requires delegated execution
lanes, its execution enrollment is subordinate to the already-signed
authorization and must match the authorization's exact key set or a strict
subset explicitly selected for the adapter.

An enrollment cannot mix linked-device and delegated-execution children. Their
principals, receipts, policies, and revocation semantics remain separate.

## Execution Admission Contract

Core signing accepts only a prepared execution admission:

```ts
type PreparedWalletExecution =
  | PreparedOwnerWalletExecution
  | PreparedLinkedDeviceWalletExecution
  | PreparedDelegatedWalletExecution;

type PreparedWalletExecutionBase = {
  authorizedOperation: Extract<AuthorizedOperation, { lifecycle: 'claimed' }>;
  materialActivation: MpcMaterialActivationRef;
  lane: ActiveSigningLaneReference;
};

type PreparedOwnerWalletExecution = PreparedWalletExecutionBase & {
  kind: 'prepared_owner_wallet_execution';
  laneKind: 'owner_passkey' | 'owner_email_otp' | 'recovery' | 'break_glass';
};

type PreparedLinkedDeviceWalletExecution = PreparedWalletExecutionBase & {
  kind: 'prepared_linked_device_wallet_execution';
  laneKind: 'linked_device';
  linkedDeviceEnrollmentId: LinkedDeviceEnrollmentId;
};

type PreparedDelegatedWalletExecution = PreparedWalletExecutionBase & {
  kind: 'prepared_delegated_wallet_execution';
  laneKind: 'delegated_execution';
  delegatedAuthorizationId: DelegatedSpendAuthorizationId;
  budgetClaim: Extract<DelegatedBudgetClaimState, { state: 'reserved' }>;
};
```

Every prepared branch carries the already admitted `AuthorizedOperation` and
the exact material activation selected by the curve-specific adapter. The
operation uses Refactor 90's fingerprint and authorized-operation contract,
extended only by the linked-device or delegated authorization variant owned by
Refactor 103 or 104. The persistent lane reference is a separate identity.

The delegated branch additionally requires:

- verified agent request signature;
- verified owner authorization signature;
- active delegated authorization and current revocation epoch;
- atomically reserved delegated budget claim;
- replay and idempotency claim;
- exact typed intent and final unsigned-transaction digest;
- active wallet key;
- exact holder/server participant and share epochs.

Diagnostics, UI projections, and audit summaries cannot construct this type.

## Storage Ownership

Refactor 101 owns the domain interfaces, parsers, strict projections, and active
owner-lane lookup. The first implementation projects `WalletKeyRecord` and
owner `SigningLaneRecord` views from the existing canonical `wallet_signers`
records. It does not add parallel `wallet_keys` or `signing_lanes` tables.
Those tables would duplicate identity, capability, and activation state before
R102 introduces independently created lanes.

Gateway D1 remains authoritative for the existing signer records, lifecycle,
activation receipts, and public capability bindings. R101 adds precise store
ports and projection adapters over that authority. R102 may extend persistence
when a wallet key can own more than one independently provisioned lane.

Refactor 102 owns protocol jobs, material delivery, activation receipts,
refresh, and cryptographic revocation receipts. Gateway D1 owns product
ceremony outcomes, Wallet Session authorization, quotas, authorized operations,
and authorization audit. SigningWorker private D1 owns activated server
material, delivery state, cryptographic effect deduplication, presignature or
Yao material consumption, and terminal response replay; Deriver A/B private D1
owns role-local custody and one-use state.
Router transports typed commands and receipts and owns no mutable lane,
manifest, or activation store.

Refactor 103 owns linked-device sessions and aggregate device enrollments.

Refactor 104 owns agent identities, public keys, owner authorizations, custody
bindings, budgets, replay claims, spend requests, and delegated audit records.

No R101 store or projection persists plaintext roots, holder shares, PRF
outputs, KEKs, presignatures, live capability handles, or a second copy of
canonical signer state.

## Current Scaffolds To Replace

The repository currently contains dormant development shapes that encode the
superseded model:

- `SigningLaneKind: 'delegated_agent'`;
- `DelegatedAgentSigningLaneRecord` with lane-owned mandate policy;
- `AgentPrincipalId` described as a principal that holds an MPC share;
- `DelegatedSigningRequest` whose authority is inferred from lane identity;
- agent wallet summaries derived from delegated lanes.

Replace these directly with the Refactor 104 identity and authorization model
plus the optional `delegated_execution` lane. Delete obsolete fixtures and
tests that protect the old coupling.

## Delivery Strategy

R101 uses one short contract-seed change followed by four concurrent agents in
separate worktrees. The seed must land before the agents branch. It contains
only final public type names, store ports, result unions, and module paths. It
does not contain persistence, hydration, route behavior, or compatibility
logic.

The four agents own disjoint directories. They may add dedicated test files,
but they do not edit shared test helpers, central dependency-injection files,
package barrels outside their owned directory, source guards, or this plan.
The integrator owns those conflict-prone files after all four branches land.

```text
contract seed
  ├── Agent A: shared domain and parsers ───────────┐
  ├── Agent B: Gateway projections and stores ─────┤
  ├── Agent C: browser capability hydration ───────┤
  └── Agent D: server admission boundary ──────────┤
                                                    └── integration wave
```

### Contract Seed: Integrator Prerequisite

Freeze these contracts before parallel work starts:

- `WalletKeyRecord`, `SigningLaneRecord`, `SigningLaneLifecycle`, and
  `ActiveSigningLaneReference` keep the shapes defined in this document;
- `LaneHolderParticipantRecordV1`, `SigningWorkerParticipantRecordV1`, and
  `LaneParticipantBindingDigestB64u` are the canonical participant bindings;
- `WalletKeyStore` and `SigningLaneStore` expose exact branded lookup inputs and
  parsed records only;
- `ActiveOwnerLaneResolution` is an exhaustive union of `active` and typed
  refusal reasons. It carries the wallet key, lane, exact material activation,
  participant bindings, share/revocation epochs, and verified activation
  receipt digest;
- `PreparedWalletExecution` retains owner, linked-device, and delegated
  branches, while R101 constructs only the owner branch;
- linked-device and delegated admission return explicit `unsupported_lane`
  refusals until R103 and R104 supply their authorization records;
- deterministic owner `WalletKeyId` and `SigningLaneId` derivation from current
  signer identities is frozen and independently collision-tested.

The seed is complete when all four agent branches compile against it without
editing a contract-owned file.

## Four Concurrent Workstreams

### Agent A: Shared Domain, Parsers, And Type Rejection

Owns:

- `packages/shared-ts/src/signing-lanes/records.ts`;
- new `packages/shared-ts/src/signing-lanes/recordParsers.ts`;
- new `packages/shared-ts/src/signing-lanes/execution.ts`;
- `packages/shared-ts/src/signing-lanes/index.ts`;
- dedicated signing-lane type fixtures and parser tests.

Delivers:

- strict builders and parsers for wallet keys, lane records, lane lifecycle,
  and active lane references;
- exhaustive prepared-execution branches using narrow admission-token
  identities rather than sdk-server domain types;
- unknown-field rejection and exact curve/branch parsing;
- type fixtures rejecting cross-curve key fields, agent keys as wallet keys,
  mandates inside lanes, delegated fields on owner lanes, and inactive lanes
  as prepared execution.

Agent A consumes the existing participant parsers and material-activation
parser. It does not edit `rotation.ts`, participant encoding, R103 device
policy, R104 authorization policy, server stores, or sdk-web hydration.

Agent gate:

```bash
pnpm -C packages/shared-ts type-check
pnpm -C tests exec playwright test -c playwright.lite.config.ts unit/signingLaneRecords.unit.test.ts
git diff --check
```

### Agent B: Gateway Store Projections

Owns:

- `packages/sdk-server-ts/src/core/signingLanes/*`;
- new `packages/sdk-server-ts/src/router/cloudflare/d1/signingLanes/*`;
- narrow read-only additions to `WalletStore.ts` and `d1WalletStore.ts` when an
  existing exact lookup is unavailable;
- dedicated D1 projection tests and fixtures.

Delivers:

- `WalletKeyStore` and `SigningLaneStore` implementations projected from
  canonical `wallet_signers` rows;
- deterministic owner wallet-key and lane identities;
- exact Ed25519 projection from registered key, active Yao capability,
  material activation, runtime scope, and participant facts;
- exact ECDSA projection from key handle/slot, threshold public identity,
  activation receipt, server generation, and participant facts;
- typed refusal for missing, corrupt, ambiguous, inactive, or binding-mismatched
  records;
- proof that projections persist no additional secret or capability material.

Agent B does not create a new lane table, a generic activation journal, a
protocol job, or a signing route. Existing curve-specific activation journals
remain authoritative and are reconciled by their current owners before a
record can project as active.

Agent gate:

```bash
pnpm -C packages/sdk-server-ts type-check
pnpm -C tests exec playwright test -c playwright.lite.config.ts unit/d1WalletExecutionLaneProjection.unit.test.ts
git diff --check
```

### Agent C: Browser Capability Hydration

Owns:

- `packages/sdk-web/src/core/signingEngine/session/lanes/*`;
- dedicated sdk-web type fixtures and hydration tests.

Delivers:

- one boundary parser for the server-projected wallet key and lane;
- Ed25519 owner-lane hydration through the canonical active Yao capability
  resolver;
- ECDSA owner-lane hydration through `ActiveEcdsaCapabilityManifest` and the
  existing activation-journal reconciliation path;
- exact comparison of wallet key, public identity, material activation,
  participant binding, share epoch, revocation epoch, and activation receipt;
- a precise active-owner-lane result consumed by signing, plus typed refusals
  for inactive, stale, missing, corrupt, or unsupported lanes.

Agent C does not persist Gateway records, mutate activation journals, edit
normal-signing flows, create R102 jobs, or enable linked/delegated branches.
It replaces the partial lane-reference parser with the shared boundary parser
instead of maintaining a second record shape.

Agent gate:

```bash
pnpm -C packages/sdk-web type-check
pnpm -C tests exec playwright test -c playwright.lite.config.ts unit/walletExecutionLaneHydration.unit.test.ts
git diff --check
```

### Agent D: Server Admission And Private-Worker Boundary

Owns:

- new `packages/sdk-server-ts/src/router/domains/signingLanes/*`;
- new `packages/sdk-server-ts/src/router/domains/signingOperations/walletExecutionAdmission.ts`;
- the narrow admission call sites in
  `routerAbPrivateSigningWorker.ts`, `thresholdEcdsa.ts`, and
  `thresholdEd25519.ts`;
- dedicated admission and zero-dispatch tests.

Delivers:

- construction of `PreparedOwnerWalletExecution` only after the R90
  `AuthorizedOperation` is claimed;
- exact active wallet-key/lane/material/participant/share/revocation checks
  before Router, Deriver, SigningWorker, Yao, or presignature work;
- typed refusal for every inactive or ambiguous lane and for linked-device or
  delegated lanes whose owning refactor has not supplied admission;
- a private-worker input containing only prepared execution evidence. Raw
  requests, JWTs, diagnostics, and persistence rows do not cross this seam;
- proof that denial performs zero private-worker or protocol dispatch.

Agent D does not implement lane provisioning, refresh, aggregate activation,
device sessions, agent identity, budgets, replay stores, or new Router wire
encodings. It exposes narrow adapter ports for R102–R104.

Agent gate:

```bash
pnpm -C packages/sdk-server-ts type-check
pnpm -C tests exec playwright test -c playwright.lite.config.ts unit/walletExecutionAdmission.unit.test.ts
git diff --check
```

## Integration Wave

The integrator merges Agent A, B, C, then D. File ownership makes the branches
independent; the order only ensures compile-time dependencies become available
before their consumers.

After the four merges, the integrator alone:

1. updates package barrels, Gateway dependency injection, and route assembly;
2. connects the browser owner-lane resolver to current owner signing flows;
3. connects Gateway admission to the store projection and existing R90 claim;
4. deletes duplicate lane-reference parsing and any dormant
   `delegated_agent` core shape with no remaining caller;
5. keeps R103/R104-owned intent and policy modules isolated until those
   refactors replace them;
6. updates or deletes stale fixtures according to their current invariant;
7. runs the broad validation once, rather than having every agent rebuild the
   full repository.

Conflict rules:

- only Agent A edits shared signing-lane contracts;
- only Agent B edits current signer-store read ports;
- only Agent C edits sdk-web lane hydration;
- only Agent D edits signing admission call sites;
- only the integrator edits central barrels, dependency injection, source
  guards, shared fixtures, and documentation;
- no agent rebases another agent's files or restores unrelated changes.

## R101 Completion Boundary

Implementation status:

- [x] Land strict shared wallet-key, lane, lifecycle, and active-reference parsers and type rejection.
- [x] Project current Ed25519 and ECDSA signer rows into exact owner wallet keys and lanes.
- [x] Hydrate both owner curves through their canonical browser capability paths with fail-closed checks.
- [x] Admit prepared owner execution only after the claimed operation and exact active lane agree.
- [x] Wire Gateway projection and server admission into the current owner normal-signing route.
- [x] Remove duplicate lane-reference and dormant `delegated_agent` core shapes.
- [x] Connect the browser owner-lane hydration result to the current owner signing-flow composition.
- [ ] Run and repair the full intended-behavior, source-guard, and wallet-iframe integration gates.

R101 is complete when existing owner passkey and Email OTP signer records:

1. project to exact curve-specific wallet keys and owner lanes;
2. hydrate through the current canonical capability and activation paths;
3. produce prepared owner execution only after authorization claim;
4. fail before private work for inactive, corrupt, stale, mismatched,
   linked-device, or delegated lanes;
5. preserve current public keys, addresses, signing behavior, recovery, export,
   and Wallet Session semantics.

R101 does not create, refresh, activate, or cryptographically revoke a lane.
R102 owns those protocols and receipts. R103 enables linked-device admission.
R104 enables delegated admission and replaces the remaining dormant agent
request/policy scaffolds.

## Validation

Static checks prove:

- agent identity keys cannot construct wallet-key records;
- wallet signing lanes cannot contain delegated mandates;
- delegated execution lanes require authorization, agent-key, and custody
  binding IDs;
- owner and linked-device lanes reject delegated-execution fields;
- inactive lanes cannot construct prepared execution;
- Ed25519 and ECDSA identities and participant bindings cannot be swapped;
- export admissions reject linked-device and delegated branches.

Focused tests prove:

- current Ed25519 and ECDSA signer records project to exact, stable wallet-key
  and owner-lane identities;
- projection refuses malformed receipts, public-identity disagreement,
  participant substitution, stale material activation, and duplicate lane
  identity;
- browser hydration accepts only the exact projected capability and current
  activation receipt;
- a claimed owner operation plus one exact active owner lane constructs
  `PreparedOwnerWalletExecution`;
- inactive, corrupt, linked-device, and delegated lanes perform zero private
  worker, Router, Yao, Deriver, SigningWorker, or presignature calls;
- Wallet Session expiry blocks owner admission while preserving lane material;
- recovery and export continue using their existing authorization branches;
- owner wallet public keys, EVM addresses, and current signing outputs remain
  unchanged by the projection cutover.

Integrator validation:

```bash
pnpm -C packages/shared-ts type-check
pnpm -C packages/sdk-server-ts type-check
pnpm -C packages/sdk-web type-check
pnpm test:intended
pnpm test:source-guards
pnpm test:wallet-iframe
git diff --check
```

The Google OIDC intended-behavior prerequisites must be configured before the
integration run. Environment failure is recorded separately from an R101
behavior failure.

## Non-Goals

- treating an agent key as a wallet key;
- transferring funds into an agent-owned wallet as the delegation mechanism;
- storing delegated policy inside a cryptographic lane;
- granting export or account administration through ordinary execution lanes;
- requiring every payment rail to use an MPC delegated-execution lane;
- defining agent UX, AP2 payloads, or device-link transport in this plan.

## Decisions Resolved For The R101 Foundation

- R101 selects no delegated execution topology. The branch remains typed and
  fail closed until R104 chooses and proves one.
- Existing owner signer rows project through
  `OwnerLaneParticipantContinuityV1`; no HPKE or custody identity is synthesized
  for those rows. `LaneHolderParticipantRecordV1` and
  `SigningWorkerParticipantRecordV1` remain required for independently
  provisioned linked-device and delegated lanes. R102 must reuse them.
- Mixed-key device authorization and aggregate ordering are R103 decisions.
  R101 models and resolves one exact wallet key per lane.
- Cryptographic revocation receipt encoding and post-compromise share refresh
  are R102 decisions. R101 persists and checks the product revocation epoch and
  verified receipt digest exposed by the canonical signer record.
- Existing `wallet_signers` records remain the first R101 persistence source.
  New lane tables require a demonstrated R102 multi-lane write path.

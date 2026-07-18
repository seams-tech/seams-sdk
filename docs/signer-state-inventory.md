# Signer State Inventory

Date: 2026-07-18

Status: diagnostic inventory of the current working tree. This document describes
the implementation as it exists during the active ECDSA role-local material
refactor.

Disposition: the canonical ECDSA capability manifest, persistence commit, flow
cutover, and `ThresholdEcdsaSessionRecordCore` deletion described here are now
owned by Refactor 90 Pre-Phase 4/19B. Refactor 90 Pre-Phase 4/19A owns the shared
MPC hydration outcome.

## Finding

The recurring failures come from split ownership of one logical signing
capability.

The code persists public key identity, authorization metadata, session policy,
sealed refresh data, encrypted role-local material, and hot worker state through
different stores. No single durable capability manifest binds those records
together. Registration, wallet unlock, and page refresh reconstruct the logical
state through different code paths, so each path can derive a different answer
for:

- which ECDSA key owns the operation;
- which target lane is current;
- which signing grant and threshold session are active;
- whether material is live, rehydratable, or requires reauthorization;
- which durable material reference belongs to the selected capability.

The repository already contains most of the intended concepts: exact lane
identity, canonical lane inventory, runtime validation, durable role-local
material, public reauthorization anchors, sealed recovery, and the new
`MpcCapabilityHydrationPlan`. Their composition remains record-shaped and
flow-specific.

## Intended Architecture

The active architecture document says:

1. page refresh is normal runtime loss;
2. worker memory is hot material only;
3. durable IndexedDB state is the recovery source of truth;
4. one exact lane is selected before restore, auth, budget, or signing;
5. every subsequent operation carries that same lane.

See:

- `docs/signing-session-architecture/README.md`
- `docs/signing-session-architecture/sealed-refresh.md`
- `docs/refactor-79-exact-signing-lane.md`

The implementation currently violates the composition part of those
invariants. Exact identity types exist, while discovery, material selection,
and lifecycle restoration still reconstruct authority independently.

## Identity Cardinality

Several identities have different cardinalities and lifetimes.

| Identity | Cardinality | Lifetime | Current risk |
| --- | --- | --- | --- |
| wallet | one profile | durable | repeated in several records |
| EVM-family ECDSA key | one shared key across supported EVM-family targets | durable | copied into per-target session records |
| target membership | one membership per chain target | durable/configured | inferred from copied key records |
| auth authority | one registered holder binding | durable until signer change | mixed with active session credentials |
| signing grant | one server-authorized policy/budget scope | session | ranked or superseded after discovery |
| threshold session | one active cryptographic session | session | mixed with durable key facts |
| material owner | one role-local key-material owner | key/session dependent | represented through optional handle, ref, or ready record |
| runtime handle | one worker-local handle | worker lifetime | sometimes treated as lane readiness |
| durable material reference | one pointer to encrypted worker material | session/material lifetime | can disappear with runtime records |
| exact lane | key + target + auth + grant + threshold session | operation/session | selected separately from material in some flows |

The shared EVM-family key is the clearest mismatch. The key is family-wide.
Target membership, policy scope, nonce scope, and operation lane can be
target-specific. A per-target record currently carries both kinds of facts.
Availability can then project a session from one target into another based on
the shared key:

- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:2563`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:2578`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:2614`

That projection copies `signingGrantId` and `thresholdSessionId`. The model
needs an explicit server-authorized capability scope before this copy is safe:

```ts
type EcdsaCapabilityScope =
  | {
      kind: 'evm_family';
      targetMemberships: readonly [
        ThresholdEcdsaChainTarget,
        ...ThresholdEcdsaChainTarget[],
      ];
      target?: never;
    }
  | {
      kind: 'exact_target';
      target: ThresholdEcdsaChainTarget;
      targetMemberships?: never;
    };
```

## Persistence Inventory

### Public account and signer identity

`persistThresholdEcdsaBootstrapForWalletTarget` writes profile and account
signer data:

- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence.ts:90`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence.ts:208`

This record contains durable public key facts and target membership. It does
not contain the active threshold-session capability or the durable encrypted
material reference.

### Runtime threshold-session records

The signing runtime creates fresh maps:

- `packages/sdk-web/src/core/runtime/createSigningRuntime.ts:23`

`recordsByLane` and the module-level ECDSA record index are runtime state. A
page refresh recreates them.

`storeThresholdEcdsaSessionFact` removes the volatile worker handle before
writing to `recordsByLane`, retains the durable material reference, and keeps a
full copy in another in-memory map:

- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts:3222`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts:3235`

The name `durableThresholdEcdsaSessionRecord` describes the shape of the value.
The destination remains a `Map`, so the descriptor does not survive a page
refresh.

### Browser role-local ready records

The browser platform can persist an `EcdsaRoleLocalReadyRecord` through the
general app-state IndexedDB store:

- `packages/sdk-web/src/core/platform/browser/createBrowserPlatformRuntime.ts:290`
- `packages/sdk-web/src/core/platform/browser/createBrowserPlatformRuntime.ts:350`

The common passkey provisioning path requires and persists this record:

- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts:616`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts:635`

The current registration worker-handle path produces no
`ecdsaRoleLocalReadyRecord`. Registration therefore bypasses the durable record
used by the older sealed-recovery path:

- `tests/unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts:440`
- `tests/unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts:454`

### Encrypted worker material

The ECDSA derivation worker stores the finalized role-local state blob in its
own IndexedDB database:

- database: `seams_router_ab_ecdsa_role_local_session_v1`
- object store: `active_material`
- primary key: `durableMaterialRef`

See:

- `packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsaRoleLocalSessionMaterialStore.ts:1`
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsaRoleLocalSessionMaterialStore.ts:65`
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsaRoleLocalSessionMaterialStore.ts:220`

Registration finalization writes the encrypted record and publishes a hot
worker handle:

- `packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-derivation-client.worker.ts:555`
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-derivation-client.worker.ts:633`
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-derivation-client.worker.ts:644`

Rehydration requires all of:

- `materialHandle`;
- `durableMaterialRef`;
- `expectedBindingDigest`.

See:

- `packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-derivation-client.worker.ts:1244`

The encrypted material can therefore survive while its addressing descriptor
is lost.

### Sealed signing-session records

The sealed-session repository persists refresh records in IndexedDB. A full
sealed record can contain the recovery artifact and exact session metadata.

The current registration path persists an ECDSA public reauthorization anchor:

- `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions.ts:260`
- `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions.ts:274`
- `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts:2401`

The anchor type explicitly excludes secrets, sealed material, and runtime
state:

- `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts:139`
- `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts:161`

It also omits `roleLocalDurableMaterialRef` and the role-local binding digest.
It can support fresh reauthorization. It cannot address the encrypted
role-local material by itself.

### Server authority

The server owns current grant validity, expiry, remaining budget, route
authority, and revocation. Browser records are hints until checked against this
authority.

The active capability manifest therefore needs a server-issued generation and
an exact policy scope. Local timestamps and source priority cannot establish
authority.

## Current Record Shape

`ThresholdEcdsaSessionRecordCore` combines durable key identity, auth authority,
active session authority, budget, public facts, volatile worker handles,
durable material references, ready records, seal parameters, and provenance:

- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts:142`

Many lifecycle-bearing fields remain optional. Examples include:

- `roleLocalMaterialHandle`;
- `roleLocalDurableMaterialRef`;
- `ecdsaRoleLocalReadyRecord`;
- `runtimePolicyScope`;
- `routerAbEcdsaDerivationNormalSigning`;
- `walletSessionJwt`;
- seal parameters;
- verified public facts.

The code recovers lifecycle state from field presence. This allows combinations
such as:

- an active grant with no live or durable material;
- durable material with no durable manifest that points to it;
- a ready record for one lifecycle branch and a worker handle for another;
- a public reauth anchor classified as restorable;
- copied shared-key identity carrying a target session whose scope is implicit.

Auth method is also derived through two independent fields. Record source
determines the top-level auth method, while `ecdsaRoleLocalAuthMethod.kind`
describes the material owner:

- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts:543`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts:552`

The passkey-source type does not statically require passkey role-local auth.
Core helpers discover that mismatch by throwing.

Unknown or missing persisted `source` values normalize to `manual-bootstrap`:

- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts:1414`

Because source later participates in material priority, malformed boundary data
can change an authority-bearing choice.

`buildOperationUsableThresholdEcdsaSessionRecord` brands a record after checking
session id, grant id, JWT presence, remaining uses, and generation:

- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts:3183`

It does not prove coherent material residency, exact material binding, runtime
validation, or current expiry. The branded result overstates the guarantee.

## Lifecycle Traces

### After registration

Current passkey ECDSA registration:

1. finalizes and encrypts role-local material in the derivation worker;
2. persists public account/signer identity per target;
3. commits a full runtime record to an in-memory session store;
4. marks the worker handle runtime-validated;
5. persists a public reauthorization anchor.

See:

- `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions.ts:201`

Immediate signing works because the runtime record and worker handle are live.
The durable worker bytes and public reauth anchor do not form one rehydratable
capability record.

### After wallet unlock

Unlock reconstructs canonical public ECDSA key facts from account signer
records, runtime records, and authenticated inventory where needed. It then
plans and provisions warm sessions through passkey/session provisioning.

Relevant entry points include:

- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts:3098`
- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts:3236`
- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts:3264`
- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts:3385`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts:635`

This path persists a role-local ready record and may persist a sealed session.
It reaches sign-ready state through a different orchestration and persistence
sequence from registration.

There are two additional ownership gaps inside unlock:

1. `resolvePersistedEcdsaPublicCapabilityForLogin` reads the supposedly
   persisted public capability from runtime threshold-session records and picks
   the newest candidate:
   - `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts:2201`
   - `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts:2720`
2. Profile-continuity warmup planning is invoked with
   `localSessionRecords: []`, even though durable local role-material records
   may exist:
   - `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts:3436`

Unlock also creates a fresh threshold session per configured target:

- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts:2704`

Seal persistence is mandatory only for reconnect requests. A fresh unlock can
finish successfully when seal persistence is unavailable:

- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts:641`
- `packages/sdk-web/src/core/signingEngine/session/passkey/runtime.ts:22`

This creates a valid `ready` state whose refresh recovery postcondition is
weaker than the reconnect path.

### After page refresh

Refresh clears:

- runtime `recordsByLane`;
- module-level record maps;
- hot worker material maps;
- runtime validation observations.

Refresh can retain:

- public account/signer identity;
- sealed-session records or public reauth anchors;
- role-local ready records when a path wrote them;
- encrypted worker material.

The available-lane reader merges durable sealed records, public reauth anchors,
runtime records, status advisories, and shared-key projections:

- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:2727`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:2810`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:2863`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:3099`

A live public reauth anchor is mapped to `state: 'restorable'`:

- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:1296`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:1361`

A full sealed recovery record is also mapped to `state: 'restorable'`:

- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:1373`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:1465`

Those states have different next transitions:

- sealed material can be rehydrated without a new user authorization while the
  grant remains valid;
- a public anchor requires a fresh authorization ceremony;
- encrypted role-local material requires its exact durable ref and binding
  digest.

The single `restorable` label hides these distinctions.

## Lane Selection

Availability builds a lane candidate first. EVM-family signing then separately:

1. constructs a resolved lane from the candidate;
2. searches for an exact session record;
3. enumerates visible passkey material by provenance source;
4. resolves Email OTP authority separately;
5. selects material;
6. commits a lane/material/authority combination;
7. resolves wallet auth.

See:

- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts:1413`

Passkey material enumeration uses this priority:

```text
login
manual-bootstrap
registration
```

See:

- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts:87`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts:965`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts:1028`

The source lookup catches every error and converts it to an absent candidate:

- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts:428`

Duplicate or ambiguous authority can therefore enter the fallback path as
“missing,” allowing another provenance source to win.

The selected availability candidate no longer carries the original
branch-specific storage semantics. Rebuilding the exact lane fills them with
constants:

- passkey `storageSource: 'manual-bootstrap'`;
- Email OTP `retention: 'session'`;
- Email OTP `sessionOrigin: 'per_operation'`.

See:

- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts:538`

Lifecycle provenance is therefore influencing an authority-bearing material
decision. Registration and unlock naturally produce different source labels,
so the selected material can change after a transition even when the durable
key identity is unchanged.

Availability also applies source priority and stable tie breaks during
canonicalization:

- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:2370`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts:2413`

This contradicts the exact-lane design in
`docs/refactor-79-exact-signing-lane.md`, which requires ambiguity to fail
closed instead of ranking candidates.

## Root Causes

### 1. No durable capability manifest

The encrypted material, its addressing descriptor, exact session authority,
and public signer identity are committed through separate owners. A successful
write in one store does not imply a usable capability after runtime loss.

### 2. Lifecycle state is inferred from optional fields

The aggregate record permits incomplete and mixed lifecycle combinations.
Classifiers and runtime assertions recover intent later.

### 3. Entry points implement the same transition independently

Registration, wallet unlock, sealed recovery, and page refresh each implement a
version of “make this signer sign-ready.” Their persistence steps and
postconditions differ.

### 4. `restorable` combines rehydration and reauthorization

The state name does not identify the required authority or material. Code must
inspect record source and optional data to choose the next action.

### 5. Lane identity and material are selected through separate searches

The selected candidate, exact record, visible material, and auth authority can
come from separate derivations. Validation detects some drift after selection.

### 6. Provenance participates in authority selection

`registration`, `login`, and `manual-bootstrap` describe how a capability was
created. Current priority lists use those values to choose material.

Boundary normalization can also invent `manual-bootstrap` provenance for an
unknown source, and source lookup failures are swallowed as absence.

### 7. Shared key identity and target capability scope are implicit

One EVM-family key is copied into target records. Missing targets are synthesized
from a sibling lane while grant/session scope is carried along.

### 8. Tests emphasize adapters and final scenarios

The intended-behaviour browser contracts cover registration, unlock, refresh,
step-up, export, Tempo, and Arc/EVM. Many unit tests begin with hand-built
records or an in-memory `recordsByLane` map. Few tests exercise this complete
boundary:

```text
registration/unlock commit
  -> all durable stores
  -> destroy page runtime and worker
  -> reconstruct from durable state
  -> rehydrate worker material
  -> select one exact lane
  -> sign with that same lane
```

Examples:

- `tests/e2e/intended-behaviours/passkey.registration.contract.test.ts`
- `tests/e2e/intended-behaviours/passkey.unlock.contract.test.ts`
- `tests/unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts:382`
- `tests/unit/runtimePostconditions.unit.test.ts:338`
- `tests/unit/ecdsaSelection.restorable.unit.test.ts:503`

The browser contracts discover cross-store failures late because no lower-level
transition contract owns the whole chain.

## Canonical Target Model

Use several linked aggregates with one durable active-capability manifest.

### Registered signer

```ts
type RegisteredEvmFamilySigner = {
  kind: 'registered_evm_family_signer';
  key: EvmFamilyEcdsaKeyIdentity;
  auth: SigningLaneAuthBinding;
  targetMemberships: readonly [
    ThresholdEcdsaChainTarget,
    ...ThresholdEcdsaChainTarget[],
  ];
  registeredPublicKey: VerifiedEcdsaPublicFacts;
};
```

This is durable public identity. It contains no active grant, bearer
credential, worker handle, quota, or nonce.

### Material residency

```ts
type EcdsaMaterialResidency =
  | {
      kind: 'absent';
      durable?: never;
      runtime?: never;
    }
  | {
      kind: 'durable';
      durable: {
        ref: EcdsaRoleLocalDurableMaterialRef;
        bindingDigest: EcdsaRoleLocalBindingDigest;
      };
      runtime?: never;
    }
  | {
      kind: 'live';
      durable: {
        ref: EcdsaRoleLocalDurableMaterialRef;
        bindingDigest: EcdsaRoleLocalBindingDigest;
      };
      runtime: {
        handle: EcdsaRoleLocalMaterialHandle;
        validatedForCapability: CapabilityInstanceRef;
      };
    };
```

Live material carries its durable identity. Refresh then has one unambiguous
downgrade:

```text
live -> durable
```

### Active capability manifest

```ts
type ActiveEcdsaCapabilityManifest = {
  kind: 'active_ecdsa_capability';
  capability: CapabilityInstanceRef;
  signer: RegisteredEvmFamilySigner;
  scope: EcdsaCapabilityScope;
  authority: WalletAuthAuthority;
  policy: {
    signingGrantId: SigningGrantId;
    thresholdSessionId: ThresholdEcdsaSessionId;
    serverGeneration: ServerIssuedGeneration;
    remainingUses: PositiveInteger;
    expiresAtMs: FutureTimestamp;
  };
  material: Extract<EcdsaMaterialResidency, { kind: 'durable' | 'live' }>;
};
```

Every field required to address, authenticate, and validate the active
capability is present. Persistence-boundary parsers produce this type. Core
signing receives it directly.

### Hydration plan

The current working tree already has the right high-level union:

- `packages/sdk-web/src/core/signingEngine/capability/mpcCapabilityHydration.ts:80`
- `packages/sdk-web/src/core/signingEngine/capability/mpcCapabilityHydration.ts:116`
- `packages/sdk-web/src/core/signingEngine/capability/mpcCapabilityHydration.ts:129`
- `packages/sdk-web/src/core/signingEngine/capability/mpcCapabilityHydration.ts:142`
- `packages/sdk-web/src/core/signingEngine/capability/mpcCapabilityHydration.ts:155`

Its branches are:

```text
use_live_runtime
rehydrate_active_session
reauthorize_public_anchor
blocked
```

Adopt this union as the common outcome for registration, wallet unlock, and
page refresh. Keep the entry point as provenance only. The same durable facts
must resolve to the same plan regardless of entry point.

## Canonical Transitions

| Input state | Event | Required data | Output |
| --- | --- | --- | --- |
| registration activation prepared | activation committed | registered signer, server capability, durable material write | active live capability |
| active live capability | page runtime destroyed | durable manifest and encrypted material remain | active durable capability |
| active durable capability | hydrate | exact ref, binding digest, active server policy | active live capability |
| registered public anchor | authorize | fresh holder auth and new server capability | active live capability |
| active capability | budget exhausted | trusted server budget result | retired public anchor |
| active capability | expired/revoked | trusted server result | retired public anchor |
| any | binding mismatch/corrupt persistence | exact failed read | blocked plus cleanup command |
| multiple current manifests | discovery | same logical capability group | blocked ambiguous authority |

Required transition functions:

```ts
commitRegistrationActivation(...)
commitWalletUnlockActivation(...)
readPersistedCapabilityManifest(...)
planCapabilityHydration(...)
rehydrateCapabilityMaterial(...)
reauthorizeCapability(...)
selectExactOperationLane(...)
retireCapability(...)
```

Registration and unlock may have different inputs. They must call the same
capability commit and runtime publication boundaries.

## Persistence Commit

Prefer one IndexedDB database with separate object stores and one transaction:

```text
registered_signers
active_capability_manifests
role_local_material
sealed_session_artifacts
commit_journal
```

If the worker material must remain in a separate database, use an explicit
two-phase journal:

1. write encrypted material as `prepared`;
2. write the exact capability manifest that references it;
3. mark both records `committed`;
4. publish runtime state;
5. garbage-collect orphaned prepared material after failure or timeout.

Runtime publication is the final step. Readers ignore prepared and partial
records.

## Selection Invariants

1. Source provenance never chooses authority or material.
2. A selected operation lane carries one `CapabilityInstanceRef`.
3. Material resolution accepts that exact capability ref.
4. Auth planning accepts that exact capability ref.
5. Budget admission accepts that exact capability ref and server generation.
6. Signing accepts only a lane whose runtime material was validated for that
   same capability ref.
7. Shared-target projection requires explicit capability scope.
8. Ambiguous current manifests fail closed at the persistence boundary.
9. Diagnostics never influence control flow.
10. Page refresh removes runtime state and preserves the active durable
    capability state.

## Audit Sequence

### Phase 1: freeze the model

- finish the capability manifest and hydration unions;
- add branded IDs and boundary builders;
- add `@ts-expect-error` fixtures for mixed material states, public anchors with
  secrets, live state without durable identity, and raw string identity;
- define exact server generation and capability scope.

### Phase 2: establish one persistence owner

- inventory every write to session maps, role-local ready records, worker
  material, sealed records, and account signer metadata;
- route active-capability writes through one commit API;
- persist the material ref and binding digest beside exact capability identity;
- add failure injection after each write.

### Phase 3: unify transitions

- route registration and unlock through the same capability commit;
- route unlock and refresh through the same hydration planner;
- publish runtime state only from a committed manifest;
- delete flow-specific state derivation after replacement.

### Phase 4: make exact selection terminal

- select one exact capability before material/auth resolution;
- pass it through restore, auth, budget, signing, and finalization;
- delete source-priority material selection;
- reject ambiguous current manifests at read boundaries;
- constrain shared EVM-family projection with explicit capability scope.

### Phase 5: transition matrix tests

Cover:

- passkey and Email OTP;
- registration, unlock, and page refresh;
- live, durable, public-anchor-only, missing, corrupt, expired, exhausted, and
  revoked material/capability states;
- one target and multi-target EVM-family configurations;
- runtime destruction and worker recreation;
- failures after every persistence commit step;
- exact lane continuity through auth, budget, signing, and finalization.

The key property:

```text
same durable snapshot + same server authority
  => same hydration plan and exact lane
```

Entry-point provenance must not change that result.

# Session Re-Architecture: PRF Cache, Sealed Refresh, and Threshold Session State

Last updated: 2026-04-10
Status: proposed

## 1. Why this refactor is needed

The current threshold session system is failing in a predictable way. The recurring bugs around missing PRFs, missing session auth, refresh drift, and ECDSA reconnect are not isolated mistakes. They are a consequence of an architecture with too many overlapping state holders and too many partial abstractions.

Today, warm-session truth is split across multiple places:

1. `activeSigningSessionIds` in `api/session/signingSessionState.ts`
2. canonical threshold session records in `api/thresholdLifecycle/thresholdSessionStore.ts`
3. worker PRF cache state in `touchConfirm`
4. sealed refresh records in `api/session/prfSessionSealedStore.ts`

That split creates structural failure modes:

1. the app believes a session exists, but the worker no longer has usable PRF material
2. the worker can restore from sealed state, but callers need to know which operation triggers restore
3. ECDSA readiness depends on implicit Ed25519 behavior that is not obvious from the call site
4. raw session ids leak through the system and become cross-layer routing keys
5. each flow accumulates local repair logic because no layer is actually authoritative

The result is an architecture that is hard to explain, hard to test, and easy to regress during refactors.

This redesign should not be constrained by minimal diff size. We should design the cleanest system we would want to maintain two years from now, then refactor toward that target decisively.

## 2. Design principles

These are the design principles this rewrite should optimize for.

1. One owner: exactly one runtime component owns warm threshold state.
2. One model: PRF lifecycle, capability auth, and persistence must be represented in one coherent state model.
3. Capability-first API: flows ask for `ed25519` or `ecdsa` capability readiness, not session-id plumbing.
4. No cache verbs in business logic: `peek`, `dispense`, `transfer`, and similar operations are implementation details.
5. Persistence is subordinate to runtime state: sealed refresh exists to support the warm-session model, not define it.
6. Explicit failure semantics: every flow gets the same normalized readiness and failure outcomes.
7. No drift repair by convention: the architecture should make state divergence difficult, not merely detectable.
8. Delete old paths: transitional adapters are acceptable only while migrating, not as a steady-state design.
9. Future signer families should plug into the same model without creating parallel systems.
10. The design should be understandable from the top down without reading worker internals.

## 3. Non-goals

1. Preserving existing helper APIs for convenience.
2. Keeping compatibility with duplicate planners or duplicate stores.
3. Optimizing for minimal code churn.
4. Keeping session-id-centric flow logic.
5. Letting signing or export flows perform their own PRF/session recovery.

## 4. Current architecture problems

### 4.1 Multiple local sources of truth

Warm readiness is currently inferred from a mix of:

1. an in-memory active map
2. one or more persisted session records
3. worker cache state
4. sealed blob presence

That means "session exists" and "session is usable" are different facts maintained by different systems. They inevitably drift.

### 4.2 PRF is modeled as a cache, not as a lease owned by a warm session

The code talks about PRF cache operations:

1. `putPrfFirstForThresholdSession`
2. `peekPrfFirstForThresholdSession`
3. `dispensePrfFirstForThresholdSession`
4. `transferPrfFirstForThresholdSession`
5. `clearPrfFirstForThresholdSession`

That API surface is too low-level. Callers should not reason in terms of cache verbs. They should reason in terms of warm-session semantics:

1. ensure the account has usable warm state for capability X
2. consume one authorized use from the warm session
3. get the capability auth material required to finish the operation

### 4.3 Rehydrate semantics are asymmetric and leaky

The current system makes `peek` special because it can trigger restore. That means higher-level code needs to know which primitive is safe to call first. That is the wrong abstraction boundary.

### 4.4 ECDSA is under-modeled

ECDSA currently behaves like a feature layered on top of existing session machinery rather than a first-class capability in the model. That leads to confusing behavior:

1. login derives ECDSA readiness indirectly
2. reconnect can be hidden in unrelated flows
3. export and signing do not clearly share the same readiness contract

### 4.5 Session ids are over-exposed

`thresholdSessionId` should be an internal capability-auth detail, not a primary application-facing handle. Once the rest of the system starts routing behavior through raw session ids, state repair logic spreads everywhere.

## 5. Proposed target architecture

### 5.1 High-level direction

The clean redesign is:

1. one account-scoped `WarmSessionManager`
2. one canonical persisted `WarmThresholdSessionEnvelope`
3. one worker-side `PrfLeaseStore` that only the manager talks to
4. one capability provisioner layer for `ed25519`, `ecdsa`, and future signer families

Everything else becomes a consumer of that system.

Signing flows, export flows, login warm-up, and explicit reconnect should all use the same manager.

### 5.2 Core idea: one warm envelope per account

The cleanest local model is not "many session ids with helper lookups." The cleanest local model is one account-scoped warm envelope.

Suggested shape:

```ts
export type ThresholdCapability = 'ed25519' | 'ecdsa';

export type WarmThresholdSessionEnvelope = {
  accountId: AccountId;
  warmSessionId: string;
  prfLease: PrfLeaseState;
  capabilities: Partial<Record<ThresholdCapability, WarmCapabilityState>>;
  version: 1;
  updatedAtMs: number;
};

export type PrfLeaseState = {
  state: 'missing' | 'warm' | 'sealed_only' | 'expired' | 'exhausted';
  expiresAtMs: number | null;
  remainingUses: number | null;
  persistence: 'none' | 'sealed_refresh_v1';
};

export type WarmCapabilityState = {
  state: 'missing' | 'provisioning' | 'ready' | 'stale' | 'expired';
  auth: ThresholdCapabilityAuthMaterial | null;
};
```

Important points:

1. `warmSessionId` is the local runtime handle, not the external product API.
2. capability auth records may contain server-issued session ids internally.
3. the envelope is the only local source of truth for warm-session state.
4. if the envelope is inconsistent with worker state or sealed state, the manager owns repair or invalidation.

### 5.3 What gets deleted conceptually

This redesign assumes these ideas are removed from the steady-state model:

1. active session map as a flow-facing source of truth
2. direct caller access to PRF cache verbs
3. flow-local fallback lookup against canonical session stores
4. session-id transfer as a normal operation
5. separate readiness logic for signing versus export
6. per-chain session planners with overlapping responsibilities

### 5.4 Layering

#### Layer A: `WarmSessionManager`

Responsibilities:

1. load and persist the envelope
2. answer readiness questions
3. restore PRF from sealed persistence when allowed
4. consume PRF lease uses atomically
5. resolve capability auth material
6. clear, invalidate, or reprovision inconsistent state
7. normalize errors

This is the only component that the rest of the system should call.

#### Layer B: `ThresholdCapabilityProvisioner`

Responsibilities:

1. create or reconnect `ed25519` capability state
2. create or reconnect `ecdsa` capability state
3. take WebAuthn/PRF input when required
4. produce canonical capability auth records
5. update the envelope only through the manager boundary

This layer replaces the current split between workflow helpers and ad hoc session-record handling.

#### Layer C: `PrfLeaseStore` inside the worker boundary

Responsibilities:

1. hold plaintext PRF only in worker memory
2. seal and unseal when persistence mode requires it
3. expose semantic lease operations to the manager

The worker should not present itself to core code as a general-purpose PRF cache. It is a lease store behind a manager boundary.

## 6. Public API after refactor

Suggested manager API:

```ts
export type EnsureWarmSessionArgs = {
  accountId: AccountId;
  capabilities: ThresholdCapability[];
  reason: 'login' | 'explicit_reconnect' | 'sign' | 'export';
};

export type EnsureCapabilityArgs = {
  accountId: AccountId;
  capability: ThresholdCapability;
  reason: 'sign' | 'export' | 'explicit_reconnect';
};

export type ConsumePrfLeaseArgs = {
  accountId: AccountId;
  capability: ThresholdCapability;
  uses?: number;
  reason: 'sign' | 'export';
};

interface WarmSessionManager {
  getStatus(accountId: AccountId): Promise<WarmThresholdSessionEnvelope | null>;
  ensureWarmSession(args: EnsureWarmSessionArgs): Promise<WarmThresholdSessionEnvelope>;
  ensureCapabilityReady(args: EnsureCapabilityArgs): Promise<WarmCapabilityState>;
  consumePrfLease(args: ConsumePrfLeaseArgs): Promise<{
    prfFirstB64u: string;
    envelope: WarmThresholdSessionEnvelope;
  }>;
  clear(accountId: AccountId): Promise<void>;
  clearAll(): Promise<void>;
}
```

Rules:

1. flows call `ensureCapabilityReady` and `consumePrfLease`
2. flows do not call low-level PRF methods directly
3. flows do not inspect or repair session ids directly
4. the manager decides whether to restore, reprovision, fail closed, or require explicit reconnect

## 7. Runtime state model

The system should be described with one explicit state machine.

### 7.1 Envelope state

```text
missing
  -> provisioning
  -> warm
  -> sealed_only
  -> expired
  -> exhausted
  -> invalid
  -> clearing
```

### 7.2 Capability state

```text
missing
  -> provisioning
  -> ready
  -> stale
  -> expired
  -> invalid
  -> clearing
```

### 7.3 State rules

1. `warm` means plaintext PRF is in worker memory and lease metadata is current.
2. `sealed_only` means plaintext PRF is absent but a sealed record may restore it.
3. `expired` and `exhausted` are terminal for the current envelope.
4. capability `ready` is valid only if capability auth is valid and PRF lease is usable.
5. if capability auth exists but PRF lease does not, the envelope is `invalid` until repaired or cleared.
6. if PRF lease exists but capability auth is missing, the manager may provision only the missing capability.
7. no flow is allowed to interpret an `invalid` state on its own.

## 8. Persistence model

Persist one envelope per account. Everything else is subordinate to that envelope.

### 8.1 Canonical local records

1. `WarmThresholdSessionEnvelopeStore`
   - one record per account
   - capability auth subrecords
   - TTL/use metadata
   - persistence mode and timestamps
2. `PrfSealedStore`
   - optional sealed payload only
   - keyed by `warmSessionId`
3. `PrfLeaseStore`
   - worker memory only
   - keyed by `warmSessionId`

### 8.2 Persistence rules

1. the envelope is the only persisted session model the app reasons about
2. sealed PRF is a subordinate persistence artifact
3. worker memory is not considered authoritative without envelope agreement
4. no active-map restoration path should exist after migration
5. no second session index should be necessary to answer readiness questions

## 9. Error model

The manager should expose a small normalized failure family.

Suggested codes:

1. `warm_session_missing`
2. `warm_session_expired`
3. `warm_session_exhausted`
4. `warm_session_invalid`
5. `warm_session_restore_failed`
6. `capability_not_ready`
7. `explicit_reconnect_required`
8. `user_cancelled`
9. `internal_session_error`

Rules:

1. worker-specific cache errors are internal details
2. UI and chain flows should not talk about `peek`, `dispense`, or raw worker failures
3. export and signing should surface the same error family for the same readiness conditions

## 10. Strong recommendations

These are the design choices I recommend unless we find a concrete reason not to.

### 10.1 Replace session-id-centric flow logic with capability-centric flow logic

Recommendation: yes.

Reasoning:

1. it matches what callers actually need
2. it shrinks the API surface
3. it prevents flow-local session repair logic
4. it makes ECDSA export and signing naturally share the same path

### 10.2 Keep exactly one local warm envelope per account

Recommendation: yes.

Reasoning:

1. this is the cleanest mental model
2. it eliminates the need for active-pointer restoration
3. it reduces drift opportunities dramatically

### 10.3 Treat sealed refresh as a storage strategy, not a session mode

Recommendation: yes.

Reasoning:

1. persistence strategy should not redefine the warm-session model
2. the app should ask "is the warm session usable", not "which persistence mode am I in"

### 10.4 Make export and signing use the exact same readiness path

Recommendation: yes.

Reasoning:

1. they are consuming the same underlying security state
2. separate readiness paths will drift again

### 10.5 Remove direct flow access to worker PRF operations entirely

Recommendation: yes.

Reasoning:

1. the current architecture breaks because the cache abstraction leaked upward
2. workers should expose semantic lease operations through the manager, not generic cache primitives

## 11. Debate points

These are the main design decisions worth debating before implementation.

### 11.1 One warm envelope per account, or one per capability?

My recommendation: one warm envelope per account.

Why I lean this way:

1. there is one shared PRF lease source
2. the user experience is account-unlock oriented, not capability-unlock oriented
3. multiple envelopes would reintroduce coordination and drift problems

Reasonable counterargument:

1. if `ed25519` and `ecdsa` diverge heavily in policy or lifecycle, separate envelopes could reduce coupling

Current judgment:

1. use one account envelope with capability sub-state unless we discover a hard protocol reason not to

### 11.2 Should `ecdsa` remain derived from Ed25519 login warm-up, or should both capabilities be provisioned independently?

My recommendation: keep one WebAuthn-derived PRF source, but model both capabilities independently in the envelope.

Why:

1. the cryptographic source can be shared without sharing the capability state machine
2. this removes hidden dependency semantics from business logic
3. the model stays extensible for future signer families

Uncertainty:

1. we should confirm whether there is any server or protocol assumption that still requires ECDSA to be represented as a derivative of Ed25519 session auth rather than a sibling capability

### 11.3 Should the manager auto-reconnect on demand, or require explicit reconnect for all missing capability auth?

My recommendation: be strict.

1. restore from sealed state can be automatic because it is local continuity of the same warm session
2. provisioning new capability auth should require an explicit manager-owned reconnect path, not hidden transaction-time bootstrap

Why:

1. this keeps user-consent semantics and security boundaries clear
2. hidden reconnect logic is how we got local patches spread across flows

Open question:

1. do we want a manager API that can be called from a post-confirmation reconnect step in the same flow, or do we want reconnect to always be a distinct user action before the flow starts?

### 11.4 Should the manager own capability auth persistence too, or merely reference external stores?

My recommendation: the manager should own it.

Why:

1. otherwise we still have split truth
2. external session stores can remain as implementation modules, but not as separate authoritative models

### 11.5 Should the worker know about capabilities, or only about PRF lease state?

My recommendation: keep capability semantics in the manager, not in the worker.

Why:

1. the worker should stay narrowly focused on secure PRF handling
2. capability auth is orchestration state, not worker state

### 11.6 Should we keep session ids visible anywhere above the manager boundary?

My recommendation: no, except for specialized diagnostics and internal auth payload construction.

Why:

1. exposing raw session ids is what turned them into routing keys for unrelated code
2. it is not the right abstraction for signing and export flows

## 12. Points of uncertainty

These are the areas where I think we need one more design pass before implementation.

1. Capability auth shape:
   We should define exactly what `ThresholdCapabilityAuthMaterial` contains for `ed25519` and `ecdsa`, and which fields are truly canonical versus derivable.

2. Envelope invalidation policy:
   If one capability becomes invalid, do we invalidate only that capability, or the whole envelope? My current leaning is: invalidate the capability first, invalidate the full envelope only when PRF lease state is compromised.

3. Multi-tab semantics:
   Same-tab refresh is clear. Cross-tab behavior needs a clean policy. My leaning is to keep the envelope account-scoped but treat worker plaintext PRF as tab-local, with sealed restore re-establishing continuity where allowed.

4. Atomicity boundaries:
   We should be explicit about which operations are atomic at the manager layer, especially `consumePrfLease` plus envelope policy updates.

5. Provisioning ownership:
   We should confirm whether login warm-up always provisions both capabilities by default, or whether capability provisioning should become configurable at the manager boundary.

6. Telemetry model:
   We should decide which state transitions deserve structured telemetry so regressions become obvious without leaking sensitive material.

## 13. File-level refactor plan

### 13.1 New modules to introduce

1. `client/src/core/signingEngine/session/WarmSessionManager.ts`
2. `client/src/core/signingEngine/session/warmSessionTypes.ts`
3. `client/src/core/signingEngine/session/warmSessionStore.ts`
4. `client/src/core/signingEngine/session/thresholdCapabilityProvisioner.ts`
5. `client/src/core/signingEngine/session/prfLeaseWorkerPort.ts`

### 13.2 Existing modules to simplify, absorb, or delete

1. `client/src/core/signingEngine/api/session/signingSessionState.ts`
   - shrink heavily or delete
2. `client/src/core/signingEngine/api/session/prfSessionSealedStore.ts`
   - keep only as a persistence implementation detail
3. `client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.ts`
   - absorb into manager-owned persistence or reduce to internal serializer helpers
4. `client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts`
   - remove flow-facing cache-verb surface
5. `client/src/core/signingEngine/threshold/workflows/connectEd25519Session.ts`
   - convert into a capability provisioner primitive
6. `client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts`
   - convert into a capability provisioner primitive
7. `client/src/core/signingEngine/SigningEngine.ts`
   - remove PRF/session repair responsibilities

### 13.3 APIs to delete

1. `transferPrfFirstForThresholdSession`
2. caller-visible `peekPrfFirstForThresholdSession`
3. caller-visible `dispensePrfFirstForThresholdSession`
4. `activeSigningSessionIds` as a public source of truth
5. any flow-local reconnect helper that exists only to compensate for state drift

## 14. Implementation plan

### Phase 1: Freeze behavior with tests

Goal: define the desired semantics first.

Tasks:

1. add manager-level lifecycle tests for warm, sealed-only, expired, exhausted, invalid, and cleared states
2. add cross-flow tests for NEAR signing, EVM signing, Tempo signing, and ECDSA export
3. assert that all flows surface the same normalized readiness failures
4. mark direct cache-verb tests as migration-only and plan their deletion

### Phase 2: Build the manager and envelope store

Goal: create the new source of truth.

Tasks:

1. add canonical envelope types and store
2. implement `WarmSessionManager`
3. move readiness evaluation and error normalization under the manager
4. integrate sealed persistence only through the manager
5. add transition telemetry and invariants

### Phase 3: Replace cache verbs with lease semantics

Goal: remove cache-centric flow code.

Tasks:

1. define worker lease operations for the manager
2. route restore and consume through one semantic path
3. remove `peek`-before-`dispense` assumptions
4. delete `transferPrfFirstForThresholdSession`

### Phase 4: Convert bootstraps into capability provisioners

Goal: make capability provisioning explicit and reusable.

Tasks:

1. refactor Ed25519 session creation into a capability provisioner
2. refactor ECDSA bootstrap into a capability provisioner
3. make login warm-up and reconnect use the same manager-owned provisioning path
4. persist capability auth only through the manager boundary

### Phase 5: Migrate all flows

Goal: make the manager the only entry point.

Tasks:

1. migrate NEAR signing to manager API
2. migrate EVM signing to manager API
3. migrate Tempo signing to manager API
4. migrate ECDSA export to manager API
5. delete `SigningEngine` flow-local session repair logic

### Phase 6: Delete old state systems

Goal: finish the rewrite.

Tasks:

1. remove `activeSigningSessionIds`
2. remove obsolete helpers from `signingSessionState.ts`
3. collapse or replace `thresholdSessionStore.ts`
4. remove duplicate indexes and drift-repair logic
5. remove dead docs and dead tests for the old model

### Phase 7: Hardening and final cleanup

Goal: make the final design stable and legible.

Tasks:

1. add invariant checks for impossible state combinations
2. add focused e2e coverage for refresh, reconnect, export, and sign
3. update docs so only the new architecture remains in active context
4. remove old naming tied to caches and active maps

## 15. Phased TODO list

### Phase 1

- [ ] Add manager-level lifecycle test suite.
- [ ] Add cross-flow readiness and error-normalization tests.
- [ ] Add explicit tests proving ECDSA export and ECDSA signing share the same readiness path.
- [ ] Mark direct cache-verb tests for deletion.

### Phase 2

- [ ] Create `WarmSessionManager`.
- [ ] Create canonical envelope types and persistence.
- [ ] Move readiness logic into the manager.
- [ ] Move error normalization into the manager.
- [ ] Add envelope transition telemetry and assertions.

### Phase 3

- [ ] Replace public cache verbs with lease semantics.
- [ ] Remove the need for `peek` as a prerequisite for use.
- [ ] Remove `transferPrfFirstForThresholdSession`.
- [ ] Keep worker PRF details behind the manager boundary.

### Phase 4

- [ ] Convert Ed25519 bootstrap into capability provisioner.
- [ ] Convert ECDSA bootstrap into capability provisioner.
- [ ] Make login warm-up call the manager provisioning path.
- [ ] Make explicit reconnect call the same manager provisioning path.
- [ ] Store capability auth through one persistence boundary.

### Phase 5

- [ ] Migrate NEAR signing to manager API.
- [ ] Migrate EVM signing to manager API.
- [ ] Migrate Tempo signing to manager API.
- [ ] Migrate ECDSA export to manager API.
- [ ] Delete `SigningEngine`-local PRF/session recovery helpers.

### Phase 6

- [ ] Delete `activeSigningSessionIds` as a source of truth.
- [ ] Delete obsolete helpers from `signingSessionState.ts`.
- [ ] Simplify or replace `thresholdSessionStore.ts`.
- [ ] Remove duplicate indexes and repair logic created by state drift.
- [ ] Remove dead tests and docs for the old model.

### Phase 7

- [ ] Add invariants for impossible envelope and capability combinations.
- [ ] Add focused e2e coverage for refresh, reconnect, export, and sign.
- [ ] Update architecture docs to describe only the new model.
- [ ] Remove outdated naming tied to cache verbs and active maps.

## 16. Acceptance criteria

1. There is exactly one authoritative local owner of warm threshold state.
2. Signing and export flows do not call low-level PRF operations directly.
3. Sealed refresh is an implementation detail of the manager, not a separate flow path.
4. ECDSA export and ECDSA signing use the same readiness and PRF-consumption path.
5. No threshold flow performs manual session-id repair or transfer.
6. Account refresh and reconnect behavior is deterministic from the canonical envelope.
7. `SigningEngine.ts` no longer contains targeted session-recovery patches.
8. Old state holders and helper APIs that existed only for drift repair are deleted.

## 17. Summary

The clean redesign is not to add another fallback. It is to replace the current split-state architecture with one account-scoped warm-session system.

That system should:

1. use one canonical warm envelope per account
2. treat PRF as a lease owned by that envelope
3. treat `ed25519` and `ecdsa` as explicit capability sub-states
4. hide worker cache details behind a manager boundary
5. make signing and export consume the same readiness path
6. delete old active maps, cache verbs, and flow-local repair logic

That is the design most likely to stay readable, maintainable, and correct as the signer system evolves.

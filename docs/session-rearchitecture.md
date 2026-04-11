# Session Re-Architecture: Warm-Session PRF State, Sealed Refresh, and Threshold Session State

Last updated: 2026-04-11
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
4. No cache verbs in business logic: legacy `peek`, `dispense`, `transfer`, and similar operations are implementation details.
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

### 4.2 PRF is modeled as a cache, not as claimable warm-session state

The code talks about PRF cache operations:

1. `putPrfFirstForThresholdSession`
2. `getWarmSessionStatus`
3. `claimWarmSessionMaterial`
4. delete session-id remapping helpers instead of moving leases between ids
5. `clearPrfFirstForThresholdSession`

That API surface is too low-level. Callers should not reason in terms of cache verbs. They should reason in terms of warm-session semantics:

1. ensure the account has usable warm state for capability X
2. consume one authorized use from the warm session
3. get the capability auth material required to finish the operation

### 4.3 Rehydrate semantics are asymmetric and leaky

The current system makes status-read special because it can trigger restore. That means higher-level code needs to know which primitive is safe to call first. That is the wrong abstraction boundary.

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
3. one worker-side `WarmSessionClaimStore` that only the manager talks to
4. one capability provisioner layer for `ed25519`, `ecdsa`, and future signer families

Everything else becomes a consumer of that system.

Signing flows, login warm-up, and explicit reconnect should all use the same manager.
Export flows may reuse canonical capability metadata, but they must require fresh per-export authorization instead of consuming warm-session claim state.

### 5.2 Core idea: one warm envelope per account

The cleanest local model is not "many session ids with helper lookups." The cleanest local model is one account-scoped warm envelope.

Suggested shape:

```ts
export type ThresholdCapability = 'ed25519' | 'ecdsa';

export type WarmThresholdSessionEnvelope = {
  accountId: AccountId;
  warmSessionId: string;
  prfClaim: PrfClaimState;
  capabilities: Partial<Record<ThresholdCapability, WarmCapabilityState>>;
  version: 1;
  updatedAtMs: number;
};

export type PrfClaimState = {
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
5. duplicate or inconsistent readiness logic for signing versus export
6. per-chain session planners with overlapping responsibilities

### 5.4 Layering

#### Layer A: `WarmSessionManager`

Responsibilities:

1. load and persist the envelope
2. answer readiness questions
3. restore PRF from sealed persistence when allowed
4. claim PRF material atomically
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

#### Layer C: `WarmSessionClaimStore` inside the worker boundary

Responsibilities:

1. hold plaintext PRF only in worker memory
2. seal and unseal when persistence mode requires it
3. expose semantic claim operations to the manager

The worker should not present itself to core code as a general-purpose PRF cache. It is a warm-session claim store behind a manager boundary.

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

export type ClaimWarmSessionMaterialArgs = {
  accountId: AccountId;
  capability: ThresholdCapability;
  uses?: number;
  reason: 'sign' | 'explicit_reconnect';
};

interface WarmSessionManager {
  getStatus(accountId: AccountId): Promise<WarmThresholdSessionEnvelope | null>;
  ensureWarmSession(args: EnsureWarmSessionArgs): Promise<WarmThresholdSessionEnvelope>;
  ensureCapabilityReady(args: EnsureCapabilityArgs): Promise<WarmCapabilityState>;
  claimWarmSessionMaterial(args: ClaimWarmSessionMaterialArgs): Promise<{
    prfFirstB64u: string;
    envelope: WarmThresholdSessionEnvelope;
  }>;
  clear(accountId: AccountId): Promise<void>;
  clearAll(): Promise<void>;
}
```

Rules:

1. signing and reconnect flows call `ensureCapabilityReady` and `claimWarmSessionMaterial`
2. flows do not call low-level PRF methods directly
3. flows do not inspect or repair session ids directly
4. explicit key export requires fresh authorization and does not claim warm-session PRF state
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

1. `warm` means plaintext PRF is in worker memory and warm-session claim metadata is current.
2. `sealed_only` means plaintext PRF is absent but a sealed record may restore it.
3. `expired` and `exhausted` are terminal for the current envelope.
4. capability `ready` is valid only if capability auth is valid and warm-session PRF claim is usable.
5. if capability auth exists but warm-session PRF claim does not, the envelope is `invalid` until repaired or cleared.
6. if warm-session PRF claim exists but capability auth is missing, the manager may provision only the missing capability.
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
3. `WarmSessionClaimStore`
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
2. UI and chain flows should not talk about legacy cache verbs or raw worker failures
3. signing and export should surface consistent user-facing auth/session failures without exposing worker internals

## 10. Strong recommendations

These are the design choices I recommend unless we find a concrete reason not to.

### 10.0 Chosen architecture

Decision: `Option A`.

That means the target architecture is:

1. one explicit account-scoped warm-session object
2. one shared claimable PRF state owned by that warm session
3. `ed25519` and `ecdsa` modeled as explicit capability sub-states
4. client and server converging on the same conceptual model

`Option B` remains useful only as a migration shape if some server steps need to land incrementally. It is not the desired end state.

### 10.1 Replace session-id-centric flow logic with capability-centric flow logic

Recommendation: yes.

Reasoning:

1. it matches what callers actually need
2. it shrinks the API surface
3. it prevents flow-local session repair logic
4. it keeps signing flows bound to explicit capability ownership instead of cross-curve fallbacks

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

### 10.4 Keep explicit key export outside the warm-session PRF path

Recommendation: yes.

Reasoning:

1. explicit key export is a higher-sensitivity reveal operation than signing
2. every export should require a fresh WebAuthn or Touch ID PRF confirmation
3. warm-session PRF claims should only optimize signing and reconnect paths, not private key reveal
4. export may reuse canonical capability transport, but it must not consume warm-session claim state

### 10.5 Remove direct flow access to worker PRF operations entirely

Recommendation: yes.

Reasoning:

1. the current architecture breaks because the cache abstraction leaked upward
2. workers should expose semantic claim operations through the manager, not generic cache primitives

## 11. Debate points

These are the main design decisions worth debating before implementation.

### 11.1 One warm envelope per account, or one per capability?

Decision: one warm envelope per account.

Why I lean this way:

1. there is one shared warm-session PRF source
2. the user experience is account-unlock oriented, not capability-unlock oriented
3. multiple envelopes would reintroduce coordination and drift problems

Reasonable counterargument:

1. if `ed25519` and `ecdsa` diverge heavily in policy or lifecycle, separate envelopes could reduce coupling

Current judgment:

1. this is the selected target architecture
2. separate envelopes per capability are not the intended design

### 11.2 Should `ecdsa` remain derived from Ed25519 login warm-up, or should both capabilities be provisioned independently?

Decision: keep one WebAuthn-derived PRF source, but model both capabilities independently in the envelope.

Why:

1. the cryptographic source can be shared without sharing the capability state machine
2. this removes hidden dependency semantics from business logic
3. the model stays extensible for future signer families

Constraint:

1. ECDSA must not be represented as borrowed Ed25519 auth state
2. if there are remaining protocol assumptions, they need to be removed during the refactor

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

### 11.5 Should the worker know about capabilities, or only about warm-session PRF claim state?

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
   If one capability becomes invalid, do we invalidate only that capability, or the whole envelope? My current leaning is: invalidate the capability first, invalidate the full envelope only when warm-session PRF claim state is compromised.

3. Multi-tab semantics:
   Same-tab refresh is clear. Cross-tab behavior needs a clean policy. My leaning is to keep the envelope account-scoped but treat worker plaintext PRF as tab-local, with sealed restore re-establishing continuity where allowed.

4. Atomicity boundaries:
   We should be explicit about which operations are atomic at the manager layer, especially `claimWarmSessionMaterial` plus envelope policy updates.

5. Provisioning ownership:
   We should confirm whether login warm-up always provisions both capabilities by default, or whether capability provisioning should become configurable at the manager boundary.

6. Telemetry model:
   We should decide which state transitions deserve structured telemetry so regressions become obvious without leaking sensitive material.

## 13. Server-side implications

This redesign should not be treated as a client-only cleanup. The previous ECDSA explicit export bug and the current Ed25519 fallback finding both show the same underlying issue: ECDSA capability identity and ownership are not modeled explicitly enough across the client/server boundary.

The old explicit export bug was a canonical-context mismatch:

1. the client prepared ECDSA HSS under `keyPurpose: 'threshold-ecdsa'`
2. the relayer staged `explicit_key_export` under canonical ECDSA HSS purpose `evm-signing`
3. the prepared client session and staged server inputs were bound to different contexts
4. the worker correctly rejected the `serverAssistInitMessageB64u`

That bug was not a PRF-cache bug. It was a capability-identity bug. The current ECDSA JWT fallback issue is a different symptom of the same broader design problem: ECDSA is not self-contained enough as a first-class capability.

The session refactor should therefore define an explicit cross-layer capability model and require the server to participate in that model.

### 13.1 Server design requirements

#### A. ECDSA auth must be self-contained

The server-side ECDSA auth package must be complete on its own.

That means:

1. no silent fallback from ECDSA JWT to Ed25519 JWT
2. no implicit inference that Ed25519 session state can stand in for missing ECDSA auth
3. no server response shape that leaves ECDSA capability identity partially implied

If ECDSA and Ed25519 share one PRF source, that is acceptable. If ECDSA borrows Ed25519 auth semantics implicitly, that is not.

#### B. Capability descriptors must be canonical

The client and server need one shared capability descriptor vocabulary.

Each capability auth package should explicitly declare at least:

1. `capability`
2. canonical `keyPurpose`
3. session/auth kind
4. server-issued session identifier
5. TTL and remaining-uses policy
6. any capability-specific context binding inputs that must match on both sides

This is the cleanest way to prevent bugs like `threshold-ecdsa` versus `evm-signing`.

#### C. Purpose naming must be normalized server-first

The relayer should be the canonical source for capability-purpose naming.

That means:

1. one canonical purpose for ECDSA HSS signing/export context
2. one canonical purpose for Ed25519 threshold flows
3. no alias proliferation in different client paths
4. no hidden compatibility mapping unless it is temporary and explicitly documented

#### D. Reconnect semantics must be explicit

The server needs to participate in the reconnect model instead of leaving the client to infer it.

The API spec should clearly distinguish:

1. local sealed restore of the same warm session
2. still-valid capability auth that only needs PRF rehydration
3. expired or missing capability auth that requires explicit reconnect
4. irrecoverable invalid-state cases that require full reprovision

#### E. Error model must align with client manager semantics

The server should return failures that map cleanly into the `WarmSessionManager` error family.

At minimum, the server should make it possible to distinguish:

1. `capability_not_ready`
2. `session_expired`
3. `session_exhausted`
4. `context_mismatch`
5. `explicit_reconnect_required`
6. `internal_session_error`

### 13.2 Chosen server shape

The target server architecture should match `Option A`.

That means the server should converge on:

1. one explicit account warm-session object
2. one shared policy owner for TTL, remaining uses, invalidation, and reconnect semantics
3. explicit capability sub-objects for `ed25519` and `ecdsa`
4. no cross-curve fallback anywhere
5. canonical purpose/context fields shared end-to-end

This does not require one giant server rewrite in a single change, but it does mean the server should be moving toward the same conceptual model as the client rather than preserving capability-specific session systems as the long-term design.

In steady state:

1. the account warm session owns PRF claim semantics
2. each capability owns its own explicit auth package
3. capability readiness is evaluated under one parent warm-session object
4. reconnect and invalidation decisions are made against that parent object, not inferred from unrelated curve state

### 13.3 Server refactor tasks

1. introduce an explicit account warm-session model in the server specs and response shapes
2. remove ECDSA JWT fallback to Ed25519 state
3. make ECDSA and Ed25519 auth material explicit capability sub-objects
4. canonicalize capability-purpose naming on the relayer side
5. add explicit capability descriptors to relevant session/bootstrap/export responses
6. normalize relayer/session errors so the client manager can map them directly
7. document reconnect and invalidation rules in one place and enforce them consistently

## 14. Cross-layer implementation plan

This refactor should be implemented as a client/server program with a shared spec, not as an isolated client rewrite.

### Phase 0: Write the cross-layer spec first

Goal: define one explicit capability and session model before implementation diverges again.

Tasks:

1. define the explicit account warm-session object
2. define `ThresholdCapabilityAuthMaterial` for `ed25519` and `ecdsa`
3. define canonical purpose names and context-binding inputs
4. define reconnect semantics and invalidation rules
5. define normalized error families and status mapping
6. explicitly ban cross-curve JWT fallback in the new model

Exit criteria:

1. client and server implementers can point to one spec
2. capability ownership and purpose binding are unambiguous
3. the parent account warm-session object is the agreed source of truth

### Phase 1: Introduce server-side account warm-session ownership

Goal: make server responses explicit enough for the new client architecture.

Tasks:

1. introduce the account warm-session container in server specs and endpoint responses
2. make ECDSA auth self-contained
3. remove server-side and client-side assumptions that ECDSA auth may be borrowed from Ed25519 state
4. normalize purpose naming and context binding on the relayer side
5. return explicit capability descriptors from session/bootstrap/export endpoints

Exit criteria:

1. account warm-session ownership is explicit in server contracts
2. ECDSA auth can be reasoned about without consulting Ed25519 state
3. explicit export/signing context binding is canonicalized

### Phase 2: Build the client `WarmSessionManager` against the new spec

Goal: create the new authoritative client runtime owner.

Tasks:

1. add the canonical envelope types and store
2. implement `WarmSessionManager`
3. move readiness and error normalization under the manager
4. integrate sealed persistence under the manager only

Exit criteria:

1. one client code path answers readiness questions
2. manager semantics match the cross-layer spec
3. client envelope structure mirrors the chosen account warm-session model

### Phase 3: Replace client cache verbs with claim semantics

Goal: remove the leaked worker-cache abstraction.

Tasks:

1. define worker claim operations for the manager
2. route restore and consume through one semantic path
3. remove status-read-before-claim assumptions
4. delete legacy session-id remapping helpers

Exit criteria:

1. no business flow talks directly to PRF cache verbs
2. restore semantics are manager-owned

### Phase 4: Convert capability provisioning flows

Goal: align login, reconnect, export, and signing under one capability model.

Tasks:

1. refactor Ed25519 bootstrap into a capability provisioner
2. refactor ECDSA bootstrap into a capability provisioner
3. make login warm-up and explicit reconnect use the same manager-owned provisioning path
4. persist capability auth only through the manager boundary

Exit criteria:

1. capability auth ownership is explicit
2. signing uses manager-owned readiness, while explicit export uses fresh per-export authorization

### Phase 5: Delete old state systems

Goal: finish the rewrite rather than carrying compatibility logic forward.

Tasks:

1. remove `activeSigningSessionIds`
2. remove obsolete helpers from `signingSessionState.ts`
3. collapse or replace `thresholdSessionStore.ts`
4. remove duplicate indexes, fallback lookups, and cross-curve repair logic
5. remove dead docs and dead tests for the old model

Exit criteria:

1. old cross-curve fallback logic is gone
2. client and server both implement the same explicit account warm-session model

## 15. File-level refactor plan

### 15.1 New modules to introduce

1. `client/src/core/signingEngine/session/WarmSessionManager.ts`
2. `client/src/core/signingEngine/session/warmSessionTypes.ts`
3. `client/src/core/signingEngine/session/warmSessionStore.ts`
4. `client/src/core/signingEngine/session/thresholdCapabilityProvisioner.ts`
5. `client/src/core/signingEngine/session/warmSessionClaimWorker.ts`

### 15.2 Existing modules to simplify, absorb, or delete

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

### 15.3 APIs to delete

1. `transferPrfFirstForThresholdSession`
2. caller-visible `getWarmSessionStatus`
3. caller-visible `claimWarmSessionMaterial`
4. `activeSigningSessionIds` as a public source of truth
5. any flow-local reconnect helper that exists only to compensate for state drift

## 16. Implementation plan

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

### Cross-cutting: Comprehensive `WarmSessionManager` test track

Goal: make `WarmSessionManager` the most heavily specified client boundary in the session system.

Tasks:

1. add envelope-state fixture builders so tests can express warm, sealed-only, expired, exhausted, auth-missing, and mixed-capability states without duplicated setup
2. add direct lifecycle tests for `getWarmSession(...)` covering Ed25519-only, ECDSA-only, dual-capability, and empty-account envelopes
3. add capability-resolution tests for `getEd25519CapabilityByThresholdSessionId(...)`, `ensureEcdsaCapabilityReady(...)`, and bootstrap request resolution
4. add PRF claim tests for warm claims, missing claims, expired claims, exhausted claims, and seal-persistence fallback behavior
5. add reconnect/provision tests proving the manager reconnects only when required and reuses warm capability state when it is still valid
6. add stale-state regression tests proving the manager does not inherit ECDSA session id or JWT material from non-warm capability records
7. add concurrency tests for bootstrap queueing, single-flight seal persistence, and multi-call readiness checks against the same account
8. add error-normalization tests so manager-thrown failures stay stable across signing, export, reconnect, and bootstrap callers
9. add regression fixtures for the bugs we have already hit: canonical-context mismatch, missing warm PRF material on explicit export, and stale-session drift after reconnect

Exit criteria:

1. `WarmSessionManager` behavior can be understood from its test suite without reading downstream signing flows
2. previous ECDSA export/signing regressions are covered by manager-level tests rather than only end-to-end tests
3. any future session bug can be localized first to a manager test before touching flow tests

### Phase 3: Replace cache verbs with claim semantics

Goal: remove cache-centric flow code.

Tasks:

1. define worker claim operations for the manager
2. route restore and consume through one semantic path
3. remove status-read-before-claim assumptions
4. delete legacy session-id remapping helpers

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

## 17. Phased TODO list

### Phase 1

- [x] Add manager-level lifecycle test suite.
- [x] Add cross-flow readiness and error-normalization tests.
- [x] Add explicit tests proving key export requires fresh authorization and never consumes warm-session leases.
- [x] Mark direct cache-verb tests for deletion.

### Phase 2

- [x] Create `WarmSessionManager`.
- [x] Create canonical envelope types and persistence.
- [x] Move readiness logic into the manager.
- [x] Move error normalization into the manager.
- [x] Add envelope transition telemetry and assertions.

### Phase 3

- [x] Replace public cache verbs with claim semantics.
- [x] Remove the need for status-read as a prerequisite for claim.
- [x] Remove `transferPrfFirstForThresholdSession`.
- [x] Keep worker PRF details behind the manager boundary.

### Phase 4

- [x] Convert Ed25519 bootstrap into capability provisioner.
- [x] Convert ECDSA bootstrap into capability provisioner.
- [x] Make login warm-up call the manager provisioning path.
- [x] Make explicit reconnect call the same manager provisioning path.
- [x] Store capability auth through one persistence boundary.

### Phase 5

- [x] Migrate NEAR signing to manager API.
- [x] Migrate EVM signing to manager API.
- [x] Migrate Tempo signing to manager API.
- [x] Route explicit key export through fresh per-export authorization instead of warm-session claim consumption.
- [x] Delete `SigningEngine`-local PRF/session recovery helpers.

### Phase 6

- [x] Delete `activeSigningSessionIds` as a source of truth.
- [x] Delete obsolete helpers from `signingSessionState.ts`.
- [x] Simplify or replace `thresholdSessionStore.ts`.
- [x] Remove duplicate indexes and repair logic created by state drift.
- [x] Remove dead tests and docs for the old model.

### Phase 7

- [x] Add invariants for impossible envelope and capability combinations.
- [x] Add focused e2e coverage for refresh, reconnect, export, and sign.
- [x] Update architecture docs to describe only the new model.
- [x] Remove outdated naming tied to cache verbs and active maps.

### WarmSessionManager coverage

- [x] Add reusable warm-session envelope and capability fixture builders.
- [x] Add direct lifecycle tests for empty, Ed25519-only, ECDSA-only, and dual-capability envelopes.
- [x] Add capability-resolution tests for Ed25519 auth, ECDSA auth, and bootstrap request resolution.
- [x] Add PRF claim tests for warm, missing, expired, exhausted, and seal-persisted states.
- [x] Add reconnect/provision tests proving reuse vs reconnect behavior.
- [x] Add stale-state regression tests for non-warm ECDSA session-id/JWT inheritance.
- [x] Add concurrency tests for repeated readiness checks and seal-persistence single-flight behavior.
- [x] Add error-normalization tests for signing, export, reconnect, and bootstrap callers.
- [x] Add regression tests for the known ECDSA export/signing bugs we have already fixed.

## 17A. High-impact follow-up improvements

The refactor is substantially cleaner, but a few high-leverage improvements remain. These are not legacy-compatibility tasks. They are simplification and correctness tasks that remove the last ambiguous edges from the new model.

### 17A.1 Remove the status-read precondition from claim

Problem:

`WarmSessionManager.claimPrfFirstByThresholdSessionId(...)` still performs `getWarmSessionStatus(...)` before `claimWarmSessionMaterial(...)`.

Why this matters:

1. it reintroduces the exact two-step race we said the new architecture should remove
2. it forces the manager to depend on both status-read and claim just to consume one use
3. it doubles worker round-trips on the hot path

Implementation TODO:

- [x] change `claimPrfFirstByThresholdSessionId(...)` to call `claimWarmSessionMaterial(...)` first and normalize directly from the claim result
- [x] keep at most one fallback status-read path for diagnostics-only cases where the claim result is structurally invalid
- [x] remove `getWarmSessionStatus` as a required dependency for claim-only manager operations
- [x] add regression tests proving claim succeeds/fails correctly without a preparatory status read

### 17A.2 Remove curve-agnostic threshold-session-id lookups from the manager surface

Problem:

The system now allows one account-scoped warm session to contain both Ed25519 and ECDSA capability records, and those capability records may share the same `thresholdSessionId`. Generic `thresholdSessionId -> record` resolution is therefore ambiguous by design.

Why this matters:

1. generic lookup helpers make it easy for future callers to accidentally recover the wrong curve record
2. the shared-session-id design means this ambiguity is no longer theoretical
3. correctness now depends on callers remembering when generic lookup is unsafe

Implementation TODO:

- [x] delete `readWarmSessionRecordByThresholdSessionId(...)` from [warmSessionStore.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/session/warmSessionStore.ts)
- [x] delete `resolveRecordByThresholdSessionId(...)` from [WarmSessionManager.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/session/WarmSessionManager.ts)
- [x] replace remaining generic status/transport helpers with capability-scoped or curve-scoped APIs
- [x] introduce an explicit capability reference type for any operation that cannot be inferred from account + curve
- [x] add regression tests that fail if a shared session id can resolve to the wrong curve through any public manager API

### 17A.3 Stop collapsing infrastructure errors into "missing"

Problem:

Worker/runtime failures are currently normalized into missing/not-found style states in several warm-session paths.

Why this matters:

1. broken worker communication can look like an ordinary cold/missing session
2. callers may reconnect or fall back to WebAuthn when the real problem is transport/runtime failure
3. the system loses the distinction between recoverable state absence and infrastructure outage

Implementation TODO:

- [x] add typed warm-session availability errors such as `worker_error`, `status_unavailable`, and `claim_unavailable`
- [x] make signing planning fail closed on infrastructure failures instead of silently treating them as missing cache state
- [x] emit explicit telemetry for worker/runtime failures separately from `missing`, `expired`, and `exhausted`
- [x] add tests covering worker port failure, malformed worker payloads, and worker startup failure in manager-level flows

### 17A.4 Split `WarmSessionManager` into smaller focused modules

Problem:

`WarmSessionManager.ts` currently owns envelope assembly, capability derivation, bootstrap planning, provisioning, reconnect, claim consumption, seal persistence, transitions, and caller-facing error normalization.

Why this matters:

1. the file is too large to reason about locally
2. unrelated responsibilities are coupled through one broad dependency bag
3. future fixes are more likely to create accidental cross-flow regressions

Implementation TODO:

- [x] extract envelope-read and capability-derivation logic into a dedicated read-model module
- [x] extract ECDSA bootstrap/reconnect planning into a dedicated provisioner module
- [x] extract claim/seal operations into a dedicated warm-session runtime module
- [x] keep `WarmSessionManager` as a thin orchestration facade over those modules
- [x] move tests to mirror the new module boundaries so failures localize faster

### 17A.5 Add batch/snapshot reads for warm-session status

Problem:

`getWarmSession(...)` performs multiple worker status reads, and several manager operations do repeated before/after full-envelope reads in a single flow.

Why this matters:

1. it adds latency to hot paths
2. it increases race surface between separate status reads
3. transition snapshots are less trustworthy when they are assembled from multiple independent reads

Implementation TODO:

- [x] add a batched warm-session status read at the touchConfirm/worker boundary
- [x] let `getWarmSession(...)` assemble envelopes from one snapshot instead of N independent reads
- [x] use snapshot-based before/after capture for transition events
- [x] add performance-oriented tests or instrumentation around repeated signing readiness checks

## 18. Acceptance criteria

1. There is exactly one authoritative local owner of warm threshold state.
2. Signing and export flows do not call low-level PRF operations directly.
3. Sealed refresh is an implementation detail of the manager, not a separate flow path.
4. Signing uses `WarmSessionManager`; explicit key export always requires fresh PRF authorization and does not consume warm-session claims.
5. No threshold flow performs manual session-id repair or transfer.
6. Account refresh and reconnect behavior is deterministic from the canonical envelope.
7. `SigningEngine.ts` no longer contains targeted session-recovery patches.
8. Old state holders and helper APIs that existed only for drift repair are deleted.

## 19. Summary

The clean redesign is not to add another fallback. It is to replace the current split-state architecture with one account-scoped warm-session system.

That system should:

1. use one canonical warm envelope per account
2. treat PRF as claimable state owned by that envelope
3. treat `ed25519` and `ecdsa` as explicit capability sub-states
4. hide worker cache details behind a manager boundary
5. keep signing on `WarmSessionManager` while requiring fresh authorization for explicit key export
6. delete old active maps, cache verbs, and flow-local repair logic

That is the design most likely to stay readable, maintainable, and correct as the signer system evolves.

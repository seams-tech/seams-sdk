# Refactor 90: Modular Auth And Capability Implementation Plan

Created: June 28, 2026
Slimmed: July 22, 2026

## Status

Phases 1-3 are complete. Phases 4-5 and Foundations A-B are in progress.
[Refactor 91](./refactor-91.md) is implemented, with intended-behaviour E2E
acceptance pending a working local site. The
[Email OTP local-rehydration patch](./refactor-patch-2-email-otp-local-rehydration.md)
remains current-stack groundwork that Refactor 90 must absorb without creating a
second persistence owner or factor-specific signing lane.

The progress log lives in [refactor-90-journal.md](./refactor-90-journal.md).
Implementation details and normative invariants live in the
[companion SPEC](./refactor-90-modular-auth-capabilities-SPEC.md). This document
owns execution order, dependencies, deletion points, and acceptance checks. It
does not restate the full type system or security model.

## Why This Plan Was Slimmed

The previous plan mixed an implementation checklist, architecture specification,
repository inventory, migration ledger, test matrix, and several future product
roadmaps. The same invariants appeared in up to six places. Recovery also exposed
volatile worker steps and local implementation checkpoints as durable public
states.

This revision applies four constraints:

1. The SPEC owns numbered invariants. Phases cite them.
2. Durable state records irreversible cross-boundary facts only.
3. Enforcement matches the failure mode: types for construction, parsers and
   tests for untrusted data, and guards for dependency or artifact boundaries.
4. Refactor 90 ships the smallest verticals needed to prove the authorization
   layer and migrate the two MPC capabilities.

## Goal

Registration, wallet unlock, and page refresh must resolve the same canonical
capability, material, authority, and signing-lane state. Each protocol owns one
durable material model and one precise boundary parser. Factor-specific code
produces verified evidence or custody observations; it does not select signing
lanes, own generic capability state, or publish a parallel active record.

The refactor is complete when:

- ECDSA no longer uses `ThresholdEcdsaSessionRecordCore` or an equivalent broad
  optional aggregate;
- Ed25519 and ECDSA each have one canonical durable material owner;
- registration, unlock, and refresh feed the same hydration resolver;
- exact authority and material bindings select one operation lane;
- server admission atomically claims one operation grant and, when applicable,
  one wallet-signing quota use under a stable operation fingerprint;
- recovery survives crashes through idempotent server reconciliation and a
  minimal client journal;
- obsolete wallet-first paths, records, fixtures, and source guards are deleted.

## Scope

### Included

- Canonical auth-method and exact `WalletAuthAuthorityRef` boundaries.
- Required-field ECDSA capability records and exact persistence parsing.
- Protocol-neutral hydration outcomes with protocol-local payloads.
- Near Ed25519 Yao active-material rehydration and same-root recovery.
- Exact ECDSA role-local material activation and rehydration.
- DB-backed operation grants and MPC wallet-signing quota claims.
- A minimal vault vertical proving session, evidence, grant, enforcement, and
  audit before MPC migration.
- Static route composition through narrow service ports.
- Current Cloudflare, Node, SDK, worker, UI, and provisioning migrations needed
  by the two MPC capabilities.
- Same-change deletion of replaced behavior.

### Follow-on work

These are separate refactors and do not block Refactor 90:

- service-account evidence and workload identity;
- Better Auth integration;
- IdP/OIDC provider functionality;
- Slack OTP grant evidence;
- full vault administration, delegation, rotation, break-glass, export, and
  service-account workflows;
- a general route-plugin or runtime module registry;
- package or WASM artifact splitting without a security-boundary requirement or
  measured bundle/latency evidence;
- comprehensive host/example platform migration beyond the currently supported
  Refactor 90 paths;
- `mpc_signer_proof` production until its owning capability and policy are
  decided. The reserved operation fails closed in the meantime.

Device binding is classified in a separate session-hardening decision. If the
current threat model requires device-bound sessions for theft or replay
resistance, the narrow binding required by Refactor 90 remains. Broader device
management does not enter this plan.

The [Ed25519 Yao implementation plan](./router-ab/ed25519-yao/implementation-plan.md)
remains authoritative for the Yao cryptographic construction, Deriver A/B and
SigningWorker ownership, protocol lifecycle, and production-readiness gates.
Refactor 90 owns session, authorization, capability composition, and the public
integration around that implementation; it cannot redefine the Yao backend or
advance its production status ahead of those gates.

## Settled Architecture

Each section cites the SPEC invariants it instantiates. Where prose here and the
SPEC differ, the SPEC invariant text is normative.

### 1. Canonical hydration

Invariants: `R90-INV-001`, `R90-INV-002`, `R90-INV-003`.

Foundation A owns four outcomes:

- `use_live_runtime`;
- `rehydrate_material_activation`;
- `reauthorize_public_anchor`;
- `blocked`.

Registration, wallet unlock, and page refresh are provenance for diagnostics and
tests. Current canonical state selects the outcome. Each protocol constructs its
own exact payload; the shared layer does not introduce a generic hierarchy of
material, proof, and runtime reference wrappers beyond what both protocols
actually consume.

Passkey and Email OTP must produce equivalent canonical observations for
equivalent state. A synthetic third-factor adapter is not required. Generic
preparation and coordination modules retain a source guard against factor-kind
literals because dependency direction cannot be proven by TypeScript alone.

### 2. Canonical ECDSA state

Invariants: `R90-INV-001`, `R90-INV-002`, `R90-INV-005`, `R90-INV-006`,
`R90-INV-011`.

Foundation B replaces `ThresholdEcdsaSessionRecordCore` with one boundary-parsed
`active | retired` ECDSA capability record. The active branch requires:

- registered signer and exact capability scope;
- exact wallet authority;
- active material-session and server generation;
- durable role-local material ref and authenticated binding digests;
- lifecycle, revision, expiry, and activation receipt.

Runtime handles, bearer credentials, operation grants, wallet quota, nonce,
entry-point provenance, diagnostics, and provider data are separate domains.
There is one IndexedDB capability adapter and one volatile worker-runtime
registry.

ECDSA activation uses only `activation_prepared` and
`server_activation_committed` journal branches. The final IndexedDB transaction
writes encrypted material, writes the active manifest, retires the replaced
record when applicable, and deletes the journal atomically. Runtime publication
occurs afterward and can be reconstructed from canonical durable state.

An immediate read through the canonical parser may run after transaction
completion for high-value writes. It can fail the current operation, but it does
not create a durable `*_readback_pending` or `runtime_publication_pending` state.

### 3. Minimal recovery journal

Invariants: `R90-INV-004`, `R90-INV-005`, `R90-INV-006`, `R90-INV-007`.

Near recovery has two persisted branches:

```ts
type NearEd25519YaoRecoveryCommitJournal =
  | {
      kind: 'prepared';
      recoveryId: RecoveryId;
      authority: WalletAuthAuthorityRef;
      materialOwner: MpcMaterialOwnerRef;
      source: NearEd25519YaoMaterialRecoverySourceRef;
      correlation: RecoveryCorrelation;
      disposition: 'continue' | 'cancel_requested';
    }
  | {
      kind: 'promotion_committed';
      recoveryId: RecoveryId;
      authority: WalletAuthAuthorityRef;
      materialOwner: MpcMaterialOwnerRef;
      promotionReceipt: NearEd25519YaoPromotionReceipt;
      finalization: NearEd25519YaoLocalFinalizationCommand;
    };
```

The exact target names remain SPEC-owned. The shape has these semantics:

- `prepared` is persisted before the first consuming server call. On reload it
  already represents server uncertainty; a separate `server_effect_uncertain`
  state adds no information.
- Every consuming server call is independently idempotent and queryable by
  `recoveryId`. This is the load-bearing crash-safety invariant.
- `cancel_requested` prevents reload from silently continuing abandoned work.
  Reconciliation queries server state. When no consuming effect committed it
  cleans up and deletes the journal. When an irreversible effect committed it
  completes safe convergence without authorizing or executing the parent
  operation.
- `promotion_committed` records the irreversible server receipt needed for local
  finalization.
- One IndexedDB transaction persists the replacement seal or volatile-retention
  record, retires or removes the prior source, persists the current lifecycle
  receipt, and deletes the journal. Journal absence is terminal only because this
  transaction is atomic.
- Runtime activation, handle disposal, candidate disposal, and zeroization are
  process-local worker responsibilities. They never enter durable journal state.

The client may keep private in-memory stages while an operation is live. They do
not become persisted unions, public preparation results, or cross-module proof
brands.

### 4. Preparation outcomes

Invariants: `R90-INV-010`.

Capability preparation exposes five outcomes:

```ts
type CapabilityPreparationResult<Ready, Resume, Requirement, Replacement, Failure> =
  | { kind: 'ready'; value: Ready }
  | { kind: 'pending'; resume: Resume }
  | { kind: 'authorization_required'; requirement: Requirement }
  | { kind: 'superseded'; replacement: Replacement }
  | { kind: 'failed'; failure: Failure };
```

`superseded` invalidates the prepared lane and requires exact re-resolution. It
must not collapse into retry, generic blockage, or recovery continuation.
Protocol-specific failure payloads distinguish retryable and terminal failures.

### 5. Material serialization

Invariants: `R90-INV-008`.

One per-material-owner queue serializes recovery, signing, refresh, and export.
The queue validates an owner generation/fence before material use and again
before committing effects. Callers run within a structured
`withMaterialOwnerLock(...)` boundary.

There is no public `MaterialUseLease` lifecycle, affine token transfer protocol,
or runtime registry that attempts to invalidate aliased TypeScript values.
Durable server execution leases remain separate and exist only for operations
that can outlive a request, transfer between workers, or require delivery
reconciliation.

### 6. Operation claims

Invariants: `R90-INV-009`.

The operation fingerprint excludes rotating grant, quota, session, and runtime
IDs. One server transaction on an absent fingerprint:

1. validates the exact capability operation and current authority/lifecycle;
2. validates and consumes one operation-grant use;
3. validates and consumes one wallet quota use when the descriptor requires it;
4. creates the operation claim and audit linkage.

Operation descriptors declare quota applicability: normal signing costs one
wallet-quota use beside its grant; key export declares no quota use and consumes
only its exact grant. Quota exhaustion therefore never blocks export, and export
never spends signing quota.

An existing claim returns its current or terminal result without consuming
renewed resources. A server execution lease is added only for an operation whose
execution semantics require retry by another worker or delivery reconciliation.
Ordinary request-bound execution does not become a durable job scheduler.

### 7. Revocation

Invariants: `R90-INV-006`, `R90-INV-009`.

Server claims are revoked and reconciled by server-owned epochs and claim state.
They are not local revocation-outbox targets.

When offline local cleanup must eventually trigger a server revocation, the
client stores one command containing an exact target, idempotency key, and
creation time. It does not define a target-specific lifecycle union with
cross-target `never` fields. Local secret disposal still happens immediately in
the worker and does not wait for outbox delivery.

### 8. Minimal vault proving slice

Invariants: `R90-INV-009`, `R90-INV-012`.

Slice A proves the shared authorization path before MPC migration:

```text
native session
  -> operation-bound passkey evidence
  -> one-use vault proxy/reveal grant
  -> one vault operation
  -> audit event
```

It includes only the schema, route, SDK call, evidence verification, grant claim,
operation, and audit readback needed for this vertical. Full vault product
behavior remains in its own plan.

### 9. Enforcement rule

Invariants: `R90-INV-012`.

Use one primary enforcement mechanism per failure mode:

- discriminated unions, required fields, `never`, exhaustive switches, and type
  fixtures reject invalid core construction;
- boundary parsers and focused hostile-input tests reject raw request,
  persistence, worker, and token data;
- source/import/export guards enforce dependency, worker, generated-WASM, and
  bundle boundaries that the type system cannot observe;
- integration tests cover atomicity, idempotency, crash reconciliation, and
  cross-store effects;
- E2E tests cover a small number of intended user-visible transitions.

Do not require a source guard, negative fixture, unit test, and E2E test for the
same structurally enforced property. Guards are retired when package or export
boundaries make the prohibited path impossible.

## Reduction Ledger

| Removed or reduced mechanism | Property it protected | Replacement | Cheapest effective verification |
| --- | --- | --- | --- |
| ECDSA readback/publication journal stages | exact persisted manifest/material agreement | atomic local commit plus optional immediate canonical read | adapter round-trip and focused commit test |
| Near recovery microstates | crash-safe convergence | recovery ID, server query/idempotency, two-state journal | crash fault-injection around each irreversible boundary |
| separate server-uncertain state | detection of an in-flight consuming call | `prepared` already precedes the call | reload from `prepared` test |
| pre-promotion cleanup state hierarchy | cancellation without unsafe continuation | `prepared.disposition = cancel_requested` plus reconciliation | cancel/crash/reload test |
| seal and source deletion in separate commits | journal/source consistency | one finalization transaction that swaps/retire records and deletes journal | transaction-abort fault injection |
| affine `MaterialUseLease` tokens | exclusive material use | owner queue plus generation/fence | concurrent recovery/sign/export test |
| runtime disposal/zeroization journal facts | live secret cleanup | worker ownership and `finally` disposal | worker lifecycle tests |
| target-specific revocation outbox union | eventual revocation | one exact idempotent command; server claims remain server-owned | offline/retry integration test |
| synthetic third-factor adapter | factor-neutral coordination | factor-free interfaces and literal/import guard | generic-module source guard plus Passkey/OTP tests |
| recursive evidence expression in the critical path | composed authorization | named policies or flat `all \| any` requirements used by current operations | policy table tests |
| repository-wide Phase 6 gate | migration coverage | phase-local inventory and delete ledger | scoped search and diff review per phase |
| triple enforcement artifacts | regression resistance | one enforcement layer matched to the failure mode | check named in each phase |
| broad vault feature set | proof of the authorization architecture | minimal proxy/reveal vertical | one end-to-end slice test |
| predeclared future capability kinds | future extensibility | extend closed unions when a capability lands | exhaustive build failure on extension |

Every future removal from this plan must add a row naming the protected property,
its replacement, and the check that demonstrates the replacement.

## Execution Order

The existing phase numbers remain stable for links from companion plans and the
journal. Their scope is reduced below.

| Work | Scope | Status |
| --- | --- | --- |
| Tactical Patch 2 | Email OTP exact-material local rehydration | In progress |
| Refactor 91 | canonical auth-method domains | Implemented; E2E pending |
| Foundation A | canonical hydration outcomes | In progress |
| Foundation B | canonical required-field ECDSA state | In progress |
| Phases 1-3 | registration cut, subjects, mechanical AuthService split | Complete |
| Phases 4-5 | exact subjects and ECDSA role-local cache slimming | In progress |
| Phase 6 | scoped inventory and deletion ledger | Planning |
| Phases 7-9 | current vocabulary, SDK surface, narrow route ports/static assembly | Planning |
| Phases 10-16 | minimal session/authorization/vault proving slice | Planning |
| Phases 17-20 | authority/persistence migration, MPC modules and claims | Planning |
| Phases 21-23 | required worker, UI, and provisioning cutover | Planning |
| Phase 24 | current-host assembly reconciliation only | Planning |
| Phases 25-26 | Better Auth and IdP | Moved to follow-on plans |
| Phase 27 | final deletion and hardening | Planning |

Foundations A-B and Phases 4-5 may proceed alongside the scoped Phase 6
inventory. No repository-wide inventory gates Phase 7. Each phase performs its
own scoped search before changing shared types and records its deletions before
exit.

The minimal Slice A vertical must pass before Phase 17 starts migrating live MPC
signing. Phases 19-20 form one no-release cutover: a supported build cannot expose
both the old signing authorization flow and the new capability-grant flow.

## Phased Todo Tracker

This is the progress checklist. The phase sections below define scope and exit
conditions. Check a task only after its named implementation and validation are
complete; record supporting commands, commits, and exceptions in the journal.
Granular open-item lists for in-flight work live in the Foundation A/B and
Phase 4/5 sections; symbol-level deletion targets live in the
[deletion ledger](./refactor-90-deletion-ledger.md).

### Current groundwork

- [ ] Tactical Patch 2 passes its remaining exact-local, missing-material,
  persistence-failure, intended-behaviour, audit/timing, and latency acceptance.
- [x] Refactor 91 canonical auth-method domains and exhaustive conversions are
  implemented.
- [ ] Refactor 91 intended-behaviour E2E acceptance passes against a working
  local site.
- [ ] Foundation A canonical hydration types, protocol resolvers, type fixtures,
  and entry-point-equivalence tests are complete.
- [ ] Foundation B canonical ECDSA record, parser, two-state activation journal,
  atomic finalization, exact lane resolver, and legacy-record deletion are
  complete.

### Completed and in-flight phases

- [x] Phase 1 — signer-set registration cut.
- [x] Phase 2 — wallet-rooted confirmation subjects.
- [x] Phase 3 — AuthService mechanical module split.
- [ ] Phase 4 — exact capability-subject hardening closes against Foundation A.
- [ ] Phase 5 — ECDSA role-local material contains no chain, grant, quota,
  nonce, or broad session state.

### Slice A — authorization proving vertical

- [ ] Phase 6 — scoped Slice A inventory and deletion ledger are complete.
- [ ] Phase 7 — current closed capability/evidence vocabulary and exhaustive
  operation mappings compile.
- [ ] Phase 8 — narrow SDK runtime/capability selection fails early for disabled
  server capabilities.
- [ ] Phase 9 — current routes use narrow ports and static assembly; replaced
  facade/helper/parallel paths are deleted.
- [ ] Phase 10 — minimal session, factor, capability, grant, claim, vault, and
  audit schema plus boundary parsers are complete.
- [ ] Phase 11 — native session exchange produces an opaque, correctly bound
  `SeamsSession`.
- [ ] Phase 12 — verified evidence, exact grant issuance, stable fingerprints,
  atomic claim/use, and audit linkage are complete.
- [ ] Phase 13 — management/session routes use exact subjects and no obsolete
  wallet-first policy aliases.
- [ ] Phase 14 — Passkey and Email OTP evidence flow through factor-neutral
  confirmation coordination.
- [x] Phase 15 — service-account work is removed from Refactor 90 and assigned
  to a follow-on plan.
- [ ] Phase 16 — the minimal real session → Passkey evidence → one-use grant →
  vault operation → audit vertical passes end to end.

### Slice B — MPC migration

- [ ] Phase 17 — active signing lanes use exact `WalletAuthAuthorityRef` without
  duplicate identity bags.
- [ ] Phase 18 — ECDSA and Near persistence, two-state recovery, simple
  revocation commands, grants, and wallet quota have canonical owners and strict
  parsers.
- [ ] Phase 18 — persisted capability and material records use opaque material
  activation IDs independently from authorization session IDs.
- [ ] Phase 19 — registration, unlock, refresh, signing, step-up, and export use
  the same capability modules and minimal recovery lifecycle.
- [ ] Phase 19 — activation, hydration, and runtime publication resolve one exact
  `MpcMaterialActivationRef`; `active_state_session_id` and session-shaped
  material locators are deleted.
- [ ] Phase 19 — cancellation, crash recovery, atomic finalization, secret
  disposal, and `superseded` re-resolution tests pass.
- [ ] Phase 19 — the tactical symbols in the deletion ledger owned by this phase
  are deleted in the same changes that replace them.
- [ ] Phase 20 — MPC routes use exact operation grants and atomic absent-claim
  grant/quota consumption; old threshold-session authorization is deleted.
- [ ] Phase 20 — signed MPC operation scopes validate
  `authorizationSessionId` and `materialActivation` independently.
- [ ] Phase 20 — durable execution leases exist only for operations with a
  demonstrated cross-request or cross-worker need.
- [ ] Phase 21 — worker/WASM secret boundaries and required import/export guards
  pass without speculative artifact restructuring.
- [ ] Phase 22 — React, Lit, iframe, and direct SDK adapters exhaustively handle
  the five preparation outcomes.
- [ ] Phase 23 — auth-first per-capability provisioning replaces tactical
  combined cross-curve registration/unlock orchestration.
- [ ] Phase 24 — current Cloudflare, Node, local-test, and self-hosted assembly
  paths use the final static composition and thin adapters.
- [x] Phases 25-26 — Better Auth and IdP are removed from Refactor 90 and
  assigned to follow-on plans.
- [ ] Phase 27 — obsolete code, schemas, fixtures, guards, docs, and exports are
  deleted; final focused validation passes.

### Completion checkpoint

- [ ] Registration, wallet unlock, and page refresh resolve equivalent canonical
  state through the same hydration and exact-lane foundations.
- [ ] A fresh authorization session can use the same exact material activation,
  reactivation creates a new activation ID, and no authorization session ID is
  used as a material locator.
- [ ] No supported build exposes both old and new MPC authorization flows.
- [ ] All open reduction-ledger replacements have implementation evidence.
- [ ] The intended-behaviour E2E matrix and `git diff --check` pass.

## In-Flight Foundations And Completed Work

### Foundation A: Canonical MPC hydration

Implement the four shared outcome names and protocol-local resolvers described
above. Boundary observations remain precise `present | absent | invalid` or
protocol-specific closed unions. Entry-point provenance cannot affect resolver
control flow.

Exit checks (`R90-INV-001`, `R90-INV-002`, `R90-INV-003`, `R90-INV-012`):

- equivalent registration, unlock, and refresh observations choose the same
  outcome;
- missing, mismatched, corrupt, conflicting, and unavailable records fail
  closed;
- exact active material can become live without a new recovery ceremony;
- expired or exhausted public state can request reauthorization without carrying
  secret or bearer data;
- generic modules contain no `passkey` or `email_otp` lane-selection branches.

Open items (nothing from this list is landed at the July 20 checkpoint; the
tactical ECDSA resolver and Ed25519 local rehydration provide protocol evidence
only):

- [ ] leaf hydration module with the four-outcome union and narrow proof
      constructors that reject direct literals, broad spreads, and mixed
      live/sealed/anchor fields;
- [ ] type fixtures rejecting cross-branch combinations (expired state without a
      public anchor, sealed branch without a material activation, live
      branch without runtime proof);
- [ ] Near and ECDSA observation unions parsed from canonical persistence, never
      from entry-point state;
- [ ] table-driven entry-point equivalence tests (registration/unlock/refresh
      against live, sealed-active, expired, exhausted, missing, corrupt,
      conflicting, unavailable) for both capabilities;
- [ ] post-registration -> refresh and post-unlock -> refresh transition tests
      proving only volatile runtime state disappears;
- [ ] routine local rehydration (Passkey and Email OTP) resolves with zero
      Deriver A/B calls.

### Foundation B: Canonical ECDSA state and persistence

Implement the active/retired record, exact parser, volatile runtime observation,
exact lane resolver, and two-state activation journal. Registration, unlock,
reauthorization, recovery, and refresh converge on this one adapter.

Exit checks (`R90-INV-001`, `R90-INV-002`, `R90-INV-005`, `R90-INV-006`,
`R90-INV-011`, `R90-INV-012`, `R90-INV-013`):

- core identity, authority, session, material, persistence, recovery, export,
  and lifecycle fields are required in their valid branch;
- invalid branch combinations fail type checking;
- material, manifest, retirement of a replaced record, and journal deletion
  commit atomically after server activation;
- activation is idempotent and queryable by journal correlation;
- an optional post-commit read uses the canonical parser and creates no durable
  readback state;
- no compatibility reader or timestamp/source-priority selector survives.

Landed groundwork (July 20 checkpoint): encrypted role-local material and
presign records in `seams_wallet` with worker-local live state, and
registration/Email OTP lifecycle repair through the shared tactical resolver.

Open items:

- [ ] required-field `active | retired` record with fixtures rejecting an active
      manifest missing authority, server generation, durable material ref,
      binding digest, or revision;
- [ ] exact persistence parser distinguishing missing, mismatch, conflict,
      corrupt, and unavailable, with exhaustive switches and no
      timestamp/source-priority fallback;
- [ ] two-state activation journal with atomic
      material/manifest/retirement/journal-delete finalization, idempotent and
      queryable by correlation;
- [ ] one activation commit port shared by registration and unlock; Email OTP
      unlock commits through it with no second writer;
- [ ] refresh after worker destruction observes runtime `absent` and resolves
      `rehydrate_material_activation`;
- [ ] persisted activation identity uses a branded `MpcMaterialActivationId`
      independently from every authorization or Wallet Session ID;
- [ ] legacy `ThresholdEcdsaSessionRecordCore` family deleted (see the
      [deletion ledger](./refactor-90-deletion-ledger.md));
- [ ] end-to-end: real write, destroy runtime, reopen persistence, hydrate,
      sign — for one-target and shared EVM-family configurations.

### Phases 1-3: Completed cuts

Keep the completed signer-set registration cut, wallet-rooted confirmation
subjects, and mechanical AuthService split intact. Later route-port work deletes
the remaining facade/helper pair in the same change; it does not add a third
implementation.

### Phase 4: Exact capability subjects

Complete the current exact-subject hardening needed by Foundation A and the
operation envelope. Do not expand into future identity-provider or device
management schemas.

Done so far: NEAR Ed25519 unlock requires the exact
`nearAccountId`/`nearEd25519SigningKeyId`/`signerSlot` subject, and page-reload
unlock resolves from durable wallet signer records when runtime session records
are empty.

Open items:

- [ ] ECDSA-only wallet unlock reads no NEAR account identity (`toAccountId`,
      NEAR projections, operational keys);
- [ ] combined NEAR+ECDSA unlock warms branches from a typed
      `WalletUnlockSubjectSet`; no flattened wallet/NEAR/ECDSA identity object;
- [ ] page-refresh session restoration resolves subjects through the same
      resolver for NEAR-only, ECDSA-only, and combined wallets;
- [ ] session/login display split from per-capability readiness; an active
      restored login coexists with capability `recovery_required`;
- [ ] registered NEAR identity survives absent lane, grant, quota, and live
      Client state;
- [ ] delete `nearAccountId`-inference fallbacks, the
      `login.publicKey ? 'passkey' : null` auth-method inference, and silent
      signer-slot defaults;
- [ ] focused tests: post-registration inventory publication, ECDSA-only
      unlock, combined unlock, ECDSA-only/combined page-reload session reads,
      missing/ambiguous-profile demotion, active login with no live Yao Client.

### Phase 5: ECDSA role-local material slimming

Remove chain target, operation authorization, wallet quota, nonce, and broad
session state from role-local material. Preserve worker-only plaintext ownership,
opaque handles, TTL cleanup, validation, zeroization, and `finally` disposal.

Done so far: `evmFamilySigningKeySlotId` is removed from the role-local
identity/handle builders and their call sites, with a focused regression test.

Open items:

- [ ] `buildEcdsaRoleLocalMaterialIdentity()` and its handle/digest builders
      accept no `chainTarget`, `walletId`, `thresholdSessionId`,
      `activeStateId`, grant, quota, remaining-use, or expiry input;
- [ ] `evmFamilySigningKeySlotId` is deleted from runtime paths or renamed to a
      provisioning reservation confined to registration/bootstrap (audit first;
      see the [deletion ledger](./refactor-90-deletion-ledger.md));
- [ ] `clientVerifyingShareB64u` renamed to `clientVerifyingPublicKey33B64u` on
      ECDSA role-local surfaces (Ed25519 naming is out of scope);
- [ ] role-local material handles are stable across Tempo/ARC for the same
      material; cross-chain signing fails closed through lane/session
      validation before worker material opens;
- [ ] `activeStateId` appears only in Router A/B state/admission helpers and
      request builders;
- [ ] focused tests: same-material cross-chain reuse, cross-chain mismatch
      rejection, reload-restored material, registration-created material.

## Slice A: Prove The Shared Authorization Path

### Phase 6: Scoped inventory and deletion ledger

For the files touched by Phases 7-16:

- locate current auth/session/grant/vault route and persistence owners;
- classify current shared types and public exports that the slice changes;
- identify duplicate AuthService/facade/helper paths to delete;
- identify obsolete tests and fixtures;
- record target owner, action, and one validation check.

Generate the inventory through `rg`, type errors, and route/export maps. Do not
enumerate unrelated apps, docs, schemas, workers, or future capabilities. Repeat
a scoped inventory at the start of Slice B.

Seed each scoped inventory from the standing
[deletion ledger](./refactor-90-deletion-ledger.md), which carries the
symbol-level deletion targets reconstituted from the pre-slim plan.

### Phase 7: Current capability vocabulary

Create closed leaf unions for only the capabilities and operations implemented by
the minimal vault slice and the two MPC modules. Keep `WalletAuthMethod` and
`SignerAuthMethod` in their stable Refactor 91 shared leaf module while both SDK
and server consume them. Ownership purity alone does not justify moving them.

Introduce exact tenant, principal, session, factor, capability, operation,
grant, and evidence references required by the current verticals. Use named or
flat `all | any` evidence requirements. Do not add recursive policy expressions,
service-account evidence, provider-assurance taxonomies, IdP operations, Slack
OTP, or an implemented `mpc_signer_proof` producer.

The Refactor 82B `WalletAuthAuthority` restructure lands as one coordinated cut
with this phase: stage the 82B domain types and fixtures dark first, then flip
imports and delete the old wallet-auth shapes in the same change
([refactor-82B.md](./refactor-82B.md)).

### Phase 8: Narrow SDK runtime surface

Expose only the runtime and capability selection required by hosted wallet mode,
the minimal vault call, and MPC operations. Server tenant configuration remains
authoritative. Disabled capability requests fail early and typed.

### Phase 9: Route service ports and static assembly

Replace route-facing `Pick<AuthService, ...>` dependencies with narrow typed
ports. Cloudflare and Node use the same fetch-style handlers through thin
adapters. Delete replaced facade/helper/parallel route paths in the same change.

Use one static composition module with explicit imports. Do not introduce a
runtime-neutral plugin registry, tenant-mutated route table, or deployment module
selection framework. Optional modules can be added to static assembly when they
exist.

### Phase 10: Minimal Slice A schema

Add only the persistence required for:

- Seams sessions and exchange codes;
- current auth-factor records;
- capability instances and bindings;
- operation grants, uses, and claims;
- the minimal vault record;
- authorization audit events.

Defer service accounts, Better Auth, IdP, generalized device management, full
vault administration, and future capability rows. Migrations validate and
normalize raw rows once at their adapter.

### Phase 11: Native session exchange

Implement the native session-provider port and opaque `SeamsSession`. Bind the
session to the current tenant, principal, audience/origin, and the minimum device
fact required by the security decision. Session transport remains separate from
operation authorization.

### Phase 12: Authorization core

Implement verified evidence construction, exact operation-grant issuance,
stable operation fingerprints, atomic claim/use behavior, and audit linkage for
the operations currently in scope. `mpc_signer_proof` policy evaluation fails
closed until a producer is designed.

Invariants: `R90-INV-001`, `R90-INV-009`.

### Phase 13: Management and session route policy

Move management and session routes to exact subject and session policies. Keep
management authorization separate from capability-operation grants. Delete old
wallet-first policy aliases and fixtures.

### Phase 14: Grant evidence and confirmation UI

Implement operation-bound Passkey evidence and the existing Email OTP evidence
needed by current MPC flows. The minimal vault E2E acceptance uses Passkey.
Generic coordination consumes verified evidence and contains no factor-kind
branch. Slack OTP and provider adapters remain follow-on work.

### Phase 15: Service accounts

Moved to a follow-on plan. No service-account schema, evidence kind, policy, API
key flow, or test blocks Slice A or Slice B.

### Phase 16: Minimal vault integration

Implement one production-shaped proxy/reveal vertical proving:

1. native session exchange;
2. operation-bound Passkey evidence;
3. one-use exact grant issuance and claim;
4. one vault operation;
5. an auditable terminal result.

Exclude delegation, rotation, break-glass, export, broad administration,
service-account use, and complex UI. Exit requires the real persistence and
route adapters, rather than a mock capability, so Slice B consumes a proven
authorization core.

Invariants: `R90-INV-009`, `R90-INV-012`.

## Slice B: Migrate MPC Capabilities

### Phase 17: Exact wallet authority references

Replace factor strings and inferred wallet-auth identity on signing lanes with
boundary-constructed `WalletAuthAuthorityRef`. Put the authority on the canonical
capability/material owner and pass narrow prepared contexts downward. Avoid
threading a duplicate identity bag through every internal helper.

### Phase 18: Wallet vocabulary and persistence migration

Run a scoped inventory for wallet, session, grant, quota, recovery, and material
records. Delete obsolete wallet-first tests and records. Preserve Refactor 91's
stable auth-method leaf domains.

Implement:

- canonical ECDSA active/retired persistence from Foundation B;
- exact Near public locator, sealed active-client record, and sealed recovery
  source;
- the two-state Near recovery journal;
- one simple revocation command outbox when offline server reconciliation is
  required;
- independent operation grants and `MpcWalletSigningQuota`;
- a branded `MpcMaterialActivationId` and exact activation reference persisted
  with each active capability/material manifest, separate from
  `SeamsSessionId`;
- strict boundary parsers with no dual-schema core reader.

`signingGrantId` is classified and deleted, mapped to operation grant, or mapped
to wallet quota according to semantics. It is never mechanically renamed or used
as material identity.

The persisted/request cutover replaces `active_state_session_id` and any
threshold-session-derived material locator with the exact activation reference.
There is no compatibility alias in core types. Activation records created before
the cutover may be rejected at the persistence boundary; development accounts
can be recreated after the schema and protocol version advance.

Invariants: `R90-INV-001`, `R90-INV-002`, `R90-INV-005`, `R90-INV-006`,
`R90-INV-013`. The record and symbol deletion targets are enumerated in the
[deletion ledger](./refactor-90-deletion-ledger.md).

### Phase 19: MPC capability modules

Create Near Ed25519 and EVM-family ECDSA capability modules. Both consume
Foundation A outcomes, exact authorities, and protocol-local material adapters.
Registration, unlock, refresh, signing, step-up, and export contain no
entry-point-specific material branch.

Near recovery follows the two-state journal and server invariants in the SPEC:

1. inspect canonical source and journal state without effects;
2. collect required authorization outside the material-owner queue;
3. acquire the owner queue and re-resolve exact current state;
4. persist `prepared` before the first consuming server call;
5. reconcile idempotent/queryable admission, acquisition, and promotion by
   `recoveryId`;
6. persist `promotion_committed` when promotion is irreversible;
7. atomically finalize local durable state and delete the journal;
8. construct or publish runtime state and re-resolve the exact lane;
9. return `superseded` if authority or lifecycle changed.

Cancellation CAS-updates `prepared.disposition` to `cancel_requested`. Reload
never silently resumes user-abandoned work. Pre-promotion cancellation cleans up
after server reconciliation. Post-promotion cancellation cannot undo committed
authority; it finishes safe local convergence without executing the parent
operation.

All live secret handles remain worker-private, purpose-bound, and one-use.
Disposal and zeroization cover success, failure, cancellation, expiry,
supersession, and abandoned-handle TTL cleanup. They do not appear in the
durable journal.

The capability module owns activation identity. Registration or explicit
re-activation creates a new opaque activation ID and binds it to the capability,
material owner, key, lifecycle, and SigningWorker. Unlock, refresh, and step-up
may mint fresh authorization sessions while preserving that exact activation
reference. They never derive material identity from the fresh session ID.
Hydration returns the same activation reference for live and sealed copies of
the same exact material.

Invariants: `R90-INV-002`, `R90-INV-003`, `R90-INV-004`, `R90-INV-005`,
`R90-INV-006`, `R90-INV-007`, `R90-INV-008`, `R90-INV-010`, `R90-INV-011`,
`R90-INV-013`.
The tactical resolver, lane, reconnect, recovery, and export symbols this phase
deletes are enumerated in the
[deletion ledger](./refactor-90-deletion-ledger.md).

### Phase 20: MPC route policy and operation claims

Replace threshold-session authorization planes with exact capability-operation
grants. Existing-claim lookup occurs before fresh authorization or recovery.
Only an absent claim can consume new grant/quota resources.

The server atomically validates current promotion/revocation state, consumes the
exact grant and applicable quota, creates the claim, and writes audit linkage.
Add execution phases, leases, watchdogs, or delivery reconciliation only to
operations whose real execution can outlive the request or transfer between
workers. Client material-owner queues and server operation claims remain separate
domains.

Every signed MPC operation scope carries two independent proofs:

- `authorizationSessionId` identifies the current active `SeamsSession` and is
  checked for expiry, audience, device, and evidence policy;
- `materialActivation` identifies the exact activated material instance and is
  checked against the capability, owner, key, lifecycle, generation, and
  SigningWorker state.

The wire protocol replaces generic `session_id` and
`active_state_session_id` fields with these explicit domains and advances its
version and transcript vectors. A session refresh changes only authorization.
Material re-activation changes only the activation reference. Neither value is
accepted as a substitute for the other.

Invariants: `R90-INV-008`, `R90-INV-009`, `R90-INV-013`.

### Phase 21: Worker and bundle boundaries

Preserve responsibility-local secret ownership:

- generic confirmation receives no MPC material;
- Email OTP enrollment secret and KEKs remain in its secure worker;
- Near root and active Client material remain in the Near secure owner;
- ECDSA derivation, presign, and online signing remain separated where their
  secret ownership or existing artifacts require it.

Split or consolidate additional artifacts only when a trust boundary or measured
bundle/latency result justifies it. Keep import/export guards for worker and WASM
boundaries that TypeScript cannot express.

### Phase 22: Wallet UI migration

Migrate React, Lit, iframe, and direct SDK adapters to the exact preparation
outcomes. UI may render provenance and diagnostics but cannot choose material,
recovery, authorization, or lane branches. `superseded` discards stale prepared
state and initiates exact re-resolution.

Invariants: `R90-INV-010`.

### Phase 23: Auth-first provisioning

Registration and add-factor flows create auth identity first, then provision
each requested capability independently. Each capability commits through its
canonical persistence owner. Partial provisioning returns exact per-capability
results and does not create a combined cross-curve active record.

The tactical Email OTP registration/unlock coordination from Patch 2 is deleted
after its exact-local and missing-material behavior is preserved by the two
capability modules.

### Phase 24: Current-host assembly reconciliation

Update current Cloudflare, Node, local test, and self-hosted paths that directly
construct the replaced services. Keep one static route composition model and thin
host adapters. Broader example matrices and a generic route-module framework are
follow-on work.

### Phases 25-26: Better Auth and IdP

Moved to their own plans. Refactor 90 retains only provider-neutral session and
evidence boundaries needed to permit later adapters. No placeholder handlers,
future capability kinds, schemas, or conformance suites are required now.

### Phase 27: Final deletion and hardening

Delete:

- `ThresholdEcdsaSessionRecordCore` and equivalent optional aggregates;
- source-priority and newest-record selection;
- entry-point-specific registration/unlock/refresh material branches;
- duplicate persistence owners and compatibility readers outside explicit raw
  request/persistence boundaries;
- old signing-grant/budget/session aliases;
- replaced AuthService facade/helper/route paths;
- obsolete tests, fixtures, mocks, guards, docs, and public exports;
- synthetic-factor scaffolding and placeholder future capability handlers.

Run export-map and dependency checks, focused security-sensitive integration
tests, intended-behaviour E2E tests, and `git diff --check`.

## Validation Strategy

### Static and unit checks

Covers `R90-INV-001`, `R90-INV-009`, `R90-INV-010`, `R90-INV-012`.

- Invalid lifecycle combinations fail type checking.
- Core identity, authority, material, session, signing, recovery, export, and
  quota fields are required in their valid branch.
- Raw DB, request, token, worker, and IndexedDB data is parsed once.
- Auth-method conversions remain exhaustive and unsupported protocols fail
  closed.
- Generic preparation/coordination modules contain no factor-kind lane branches.
- Operation fingerprints exclude rotating grant/quota/session/runtime IDs.
- `superseded` cannot be treated as ready, pending, or generic retry.

### Persistence and crash tests

Covers `R90-INV-004`, `R90-INV-005`, `R90-INV-006`, `R90-INV-007`,
`R90-INV-011`.

- ECDSA activation is idempotent by journal correlation.
- Near admission, acquisition, and promotion are independently idempotent and
  queryable by `recoveryId`.
- Crash/reload from `prepared` queries server state before doing anything else.
- `cancel_requested` never silently resumes the abandoned parent operation.
- Crash after promotion resumes from the exact receipt without repeating
  acquisition or promotion.
- Local finalization atomically persists the replacement/retirement/lifecycle
  facts and deletes the journal.
- Transaction abort leaves the old source and journal eligible for
  reconciliation.
- Optional post-commit canonical reads create no persisted readback state.

### Concurrency tests

Covers `R90-INV-008`, `R90-INV-009`.

- Recovery, signing, refresh, and export serialize per exact material owner.
- A stale generation/fence cannot commit after replacement or revocation.
- Different material owners progress independently.
- User interaction occurs outside the material-owner queue.
- Existing operation claims do not consume renewed grants or quotas.

### Intended-behaviour E2E

Covers `R90-INV-003`, `R90-INV-010`, `R90-INV-012`.

Keep a small matrix:

- registration immediately followed by signing;
- wallet unlock immediately followed by signing;
- page refresh followed by concurrent signing;
- exact local rehydration without Yao recovery;
- missing-material recovery followed by signing;
- corrupt or mismatched material failing closed;
- stale lane returning `superseded` and resolving the replacement;
- one minimal vault session/evidence/grant/operation/audit vertical.

Passkey and Email OTP cover the real factor paths. No synthetic third-factor E2E
suite is required.

## Implementation Checkpoint Order

Create stable commits at these boundaries:

1. current tactical patches and Refactor 91 validation;
2. Foundations A-B types, parsers, persistence adapters, and focused tests;
3. minimal Slice A authorization/vault vertical;
4. exact authority and persistence migration;
5. Phase 19-20 no-release MPC cutover;
6. worker/UI/provisioning migration;
7. final deletion and public-surface hardening.

Do not combine an unfinished recovery-state rewrite with unrelated Better Auth,
IdP, service-account, full-vault, route-framework, or bundle-optimization work.

## Open Decisions

| Decision | Blocking point | Default until decided |
| --- | --- | --- |
| Which MPC capability produces `mpc_signer_proof`? | its follow-on implementation | deny all policies requiring it |
| Does the current session threat model require device binding? | Phase 10 schema freeze | retain only the minimum existing binding; move broader management out |
| Which operations require durable server execution leases? | Phase 20 per-operation review | request-bound claim without lease |

## Related Plans

- [Refactor 90 deletion ledger](./refactor-90-deletion-ledger.md)
- [Refactor 90A patches](./refactor-90A-patches.md)
- [Email OTP local rehydration](./refactor-patch-2-email-otp-local-rehydration.md)
- [Refactor 91 auth-method domains](./refactor-91.md)
- [Refactor 82B authority typing](./refactor-82B.md)
- [Refactor 85 IndexedDB minimization](./refactor-85-indexedDB.md)
- [Ed25519 Yao implementation plan](./router-ab/ed25519-yao/implementation-plan.md)
- [Refactor 101 enterprise SSO](./refactor-101-enterprise-sso.md)

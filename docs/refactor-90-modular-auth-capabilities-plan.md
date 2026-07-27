# Refactor 90: Modular Auth Capabilities — Implementation Plan

Created: 2026-06-28

Consolidated: 2026-07-27

Status: **in progress — Unit 1 implementation and Unit 3b complete; Unit 2
operating core complete; Units 3a and 4 in progress**

This document is the execution tracker for
[the normative SPEC](./refactor-90-modular-auth-capabilities-SPEC.md). If this plan
and the SPEC diverge, the SPEC controls.

Operational records:

- [implementation journal](./refactor-90-journal.md)
- [deletion ledger](./refactor-90-deletion-ledger.md)
- [signer-state inventory](./signer-state-inventory.md)

## Verification Budget

This budget is binding across every unit and overrides broader verification
language elsewhere in the plan or SPEC.

- Make the operating path work and demonstrate it once before adding secondary
  verification or abstractions.
- Use one enforcement per failure mode. A compiler-enforced property gets a type
  fixture, without a duplicate unit test, source guard, or E2E case.
- Add no new `check-*.mjs` source guards. Extend an existing guard only for a
  worker-secret, generated-WASM, or workspace-package boundary the type system
  cannot observe.
- Prefer type fixtures in `tests/typecheck/` for construction-time constraints.
- Refactor 90 E2E is capped at the eight scenarios listed below. Refactor 92
  behavior is checked by running its existing contracts.
- No unit produces an inventory or justification document. Add a deletion-ledger
  row only when implementation discovers a concrete replacement target.
- This plan owns task status. The SPEC checklist owns invariant-conformance
  evidence. Update only the applicable surface.
- Removing scope requires no ledger row, replacement check, or separate
  justification.

## Grounding

Refactor 90 builds on behavior already established by:

- [Refactor 91](./refactor-91.md): canonical auth domains and exhaustive
  conversions;
- [Refactor 92](./refactor-92-session-expiry-handling.md): the signing-session
  lifecycle, which is frozen for this refactor;
- [Refactor 93](./refactor-93.md): request-scoped server routing and gateway
  ownership;
- [Email OTP local rehydration](./refactor-patch-2-email-otp-local-rehydration.md):
  the current local-material recovery boundary.

Refactor 90 must preserve those behaviors. It replaces temporary shapes and
duplicated transitions without reopening their product semantics.

## Goal

Make signer selection, authorization, material hydration, persistence, and
operation execution use one precise capability model across registration,
wallet unlock, page refresh, signing, and export.

The completed system must:

1. resolve the exact wallet, authorization session, and material activation;
2. distinguish live runtime use, local rehydration, public-anchor
   reauthorization, and blocked state;
3. persist only durable state and keep secret material in its intended owner;
4. claim authorization and reusable-session quota atomically;
5. use the same lifecycle rules for Passkey and Email OTP;
6. remove replaced paths in the same change that installs their replacement.

## Scope

### Included

- canonical hydration and ECDSA session/material state;
- shared authorization, evidence, grant, claim, and audit primitives;
- capability selection at SDK and server boundaries;
- MPC signing and export cutover;
- the minimal vault proving slice owned by the Satyr plan;
- UI confirmation and provisioning integration;
- worker, WASM, host-assembly, and persistence boundary enforcement;
- removal of obsolete aliases, record families, routes, fixtures, and guards.

### Follow-on context

These remain separate plans unless a narrow interface is required here:

- enterprise SSO and Better Auth integration;
- delegate wallets and delegated-agent linked-device behavior;
- service-account product behavior;
- broad vault product surface;
- new MPC protocols or production advancement of the Yao backend.

Refactor 90 may consume the current Yao interfaces. The
[Ed25519 Yao implementation plan](./router-ab/ed25519-yao/implementation-plan.md)
owns its cryptographic and production gates; Refactor 90 cannot redefine that
backend or advance its production status ahead of those gates.

## Normative Architecture Index

The SPEC contains the definitions and proof obligations. This table assigns
their implementation ownership without restating them.

| Decision                                         | Normative invariants                                                                     | Owning unit        | Load-bearing result                                                                                         |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------- |
| Exact subject resolution and canonical hydration | `R90-INV-001`, `R90-INV-002`, `R90-INV-003`                                              | Units 1 and 3a     | Unit 1 establishes the shared contract and ECDSA adapter; Unit 3a supplies the canonical Near adapter.      |
| ECDSA persistence and activation identity        | `R90-INV-001`, `R90-INV-002`, `R90-INV-005`, `R90-INV-006`, `R90-INV-011`, `R90-INV-013` | Unit 1             | Required `active \| retired` records and stable material activation identity replace optional session bags. |
| Durable recovery journals                        | `R90-INV-004`, `R90-INV-005`, `R90-INV-006`, `R90-INV-007`                               | Units 1 and 3a     | Durable state records server uncertainty and final material promotion only.                                 |
| Preparation outcomes                             | `R90-INV-010`                                                                            | Units 3a and 4     | Every preparation ends as `ready`, `pending`, `authorization_required`, `superseded`, or `failed`.          |
| Material serialization and secret ownership      | `R90-INV-008`                                                                            | Unit 3a            | Workers and WASM own live secret material; generic code receives typed references.                          |
| Evidence, grants, operation claims, and quota    | `R90-INV-009`                                                                            | Units 2 and 3a     | One fingerprint and one atomic claim govern retries and reusable-session use.                               |
| Revocation and session expiry                    | `R90-INV-006`, `R90-INV-009`, `R90-INV-013`, `R90-INV-014`                               | Units 1, 3a, and 4 | Authorization, material activation, and operation grants remain separate identities.                        |
| Minimal vault proof                              | `R90-INV-009`, `R90-INV-012`                                                             | Unit 3b            | One real secret operation proves the shared authorization core.                                             |
| Boundary enforcement                             | `R90-INV-012`                                                                            | All units          | Each failure mode has one cheapest effective enforcement.                                                   |

## Load-Bearing State Index

Keep these SPEC-defined state families intact during consolidation:

- hydration:
  `use_live_runtime | rehydrate_material_activation | reauthorize_public_anchor | blocked`;
- ECDSA records: required `active | retired`;
- ECDSA activation journal:
  `activation_prepared | server_activation_committed`;
- NEAR recovery journal: `prepared | promotion_committed`, with cancellation as
  the prepared disposition;
- preparation:
  `ready | pending | authorization_required | superseded | failed`;
- operation authorization: reusable-session authority or one-operation step-up
  authority, plus an independent exact material-activation reference.

The SPEC owns every branch payload, parser, transition, and atomicity rule.

## Execution Model

The old phase numbers remain useful for history and the deletion ledger. Active
work is tracked in five units.

| Unit                                               | Consolidates                                             | Dependency                                    | Result                                                                                                             |
| -------------------------------------------------- | -------------------------------------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **1. Canonical hydration + canonical ECDSA state** | Foundations A/B, Phases 4–5, ECDSA identity work from 18 | Implementation complete; exit validation open | Exact subjects, protocol-local resolvers with shared outcomes, required ECDSA state, and slim material references. |
| **2. Shared authorization core**                   | Phases 7–14, including Phase 8 SDK selection             | Operating core complete; cleanup gate open    | Closed capability vocabulary plus DB-backed session → evidence → grant → claim → audit flow.                       |
| **3a. MPC cutover — no release**                   | Phases 17–21 and 24                                      | In progress                                   | All MPC operations use the shared core; legacy and replacement paths do not ship together.                         |
| **3b. Vault proving vertical**                     | Phase 16                                                 | Complete                                      | [Satyr vault plan Phase 6](./satyr-secrets-vault.md) proves one real vault operation.                              |
| **4. UI + provisioning**                           | Phases 22–23                                             | Started; typed expiry complete                | Typed lifecycle events and provisioning use the canonical capability model.                                        |

Units 3a and 3b may be implemented in parallel after Unit 2 interfaces
stabilize. Unit 3b does not block development of the MPC cutover. Supported
release and Refactor 90 completion still require both proving tracks unless the
SPEC and Satyr plan are amended together.

### Historical phase disposition

| Previous phase          | Current disposition                                                                                         |
| ----------------------- | ----------------------------------------------------------------------------------------------------------- |
| 1–3                     | Completed baseline retained below.                                                                          |
| 4–5 and Foundations A/B | Merged into Unit 1.                                                                                         |
| 6                       | Removed. The existing deletion ledger seeds implementation directly.                                        |
| 7–14                    | Merged into Unit 2.                                                                                         |
| 15 and 25–26            | Follow-on context, outside active execution.                                                                |
| 16                      | Unit 3b, with detailed execution owned by Satyr Phase 6.                                                    |
| 17–20                   | Merged into Unit 3a.                                                                                        |
| 21                      | Worker/bundle acceptance checks inside Unit 3a.                                                             |
| 22–23                   | Merged into Unit 4.                                                                                         |
| 24                      | Host call-site migration inside the Unit 3a cutover.                                                        |
| 27                      | Removed as a work phase; same-change deletion is enforced per unit, followed by the final conformance gate. |

## Working Rules

1. Make the requested operating path work first. Use the deletion ledger to
   locate known targets and append concrete targets discovered while coding.
2. Delete a replaced path in the same change that installs its replacement.
   Close the corresponding deletion-ledger row in that unit.
3. Validate raw DB, request, worker, UI, and decoded-token shapes once at their
   boundary. Core code accepts precise domain types.
4. Keep compatibility logic only at an intentional persistence or request
   boundary, with an explicit deletion owner.
5. Use one enforcement per failure mode: a type fixture for invalid state, a
   boundary parser for untrusted data, a behavior test for lifecycle behavior,
   and a source guard only for an architectural boundary types cannot express.
6. Record stable checkpoints and genuine blockers in the journal.

## Completed Baseline

- [x] Phase 1: signer-set registration cut.
- [x] Phase 2: wallet-rooted confirmation subjects.
- [x] Phase 3: AuthService mechanical module split.
- [x] Refactor 91 auth-domain cutover is treated as current behavior.
- [x] Refactor 92 signing-session lifecycle is frozen.
- [x] Refactor 93 request-scoped gateway ownership is the server baseline.

## External Acceptance Gates

These checks depend on deployment or environment state and do not authorize
parallel compatibility paths.

- [ ] Verify the effective 24-hour Wallet Session default in staging.
- [ ] Verify the effective 24-hour Wallet Session default in production.
- [ ] Patch 2 records its remaining timing, manual, audit, and intended-behavior
      evidence.
- [ ] Refactor 91 intended-behavior acceptance passes against a healthy site.
- [ ] Refactor 92 network traces prove expiry never invokes Yao recovery or
      device linking.
- [ ] Refactor 93 hosted recovery and latency acceptance passes before Near
      release.
- [ ] Run the intended-behavior suite against a healthy local or deployed site.
- [ ] Complete required Yao production gates before claiming Yao production
      readiness.

## Unit 1 — Canonical Hydration + Canonical ECDSA State

Invariants: `R90-INV-001`, `R90-INV-002`, `R90-INV-003`,
`R90-INV-005`, `R90-INV-006`, `R90-INV-011`, `R90-INV-012`,
`R90-INV-013`, `R90-INV-014`.

### 1A. Exact subjects and secure-origin projections

- [x] ECDSA unlock resolves through an isolated subject resolver.
- [x] Mixed or ambiguous ECDSA subjects are rejected.
- [x] App identity, authorization-session identity, readiness, and material
      activation are separate projections.
- [x] The secure wallet origin returns the exact active or restorable wallet and
      session projection.
- [x] NEAR session state survives without an inferred signing lane.
- [x] Replace combined optional wallet-unlock bags with an exhaustive subject
      union.
- [ ] Make registration, unlock, and refresh enter the protocol-local resolver
      for each capability and return the shared outcome union.
- [ ] Delete JWT-presence, optional-ID, and authentication-method lane
      inference.
- [x] Add boundary and lifecycle tests for missing, mixed, stale, and exact
      subjects.

### 1B. Canonical hydration

- [x] Define the protocol-neutral four-outcome hydration union.
- [x] Add branch-specific builders and type fixtures that reject invalid
      combinations.
- [x] Normalize ECDSA observations once into the shared hydration input.
- [ ] Prove entry-point provenance is absent from resolver input, then cover the
      seven canonical states for each capability: live, sealed-active, retired,
      missing, corrupt, conflicting, and unavailable.
- [ ] Delete protocol-specific derivation and duplicate readiness helpers after
      their callers move.
- [x] Verify there is one hydration decision for Passkey and Email OTP.
- [x] Prove routine Passkey/OTP local rehydration makes zero Deriver A/B calls.
- [x] Fail closed for missing, mismatched, corrupt, conflicting, or unavailable
      canonical observations.

Near normalization begins Unit 3a after its session-shaped persistence and
runtime identity are replaced. An adapter over `thresholdSessionId` or
`activeStateSessionId` would preserve the identity coupling this refactor
removes.

### 1C. Canonical ECDSA record and activation journal

- [x] Define the required `active | retired` record and rejection fixtures.
- [x] Persist the current manifest pointer independently of authorization
      session state.
- [x] Parse persisted state into exact internal records at the IndexedDB
      boundary.
- [x] Introduce branded material-activation identity independent of
      `authorizationSessionId`.
- [x] Reduce the activation journal to two states: `activation_prepared` and
      `server_activation_committed`.
- [x] Make server activation idempotent and queryable by journal correlation.
- [x] Prove finalized encrypted material survives worker termination and a
      fresh worker rehydrates the same durable material reference.
- [x] Implement selector-scoped store/worker reconciliation for prepared and
      server-committed journals; prepared remains pending and committed reuses
      the canonical atomic finalizer.
- [x] Invoke reconciliation after refresh/unlock once the exact-subject cut
      supplies `CapabilityInstanceRef + WalletAuthAuthorityRef`; do not infer
      either identity from legacy session fields or resume an abandoned parent
      registration/add-signer operation.
- [x] Route every activation through one commit port.
- [x] Finalize replacement, retire the source, and delete the journal in one
      IndexedDB transaction.
- [x] Rehydrate the same exact material activation across refresh while
      authorization session identity may change.
- [x] Remove canonical material ownership, material readers, and material
      writers from the legacy `ThresholdEcdsaSessionRecord*` family; forbid new
      legacy material writes.
- [x] Reject and clear pre-cutover development records at the persistence
      boundary; add no dual-schema core reader, alias, or fallback.
- [x] Prove persisted hydration → worker bind → sign through the shared path.

### 1D. Slim material references

- [x] Keep broad session state out of live material handles.
- [x] Use a branded public-key representation at the material boundary.
- [x] Add fixtures rejecting raw strings, broad spreads, and forged material
      references.
- [x] Keep role-local material handles stable across Tempo and ARC for the same
      exact activated material.
- [x] Remove raw share bytes and broad state objects from generic callers.
- [ ] Delete `evmFamilySigningKeySlotId` from runtime paths or prove it is a
      provisioning-only identifier outside material selection.
- [x] Verify Tempo, EVM, and export consumers use the same durable material
      reference.
- [x] Reject cross-chain mismatch before worker open or material use.
- [x] Confine any transitional `activeState` shape to its boundary and schedule
      its same-unit deletion.

### Unit 1 exit

- [ ] Every deletion-ledger entry assigned to Unit 1 is closed; ownership
      corrections are recorded before implementation.
- [ ] One type fixture proves registration, unlock, and refresh provenance cannot
      affect resolver input; fourteen state cases cover both capabilities.
- [x] Required-field and invalid-state type fixtures pass.
- [ ] IndexedDB crash tests prove atomic activation finalization.
- [ ] Focused intended-behavior tests preserve refresh allowance and exact
      material rehydration.

## Unit 2 — Shared Authorization Core

Invariants: `R90-INV-001`, `R90-INV-009`, `R90-INV-012`,
`R90-INV-013`.

### Completed inputs

- [x] Refactor 91 supplies the closed capability, operation, evidence, signer
      auth, and wallet-authority vocabularies with boundary parsers and type
      fixtures.
- [x] Refactor 93 supplies the static shared route graph and request-scoped
      `MPC_ROUTER` ownership used by Cloudflare, Node, local, and self-hosted
      execution.
- [x] The existing app-session exchange and provider-verification boundary is
      the transport entry point to extend.
- [x] Existing D1 CAS batches and Wallet Session budget tests provide the
      transaction pattern; they are not the new authorization domain.

### Closed vocabulary and selection

- [ ] Adopt the existing closed capability vocabulary in production SDK,
      server, UI, and persistence boundaries.
- [ ] Include only the tenant, principal, session, factor, capability,
      operation, grant, and evidence references required by current verticals.
- [ ] Use named or flat `all | any` evidence requirements; add no recursive
      policy grammar or speculative factor/provider taxonomy.
- [x] Preserve Refactor 82B `WalletAuthAuthority` types and fixtures as the
      baseline instead of restaging that cut.
- [x] Make SDK capability selection exhaustive and reject implicit fallbacks.
- [x] Make disabled capability requests fail early with a typed result.
- [x] Keep protocol, auth method, capability, and lifecycle as separate unions.
- [ ] Remove duplicate aliases and direct string comparisons from generic code.
- [x] Add type fixtures for invalid capability/auth/protocol combinations.

### Ports and host-independent assembly

- [x] Define narrow request-scoped ports for capability policy, session,
      evidence, grants, claims, and audit.
- [ ] Keep Cloudflare, Node, local, and self-hosted adapters behind the same
      static port shapes.
- [x] Use one statically composed module graph; add no runtime plugin registry,
      tenant-mutated route table, or deployment module-selection framework.
- [x] Preserve Refactor 93 gateway ownership and `MPC_ROUTER` request-scoped
      binding.
- [x] Reject tenant-runtime service locators and direct infrastructure roles in
      domain handlers.

### Authorization data model

- [x] Persist precise records for session exchange codes, authorization
      sessions, factor evidence, capability instances/bindings, operation
      grants, operation claims, and audit events.
- [x] Implement opaque native session exchange bound to tenant, principal,
      audience/origin, and the minimum required device fact.
- [x] Keep session transport and management authorization separate from
      capability-operation grants.
- [x] Normalize DB and route data once into required-field domain unions.
- [x] Define the stable operation fingerprint from operation semantics without
      rotating authorization, quota, session, or runtime identities.
- [x] Atomically create an absent claim, consume its grant, and consume reusable
      quota when the operation declares quota use.
- [x] Make repeated claims return the recorded outcome without double
      consumption.
- [x] Keep export quota-neutral.
- [x] Keep step-up grants single-operation and incapable of creating a reusable
      Wallet Session.

### Shared authorization behavior

- [x] Passkey and Email OTP create the same evidence and grant shapes.
- [x] Bind Passkey and existing Email OTP evidence to the exact operation.
- [x] Policy evaluates declared capability, operation, factor evidence, and
      current authorization state.
- [x] Fail `mpc_signer_proof` policy evaluation closed until a verified producer
      exists.
- [x] Audit records the decision and identifiers without secret material.
- [ ] Move management and session routes to exact subjects, keep their policy
      separate from operation grants, and delete wallet-first policy aliases.
- [x] One DB-backed integration test proves
      session → evidence → grant → claim → audit before Units 3a/3b depend on the
      core.
- [x] Keep the no-factor-literal guard in generic preparation and coordination
      modules.

### Unit 2 exit

- [ ] Every deletion-ledger entry assigned to Unit 2 is closed; ownership
      corrections are recorded before implementation.
- [x] Shared/session/server type checks pass.
- [x] Concurrent identical and conflicting claim tests prove exactly-once
      grant/quota consumption.
- [ ] SDK and each host adapter pass the same capability-selection contract.

## Unit 3a — MPC Cutover, No Release

Invariants: `R90-INV-001`, `R90-INV-002`, `R90-INV-003`,
`R90-INV-004`, `R90-INV-005`, `R90-INV-006`, `R90-INV-007`,
`R90-INV-008`, `R90-INV-009`, `R90-INV-010`, `R90-INV-011`,
`R90-INV-012`, `R90-INV-013`, `R90-INV-014`.

This is one no-release cutover. Intermediate commits may compile and test, but
the replacement and legacy MPC paths must not ship together.

### Durable recovery and authority

- [x] Keep authorization session, material activation, recovery, grant, and
      operation identities independent and branded.
- [x] Persist one canonical Near public locator, sealed active-client record,
      and sealed recovery source; create no parallel D1/DO material owner.
- [x] Parse Near persistence once with no dual-schema core reader or legacy
      lifecycle inference.
- [x] Normalize the exact Near record, runtime binding, and unlock-source
      observation once into the shared hydration input.
- [x] Reduce NEAR recovery persistence to `prepared | promotion_committed`.
- [x] Persist `prepared` before the first consuming call, query before replay
      after reload, and persist `promotion_committed` from the exact receipt.
- [x] Preserve `cancel_requested` on prepared recovery; reload reconciles it
      without executing the abandoned parent operation.
- [x] Make every consuming recovery call independently idempotent and queryable
      by recovery ID.
- [x] Atomically finalize local promotion and delete its journal.
- [ ] Use one exact idempotent revocation command only when offline local
      cleanup requires eventual server revocation; dispose local secrets
      immediately.
- [ ] Add fault-injection tests for crashes before call, after call, after
      readback, and during atomic local finalization.
- [ ] Ensure expiry never invokes recovery or device linking.

### Capability-owned MPC operations

- [ ] Move registration, unlock, refresh, signing, step-up, and export to
      capability-owned modules using the shared authorization core.
- [ ] Use the five preparation outcomes exhaustively:
      `ready | pending | authorization_required | superseded | failed`.
- [ ] Serialize recovery, signing, refresh, and export material use per exact
      material owner; keep user interaction outside the queue, check
      generation/fence before use and commit, fail stale fences, and allow
      different owners to progress independently.
- [x] Bind live worker material to the exact material activation.
- [x] Give a server-side expiry race at most one retry after same-method
      step-up.
- [x] Return a typed expiry result immediately to UI confirmation.
- [x] Apply one session classifier to NEAR, Tempo, EVM, delegate signing, and
      key export.
- [x] Preserve the three-use reusable-session budget across refresh.
- [x] Keep expiry, exhaustion, missing, unavailable, and invalid as distinct
      typed states.
- [ ] Look up an existing operation claim before fresh authorization or
      recovery; reuse its outcome without another grant/quota use.
- [ ] For an absent claim, atomically validate lifecycle, consume the exact
      grant and applicable quota, create the claim, and link its audit event.
- [x] Require reusable-session authority to carry
      `WalletSessionId + CapabilityGrantId`; require step-up authority to carry
      `CapabilityGrantId` and forbid `WalletSessionId`.
- [x] Require both authorization branches to carry the independent exact
      `MpcMaterialActivationRef`.
- [x] Replace generic wire `session_id` and `active_state_session_id` fields
      with the discriminated authorization branch and exact activation reference;
      update the unreleased protocol schema and transcript vectors together.
- [ ] Commit Near grant/quota admission at the request-scoped Gateway before
      the Router effect; bind its digest into Refactor 93 exact replay without
      crypto reevaluation or repeated resource consumption.
- [ ] Add execution leases or delivery reconciliation only for a demonstrated
      operation that outlives its request or transfers between workers.

### Worker, WASM, and bundle boundary

- [ ] Keep live secret material owned by the worker or WASM boundary.
- [ ] Preserve the Refactor 93 rule that `SigningWorker` receives the exact A/B
      package pair atomically.
- [ ] Keep generic confirmation free of MPC material; preserve Email OTP
      KEK/secret, Near root/client, and ECDSA derivation/presign/online-signing
      custody in their secure owners.
- [ ] Remove replaced worker entrypoints, loaders, manifest rows, and public
      exports.
- [ ] Preserve existing import/export and bundle guards.
- [ ] Split no worker or bundle without measured evidence.
- [ ] Verify generic orchestration cannot import secret-bearing worker
      internals.

### Host assembly

- [ ] Complete the hosted-wallet Seams Session one-time exchange in the iframe
      client only after Email OTP recovery and signing consume canonical Wallet
      Session/material authorization. Until then, removing parent-posted
      `appSessionJwt` would strand required wallet/material claims; copying
      those claims into `SeamsSession` is forbidden.
- [ ] Update Cloudflare, Node, local, and self-hosted call sites in the same
      cutover.
- [ ] Preserve static host ports and Refactor 93 request-scoped gateways.
- [ ] Verify each host assembles the same statically composed capability
      modules and policies.
- [ ] Preserve one admitted Gateway → Router command; forbid ceremony-wide
      Router ledgers, tenant-wide Gateway state, tenant runtime/cutover
      selectors, direct Deriver origins, direct Gateway role calls, and
      Gateway-owned SigningWorker delivery.
- [ ] Remove obsolete route handlers, service locators, and direct host-role
      access with their last caller.

### Same-change deletion

- [ ] Delete the complete `ThresholdEcdsaSessionRecord*` family, public APIs,
      runtime maps, and fixtures after Unit 2 supplies the narrow
      authorization/session/quota projection and this cutover removes the final
      reader.
- [ ] Delete `active_state_session_id`, generic wire session aliases, and
      remaining authorization/material-scope aliases owned by this cutover.
- [ ] Delete legacy recovery microstates and compensation branches.
- [ ] Delete duplicate signing-lane selectors, auth-method fallbacks, direct
      protocol dispatch, and superseded export coordinators.
- [ ] Delete obsolete tests, handwritten records, mocks, guards, and fixtures
      that encode pre-cutover behavior.

### Unit 3a exit

- [ ] All Unit 3a deletion-ledger entries are closed.
- [ ] The full MPC matrix passes for registration, unlock, refresh, signing,
      step-up, export, expiry, exhaustion, retry, cancellation, and crash recovery.
- [ ] Named acceptance cases pass: transaction abort preserves the old
      source+journal; post-promotion crash reuses the receipt; activation
      correlation replay converges; local rehydration and normal signing make
      zero Yao calls; stale fences fail; different owners progress concurrently;
      concurrent expiry invalidates/emits once; corrupt or mismatched material
      fails closed; stale preparation returns `superseded` and re-resolves.
- [ ] Passkey and Email OTP agree across signing and export.
- [ ] Rust vectors, TS bindings, worker/WASM guards, host adapter tests, and
      bundle checks pass.
- [ ] No legacy and replacement MPC path coexist in a releasable tree.

## Unit 3b — Vault Proving Vertical

Invariants: `R90-INV-009`, `R90-INV-012`.

Detailed implementation belongs to
[Satyr Secrets Vault, Phase 6](./satyr-secrets-vault.md). Refactor 90 needs only
the proof that the shared authorization core supports `vault.proxy_use` through
the minimal local broker/gateway adapter.

- [x] Use Unit 2 sessions, evidence, grants, claims, and audit without a
      vault-specific authorization framework.
- [x] Prove native session exchange → operation-bound Passkey evidence → exact
      one-use grant → atomic claim/use → real persisted/routed
      `vault.proxy_use` → audit readback.
- [x] Keep broad vault product UI, recovery, rotation, sharing, and future
      capability kinds in the Satyr plan.
- [x] Delete each concrete replaced vault target in the change that replaces it.

Unit 3b may run in parallel with Unit 3a after the Unit 2 integration gate and
does not block the Unit 3a implementation checkpoint. Refactor 90 completion
and its supported release gate still require this proving vertical unless the
normative plans are amended together.

## Unit 4 — UI + Provisioning

Invariants: `R90-INV-010`, `R90-INV-012`, `R90-INV-013`,
`R90-INV-014`.

### Typed UI lifecycle

- [ ] Make React, Lit, iframe, and direct SDK adapters render
      `ready | pending | authorization_required | superseded | failed`
      exhaustively.
- [ ] Discard and re-resolve stale state on `superseded`.
- [x] Terminate confirmation immediately on the typed expiry result.
- [x] Wait for secure-origin initialization and consume typed state/events.
- [x] Stop inferring unlocked state from optional IDs, JWT presence, or auth
      method.
- [x] Treat the demo wallet as unlocked only while a reusable Wallet Session is
      active.
- [x] Lock on authoritative expiry, request step-up on exhaustion, and preserve
      the broader app identity session.
- [ ] Ensure only explicit wallet unlock creates a reusable Wallet Session.
- [ ] Keep step-up single-operation across signing and export surfaces.

### Provisioning

- [ ] Create registration/add-factor auth identity first, then provision each
      capability independently through statically composed canonical owners.
- [ ] Make partial capability results explicit and exhaustively handled.
- [x] Return exact per-capability results with no combined cross-curve record.
- [ ] Use exact wallet, authorization-session, and material-activation
      projections.
- [ ] Delete Patch 2 tactical UI/provisioning bridges after their last caller
      moves.
- [ ] Delete obsolete loading heuristics, fallback lane selection, and
      pre-cutover fixtures in the same change.

### Unit 4 exit

- [ ] Every deletion-ledger entry assigned to Unit 4 is closed; ownership
      corrections are recorded before implementation.
- [ ] UI type fixtures reject incomplete lifecycle states.
- [ ] Existing Refactor 92 contracts still prove expiry/exhaustion separation,
      refresh allowance, step-up behavior, and Passkey/OTP parity.
- [ ] Registration and provisioning expose no partial legacy capability shape.

## Final Conformance Gate

This is a validation gate, not a deferred cleanup phase.

- [ ] Every applicable deletion-ledger entry is closed; any reassignment names a
      follow-on plan outside Refactor 90 scope.
- [ ] Prohibited legacy symbols, routes, imports, exports, aliases, record
      families, and obsolete source guards are absent.
- [ ] Required factor-neutral, worker/WASM, import, and bundle guards pass.
- [ ] Public export and dependency-direction checks pass.
- [ ] Shared, SDK, server, worker, intended-test, and Rust type/build checks
      pass.
- [ ] Focused unit, crash, concurrency, host-adapter, worker/WASM, and vector
      tests pass.
- [ ] `pnpm test:intended` passes against a healthy environment.
- [ ] `git diff --check` passes.
- [ ] The journal records the final implementation and validation state.

## Verification Budgets

### Fault-injection and concurrency

Keep the load-bearing crash cases at irreversible Near boundaries, ECDSA
activation-correlation replay, atomic local finalization, stale material-owner
generation/fence rejection, per-owner serialization, existing-claim
non-consumption, and the single server-expiry retry. Add no broader matrix until
one of those demonstrations exposes a distinct failure mode.

### Intended-behaviour E2E

Refactor 90 adds at most these eight scenarios:

1. registration immediately followed by signing;
2. wallet unlock immediately followed by signing;
3. page refresh followed by concurrent signing;
4. exact local rehydration without Yao recovery;
5. missing-material recovery followed by signing;
6. corrupt or mismatched material failing closed;
7. stale preparation returning `superseded` and resolving the replacement;
8. one minimal vault session/evidence/grant/operation/audit vertical.

Run Refactor 92's existing contracts unchanged for expiry, exhaustion, step-up,
invalidation, demo-lock, and app-identity behavior. Refactor 90 adds no duplicate
E2E cases for those behaviors.

## Validation Ownership

The SPEC verification checklist is normative. Unit-local checks provide the
short execution view.

| Unit  | Primary verification                                                                                    |
| ----- | ------------------------------------------------------------------------------------------------------- |
| 1     | Domain type fixtures, IndexedDB store tests, fourteen canonical-state cases, and activation crash tests |
| 2     | Schema/boundary tests, authorization integration, atomic claim concurrency, host-port contracts         |
| 3a    | MPC intended behaviors, recovery fault injection, vectors/bindings, worker/WASM/bundle and host checks  |
| 3b    | Satyr Phase 6 end-to-end vault operation and authorization/audit assertions                             |
| 4     | UI type fixtures and intended registration/unlock/refresh/expiry/exhaustion tests                       |
| Final | Full intended suite, architecture/export guards, deletion ledger, and diff hygiene                      |

When a lower-authority fixture or source guard fails, classify it against the
SPEC and intended behavior before changing production code.

## Checkpoint Order

1. **Unit 1 checkpoint:** canonical hydration and ECDSA state are coherent and
   independently validated.
2. **Unit 2 checkpoint:** the DB-backed authorization integration gate passes.
3. **Unit 3a and 3b checkpoints:** proceed in parallel once Unit 2 interfaces
   stabilize; each lands as an independently reviewable checkpoint.
4. **Unit 4 checkpoint:** UI and provisioning consume stable capability
   interfaces.
5. **Final checkpoint:** all deletion and conformance gates pass.

Pull or merge `dev` at stable checkpoint boundaries. Re-run the narrow
unit-owned validation after reconciliation before continuing.

## Open Decisions

| Decision                                                      | Needed by                    | Default if unresolved                                                                                            |
| ------------------------------------------------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Does the current session threat model require device binding? | Unit 2 schema freeze         | Retain only the minimum existing binding; keep broader management out.                                           |
| Which operations require durable server execution leases?     | Unit 3a per-operation review | Use a request-bound claim without a lease until a real operation proves cross-request or cross-worker execution. |
| Which MPC capability produces `mpc_signer_proof`?             | Follow-on implementation     | Deny every policy requiring it until a verified producer is designed.                                            |

## Related Plans

- [Refactor 90 SPEC](./refactor-90-modular-auth-capabilities-SPEC.md)
- [Refactor 90 deletion ledger](./refactor-90-deletion-ledger.md)
- [Refactor 90 journal](./refactor-90-journal.md)
- [Refactor 90A patches](./refactor-90A-patches.md)
- [Email OTP local rehydration](./refactor-patch-2-email-otp-local-rehydration.md)
- [Refactor 91](./refactor-91.md)
- [Refactor 92](./refactor-92-session-expiry-handling.md)
- [Refactor 93](./refactor-93.md)
- [Refactor 82B authority typing](./refactor-82B.md)
- [Ed25519 Yao implementation plan](./router-ab/ed25519-yao/implementation-plan.md)
- [Satyr Secrets Vault](./satyr-secrets-vault.md)

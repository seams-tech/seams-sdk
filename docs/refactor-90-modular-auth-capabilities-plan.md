# Refactor 90: Modular Auth Capabilities — Implementation Plan

Created: 2026-06-28

Consolidated: 2026-07-27

Status: **in progress — Unit 1 implementation and Unit 3b complete; Unit 2
operating core complete; Units 3a and 4 in progress**

This document is the execution tracker for
[the normative SPEC](./refactor-90-modular-auth-capabilities-SPEC.md). If this plan
and the SPEC diverge, the SPEC controls.

Operational records:

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
- [Refactor 93](./refactor-93.md): pair-bound Router/Deriver execution and exact
  role-result replay;
- [Refactor 94C](./refactor-94C-regression-fixes.md): the final Cloudflare
  durable-owner map and zero-Durable-Object topology;
- [Email OTP local rehydration](./refactor-patch-2-email-otp-local-rehydration.md):
  the current local-material recovery boundary.

Refactor 90 must preserve those behaviors. It replaces temporary shapes and
duplicated transitions without reopening their product semantics.

### Refactor 94C reconciliation boundary

[Refactor 94C](./refactor-94C-regression-fixes.md) is a follow-on
topology change that may supersede Refactor 93 placement decisions while this
branch is in flight. Future merges from `dev` must preserve Refactor 90's domain
contracts and accept Refactor 94C's final durable-owner placement.

Known conflicts:

- The request-scoped Gateway owns canonical authorization claims, Wallet Session
  quota consumption, and authorization audit records. Refactor 94C keeps
  cryptographic effect deduplication, terminal replay, and presignature
  consumption in SigningWorker private D1. The Gateway forwards only a typed
  claim receipt over an internally authenticated Router route.
- Refactor 90 models activation as idempotent and queryable by activation
  correlation. Refactor 94C folds standalone prepare/finalize routes into its
  three blocking registration routes. Preserve prepared coordinates, exact
  replay, crash reconciliation, and queryable completion even if the route
  shape changes.
- Refactor 94C removes redundant server journals and standalone managed-grant
  rows. It must not remove the logical `CapabilityGrantId`, signed admitted
  policy, operation claim, or the client IndexedDB two-state activation journal
  used to resolve server uncertainty.
- Refactor 94C's stateless compute Workers may use private D1-owned durable
  effects. Do not restore DO/Gateway state merely to satisfy Refactor 93-era
  call sites during conflict resolution.

Merge rule: keep the Refactor 90 capability, authorization, activation,
fingerprint, replay, and typed-result interfaces; take Refactor 94C's storage
and routing ownership; delete the superseded owner in the same merge. Update
the affected Unit 2 and Unit 3a checkboxes before marking either unit complete.

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

| Unit                                               | Consolidates                                             | Dependency                                                                                         | Result                                                                                                             |
| -------------------------------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **1. Canonical hydration + canonical ECDSA state** | Foundations A/B, Phases 4–5, ECDSA identity work from 18 | Implementation complete; remaining state/crash acceptance open                                     | Exact subjects, protocol-local resolvers with shared outcomes, required ECDSA state, and slim material references. |
| **2. Shared authorization core**                   | Phases 7–14, including Phase 8 SDK selection             | Atomic claim core complete; effect-owner response replay awaits Refactor 94C                       | Closed capability vocabulary plus DB-backed session → evidence → grant → claim → audit flow.                       |
| **3a. MPC cutover — no release**                   | Phases 17–21 and 24                                      | Core operating paths and production record deletion complete; acceptance and residual cleanup open | All MPC operations use the shared core; legacy and replacement paths do not ship together.                         |
| **3b. Vault proving vertical**                     | Phase 16                                                 | Complete                                                                                           | [Satyr vault plan Phase 6](./satyr-secrets-vault.md) proves one real vault operation.                              |
| **4. UI + provisioning**                           | Phases 22–23                                             | Provisioning and typed lifecycle implementation complete; cleanup and Refactor 92 acceptance open  | Typed lifecycle events and provisioning use the canonical capability model.                                        |

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
6. Record stable checkpoints and genuine blockers in the commit history and
   the applicable plan or deletion-ledger entry.

## Completed Baseline

- [x] Phase 1: signer-set registration cut.
- [x] Phase 2: wallet-rooted confirmation subjects.
- [x] Phase 3: AuthService mechanical module split.
- [x] Refactor 91 auth-domain cutover is treated as current behavior.
- [x] Refactor 92 signing-session lifecycle is frozen.
- [x] Refactor 93 pair-bound role execution and exact replay are retained.
- [x] Refactor 94C replaces the Cloudflare Gateway/DO ownership baseline before
      Refactor 90 release.

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
- [ ] Refactor 93 hosted recovery behavior remains correct on the Refactor 94C
      topology before Near release.
- [ ] Refactor 94C zero-DO registration and ordinary-signing acceptance passes.
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
- [x] Make registration, unlock, and refresh enter the protocol-local resolver
      for each capability and return the shared outcome union.
- [x] Delete authentication-method inference from canonical ECDSA lane
      selection.
- [x] Delete JWT-payload inference from normal signing and worker orchestration;
      retain token decoding only in boundary parsers.
- [x] Delete remaining optional-ID inference from core transitions. Status,
      lane discovery, and Email OTP Ed25519 consumption now require the exact
      grant or threshold-session identity (`00d5130f9`).
- [x] Require persisted-session discovery to name one exact auth method; delete
      the omitted-method branch that silently searched Passkey and Email OTP.
- [x] Add boundary and lifecycle tests for missing, mixed, stale, and exact
      subjects.

### 1B. Canonical hydration

- [x] Define the protocol-neutral four-outcome hydration union.
- [x] Add branch-specific builders and type fixtures that reject invalid
      combinations.
- [x] Normalize ECDSA observations once into the shared hydration input.
- [x] Prove registration, unlock, and refresh provenance is absent from ECDSA
      and Near resolver input.
- [x] Cover the seven canonical states for each capability: live,
      sealed-active, retired, missing, corrupt, conflicting, and unavailable.
- [x] Delete duplicate readiness helpers after the shared path is active.
- [x] Delete remaining protocol-specific derivation helpers after their last
      caller moves to the shared path.
  - [x] Delete the zero-caller key-ref, server-record, bootstrap-context,
        wallet-key projection, and record-fingerprint adapters (`26bd50338`).
  - [x] Move sealed-export public-facts validation onto exact manifest/runtime
        correlation and delete its durable-record adapter (`2d447bc05`).
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
      fresh worker rehydrates the same durable material reference using the
      current worker-open request fixture.
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
- [x] Prove persisted hydration → worker bind → sign through the shared path
      using the current worker-open request fixture.
- [x] Keep warm ECDSA Email OTP context explicit at the read-model boundary:
      require a nullable context value, preserve `never` exclusion branches,
      and repair the identity guard's protocol-owned allowlist (`e9ed27172`).

### 1D. Slim material references

- [x] Keep broad session state out of live material handles.
- [x] Use a branded public-key representation at the material boundary.
- [x] Add fixtures rejecting raw strings, broad spreads, and forged material
      references.
- [x] Keep role-local material handles stable across Tempo and ARC for the same
      exact activated material.
- [x] Remove raw share bytes and broad state objects from generic callers.
  - [x] Remove the unbranded client-verifying-share copy from the exact ECDSA
        runtime. The runtime now carries the manifest-owned branded client
        verifying public key, while the normal-signing wire adapter performs
        the only protocol-name conversion (`085b9c01a`).
- [x] Delete `evmFamilySigningKeySlotId` from role-local public facts,
      activation/durable bindings, persistence keys, and sealing AAD.
- [x] Delete `evmFamilySigningKeySlotId` from remaining runtime paths or prove
      it is a provisioning-only identifier outside material selection.
  - [x] Delete the zero-caller slot-bearing server-planned WASM context and its
        type fixture (`2b2d2f4b3`).
  - [x] Delete the zero-caller server export-share request, response, and parser
        contract that still carried the slot identity (`84677131e`).
  - [x] Delete the zero-caller slot-bearing ECDSA connect adapter and consume
        the bootstrap result shape directly (`713fc967c`).
  - [x] Remove the slot from server normal-signing provision admission and
        durable ECDSA MPC session records (`a980592a0`, `9bada9733`).
  - [x] Remove the slot from local ECDSA normal-signing session seeding and
        assert budget identity with the exact key handle (`5f63b4de9`).
  - [x] Remove the slot from runtime wallet-key projections and persisted
        signer metadata; existing-key Email OTP handles and sealed rehydration
        now correlate by exact key handle. Registration-only handles retain
        their provisioning slot (`6113b36bb`).
  - [x] Delete the unused client ECDSA session-policy type, builder, digest,
        public exports, and slot-pinning source checks. Email OTP bootstrap now
        clamps TTL and use count directly (`3d6c4c74b`).
  - [x] Stop copying the provisioning slot into durable IndexedDB signer
        metadata during registration, add-signer, and bootstrap persistence;
        exact key handles remain the persisted correlation identity
        (`0fbbbb04b`).
  - [x] Delete the zero-caller server role-local ECDSA key-record parser and
        in-memory, Redis, Upstash, and Durable Object stores with their obsolete
        fixtures and source checks (`a913d461f`).
  - [x] Remove unused provisioning-slot projections from Wallet Session
        `stableKeyContext`, persisted Email OTP capability lookup, and sealed
        refresh validation (`45e495ddc`).
  - [x] Remove the provisioning slot from server-persisted ECDSA signer
        records and key inventory, require exact top-level/nested key-handle
        correlation, and delete the forbidden slot from post-registration
        normal-signing scope (`5f7075386`).
  - [x] Remove the provisioning slot from exact-session bootstrap results;
        registration keygen retains its reservation input without projecting it
        through the activated-session result (`1f04bb1bb`).
  - [x] Forbid provisioning slots on ready ECDSA use-case lanes and Email OTP
        runtime activation authority with negative type fixtures
        (`47070b2b0`).
  - [x] Replace the dead keygen-derived activation projection with required,
        slot-free activated ECDSA key facts for Passkey and Email OTP
        (`2768d24a0`).
  - [x] Delete the zero-caller ECDSA keygen facade and its dead
        normal-signing-state builder (`f762803df`).
  - [x] Delete the registration-era ECDSA enrollment activation/bootstrap
        variant; activation now accepts exact existing-session identity only
        (`1e317e433`).
  - [x] Delete registration-era bootstrap tests that exercised the retired
        activation request shapes while retaining the client-root proof
        boundary test (`499a9e00e`).
  - [x] Remove provisioning-slot inputs from post-registration relayer-key
        derivation; exact-session bootstrap now supplies wallet and signing-root
        facts while the derivation preserves the established wire identifier
        (`fca3baaf2`).
  - [x] Audit the remaining positive uses as registration/provisioning-only,
        retain explicit runtime `never`/parser rejection, and delete the
        zero-consumer bootstrap relayer port family (`a843d8dbc`).
- [x] Bind server ECDSA Wallet Session records, budget bindings, runtime/DO
      equality, and sealed projections to required branded `EcdsaKeyHandle`;
      reject old slot-bearing persisted records at the parser boundary.
- [x] Verify Tempo, EVM, and export consumers use the same durable material
      reference.
- [x] Reject cross-chain mismatch before worker open or material use.
- [x] Confine any transitional `activeState` shape to its boundary and schedule
      its same-unit deletion.
- [x] Delete the zero-caller ECDSA activation-journal id projection; journal
      owners read the required id directly (`c51134bba`).

### Unit 1 exit

- [ ] Every deletion-ledger entry assigned to Unit 1 is closed; ownership
      corrections are recorded before implementation.
- [x] Type fixtures prove registration, unlock, and refresh provenance cannot
      affect ECDSA or Near resolver input.
- [x] Fourteen state cases cover the seven canonical states for both
      capabilities.
- [x] Required-field and invalid-state type fixtures pass.
- [x] Reject the retired `restorable` label on concrete ECDSA lanes while
      retaining it for Ed25519 durable sealed material.
- [x] IndexedDB crash tests prove atomic activation finalization.
- [ ] Focused intended-behavior tests preserve refresh allowance and exact
      material rehydration.

## Unit 2 — Shared Authorization Core

Invariants: `R90-INV-001`, `R90-INV-009`, `R90-INV-012`,
`R90-INV-013`.

### Completed inputs

- [x] Refactor 91 supplies the closed capability, operation, evidence, signer
      auth, and wallet-authority vocabularies with boundary parsers and type
      fixtures.
- [x] Refactor 93 supplies the pair-bound Router/Deriver protocol and exact
      role-result replay used by every host.
- [x] Refactor 94C supplies Cloudflare's final Gateway D1, role-private D1, and
      SigningWorker private-D1 ownership behind the shared host ports.
- [x] The existing app-session exchange and provider-verification boundary is
      the transport entry point to extend.
- [x] Existing D1 CAS batches and Wallet Session budget tests provide the
      transaction pattern; they are not the new authorization domain.

### Closed vocabulary and selection

- [x] Adopt the existing closed capability vocabulary in production SDK,
      server, UI, and persistence boundaries.
- [x] Include only the tenant, principal, session, factor, capability,
      operation, grant, and evidence references required by current verticals.
- [x] Use named or flat `all | any` evidence requirements; add no recursive
      policy grammar or speculative factor/provider taxonomy.
- [x] Preserve Refactor 82B `WalletAuthAuthority` types and fixtures as the
      baseline instead of restaging that cut.
- [x] Make SDK capability selection exhaustive and reject implicit fallbacks.
- [x] Make disabled capability requests fail early with a typed result.
- [x] Keep protocol, auth method, capability, and lifecycle as separate unions.
- [x] Remove duplicate aliases and direct string comparisons from generic code.
      Generic signing, hydration, export, sealed-runtime, and step-up surfaces
      now use the canonical auth-method domains and exhaustive factor
      projection; the auth-domain guard passes with the stale allowances
      removed (`157eb7562`, `732802dc9`, `40fb0203f`, `bdf6cc5da`).
- [x] Delete the restore-purpose, bootstrap-request, ECDSA transport-auth, and
      ready-session-policy aliases after their consumers adopt the canonical
      types directly.
- [x] Add type fixtures for invalid capability/auth/protocol combinations.

### Ports and host-independent assembly

- [x] Define narrow request-scoped ports for capability policy, session,
      evidence, grants, claims, and audit.
- [x] Keep Cloudflare, Node, local, and self-hosted adapters behind the same
      static port shapes.
- [x] Use one statically composed module graph; add no runtime plugin registry,
      tenant-mutated route table, or deployment module-selection framework.
- [x] Preserve the request-scoped `MPC_ROUTER` service-binding contract while
      applying Refactor 94C's Cloudflare durable-owner map; keep Router
      stateless.
- [x] Reject tenant-runtime service locators and direct infrastructure roles in
      domain handlers.

### Authorization data model

- [x] Define precise records for session exchange codes, authorization
      sessions, factor evidence, capability instances/bindings, logical
      operation grants, operation claims, and audit events. A host may carry an
      admitted grant as a signed payload instead of a standalone durable row.
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
- [x] Keep the normal-signing prepare-response parser and endpoint fixture
      aligned on the required budget claim fields; the canonical operating-path
      proof completes pooled prepare/finalize to a verified 65-byte signature
      (`7c20fe644`, `e75d2bcfb`).
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
- [x] Move management and session routes to exact subjects, keep their policy
      separate from operation grants, and delete wallet-first policy aliases.
- [x] One DB-backed integration test proves
      session → evidence → grant → claim → audit before Units 3a/3b depend on the
      core.
- [x] Keep the no-factor-literal guard in generic preparation and coordination
      modules.

### Unit 2 exit

- [x] Every deletion-ledger entry assigned to Unit 2 is closed; the historical
      Phase 9 carryover rows were confirmed absent and the ledger records the
      retained request-scoped registration boundaries (`5d3518c98` audit).
- [x] Shared/session/server type checks pass.
- [x] Concurrent identical and conflicting claim tests prove exactly-once
      grant/quota consumption.
- [x] SDK and each host adapter pass the same capability-selection contract.
      Cloudflare, Express/Node, local D1, and self-hosted assembly use the same
      static `RouterApiServiceBag`; the focused route-surface and self-host
      parity suites pass 15/15.

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
- [x] Name the Ed25519 active-capability lifecycle with branded
      `ThresholdEd25519SessionId`; keep reusable `WalletSessionId` and quota
      identity on authorization only, and bind recovery admission to the
      threshold-material session.
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
- [x] Use no eventual-revocation command: no implemented offline cleanup path
      requires one. Continue disposing local secrets immediately; add a command
      only if a concrete server revocation obligation appears.
- [x] Add fault-injection tests for crashes before call, after call, after
      readback, and during atomic local finalization.
- [x] Ensure expiry never invokes recovery or device linking; the canonical
      Email OTP refresh and sealed-lifecycle paths preserve material and its
      activation while invalidating authorization/runtime projections.

### Capability-owned MPC operations

- [x] Keep the durable ECDSA capability and material activation independent
      from active reusable-session authorization; preserve material facts and
      return `authorization_required` when authorization is absent.
- [x] Delete the client-side ECDSA wallet-budget lane path; keep the remaining
      client budget subsystem Ed25519-only and fail closed for other curves.
- [x] Select ECDSA signing lanes and live material by exact canonical material
      identity; delete the source-priority scan, record-candidate builders,
      `findExact`/`readSelected` readers, and obsolete budget-blocked lane kind.
- [x] Key ECDSA provisioning and reconnect by exact material activation, flow
      kind, and budget; remove authorization-session/grant identity from the
      reconnect key, delete record/lane fallback paths, and reject rehydration
      that changes the activation.
- [x] Require exact runtime policy scope on every ECDSA session-lane policy;
      reject missing scope before strict activation and pin omission as a
      compile-time error (`ff6464baf`).
- [x] Remove session transport kind, Wallet Session bearer credentials, and
      the unused MPC-session alias from ECDSA bootstrap material key
      references; type fixtures reject all three projections (`f32baab61`).
- [x] Make the bootstrap `session` branch the sole owner of threshold-session
      and signing-grant identity. Delete key-reference copies, precedence and
      rewrite helpers, and fail when the worker-issued grant disagrees with the
      requested grant (`3fdeba8b7`). Its remaining policy scope, Wallet Session
      bearer, and client verifying share are required; the dead optional
      success base, `sessionId`, budget-projection alias, and inert login
      reconstruction are deleted (`04221828c`). The exact key reference is now
      the sole owner of bootstrap material facts; the duplicate `keygen` result
      branch and its hand-written fixtures are deleted (`118f5c882`,
      `7d1e31bbd`).
- [x] Cut ECDSA export over atomically across the client, Gateway, Router,
      SigningWorker, sealed-share AAD, and Rust protocol mirrors so requests
      carry discriminated authorization plus the exact material activation.
- [x] Prepare EVM-family operation step-up before confirmation, bind Passkey
      and Email OTP to that one prepared operation, and delete the
      post-confirmation ECDSA preparation path.
- [x] Regenerate the normal-signing vectors after the authorization-wire cut;
      the focused export protocol, client-protocol, WASM ceremony, and
      challenge-binding checks pass.
- [x] Add one manifest-to-sealed-record runtime resolver selected by exact
      material activation, with typed missing, conflict, and corrupt results,
      and expose its canonical persisted material reference.
- [x] Before sealed-runtime consumers move, match sealed public, auth, and
      normal-signing facts against the manifest binding; require the exact
      two-party participant shape and valid allowance facts.
- [x] Move ECDSA export and operation step-up to capability-owned modules using
      the shared authorization core; active Email OTP export resolves the exact
      manifest + sealed runtime, and the write-dead runtime record map and
      record-backed ready-export branch are deleted.
- [x] Move Email OTP signing-session refresh, sealed restore, and sealed
      refresh policy to the exact manifest + sealed-runtime boundary.
- [x] Move the warm ECDSA read model, login public-capability warm-up, and
      presignature prefill to the exact manifest + sealed-runtime boundary;
      preserve reusable-session authorization as an independent proof.
- [x] Remove `EcdsaWalletSessionAuthority`, ECDSA signing-grant aliases, and
      Wallet Session JWT control-state reads from committed ECDSA lanes; carry
      the typed active authorization and use the JWT only as its bearer
      credential.
- [x] Make ECDSA selection and prepared signing decide exact lane and
      authorization without a duplicate material-readiness model; delete
      `ecdsaMaterialState.ts` and hydrate canonical material immediately before
      worker use.
- [x] Remove the composite session record from
      `ReadyEvmFamilyEcdsaMaterial` and delete the record-backed ready-material
      and export helpers that depended on it.
- [x] Construct the Passkey committed material lane from its exact Passkey
      binding; selection no longer depends on record-backed or pre-hydrated
      material state.
- [x] Demonstrate Passkey and Email OTP normal signing through canonical
      hydration and worker binding using current shared factories. The
      canonical ECDSA operating-path proof completes persisted hydration,
      dedicated worker binding, pooled prepare/finalize, and verifies the
      resulting 65-byte signature; its endpoint fixture and prepare-response
      parser agree on the required operation-claim fields (`7c20fe644`,
      `e75d2bcfb`). The focused hydration, signing, step-up, and sealed-runtime
      proof set passes 26/26; the presign bridge, pool policy, and browser
      pool-hit proofs pass 19/19 at `917439856`.
- [x] Move the remaining registration and explicit-unlock entry points to
      capability-owned state: Passkey unlock plans from active signer and
      capability facts, while Email OTP registration/unlock resolves existing
      role-local material from active manifests instead of the write-dead
      composite session store.
- [x] Use the five preparation outcomes exhaustively:
      `ready | pending | authorization_required | superseded | failed`.
- [x] Treat exact-material supersession during signing as a typed retryable
      re-resolution and preserve it as distinct from terminal signing failure.
- [x] Serialize normal signing per exact material owner after user interaction;
      re-resolve canonical material inside the queue and allow different owners
      to progress independently.
- [x] Serialize export by exact material owner after user interaction; re-resolve
      the canonical manifest and sealed runtime after the queue wait and reject
      a superseded activation before provisioning or worker export.
  - [x] Route NEAR Ed25519-Yao transaction, delegate, NEP-413, Passkey export,
        and Email OTP export through the same exact-material activation queue
        instead of keying signing by threshold session identity
        (`10c8a61da`).
- [x] Complete canonical activation serialization and re-resolution immediately
      before every recovery and refresh consuming call and commit.
  - [x] Email OTP ECDSA signing-session refresh enters the exact activation
        queue, re-resolves before the consuming login call and after refresh,
        and rejects disappearance or replacement (`71c67e3dc`).
  - [x] Email OTP Ed25519 silent sealed recovery uses the queue shared by NEAR
        signing and export, re-resolves before rehydration, persists before
        releasing the owner, and verifies the durable activation afterward
        (`b78210618`).
  - [x] Email OTP Ed25519 direct login and unlock activation persist under the
        same exact-owner queue and reject an activation replaced during commit
        (`fbf4be6a4`).
  - [x] Route Passkey login hydration and sync/unlock recovery through the
        shared exact material-owner runner. Login rereads the locator before
        hydration; sync parses once and keeps recovery, durable promotion,
        sealed refresh persistence, and registry activation in one queued
        commit (`26c3cedf2`, `5f3d52bab`).
  - [x] Run the Passkey sync/unlock queue-state operating test with the durable
        recovery-store port supplied. The test exercises the production
        source seal, two-state journal, atomic material replacement, registry
        publication, and seal persistence inside one exact-owner queue. It
        also proves that recovery publication adopts the promoted activation
        instead of comparing it with the retired pre-promotion activation.
- [x] Bind live worker material to the exact material activation.
- [x] Give a server-side expiry race at most one retry after same-method
      step-up.
- [x] Return a typed expiry result immediately to UI confirmation.
- [x] Apply one session classifier to NEAR, Tempo, EVM, delegate signing, and
      key export.
- [x] Preserve the three-use reusable-session budget across refresh.
- [x] Keep expiry, exhaustion, missing, unavailable, and invalid as distinct
      typed states.
- [x] Look up an existing operation claim before fresh authorization or
      recovery; reuse its outcome without another grant/quota use
      (`b166b0bf1`, `b4a286bb5`).
- [x] For an absent claim, atomically validate lifecycle, consume the exact
      grant and applicable quota, create the claim, and link its audit event
      (`6fd6c7c25`, `b166b0bf1`, `b4a286bb5`, `f260700e4`).
- [x] Require reusable-session authority to carry
      `WalletSessionId + CapabilityGrantId`; require step-up authority to carry
      `CapabilityGrantId` and forbid `WalletSessionId`.
- [x] Require both authorization branches to carry the independent exact
      `MpcMaterialActivationRef`.
- [x] Separate hydrated ECDSA signer material from execution authorization;
      prepare step-up from neutral material and attach the reusable-session or
      one-operation grant only in the ready execution envelope.
- [x] Resolve the canonical ECDSA capability and reusable Wallet Session
      authorization independently; hydrate canonical material even when the
      reusable authorization is absent.
- [x] Key canonical ECDSA availability identity by exact material activation;
      forbid `signingGrantId` and `thresholdSessionId` on canonical availability
      records and their type fixtures.
- [x] Carry export authorization beside the exact export material lane instead
      of reading it from material identity; Email OTP Ed25519 export now sends
      only selected lane, authorization, activation, and capability facts to
      the worker (`f20403de5`).
- [x] Flatten the one-arm `ExactEcdsaExportSession` wrapper into the exact
      export lane so export state, target, factor, and material availability
      have one required-field carrier (`643dde348`).
- [x] Delete the redundant Passkey ECDSA export bootstrap identity after the
      exact export lane owns material identity; retain only the relayer URL
      required by the fresh-authorization operation.
- [x] Require warm-capability and seal-transport consumers to receive their
      reusable authorization explicitly.
- [x] Key ECDSA step-up freshness authority by exact material activation rather
      than Wallet Session or quota identity.
- [x] Let canonical preparation discovery select an exact material lane without
      requiring an active reusable Wallet Session. Preserve exact activation,
      target, and factor as `authorization_required` without constructing a
      `SelectedEcdsaLane`.
- [x] When reusable authorization is absent, derive the operation-step-up
      method from the capability authority and carry that prepared method into
      confirmation; active reusable authorization retains the warm-session path.
- [x] Carry the selected `authorization_required` material into operation
      preparation and attach a same-method single-operation grant as a separate
      execution proof. Do not mint or reread a reusable Wallet Session.
- [x] Remove reusable authorization from `ExactEcdsaSigningLaneIdentity` and
      require persistence, expiry, warm-capability, seal, and export consumers
      to receive authorization through their explicit operation carrier.
- [x] Replace generic wire `session_id` and `active_state_session_id` fields
      with the discriminated authorization branch and exact activation reference;
      update the unreleased protocol schema and transcript vectors together.
- [x] Commit the reusable-session Near operation claim, quota use, and audit
      atomically in Gateway authorization D1 before execution. Forward its typed
      receipt through the internally authenticated Router route; SigningWorker
      private D1 owns exact cryptographic-effect deduplication and terminal
      replay (`b166b0bf1`).
- [x] Commit the operation-step-up Near claim and consume its exact one-use grant
      before forwarding execution. Preserve the same operation fingerprint and
      SigningWorker terminal replay used by reusable-session signing
      (`b4a286bb5`).
- [x] Add no execution lease: no implemented operation outlives its request or
      transfers between workers. Reopen this only for a demonstrated owner
      transfer.
- [x] Stop deriving NEAR budget readmission from material-hydration provenance;
      only a real authorization/session replacement refreshes budget identity
      (`30b52879b`).
- [x] Replace the closure-bearing NEAR committed-capability carrier with the
      shared hydration plan plus an independent reusable-authorization state.
      Transaction, delegate, and NEP-413 payloads carry preparation data and an
      explicit material executor, and exact activation is checked before use
      (`6a818aea3`, `e118d0d5e`).
- [x] Make delegate and NEP-413 authorization planning consume the canonical
      preparation's active-status proof. Delete the record-backed warm-capability
      reader, record-to-lane reconstruction, and obsolete handwritten
      session-selection suite (`5a8ce9090`, `70ef2a420`).
- [x] Remove the final composite-session-record read and cache reseeding from
      NEAR transaction, delegate, and NEP-413 preparation. Expiry cleanup reads
      the independent reusable-authorization status; signing preparation now
      succeeds from canonical material plus authorization after refresh
      (`4f089b483`).
- [x] Remove the composite-session lookup from recovered local-login
      restoration; the verified recovery binding plus canonical app and Wallet
      Session identity own the restore checks (`51e71d7e8`).
- [x] Carry required Passkey Ed25519 restore metadata from provisioning and
      sync recovery into sealed persistence. The durable Passkey MPC owner no
      longer reverse-resolves a composite record by threshold session ID, and
      the focused sealed-refresh suite passes 4/4 (`0f5d7e6b6`).
- [x] Publish Email OTP Ed25519 sealed refresh state from the canonical active
      capability plus factor-only publication context. The publication
      boundary, sealed-session registry, and silent-recovery persistence port
      no longer accept a composite session record; the focused recovery suite
      passes 13/13 (`93ae1e20a`).
- [x] Build Email OTP Ed25519 cold login/unlock state directly from the exact
      bootstrap. Correlate JWT claims, active allowance, expiry, signing root,
      and signer identity at the boundary; return the activated lane's signer
      through Browser and SeamsWeb without creating or returning a composite
      session record. The focused recovery suite passes 14/14 (`f5062fc13`).
- [x] Prepare Email OTP Ed25519 cold recovery from one exact sealed record
      correlated by wallet, factor subject, account, signer slot, and material
      activation. Browser no longer reads the composite session cache to choose
      the recovery session or runtime policy (`e4322bd15`).
- [x] Resolve the legacy NEAR unlock wrapper's wallet from the active user
      binding it already owns, instead of consulting the composite signing
      record solely for `walletId` (`2cdfea541`).
- [x] Resolve NEAR wallet-unlock subjects solely from canonical active signer
      profile rows. Delete the inert runtime-record subject duplicate and its
      diagnostic provenance branch (`8c2aeb3ac`).
- [x] Clear wallet-scoped volatile Ed25519 material by enumerating exact
      Passkey and Email OTP sealed sessions. Runtime cleanup no longer needs a
      composite record to discover material-session IDs (`b9638246a`).
- [x] Make Ed25519 key-export lifecycle preflight read the canonical active
      Wallet Session authorization projection asynchronously. Missing,
      corrupt, unavailable, mismatched, active, and expired states no longer
      depend on the composite record cache (`47fbe2cbc`).
- [x] Add one exact Ed25519 sealed-session runtime boundary that validates
      persisted signer, factor, JWT, policy, signing-root, participant, worker,
      allowance, and expiry facts and returns distinct resolved, missing,
      conflict, and corrupt outcomes (`2733f7960`).
- [x] Replace the wallet-scoped Ed25519 warm-capability envelope with the exact
      sealed runtime, independent active Wallet Session authorization, and
      worker claim. Missing authorization preserves material as
      `authorization_required`; the read model no longer embeds or derives its
      bearer credential from the composite session record (`cdd9cc2b8`).
- [x] Make Ed25519 session status wallet, account, and signing-key qualified.
      Resolve the exact sealed runtime first, validate the independent active
      authorization and its bearer claims, preserve expiry-before-exhaustion,
      and derive budget identity from the runtime rather than a composite
      record (`4ea6eccb7`).
- [x] Hydrate Passkey Ed25519 local material after login from the exact sealed
      runtime correlated to the returned Wallet Session and active JWT. Wallet
      lock now clears volatile material without clearing the retired composite
      record cache (`5a582a992`).
- [x] Resolve NEAR signing preparation, Passkey and Email OTP operation
      step-up, and local-material rehydration from the exact sealed Ed25519
      runtime. Delete the sealed-record-to-composite-record signing adapter
      (`7a97a1363`).
- [x] Project persisted Ed25519 available lanes and their local/server budget
      advisory directly from exact sealed runtimes. Delete the inert
      in-memory-record inventory and the sealed-record-to-composite-record
      conversion (`06f22ac7d`).
- [x] Build Passkey recovery and provisioning Wallet Session state from exact
      response/runtime facts and publish only the resolved identity. These
      operating paths no longer write or rebuild the composite Ed25519 record
      (`98a595709`).
- [x] Discover readiness lanes asynchronously from exact sealed Ed25519
      runtimes. Durable seals remain record-policy reauthorization anchors,
      consume only against trusted server budget, and survive grant clear,
      expiry, and exhaustion; delete the duplicate composite-record mutation
      port (`e3a562ed3`).
- [x] Delete the zero-caller composite Ed25519 store, persistence adapter,
      Wallet Session parsing, and state adapters; retain only exact-runtime
      builders and the JWT boundary parser (`40e9c34fc`).
- [x] Isolate and narrow sealed transport authorization to its live ECDSA
      domain. Remove the unused Ed25519 arm, grant alias, and source
      discriminator (`d82cda777`, `2e28e741f`).
- [x] Retire composite-record browser rehydrate and Email OTP inventory tests,
      migrate valid seal/export coverage to current builders, and remove
      obsolete record resets from unrelated suites (`a62080152`).
- [x] Make non-iframe implicit NEAR funding read its bearer credential from the
      canonical active Wallet Session authorization projection; missing or
      expired authorization fails before network use, independently of MPC
      material persistence (`174c89600`).
- [x] Delete the unread record-derived Wallet Session bearer projection from
      NEAR transaction admission. Canonical preparation and the admitted
      operation-claim receipt remain the authorization inputs (`5173ad50b`).
- [x] Make NEAR transaction readiness and authorization planning consume the
      shared canonical preparation plus independent reusable-authorization
      state. The composite session record remains only for the still-open
      lifecycle hook adapters (`6edc2d100`).
- [x] Derive NEAR transaction expiry invalidation, retry admission, and
      same-method UI routing from the canonical active authorization and
      selected factor instead of the composite session record (`535c0be3b`).
- [x] Build NEAR Passkey operation-step-up authority from the exact selected
      lane and its policy from canonical material preparation. Preserve the
      full signer participant set without reading the composite session record
      in the signing-flow hook (`8ad73528b`).
- [x] Validate NEAR Email OTP operation-step-up proof at the server boundary,
      consume the exact OTP challenge, persist factor evidence, and issue a
      one-use operation grant without minting a reusable Wallet Session or
      consuming its quota (`007416714`).
- [x] Extend the NEAR operation-grant boundary with a strict discriminated
      material-recovery request and mirrored response. Passkey admits no
      recovery branch; Email OTP removes the exact enrollment server seal after
      OTP consumption and before grant issuance, and rejects key-version
      substitution (`7dea7838a`).
- [x] Parse the same material-recovery union at the SDK grant boundary and
      correlate the mirrored response with the requested wallet, material
      session, activation, and enrollment-key version. Passkey cannot request
      local recovery in the client domain types (`88cc478f0`).
- [x] Define the Email OTP worker transport for operation-material
      rehydration. Its strict boundary parser validates the prepared
      operation-step-up authorization, intent, display digest, proof authority,
      expected material activation, threshold session, and public key; the
      browser client rejects response correlation drift (`f07020d80`).
- [x] Complete NEAR Email OTP operation step-up for transaction, delegate, and
      NEP-413 signing when the canonical material is already live. Prepare the
      exact operation before confirmation, consume one operation grant, and
      keep reusable Wallet Session creation and quota use out of the step-up
      branch (`069db2326`).
- [x] Route transaction, delegate, and NEP-413 signing through one
      authorization-neutral operation-material carrier. Live and sealed
      Passkey/Email OTP branches prepare before confirmation, preserve exact
      activation and factor, attach the issued one-use grant beside material,
      and never construct or reread a reusable Wallet Session (`2b585ed38`).
- [x] Complete sealed Email OTP operation-material recovery inside the worker:
      apply the ephemeral client seal, request the one-operation grant and
      server-unsealed ciphertext, remove the client seal, import and correlate
      the exact material, zeroize/dispose temporary secrets, and return the
      active material beside the issued grant (`126df7138`).
      The focused supersession, exact-owner queue, operation-material, and
      Email OTP unseal/step-up suites pass 37/37 at the current checkpoint.
- [x] Replace the five public NEAR factor-specific preparation, Passkey
      rehydration, and Email OTP recovery ports with one Browser-owned
      `{ preparation, executor }` material boundary. Exact factor, signer,
      session, and activation correlation now occurs before any active client
      crosses into generic signing orchestration (`fe33b405a`).

### Worker, WASM, and bundle boundary

- [x] Delete the unread ECDSA runtime-validation registry and its
      JWT/expiry-derived material key; retain canonical manifest/runtime
      correlation and role-local resolver validation.
- [x] Keep pending Ed25519 Yao registration material inside its browser/WASM or
      Email OTP worker owner; generic registration invokes typed persistence
      and never receives the active client.
- [x] Delete the dead Email OTP registration-commit worker operation and reject
      non-positive or unsafe signer slots at the remaining persistence boundary.
- [x] Keep live secret material owned by the worker or WASM boundary.
- [x] Preserve the Refactor 93 rule that `SigningWorker` receives the exact A/B
      package pair atomically and the Refactor 94C rule that its activation,
      delivery, session, budget, and presign effects live in private D1.
- [x] Keep generic confirmation free of MPC material; preserve Email OTP
      KEK/secret, Near root/client, and ECDSA derivation/presign/online-signing
      custody in their secure owners.
  - [x] Move Passkey secp256k1 and Ed25519-Yao raw export handling into the
        dedicated Passkey MPC export worker; the generic confirmation worker
        no longer imports export WASM/Yao runtime or handles export messages.
  - [x] Move Passkey MPC export transport, response validation, prompt routing,
        and viewer lifecycle into a dedicated main-thread export owner;
        `UiConfirmManager` no longer imports or sends the export protocol.
  - [x] Move Passkey warm-session material, PRF claims, sealing, rehydration,
        policy updates, and Shamir3Pass prewarm into the dedicated Passkey MPC
        session worker; the generic confirmation worker now handles prompts
        only.
  - [x] Move volatile Passkey warm-material writes, status reads, claims,
        consumption, clearing, session-worker lifecycle, and prewarm into the
        dedicated main-thread `PasskeyMpcSessionManager`; generic confirmation
        no longer imports or sends the session-worker protocol.
  - [x] Move durable seal persistence, restore, deletion, and policy
        coordination into `PasskeyMpcSessionManager`, then delete the temporary
        durable session-worker seam from generic confirmation (`d9c303f3c`,
        `fe07fea5b`, `fa1f21657`).
    - [x] Require Passkey persisted-session discovery at the lifecycle port;
          remove the optional host-assembly fallback that silently omitted it
          and the redundant `authMethod` discriminators from Passkey discovery
          and restore ports.
    - [x] Move persisted-session discovery and exact sealed-record listing into
          `PasskeyMpcSessionManager`; session-public and no-prompt ECDSA reuse
          call the session owner directly.
    - [x] Move raw worker seal and rehydrate operations onto
          `PasskeyMpcSessionManager`; generic confirmation calls the owner
          internally and exposes no forwarding methods.
    - [x] Move persisted restore command routing, exact-record correlation,
          module-global single-flight, restore leases, readback, and
          invalid-record cleanup into `PasskeyMpcSessionManager`; expiry keeps
          the sealed material available for same-method step-up.
    - [x] Delete the redundant exported
          `PasskeyMpcSessionDurableWorkerPort`; the dedicated session port is
          the only raw seal/rehydrate worker contract.
    - [x] Delete the one-call
          `ensurePasskeySealedRecordPersisted` coordinator and move its
          optional missing-restore-metadata handling into
          `PasskeyMpcSessionManager`.
    - [x] Move high-level seal persistence, exact-record registration/readback,
          and persistence single-flight into `PasskeyMpcSessionManager`
          (`d9c303f3c`).
    - [x] Move sealed-session policy coordination into
          `PasskeyMpcSessionManager`; preserve sealed material on expiry and
          exhaustion, and delete only invalid persisted records (`fe07fea5b`,
          `fa1f21657`).
    - [x] Delete the remaining generic durable-session ports and callback cycle
          after the dedicated session owner supplies persistence and policy
          coordination directly (`d9c303f3c`).
- [x] Remove replaced worker entrypoints, loaders, manifest rows, and public
      exports.
  - [x] Delete the generic worker's `EXPORT_PRIVATE_KEYS_WITH_UI` protocol arm
        and export-runtime imports; register the dedicated Passkey MPC export
        worker in build, freshness, runtime-path, test, and bundle inventories.
  - [x] Delete the generic manager's export worker fields, initialization,
        message union, lifecycle callback map, and recovery forwarding adapter;
        assembly exposes the narrow `PasskeyMpcExportPort` directly.
  - [x] Delete the generic worker's `WARM_SESSION_*` and
        `PREWARM_SHAMIR3PASS` protocol arms; register the dedicated Passkey MPC
        session worker in build, freshness, runtime-path, test, static-asset,
        and bundle inventories.
  - [x] Delete the generic manager's volatile warm-session methods, session
        worker fields, initialization, message union, and request routing;
        assembly exposes the narrow `PasskeyMpcSessionPort` directly.
- [x] Delete the unused `UiConfirmSigningRuntimePort` and the generic combined
      `UiConfirmSigningSessionPort`; the Near runtime names its required
      confirmation and warm-material capabilities directly.
- [x] Delete the zero-caller wallet-host registration-preparation loader and
      module-type exports; retain the single registration-surface preload entrypoint.
- [x] Delete the zero-caller Router A/B ECDSA refresh-client-proof worker
      operation across its wrapper, channel, type map, and worker dispatch.
- [x] Delete the unreachable Email OTP `session_bootstrap` worker branch and
      require registration-attempt identity as an explicit worker input.
- [x] Preserve existing import/export and bundle guards. The key-export,
      Ed25519-Yao custody, ECDSA client-worker split, Email OTP branch
      isolation, and static-wallet-asset checks pass.
  - [x] Point the key-export and Ed25519-Yao custody guards at the dedicated
        Passkey MPC export runtime; both focused guards pass.
  - [x] Keep the generic confirmation worker's static asset graph WASM-free
        while admitting the dedicated Passkey MPC session worker's required
        signer assets.
- [x] Split no worker or bundle without measured evidence. The current
      worker split follows the measured production caller map: generic prompts,
      Passkey MPC session custody, and Passkey MPC export custody have separate
      entrypoints and bundle inventories.
- [x] Verify generic orchestration cannot import secret-bearing worker
      internals. The static wallet asset graph remains WASM-free for generic
      confirmation, and the focused key-export, ECDSA client-worker, and Email
      OTP branch-isolation checks pass after the capability-envelope cutover
      (`def400d94`).

### Host assembly

- [x] Complete the hosted-wallet Seams Session one-time exchange in the iframe
      client. The parent sends only the opaque code and nonce; the wallet origin
      redeems and stores its own JWT, and parent-posted bearer credentials are
      rejected.
- [x] Update Cloudflare, Node, local, and self-hosted call sites in the same
      cutover.
- [x] Preserve static host ports and request-scoped service bindings; apply the
      Refactor 94C owner map only inside the Cloudflare adapter.
- [x] Verify each host assembles the same statically composed capability
      modules and policies.
      Cloudflare, Express/Node, local D1, and self-hosted assembly consume the
      same `RouterApiServiceBag`; route handlers do not access D1 or claim and
      session stores directly. The focused route-surface and self-host parity
      suites pass 15/15.
- [x] Preserve one signed, admitted Gateway → Router command. Keep Router
      stateless; forbid ceremony-wide Router ledgers, tenant-wide Gateway
      runtime state, tenant runtime/cutover selectors, direct Deriver origins,
      direct Gateway role calls, and Gateway-owned SigningWorker delivery.
- [x] Remove obsolete route handlers, service locators, and direct host-role
      access with their last caller.
  - [x] Delete the forwarding-only wallet-unlock service locator; Cloudflare
        unlock routes use the request-scoped `ctx.service.walletUnlock`
        directly (`5f989ea9f`).
- [x] Delete the zero-caller Cloudflare route-registration wrapper and its
      obsolete wrapper-only unit test; production routing remains owned by the
      canonical route-definition dispatcher.
- [x] Delete the obsolete standalone Email OTP ECDSA enrollment SDK/iframe
      route and its JWT-derived runtime-policy scope; canonical `registerWallet`
      remains the sole registration owner.
- [x] Delete the zero-caller standalone ECDSA refresh HTTP adapter and its
      wrapper-only test; canonical route definitions retain the refresh route
      (`a89ede462`, `df478bfed`).
- [x] Delete the duplicate persisted Ed25519 capability fallback service
      locator; the request-scoped runtime remains the single persisted
      load/install/reread owner (`729ad4cdd`).
- [x] Delete the forwarding-only Ed25519 recovery runtime locator; recovery
      consumers use the service's narrow installation and lookup ports
      directly (`868ba6dee`).

### Same-change deletion

- [x] Delete the write-dead composite-record key-ref lookup, record-first
      probes, no-prompt reconnect path, and record-backed ECDSA
      selection/material branches.
- [x] Restore current shared authorization/ECDSA factories, regenerate their
      current shapes through canonical builders, and delete obsolete
      record-store and pre-cutover export tests.
- [x] Restore unit-suite collection by deleting obsolete imports/tests and
      updating still-valid tests through current shared factories; require a
      successful non-empty Playwright unit test listing before normal-signing
      work proceeds.
- [x] Delete the complete production `ThresholdEcdsaSessionRecord*` family,
      public APIs, runtime maps, readers, writers, parsers, and adapters after
      Unit 2 supplies the narrow authorization/session/quota projection.
- [x] Remove legacy-only composite-record fixtures and move retained Email OTP
      coordinator setup to canonical manifest, authorization, and sealed-runtime
      factories.
- [x] Delete `active_state_session_id` from production types and wire shapes.
- [ ] Delete remaining generic wire session aliases and
      authorization/material-scope aliases owned by this cutover.
  - [ ] Remove Wallet Session bearer/grant state from durable Ed25519 and
        active ECDSA sealed-material restore metadata. Recovery and signing
        must receive reusable authorization or a one-operation grant through
        an independent operation carrier.
    - [x] Email OTP ECDSA sealed rehydration reads and correlates the current
          reusable authorization independently; its persisted bearer is no
          longer trusted or transported (`17f0a622f`).
    - [x] Passkey Ed25519 export, hydration, availability, and sealed-runtime
          reads correlate current authorization independently; sealed runtime
          state no longer carries or validates a persisted bearer
          (`7a2ad4bca`, `3d05abca5`).
    - [x] Passkey MPC sealed ECDSA restore reads current authorization and
          correlates wallet, factor, authority, and expiry before rehydration;
          neither worker transport nor reconstructed metadata trusts the
          persisted bearer (`a39e90add`).
    - [ ] Delete bearer and grant fields from sealed restore metadata and its
          boundary parser after the remaining persistence writers stop storing
          them.
  - [x] Require canonical JWT `sid` at the Cloudflare Router boundary and
        delete the legacy `session_id` claim fallback and selector
        (`af6dc1514`).
  - [x] Delete the pure `SigningAuthMethod = SignerAuthMethod` alias and use
        canonical `SignerAuthMethod` throughout signing operation state.
  - [x] Delete zero-caller wallet/session helpers and exact aliases for ECDSA
        authorization, activation requests/results, bootstrap args, and sealed
        resolved identity (`6207cea1f`, `dfee38d07`).
  - [x] Keep the Email OTP ECDSA signing-session route grant-free while
        requiring the independent authorizing grant on Ed25519. The worker
        boundary accepts the canonical ECDSA lane and rejects the retired
        grant alias (`440e3dd10`).
  - [x] Delete the zero-caller ECDSA Wallet Session transport-auth wrapper and
        its wrapper-only type fixtures; active authorization and route
        boundaries carry the bearer credential directly.
- [x] Inline the canonical bootstrap and exact/missing Wallet Session payload
      types in the iframe envelope and delete their one-use wire aliases.
- [x] Delete the unread duplicate ECDSA export operation-authorization carrier;
      explicit export authorization remains the operation's sole authority.
- [x] Delete legacy recovery microstates and compensation branches.
  - [x] Delete the zero-producer Passkey ECDSA warm-seal pending registry, its
        restore wait, and its obsolete unit suite (`c72cbf31f`).
- [x] Delete duplicate signing-lane selectors, auth-method fallbacks, direct
      protocol dispatch, and superseded export coordinators.
  - [x] Replace binary Passkey/Email OTP fallbacks and ad hoc two-factor unions
        across signing, hydration, export, sealed-runtime, and step-up
        boundaries with exhaustive canonical-domain control flow; remove the
        duplicate runtime-postcondition auth alias and shrink the guard
        allowlists (`157eb7562`, `732802dc9`, `40fb0203f`, `bdf6cc5da`).
  - [x] Delete the zero-caller duplicate ECDSA material-key selector
        (`5cc54814d`).
  - [x] Delete the zero-caller private-key export coordinator and its dead
        dependency/store wiring; dedicated capability export owners remain
        (`d3201483b`).
  - [x] Delete the zero-caller Email OTP route-plan auth forwarding selector;
        the canonical auth-lane adapter remains the sole projection owner
        (`6910f4d94`).
  - [x] Delete the zero-caller exact ECDSA and Ed25519 lane-signer projection
        selectors; consumers narrow the canonical signer binding directly
        (`151110bd8`).
  - [x] Delete the local Email OTP route-plan auth wrapper and inline the
        canonical auth-lane projection at its worker callers (`e90c3f09a`).
  - [x] Delete the zero-caller Passkey Ed25519 Wallet Session JWT fallback;
        active authorization remains canonical and sealed-runtime-owned
        (`563909459`).
  - [x] Delete the zero-caller duplicate Email OTP ECDSA publication target
        planner; live publication uses the canonical chain-target planner
        (`b6b691bce`).
  - [x] Delete the zero-caller Email OTP existing-public-capability fallback;
        the canonical existing-key resolver remains live (`d51f1da06`).
  - [x] Delete the zero-caller sealed-session identity converter; the live
        sealed-session filter remains the persistence boundary (`45a4222b2`).
  - [x] Delete the zero-caller ECDSA manifest identity projection; manifest
        identity builders remain the canonical construction path (`19ec99d94`).
  - [x] Delete the zero-caller silent PRF-cache fallback; strict cache setup
        remains the sole writer path (`5a619687a`).
  - [x] Delete the zero-caller Email OTP Ed25519 signing-session authority
        module; canonical `EmailOtpSigningSessionAuthLane` remains the active
        authority boundary (`4f11a1211`).
  - [x] Delete the zero-caller role-local active-state projection and
        unavailable-material constructor; callers use canonical active-state
        builders and explicit unavailable branches (`01521c796`).
  - [x] Delete the zero-caller sealed-record runtime wrapper; active runtime
        resolution uses the wallet/target or chain-kind canonical selectors
        (`3f251b7cb`).
  - [x] Delete the zero-caller recovery-record-to-session identity converter;
        recovery commands accept the canonical exact identity directly
        (`750138097`).
  - [x] Delete the zero-caller composite seal-transport auth type and its
        ECDSA/session aliases; sealed recovery owns the live transport shapes
        (`6dc24c395`).
  - [x] Delete zero-caller threshold-status error constants, formatters, and
        normalization helpers from the warm-session reader; canonical status
        mapping remains in the read model (`308910932`, `111345f7c`).
  - [x] Delete zero-caller warm-claim sufficiency and error-formatting
        helpers; claim/status mapping remains the sole read-model boundary
        (`9427bc746`).
  - [x] Delete the superseded `EcdsaPublicReauthLane` and
        `EvmFamilySharedEcdsaState` unions; canonical selection and hydration
        outcomes own those branches (`f6ce0651e`, `5db9ad87e`).
- [x] Route Ed25519 Yao export through one exhaustive same-method coordinator
      and delete the public Passkey/Email OTP-specific export entrypoints.
- [x] Delete method-specific Passkey/Email OTP committed-lane aliases and the
      duplicate two-slot committed-lane selector.
- [x] Delete the dead in-place ECDSA lane-identity updater, its record-era unit
      test, and the source-range guard whose remaining subject it owned.
- [x] Delete the dead record-backed Email OTP Ed25519 routine-signing lane and
      its active-material recovery path. Retain cold login/unlock recovery,
      sealed refresh, and export recovery; the focused retained recovery suite
      passes 12/12 (`069db2326`).
- [x] Delete zero-caller Ed25519 composite-record rejection, commit,
      runtime-reseed, broad-list, exact-clear, and recovered-session retirement
      helpers (`7886fd39f`).
- [x] Delete the remaining zero-caller operation-usable Ed25519 record,
      current-generation commit/supersession branch, and its obsolete unit and
      type fixtures (`f5c6ec6d9`).
- [x] Delete the zero-caller account/session record readers, record-derived
      Email OTP authority resolver, per-session status port, and record auth
      predicate from the warm capability surface (`94aa9b344`).
- [x] Delete the Passkey durable-state composite-record reverse lookup and its
      record-to-restore parsers after exact Ed25519 restore metadata becomes a
      required seal-transport field (`0f5d7e6b6`).
- [x] Delete composite-record authority from Email OTP Ed25519 sealed
      publication. Correlate the active-client metadata, exact activation,
      canonical Wallet Session state, and factor publication context before
      writing the sealed record (`93ae1e20a`).
- [x] Delete composite-record construction and record-to-signer conversion
      from Email OTP Ed25519 cold login/unlock. The exact bootstrap now builds
      the Wallet Session state and private SDK activation surfaces return the
      canonical signer directly (`f5062fc13`).
- [x] Delete Browser's composite-record lookup from Email OTP Ed25519 recovery
      preparation; exact sealed state now owns its recoverable session identity
      and runtime policy (`e4322bd15`).
- [x] Delete the NEAR unlock wrapper's composite-record wallet lookup; the
      active user binding owns wallet selection (`2cdfea541`).
- [x] Delete the composite-record NEAR wallet-unlock subject and runtime-record
      provenance branch; active signer profile rows own the exact subject
      projection (`8c2aeb3ac`).
- [x] Delete composite-record discovery from wallet-scoped volatile Ed25519
      cleanup; exact sealed records own the material-session IDs
      (`b9638246a`).
- [x] Delete the composite-record authorization lookup from Ed25519 key-export
      preflight; the canonical Wallet Session projection owns lifecycle expiry
      and factor correlation (`47fbe2cbc`).
- [x] Delete composite-record ownership from the wallet-scoped Ed25519 warm
      capability envelope and its transition/provision readback consumers.
      Exact sealed runtime, active authorization, and worker claim now remain
      separate typed inputs (`cdd9cc2b8`).
- [x] Delete the record-backed Ed25519 authorization parser, its 303-line
      record-era unit suite, and the dead manager convenience status port.
      Login postconditions and the public status surface now consume the exact
      runtime plus active authorization (`4ea6eccb7`).
- [x] Delete the forwarding-only selected-lane auth-method selector; prepared
      signing now reads the canonical auth binding directly, and its focused
      auth-neutral preparation suite passes 7/7 (`0983a94ec`).
- [x] Delete obsolete tests, handwritten records, mocks, guards, and fixtures
      that encode pre-cutover behavior.
  - [x] Delete the route-wrapper-only test and the stale public route-catalog
        assertion for the private 94C ECDSA bootstrap plane.
  - [x] Delete the NEAR recovery-ordering and sealed-refresh source guards after
        their retired markers and hydration-derived budget assumption were
        removed (`6d6002e3c`).
  - [x] Delete the combined Email OTP unlock fixture after unlock began
        returning exact sibling capability outcomes (`89e9cd4a5`).
  - [x] Delete the wrapper-only ECDSA refresh test with its duplicate HTTP
        adapter (`df478bfed`).
  - [x] Delete the record-era NEAR session-selection suite after delegate and
        NEP-413 planning moved to canonical hydration plus independent
        authorization; retain same-method step-up coverage through current
        typed hooks (`70ef2a420`).
  - [x] Retire source-guard blocks whose guarded paths were deleted or moved;
        active registration and key-brand checks remain (`703fa1d95`).
  - [x] Retire the obsolete signing-session seal default-key guard; current
        Cloudflare seal configuration uses root/current/accepted key-version
        fields (`2744c6c02`).
  - [x] Repoint the EVM key-slot branding guard at the live provisioning,
        worker, Router validation, and registration/recovery boundaries
        (`fc048026f`).
  - [x] Restore unit-suite collection through the shared sealed-session factory:
        Email OTP Ed25519 fixtures now carry canonical material activation and
        valid runtime-policy scope; 1,975 tests collect in 349 files
        (`e5cb737c8`).
  - [x] Delete zero-caller budget owner, availability, and unknown-status
        adapters; live admission and status readers remain unchanged
        (`20f1bcfca`, `1ce066cf9`, `69b0e6b30`).
  - [x] Delete the zero-caller network-only ECDSA chain-target adapter;
        configured-request and chain-family builders remain (`4250a8871`).
  - [x] Delete the zero-caller ECDSA lane-specific presignature retirement
        helper; global pool clearing and live worker retirement remain
        (`814616909`).
  - [x] Replace the record-era ECDSA export-lane fixture with the shared
        canonical-capability builder, retain exact selection and ambiguity
        coverage, and delete tests for retired runtime/sealed/shared-key lane
        sources (`79bd0e00b`; 16/16 focused tests).

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
      `vault.proxy_use` → audit readback. The persisted D1 vertical is covered
      by `vaultProxyUse.unit.test.ts` and passes at the current checkpoint
      (`5db9ad87e`).
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

- [x] Make React, Lit, iframe, and direct SDK adapters render
      `ready | pending | authorization_required | superseded | failed`
      exhaustively.
- [x] Discard and re-resolve stale state on `superseded` across the direct SDK,
      React, iframe, and demo-wallet projections without locking the wallet.
      A bounded React reread that is still `superseded` preserves the current
      login until the next typed lifecycle event (`c258b94fb`).
- [x] Terminate confirmation immediately on the typed expiry result.
- [x] Wait for secure-origin initialization and consume typed state/events.
- [x] Stop inferring unlocked state from optional IDs, JWT presence, or auth
      method.
- [x] Treat the demo wallet as unlocked only while a reusable Wallet Session is
      active.
- [x] Lock on authoritative expiry, request step-up on exhaustion, and preserve
      the broader app identity session.
- [x] Ensure only explicit wallet unlock creates a reusable Wallet Session.
      Move first ECDSA session activation inside verified wallet unlock, make
      the activation route Wallet-Session-only for additional targets, and
      delete the app-session/export path that can currently mint one.
- [x] Restrict direct ECDSA session activation to an existing same-wallet
      Wallet Session and expose first-session provisioning only after a verified
      unlock proof.
- [x] Send the first exact activation through Passkey session exchange and
      Email OTP wallet-unlock verification; use its Wallet Session JWT for
      additional configured targets.
  - [x] Passkey assertion exchange verifies the proof, provisions the first
        exact ECDSA activation, adopts that correlated activation locally, and
        reuses its Wallet Session JWT for later targets.
  - [x] Email OTP wallet-unlock verification performs the equivalent first
        activation and later-target reuse without exposing worker-owned secret
        material.
- [x] Keep step-up single-operation across signing and export surfaces.

### Provisioning

- [x] Create registration/add-factor auth identity first, then provision each
      capability independently through statically composed canonical owners.
- [x] Make partial capability results explicit and exhaustively handled.
- [x] Return exact per-capability results with no combined cross-curve record.
      Email OTP unlock now returns exact sibling ECDSA and Ed25519-Yao outcomes
      under one proof envelope; the combined discriminants and fixture were
      deleted in `def400d94` and `89e9cd4a5`.
- [x] Use exact wallet, authorization-session, and material-activation
      projections.
- [x] Delete Patch 2 tactical UI/provisioning bridges after their last caller
      moves.
- [ ] Delete obsolete loading heuristics, fallback lane selection, and
      pre-cutover fixtures in the same change.
- [x] Delete the Ed25519 updated-at fallback lane and select directly from the
      canonicalized, priority-sorted candidates.
  - [x] Delete the zero-caller ECDSA reauth-anchor candidate fallback and its
        candidate-only freshness helpers; retain the canonical operation-state
        builder (`24e0c2335`).
  - [x] Delete the zero-caller available-lane reauth-anchor fallback and its
        lane-selection/version/source helpers; retain canonical operation-state
        freshness and lane admission (`acb368888`).
  - [x] Delete the zero-caller dual-PRF registration credential helper and its
        allow-list adapter; the canonical credential collector remains live
        (`93958f9a6`).

### Unit 4 exit

- [ ] Every deletion-ledger entry assigned to Unit 4 is closed; ownership
      corrections are recorded before implementation.
- [x] UI type fixtures reject incomplete lifecycle states.
- [ ] Existing Refactor 92 contracts still prove expiry/exhaustion separation,
      refresh allowance, step-up behavior, and Passkey/OTP parity.
  - [x] The local Refactor 92 boundary, retry, invalidation, planning, demo,
        persistence, and policy set passes 38/38 and proves typed
        expiry/exhaustion separation plus same-method step-up. Refresh
        allowance and cross-factor parity remain environment-backed gates.
- [x] Registration and provisioning expose no partial legacy capability shape.

## Final Conformance Gate

This is a validation gate, not a deferred cleanup phase.

- [ ] Every applicable deletion-ledger entry is closed; any reassignment names a
      follow-on plan outside Refactor 90 scope.
- [ ] Prohibited legacy symbols, routes, imports, exports, aliases, record
      families, and obsolete source guards are absent.
- [x] Required factor-neutral, worker/WASM, import, and bundle guards pass.
      Key-export custody, ECDSA worker ownership, signing-engine architecture
      and identity, and static-wallet-asset checks pass after the latest
      `dev` merge.
- [x] Public export and dependency-direction checks pass. The SeamsWeb public
      surface and workspace-package boundary checks pass after the latest
      `dev` merge.
- [ ] Shared, SDK, server, worker, intended-test, and Rust type/build checks
      pass.
  - [x] Repository SDK/server/app type checks pass at the local acceptance
        checkpoint; Rust normal-signing vectors pass 3/3 and the ECDSA client
        protocol passes 9/9.
- [ ] Focused unit, crash, concurrency, host-adapter, worker/WASM, and vector
      tests pass.
  - [x] Focused Refactor 92 lifecycle tests pass 38/38; hosted-recovery,
        activation-pair, escrow, and operation-material tests pass 18/18; key
        export, branding, Email OTP isolation, signing architecture, and ECDSA
        client-worker boundary checks pass.
- [ ] `pnpm test:intended` passes against a healthy environment.
- [ ] `git diff --check` passes.

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
- [Refactor 90A patches](./refactor-90A-patches.md)
- [Email OTP local rehydration](./refactor-patch-2-email-otp-local-rehydration.md)
- [Refactor 91](./refactor-91.md)
- [Refactor 92](./refactor-92-session-expiry-handling.md)
- [Refactor 93](./refactor-93.md)
- [Refactor 94C](./refactor-94C-regression-fixes.md)
- [Refactor 82B authority typing](./refactor-82B.md)
- [Ed25519 Yao implementation plan](./router-ab/ed25519-yao/implementation-plan.md)
- [Satyr Secrets Vault](./satyr-secrets-vault.md)

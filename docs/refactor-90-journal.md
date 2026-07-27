# Refactor 90 Progress Journal

Companion to the [Modular Auth And Capability Refactor Plan](./refactor-90-modular-auth-capabilities-plan.md).

This file holds dated progress entries so the plan stays a readable checklist.
The plan records active execution-unit status; the narrative and historical
phase record live here.

## July 27, 2026: Plan Consolidated Into Five Execution Units

- Consolidated Foundations A/B, Phases 4–5, and the ECDSA portion of Phase 18
  into Unit 1: canonical hydration and canonical ECDSA state.
- Consolidated Phases 7–14, including the typed SDK capability-selection work
  from Phase 8, into Unit 2: the shared authorization core.
- Consolidated Phases 17–21 and 24 into Unit 3a: the no-release MPC cutover.
  Worker/bundle and host-assembly obligations remain explicit exit checks.
- Assigned the minimal vault proving vertical to Unit 3b and
  [Satyr Phase 6](./satyr-secrets-vault.md). Units 3a and 3b may develop in
  parallel after Unit 2 stabilizes; supported release still requires both
  proving tracks unless the normative plans are amended together.
- Consolidated Phases 22–23 into Unit 4: UI and provisioning.
- Removed standalone Phase 6 inventory work. Every unit now begins with a
  scoped inventory seeded from the deletion ledger.
- Removed Phase 27 as an implementation phase. Deletions remain same-change
  obligations in their owning units, followed by one final conformance gate.
- Replaced repeated architecture and validation prose with a SPEC invariant
  ownership index and unit-local validation table.

### Frozen reduction history

The earlier reduction ledger recorded why the first plan slimming was safe. It
is frozen here as history. Future deletions follow the operational
[deletion ledger](./refactor-90-deletion-ledger.md) and do not require a second
row in this table.

| Removed design weight               | Protected property                     | Replacement                                                                  |
| ----------------------------------- | -------------------------------------- | ---------------------------------------------------------------------------- |
| ECDSA readback-pending microstate   | Crash-safe local finalization          | One atomic IndexedDB transaction installs, retires, and deletes the journal. |
| NEAR recovery microstates           | Server-uncertainty recovery            | Two durable states plus idempotent, queryable consuming calls.               |
| Separate server-uncertain stages    | Exact replay after ambiguous response  | Recovery ID and server readback.                                             |
| Pre-promotion cleanup stages        | Respect user cancellation              | Reload reconciles `cancel_requested` and never resumes the abandoned parent. |
| Separate seal/source cleanup states | No partially finalized local state     | Atomic finalization transaction.                                             |
| Affine runtime leases               | Exact-owner serialization              | One queue per exact material owner, with generation/fence checks.             |
| Runtime-disposal protocol           | Secret/runtime lifetime safety         | Existing worker ownership and disposal boundaries.                           |
| Target-revocation subsystem         | Eventual offline revocation             | One exact idempotent revocation command; server claims remain server-owned.   |
| Synthetic third factor              | Factor-neutral orchestration           | Passkey/OTP conformance plus the generic-module factor-literal guard.        |
| Recursive evidence grammar          | Precise current authorization evidence | Closed evidence unions for supported factors.                                |
| Repository-wide inventory phase     | Complete migration scope               | Unit-scoped inventory seeded from the standing deletion ledger.              |
| Triple enforcement for each rule    | Effective enforcement                  | One cheapest check per failure mode.                                         |
| Broad vault product slice           | Architectural proof                    | One real Satyr Phase 6 operation.                                            |
| Speculative capability kinds        | Current closed vocabulary              | Add a kind only with its first real consumer.                                |

## July 27, 2026: Canonical ECDSA Hydration Boundary Started

- Committed `bee19500b`, making canonical lookup distinguish a missing
  capability from missing ready material or its sealing key. The canonical
  store suite passes 10 of 10 tests.
- Rejected a generic exported restorable-material proof wrapper because any
  importer could subclass it and launder an unchecked string.
- Committed `98b07c672`, adding the ECDSA protocol normalizer from exact
  canonical lookup and runtime observations into the shared four-outcome
  hydration plan. The internal restorable-material constructor is nominal,
  absent from public barrels, and guarded to the protocol adapter.
- Validation: SDK and unit type checks pass; the ECDSA identity boundary guard
  passes; hydration mapping and entry-point equivalence tests pass 3 of 3;
  `git diff --check` passes.
- The legacy `ThresholdEcdsaSessionRecord*` family currently mixes material
  ownership with authorization/session/quota state. Unit 1 removes its material
  responsibility. Final family/API/map deletion moves to Unit 3a after Unit 2
  installs the narrow authorization projection, avoiding a temporary
  replacement mega-record.

## July 27, 2026: Canonical Sealing And Server Reconciliation Implemented

- Wired registration and add-signer through the exact canonical activation
  planner, encrypted worker journal, server commit, journal-backed finalizer,
  and atomic canonical material publication as `ab510dab8`.
- Moved ECDSA refresh and export hydration to exact canonical material refs.
  The tactical role-local store and its two IndexedDB object stores were
  deleted in the same checkpoint; the wallet schema advanced to v11.
- Added immediate activation reconciliation as `4c9e8c942`: ambiguous committed
  requests query then replay exactly for bootstrap, `not_committed` retries the
  exact command, and correlation conflicts fail closed while retaining the
  journal.
- Validation: SDK and unit type checks pass; canonical store, schema,
  rehydration, registration orchestration, and worker waterfall tests pass 55
  of 55; focused IndexedDB, worker-split, ECDSA identity, and key-material
  boundary guards pass; Prettier and `git diff --check` pass.
- Added a real worker restart test: canonical encrypted material survives
  termination and a fresh worker reopens persistence and rehydrates the same
  exact durable material reference and binding.
- `R90-INV-005`, `R90-INV-006`, and `R90-INV-011` now have implementation and
  focused verification evidence. Foundation B remains open for refresh-path
  selection, rehydrated signing in one-target and shared EVM-family
  configurations, and deletion of the legacy session-record family.
- Connected SDK-server registration and add-signer activation to the
  non-consuming prepare boundary before commit as `112fda830`. Commit now
  carries and verifies the exact prepared request digest.
- Registration retains its pending D1 branch after a committed Router receipt
  when later bootstrap or provisioning fails. An exact retry converges through
  the Router's query-first activation behavior without creating another D1
  lifecycle owner.
- Validation: SDK-server and unit type checks pass; focused registration and
  add-signer lifecycle tests pass 8 of 8; Prettier and `git diff --check` pass.
- The public browser route and worker-owned prepared-journal cut remain open.
  The internal server bridge alone does not close the pre-effect crash window.
- Exposed public registration prepare/query routes and made activation commit
  require the exact prepared digest as `90076575c`. The SDK registration path
  now prepares before committing, while query can reconcile pending D1 state
  with an already-committed Router receipt.
- Validation: server, web SDK, and unit type checks pass; focused public
  registration and orchestration tests pass 17 of 17. The worker still needs to
  persist encrypted pending state between prepare and commit, so this boundary
  does not yet satisfy the journal-first invariant by itself.
- Added public add-signer prepare/query and exact digest-bound commit parity as
  `ed8dc45fd`. A committed Router effect no longer destroys the pending
  add-signer ceremony when downstream provisioning fails; query and retry
  converge on the stored receipt.
- Added the factor-neutral initial activation planner as `c12636a6b`. It owns
  fresh independent capability, signer, material-owner, manifest, activation,
  and durable-material identities and rejects authorization/session/worker
  handles as substitutes.
- Added exact prepared-journal cancellation as `c66a1125b`. One IndexedDB
  transaction deletes only the matching prepared journal and its sealing key;
  committed activation is preserved for reconciliation and finalization.
- Added fixture-backed coverage for every canonical ECDSA lookup result as
  `bf08f7512`: active, retired, missing, exact binding mismatch, exact record
  conflict, corrupt, and persistence unavailable. The focused store suite
  passes 7 of 7 tests.
- Moved canonical ECDSA persistence behind high-level prepare, record-commit,
  seal/finalize, and open operations as `c5e3f3efc`. Callers no longer supply
  sealing keys, ciphertext, ciphertext digests, or ready manifests.
- Pending and ready signer state now use AES-256-GCM with nonextractable,
  activation-scoped keys, canonical authenticated headers, and recomputed
  SHA-256 ciphertext digests. `75517ba90` encrypts the decoded state bytes
  directly so the store does not create a second textual plaintext copy.
- Replacement atomically retires the prior manifest, deletes its encrypted
  material and sealing key, publishes the replacement, advances the exact
  pointer, and deletes the committed journal. A failed generation CAS preserves
  both the prior active state and the replacement journal/key for
  reconciliation.
- Fixed a server replay regression as `ffb5fc5e7`: an exact activation retry may
  rebuild a later local timestamp, while the durable original activation time
  remains authoritative and all stable activation fields still match.
- Exposed authenticated, non-consuming activation preparation and exact
  three-way query routes as `672d7fa9a`. They reuse the existing SigningWorker
  durable commit/query record and add no server ledger or schema. Activation
  commit now queries first and returns the stored receipt on exact replay.
- Added strict shared TypeScript parsers and type fixtures for preparation and
  `committed | not_committed | correlation_conflict` outcomes as `8e71f2f3d`.
- Validation: canonical-store browser tests pass 6 of 6; shared activation
  parser tests pass 12 of 12; focused Rust activation tests and strict Router
  boundaries pass; SDK, shared, unit, and strict-Router type/check gates pass;
  Prettier, rustfmt, and `git diff --check` pass.
- These foundations are not live consumers yet. Registration still needs the
  TypeScript server/browser bridge, the worker must persist prepared state
  before the consuming call, refresh/sign/export must hydrate through the
  canonical store, and the tactical store/record family remains until that
  atomic cut.

## July 27, 2026: Exact Session Projection And Activation CAS Checkpoint

- Landed the canonical ECDSA manifest/history/current-pointer store and
  two-state activation journal as `6decfb79d`. The IndexedDB v10 migration is
  additive; tactical v9 stores remain until the live writer and every hydration
  consumer move in one cut.
- Bound server activation receipts to the exact activation correlation, request
  digest, server generation, protocol lifecycle, and activation digest before
  they can become a committed journal entry.
- Added replacement CAS coverage as `a4ba253bd`. A successful replacement
  retires the prior manifest, deletes prior material, advances the exact current
  pointer, and deletes the journal atomically. A generation mismatch preserves
  the prior state and committed journal for reconciliation.
- Separated app identity, reusable Wallet Session lifecycle, and per-capability
  readiness through the secure-origin session boundary as `f164b36ac`. ECDSA
  material can remain restorable while reusable authorization is missing,
  expired, or exhausted.
- Confirmed that direct ECDSA-only unlock consumes the exact ECDSA subject with
  zero NEAR reads or activation, registered NEAR identity survives absent
  authorization/material readiness, and refresh resolves ECDSA-only identity
  without fabricating NEAR state.
- Validation: the focused subject/session suites pass 14 of 14 tests; the
  canonical-store replacement suite passes 3 of 3 tests; SDK and unit type
  checks and `git diff --check` passed at their owning checkpoints.
- The consumer-cut audit found one load-bearing gap: the worker currently keeps
  pending signer state only in memory until after the consuming server
  activation. The next cut must durably encrypt `activation_prepared` before
  that server effect and requires a replayable/queryable server activation
  contract. A direct store-class substitution would retain the crash window.

## July 26, 2026: Foundation B Durable Model Corrected

- Reconciled the canonical ECDSA model with the implemented material lifecycle:
  Wallet Session expiry and operation budgets do not expire or exhaust sealed
  ECDSA material, and replacement remains the sole modeled retirement.
- Made the two-state activation journal crash-complete. Its prepared branch now
  owns encrypted pending client state, fresh target identities, and the exact
  replayable server command; the committed branch owns the correlated server
  generation and structured receipt.
- Split immutable manifest history from the exact capability/authority current
  pointer so same-capability replacement can retire the old manifest and publish
  the new one atomically.
- Required active parser results to include validated encrypted material and
  recorded the missing server generation CAS and idempotent activation-query
  boundary as Foundation B implementation work.

## July 26, 2026: Wave 1 Phase 4A And Phase 5 Boundaries Implemented

- Landed the exact-subject Phase 4A slice as `b54cd1bca` and the role-local
  material boundary slice as `fcdf0ad3c`.
- Added an ECDSA-only wallet-unlock subject resolver whose import graph and
  reads contain no NEAR account or runtime-session identity. ECDSA subjects use
  exact `ecdsaThresholdKeyId`; broad mixed-family subjects fail type checking.
- Made combined subject discovery fail closed with typed lookup and validation
  failures. An unavailable or invalid family cannot be published as a partial
  `all_registered_mpc` subject set.
- Slimmed `buildEcdsaRoleLocalSigningMaterialHandle()` to exact material facts.
  Chain target, wallet, session, active-state, grant, quota, remaining-use, and
  expiry inputs are rejected, including through broad variables.
- Replaced the role-local handle's ambiguous verifying-share field with strict
  `EcdsaClientVerifyingPublicKey33B64u`. Its parser requires canonical unpadded
  base64url, 33 decoded bytes, and a compressed secp256k1 prefix.
- Deleted the ready-session handle adapter and the regression expectation that
  the same material produces different Tempo and ARC handles. Lane-level
  cross-chain rejection, combined unlock orchestration, complete refresh
  parity, and profile lifecycle separation remain open Phase 4/5 work.
- Classified the unchanged broader ECDSA failure as
  `valid_test_needs_update`: its fail-closed invariant is valid, while its exact
  `hydration is blocked: missing_material` message belongs to the future Wave 2
  protocol adapter rather than this handle-boundary slice.
- Classified the three unchanged profile-lifecycle failures as pre-existing
  `production_regression` evidence: current profile projections can still
  activate login state without an exact surviving signing lane. Their owning
  Phase 4 session-read/lifecycle items remain open; this slice changed neither
  those assertions nor their production behavior.
- Validation: SDK and unit type checks pass, the wallet-scoped lookup guard
  passes, seven focused subject/material assertions pass, the touched
  TypeScript files pass Prettier checks, and `git diff --check` passes.

## July 26, 2026: Wave 1 Leaf Hydration Contract Implemented

- Reclassified the focused ECDSA failures as `obsolete_test_or_fixture` under
  `tests/AGENTS.md`: the tests encoded retired public-facts and worker-response
  shapes. Commit `f41b29676` moved them to the shared current-domain factories;
  the focused files now pass 26 of 26 tests without production compatibility
  paths.
- Added nine distinct capability, material-owner, runtime, activation, worker,
  key, lifecycle, reauthorization-policy, and registered-key identities with
  boundary parsers. `RestorableMpcMaterialRef` remains an opaque proof with no
  generic parser or construction point until Wave 2 protocol adapters can prove
  both exact activation binding and an available unlock source.
- Added one proof-branded `MpcMaterialActivationRef` with a strict exact-field
  parser and canonical builder. Authorization, Wallet Session, grant, quota,
  and activation IDs remain independent.
- Added the four proof-branded hydration outcomes and branch-specific builders.
  Builders derive correlated capability/owner fields from the activation proof
  and retired capability/owner/authority fields from the public anchor, so
  mismatched duplicate inputs cannot be supplied.
- Split `blocked` into a null `missing_capability` branch and exact-capability
  branches for every other failure, making the reason/reference correlation
  unrepresentable when invalid.
- Added type fixtures rejecting raw identity substitution, direct proof
  literals, alternate-branded broad spreads, missing branch requirements, and
  mixed live, restorable, and public-anchor fields. The signing-engine identity
  guard rejects direct casts to proof types.
- Reconciled the SPEC with the implemented Refactor 82B compact
  `WalletAuthAuthorityRef` and the correlated blocked branches. Protocol-local
  observation adapters depend on canonical ECDSA and Near activation
  persistence, so they close with Wave 2 rather than wrapping the effectful
  tactical resolvers.
- Validation: shared and SDK type checks pass, unit type checking passes,
  `git diff --check` passes, the hydration boundary suite passes 45 of 45 tests,
  and the focused ECDSA fixture suite passes 26 of 26 tests.

## July 26, 2026: Implementation Kickoff Prepared

- Created the clean `codex/refactor-90-implementation` worktree from current
  `origin/dev`, including the completed Refactor 93 deletion baseline, and
  committed the reconciled Refactor 90 documents as `f9fa3bb85`.
- Installed the frozen pnpm workspace offline and linked the ignored generated
  WASM packages from the main checkout. No tracked runtime or generated artifact
  changed.
- Classified the first failed baseline checks as
  `environment_or_infrastructure_failure`: the new worktree initially lacked
  ignored WASM `pkg/` artifacts. After linking them, `pnpm -s type-check:sdk`
  and `pnpm -C tests type-check:unit` passed.
- The initial focused ECDSA run passed 4 of 26 tests. The later fixture-authority
  audit reclassified the remaining failures as `obsolete_test_or_fixture`; the
  Wave 1 entry above records their isolated repair and passing gate.
- Mapped implementation into Waves 0-7 while preserving all stable phase
  numbers and release gates.
- Identified the first dependency: Foundation A consumes a small subset of the
  Phase 7 leaf identity vocabulary. Those leaf brands and parsers land with the
  hydration contract; the rest of Phase 7 remains in the authorization slice.
- Scoped the first code commit to leaf identities, the shared four-outcome
  hydration union/builders, and type fixtures. Existing ECDSA and Email OTP
  Ed25519 tactical resolvers remain behaviorally unchanged in that commit.
- Recorded the Wave 1 owner map:
  - shared identity brands and parsers:
    `packages/shared-ts/src/utils/domainIds.ts` and its type fixture;
  - new hydration contract:
    `packages/sdk-web/src/core/signingEngine/session/material/`;
  - existing protocol evidence:
    `ecdsaRoleLocalMaterialResolver.ts` and
    `emailOtp/ed25519YaoLocalMaterial.ts`;
  - Foundation B replacement boundary:
    `session/persistence/records.ts` and its shared record factories;
  - first focused regression owners: hydration type fixtures,
    `readySecp256k1Material.rehydration.unit.test.ts`, and the canonical
    signing-session record factory.
- Corrected the remaining SPEC wording that allowed routine unlock to republish
  an ECDSA manifest. Only registration, explicit material reactivation, and
  recovery write durable activation state; unlock and refresh rehydrate it.

## July 26, 2026: Full-Plan Consistency Audit

- Removed duplicate status from the execution-order table and moved descoped
  Phases 15 and 25-26 out of the checkbox tracker.
- Reconciled companion-plan state: Patch 2 and Refactor 92 list only their real
  remaining acceptance, Refactor 82B is an implemented Phase 7 baseline, and
  the completed Refactor 93 deletion branch is a required stable-checkpoint
  dependency while hosted recovery and latency remain release gates.
- Kept Phase 4 responsible for typed session-read inputs and Phase 22
  responsible for iframe initialization sequencing and demo display behavior.
- Replaced the unconditional MPC `authorizationSessionId` scope recorded in the
  July 23 entry with `MpcOperationAuthorizationRef`. Its reusable-session branch
  requires `WalletSessionId` plus `CapabilityGrantId`; its operation-step-up
  branch requires `CapabilityGrantId` and excludes `WalletSessionId`. Both
  branches carry the independent exact material activation.
- Clarified quota behavior: warm reusable-session signing consumes wallet quota,
  operation step-up consumes only its one-operation grant, and export consumes
  no wallet-signing quota.
- Moved one-command Router and exact-replay checks to integration/persistence
  validation, leaving intended-behaviour E2E focused on user-visible lifecycle
  transitions.
- Validation: all 27 phase headings are represented, all 14 plan invariant
  citations resolve to the SPEC, relative links resolve, Markdown code fences
  balance, and `git diff --check` passes.

## July 26, 2026: Refactor 93 Yao Execution Reconciliation

- Recorded Refactor 93's request-scoped Gateway persistence, one-command MPC
  Router execution, pair-bound role-local lifecycle, and atomic SigningWorker
  delivery as the Near server baseline for Refactor 90.
- Mapped the Refactor 90 recovery journal's admission, acquisition, and
  promotion effects onto Refactor 93's request-scoped admission claim, exact
  Router execution/replay, and explicit client-verified recovery promotion.
  The client journal continues to correlate receipts by `recoveryId` without
  mirroring Router role state.
- Required Near operation grants and applicable quota claims to commit before
  Router execution, with the admitted authorization digest retained in the
  canonical input-pair binding. Exact Router replay consumes neither resource
  twice.
- Updated Phases 18-21, 24, and 27 to reuse the partitioned server owners,
  preserve Router/role/SigningWorker custody boundaries, and keep the deleted
  tenant runtime, family selectors, serial routes, and direct Gateway
  orchestration absent.
- Added focused validation for one logical Gateway-to-Router command, exact
  replay without Yao reevaluation, staged recovery until explicit promotion,
  and zero Yao calls during normal signing or Wallet Session expiry.
- Left Refactor 93's remaining hosted recovery and latency acceptance under
  Refactor 93 ownership. It gates a Near release rather than Foundations A-B or
  ECDSA implementation.

## July 23, 2026: Refactor 92 Frozen-Lifecycle Reconciliation

- Added `R90-INV-014` so Refactor 90 preserves Refactor 92's implemented
  reusable Wallet Session behavior across the identity and material cutover:
  24-hour/three-use defaults, distinct expiry and exhaustion, one-operation
  same-method step-up, explicit-unlock session creation, canonical invalidation,
  secure-origin ownership, and demo locking.
- Tightened `R90-INV-013` around five independent identities:
  `SeamsSessionId`, `WalletSessionId`, `CapabilityGrantId`,
  `MpcWalletSigningQuotaId`, and `MpcMaterialActivationId`.
- Corrected the target MPC operation scope so
  `authorizationSessionId: WalletSessionId` names reusable wallet
  authorization. Operation grants retain their independent
  `SeamsSessionId` binding, and `materialActivation` names only exact activated
  material.
- Extended Phases 17-23 and their tracker/validation checks to preserve
  post-refresh allowance, exact material rehydration, canonical expiry events,
  one server-race retry, immediate confirmation termination, no expiry-driven
  recovery/linking, and Passkey/Email OTP parity across all signing/export
  surfaces.
- Added deletion-ledger targets for the live
  `WalletSessionId = SigningGrantId` alias, authorization/material session
  aliases, recreated lifecycle inference, and pre-cutover fixtures.
- Kept Refactor 92 itself frozen. Its staging and production 24-hour default
  checks remain deployment acceptance owned by that plan.

## July 22, 2026: Invariant Wiring And Deletion-Ledger Restoration

- Wired the `R90-INV` IDs into the plan: each Settled Architecture section,
  Foundation exit-check list, migration phase, and validation subsection now
  cites the SPEC invariants it instantiates, with the SPEC text normative on
  divergence.
- Reconstituted the symbol-level deletion targets lost in the July 22 slimming
  as [refactor-90-deletion-ledger.md](./refactor-90-deletion-ledger.md),
  extracted from the pre-slim plan at `f5eb4ace9`. Phases 6, 18, and 19 and
  Foundation B link to it; scoped inventories seed from it.
- Restored granular open-item checklists for the in-flight work: Foundations A
  and B and Phases 4-5 record done-so-far groundwork and their remaining items
  at sub-phase grain, updated to the slimmed architecture (two-state journals,
  no synthetic third factor).
- Restored three decided rules the slimming dropped: operation descriptors
  declare quota applicability and key export never reads or spends wallet
  signing quota (appended to `R90-INV-009` and plan §6); the Refactor 82B
  `WalletAuthAuthority` restructure lands as one coordinated cut with Phase 7;
  and the Ed25519 Yao implementation plan remains authoritative for the Yao
  construction and production gates, which Refactor 90 cannot advance.
- Escaped the unescaped pipe in the reduction-ledger `all \| any` row and
  marked the SPEC's follow-on sections (service-account evidence, Better Auth
  bridge, Enterprise SSO, IdP mode, `mpc_signer_proof`, `capability-idp-access`,
  and the non-minimal vault surface) as design context rather than Refactor 90
  acceptance surfaces.

## July 22, 2026: Plan Simplification And Recovery-State Reduction

- Replaced the 5,383-line multi-purpose plan with a 725-line implementation
  checklist. The companion SPEC now owns twelve numbered normative invariants;
  phases cite them instead of repeating state machines, effect order, and test
  rules.
- Reduced Near recovery persistence to `prepared | promotion_committed`.
  `prepared` carries `continue | cancel_requested`; every consuming server call
  is independently idempotent and queryable by recovery ID. The final IndexedDB
  transaction writes replacement/retirement/lifecycle facts and deletes the
  journal atomically.
- Reduced ECDSA activation persistence to
  `activation_prepared | server_activation_committed`. Material, manifest,
  replaced-manifest retirement, and journal deletion commit atomically. Optional
  canonical readback is verification after commit and no longer a durable
  lifecycle stage.
- Removed the public affine material-lease protocol in favor of one exact-owner
  queue plus generation/fence checks. Volatile runtime publication, disposal,
  and zeroization remain worker lifecycle responsibilities rather than journal
  facts.
- Preserved a minimal production-shaped vault vertical to prove native session,
  operation-bound Passkey evidence, exact one-use grant enforcement, one vault
  operation, and audit. Full vault workflows, service accounts, Better Auth,
  IdP, Slack OTP evidence, speculative route registries, and unmeasured package
  splits moved out of the Refactor 90 critical path.
- Replaced the repository-wide Phase 6 gate with scoped phase-local inventories,
  removed synthetic-third-factor conformance, flattened current evidence policy,
  retained an architectural literal/import guard for factor-neutral generic
  coordination, and added a reduction ledger mapping every removed mechanism to
  its replacement security property and check.

## July 22, 2026: Canonical Auth-Method Domain Reconciliation

- [Refactor 91](./refactor-91.md) implemented canonical and distinct wallet,
  signer, and proof auth-method domains across shared types, SDK signing/session
  policy, persistence boundaries, UI routing, registration events, and server
  authority parsing. Implicit passkey fallbacks and the broad `AuthMethod` alias
  were removed; wallet-to-signer and signer-to-protocol conversion now fail
  closed and compile exhaustively.
- Refactor 90 treats this as completed current-stack groundwork for Phases 6, 7,
  17, 18, 22, and 23. It does not complete the SPEC-owned auth-factor/evidence
  vocabulary, `WalletAuthAuthorityRef` lane migration, capability-local type
  relocation, or wallet persistence migration.
- Shared, SDK, server, and intended-test type checks, the auth-domain and
  account/signer lifecycle guards, focused EVM auth tests, and `git diff --check`
  pass. Full intended-behaviour acceptance remains blocked because the local
  site returned HTTP 502 before any auth-flow assertion ran.
- Phase 6 must absorb Refactor 91's occurrence inventory and temporary guard
  allowlists into the owner/action ledger. Phases 18, 19, and 22 must retire each
  allowlist row as method decisions move to their final adapters or become
  structurally exhaustive; no compatibility alias or implicit passkey branch may
  return during relocation.

## July 22, 2026: Email OTP Exact-Material Unlock Reconciliation

- Implementation landed for
  [the Email OTP exact-material unlock patch](./refactor-patch-2-email-otp-local-rehydration.md)
  against the current wallet-first stack. The current implementation adds a
  worker-owned Email OTP Ed25519 active-Client envelope and reuses the canonical
  ECDSA role-local material owner. Same-device unlock follows fresh OTP
  verification; explicit Yao recovery remains available only for genuine
  Ed25519 envelope absence.
- Refactor 90 now treats `exact_material_ready | material_absent |
  material_invalid` as a capability-material-adapter custody observation that
  precedes fresh session binding. It is not a fifth Foundation A hydration
  branch. Imported material remains pending and non-signable until authority
  binding, durable commit, read-back, and exact canonical re-resolution.
- The patch may land before Foundations A and B. It does not complete either
  foundation: Foundation A still owns the four canonical hydration outcomes,
  and Foundation B still owns the sole active ECDSA manifest, activation
  journal, and manifest-plus-material commit.
- Phase 19 must preserve the worker-owned KDF/envelope boundary, exact identity
  verification, absent-versus-invalid semantics, and zero-Yao routine unlock
  behavior while replacing the tactical combined two-curve coordinator with
  capability-specific material adapters. It must preserve the new exact-local
  session versus missing-material recovery intent split and the pinned Yao
  lifecycle identity while rotating wallet authority. Phase 23 replaces the
  wallet-first Ed25519-envelope-plus-canonical-ECDSA registration commit with
  canonical per-capability provisioning.
- Phase 6 inventory, Phase 17 authority migration, and Phase 21 worker split now
  explicitly include the patch's new Ed25519 record, worker commands, stable
  custody binding, imported active-Client handle, route intents, combined unlock
  result types, and deletion targets.
- The companion patch reports implementation complete with manual latency and
  intended-behaviour acceptance pending. SDK and server type checks plus the
  focused worker regression tests pass at this checkpoint. Refactor 90 continues
  to treat the patch as in progress until the exact-local and missing-material
  server paths, persistence-failure activation rollback, distinct path audit and
  timing labels, intended-behaviour matrix, and performance gates pass. The
  current request boundary also accepts an omitted Ed25519 session intent
  without an explicit requested-capability set; Phase 19 must remove that
  implicit branch.

## July 20, 2026: Stable Wallet Lifecycle Checkpoint Reconciliation

- Reconciled stabilization commits after `06c923053` through checkpoint
  `f978ae98b`. Current head `ac22999de` adds a release guard for centralized
  worker service authentication and does not change the capability-state model.
- Production-shaped local execution now separates the Gateway, MPCRouter,
  Deriver A, Deriver B, and SigningWorker and uses Cloudflare service bindings.
  Router and SigningWorker persistence, activation lookup, presign routing,
  registration cleanup, and server key-selector persistence were repaired.
- ECDSA groundwork for Foundation B landed. Encrypted role-local material and
  presign records use `seams_wallet`; durable records contain sealed material
  references and public facts; volatile handles remain in worker memory; lookup
  is chain-qualified; and registration, unlock, signing, step-up, and export use
  the shared tactical material resolver. Passkey and Email OTP registration
  retain public reauthorization anchors.
- Foundation B remains in progress. The canonical
  `ActiveEcdsaCapabilityManifest`, activation commit journal, atomic
  manifest-plus-material transaction, exact manifest read/commit ports,
  required-field transition model, and
  `ThresholdEcdsaSessionRecordCore` deletion have not landed.
- Email OTP registration, immediate signing, step-up, ECDSA export, reload, and
  later unlock now preserve enrollment escrow and rehydrate exact durable ECDSA
  material.
- Passkey Near Ed25519 now persists an authenticated encrypted activated-Client
  envelope in `seams_wallet`. Routine passkey unlock, page-refresh restoration,
  signing, and budget refresh import it locally with zero Deriver A/B calls.
  Device linking and explicit same-root recovery retain the root-recovery
  lifecycle. Export retains its separate one-use material-acquisition ceremony.
- Foundation A's four decision branches remain the canonical target. The prior
  shared implementation and ECDSA adapter over the optional legacy session
  record are absent at this checkpoint. Reimplementation must begin with exact
  ECDSA and Near Ed25519 protocol observation unions, followed by the small
  shared decision contract, narrow proof constructors, and compile-time
  rejection fixtures.
- YAOS Phase 14B is complete. Refactor 90 must preserve the responsibility-local
  derivation, presign, and online-signing worker split and use Router A/B ECDSA
  derivation terminology in active tasks.
- The manually verified acceptance matrix and the intended-behaviour guard that
  rejects routine Deriver A/B recovery are recorded in `f978ae98b`.

Note: the Phase 2A entries below were originally appended to the plan out of
order. They are re-ordered here by the recorded `AuthService.ts` line count,
which decreased monotonically through the split. All entries were logged on
July 3, 2026.

## Phase 2A: AuthService Mechanical Module Split

- July 3, 2026: First mechanical helper extraction completed.
  `AuthService.ts` kept the public facade and route-facing method surface while
  WebAuthn/OIDC boundary helpers moved to
  `packages/sdk-server-ts/src/core/authService/webauthnOidcHelpers.ts` and NEAR
  private-key transaction signing helpers moved to
  `packages/sdk-server-ts/src/core/authService/nearPrivateKeySigning.ts`.
  Route files still have no direct dependency on `core/authService/**`.
  A dead registration-diagnostics extraction was deleted during the import audit
  to avoid carrying unused AuthService-era code. Line count: `AuthService.ts`
  dropped from 11,769 to 11,289 lines; the two live helper modules contain 325
  lines total.
- July 3, 2026: Split inventory and delete-candidate ledger added before
  moving stateful methods. The ledger names active helper owners, duplicated
  AuthService/D1 ownership, and delete phases for stale registration/session
  authority paths.
- July 3, 2026: Second pure helper extraction completed. Random-id helpers
  moved to `core/authService/bytes.ts`, boundary object checks to
  `core/authService/record.ts`, signer WASM URL resolution moved to
  `core/authService/signerWasmUrls.ts`, and threshold-store diagnostics moved to
  `core/authService/thresholdStoreSummary.ts`. The import audit deleted the
  unused timing helper instead of preserving stale diagnostics surface.
  `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Additional pure helper extraction completed without route
  imports or broad dependency bags. WebAuthn authority and wallet-binding
  helpers moved to focused modules, portable crypto helpers moved to
  `core/authService/portableCrypto.ts`, threshold ECDSA key inventory helpers
  moved to `core/authService/thresholdEcdsaKeyInventory.ts`, threshold runtime
  policy helpers moved to `core/authService/thresholdRuntimePolicy.ts`, and
  wallet-registration planning helpers moved to
  `core/authService/walletRegistrationPlanning.ts`.
- July 3, 2026: Review pass completed for the current mechanical split.
  Router modules still import the public `AuthService` facade rather than
  `core/authService/**` internals. Extracted modules do not import Cloudflare D1
  route adapters, Express handlers, React, browser SDK code, or tests. No
  `AuthServiceContext`, `AuthServiceDeps`, or similar broad dependency bag was
  introduced. Line count: `AuthService.ts` is now 10,250 lines; live helper
  modules contain 1,052 lines total.
- July 3, 2026: WebAuthn login/listing slice moved into
  `core/authService/webauthn.ts`. `AuthService` now delegates WebAuthn
  registration-credential verification, lite assertion verification,
  authenticator listing, login option creation, and login verification through
  explicit `WebAuthn*Store` and `IdentityStore` inputs. No route imports were
  changed, and no broad dependency bag was introduced. Line count:
  `AuthService.ts` is now 9,843 lines; live helper modules contain 1,776 lines
  total.
- July 3, 2026: Email OTP boundary utility slice moved out without changing
  the public facade. Config/env reads moved to
  `core/authService/configValues.ts`, OTP policy parsing and masking moved to
  `core/authService/emailOtpConfig.ts`, OTP delivery moved to
  `core/authService/emailOtpDelivery.ts`, shared random ID/code generation
  moved into `core/authService/bytes.ts`, and Email OTP plus registration
  prepare rate-limit consumption moved to `core/authService/rateLimits.ts`.
  `AuthService` still owns the stores, caches, and public methods. Line count:
  `AuthService.ts` is now 9,485 lines; live helper modules contain 2,424 lines
  total. `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Threshold ECDSA inventory facade loop moved into
  `core/authService/thresholdEcdsaKeyInventory.ts`. `AuthService` now passes the
  threshold service and logger explicitly; route imports and public method
  signatures stayed unchanged. Line count: `AuthService.ts` is now 9,403 lines;
  live helper modules contain 2,521 lines total. `packages/sdk-server-ts`
  typecheck passed after the move.
- July 3, 2026: OIDC verification moved into
  `core/authService/oidcVerification.ts`. `AuthService` now owns only provider
  subject linking and delegates JWT parsing, JWKS fetch/cache, signature
  validation, issuer/audience/time checks, and Google claim extraction to the
  helper. Route imports remain behind the public facade. Line count:
  `AuthService.ts` is now 8,825 lines; live helper modules contain 3,061 lines
  total. `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Identity and app-session version facade logic moved into
  `core/authService/identity.ts`. `AuthService` now delegates identity listing,
  identity linking/unlinking, app-session version creation, rotation, and
  validation through an explicit `IdentityStore` input. Result types are modeled
  as branch unions in the helper module instead of the previous broad optional
  result object. Line count: `AuthService.ts` is now 8,776 lines; live helper
  modules contain 3,198 lines total.
- July 3, 2026: OIDC facade result shaping and provider-subject identity
  linking moved into `core/authService/oidcVerification.ts`. `AuthService` now
  supplies only OIDC config, JWKS cache state, and `IdentityStore` to the helper.
  The typecheck also exposed a partially deleted Router A/B ECDSA key-identities
  route; the stale shared path, parser, Express route, route definition, and type
  fixture are now consistently removed instead of reintroduced. Line count:
  `AuthService.ts` is now 8,657 lines; live helper modules contain 3,361 lines
  total.
- July 3, 2026: WebAuthn sync-account option creation moved into
  `core/authService/webauthn.ts`. The moved helper takes only
  `WebAuthnSyncChallengeStore` and `WebAuthnCredentialBindingStore`; sync
  verification remains in `AuthService` until its threshold/session dependencies
  can be split without a broad context bag. Line count: `AuthService.ts` is now
  8,567 lines; live helper modules contain 3,473 lines total.
- July 3, 2026: NEAR public-key metadata record/list logic moved into
  `core/authService/nearPublicKeyMetadata.ts`. `AuthService` now delegates
  metadata persistence and listing through an explicit `NearPublicKeyStore`
  input and keeps route-facing method names stable. Line count:
  `AuthService.ts` is now 8,491 lines; live helper modules contain 3,642 lines
  total.
- July 3, 2026: Recovery session/execution facade tracking moved into
  `core/authService/recoveryTracking.ts`. `AuthService` now delegates recovery
  session reads, status updates, execution reads/lists, and execution recording
  through explicit `RecoverySessionStore` and `RecoveryExecutionStore` inputs.
  The D1 adapter still owns its canonical route implementation until Refactor
  82 cleanup collapses the remaining parallel AuthService-era surfaces. Line
  count: `AuthService.ts` is now 8,332 lines; live helper modules contain 3,982
  lines total.
- July 3, 2026: NEAR RPC and relayer transaction helper logic moved into
  `core/authService/nearTransactions.ts`. `AuthService` now delegates
  access-key listing, signed Borsh dispatch, account-existence checks,
  access-key visibility checks, transaction context fetching, and gas-router
  transaction signing through explicit `MinimalNearClient`, relayer key, and
  logger inputs. Account creation and delegate execution remain in the facade
  because they still coordinate queueing and higher-level registration
  semantics. Line count: `AuthService.ts` is now 8,238 lines; live helper
  modules contain 4,204 lines total.
- July 3, 2026: Wallet ID allocation helpers were removed from
  `AuthService.ts` and kept in `core/authService/walletRegistrationPlanning.ts`.
  The canonical helper module now owns server-allocated wallet ID reservation,
  provided implicit wallet ID reservation, generic wallet selection, and
  signer-plan-aware registration wallet selection. The D1 registration intent
  service still has a parallel local copy because router code must not import
  `core/authService/**` internals during this mechanical split; collapse that
  duplicate through the Refactor 82 route-port cleanup. Line count:
  `AuthService.ts` is now 8,108 lines; live helper modules contain 4,338 lines
  total.
- July 3, 2026: Email OTP Shamir seal cipher setup moved into
  `core/authService/emailOtpSeal.ts`. `AuthService` now reads the four raw seal
  config values and delegates typed key-version, Shamir-prime, and cipher
  construction to the helper. Remaining local random/masking wrapper methods
  were also removed in favor of direct calls to the extracted helper functions.
  This keeps config-boundary validation isolated without adding a new service
  object. Line count: `AuthService.ts` is now 8,047 lines; live helper modules
  contain 4,415 lines total.
- July 3, 2026: Email OTP registration challenge-proof and challenge-purpose
  boundary modeling moved into `core/authService/emailOtpChallengeProof.ts`.
  `AuthService` now imports the typed proof, verified challenge, challenge
  purpose, and recovery escrow redaction helpers instead of defining them
  inline. The move keeps raw request proof parsing at the boundary and preserves
  the public facade. Line count: `AuthService.ts` is now 7,523 lines; live
  helper modules contain 4,978 lines total. `packages/sdk-server-ts` typecheck
  passed after the move.
- July 3, 2026: Registration threshold helper code moved into
  `core/authService/registrationThresholdHelpers.ts`. The helper owns
  threshold-Ed25519 registration input parsing, bootstrap session normalization,
  ECDSA bootstrap identity comparison, ECDSA wallet-key derivation from server
  bootstrap output, and NEAR add-key bootstrap action construction. `AuthService`
  still coordinates stores and route-facing methods. Line count:
  `AuthService.ts` is now 7,206 lines; live helper modules contain 5,337 lines
  total. `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Signer WASM runtime setup and more Email OTP lifecycle
  helpers moved behind focused modules. `core/authService/wasm.ts` owns signer
  WASM initialization, `emailOtpDelivery.ts` owns dev outbox reads,
  `emailOtpSeal.ts` owns server seal operations, `emailOtpEnrollment.ts` owns
  enrollment/auth-state/strong-auth helpers, `emailOtpGrant.ts` owns grant
  consumption, and `googleEmailOtpRegistration.ts` owns Google Email OTP
  registration attempt/offer lifecycle. `AuthService` remains the public facade
  and supplies only explicit stores plus the two narrow callbacks needed for
  hosted wallet derivation and wallet-shape checks. Router modules still have no
  direct `core/authService/**` imports, and no `AuthServiceContext` or
  `AuthServiceDeps` bag was introduced. Line count: `AuthService.ts` is now
  6,085 lines; live helper modules contain 7,022 lines total.
  `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Rate-limit backend construction moved out of
  `AuthService.ts` and into `core/authService/rateLimits.ts`. The helper now
  owns raw limiter-kind parsing and environment/config-backed limiter
  construction for Email OTP and registration-prepare throttles, while
  `AuthService` only caches limiter instances and delegates consumption. No
  route imports of helper internals were added. Line count: `AuthService.ts` is
  now 6,044 lines; live helper modules contain 7,122 lines total.
  `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Email OTP challenge cleanup and active-challenge limiting
  moved into `core/authService/emailOtpChallenges.ts`. The helper owns
  challenge-store expiry pruning, active-context cap enforcement, and associated
  memory-outbox cleanup through explicit store and outbox inputs. `AuthService`
  still owns request parsing and challenge issuance orchestration. Line count:
  `AuthService.ts` is now 6,037 lines; live helper modules contain 7,198 lines
  total. `packages/sdk-server-ts` typecheck and build passed after the move.
- July 3, 2026: Public facade barrel move completed.
  `packages/sdk-server-ts/src/core/AuthService.ts` now re-exports the public
  `AuthService` class and Google Email OTP public result types from
  `core/authService/**`. The remaining implementation lives in
  `core/authService/AuthService.ts`; route and router layers still import the
  public facade path only. Line count: public `AuthService.ts` is now 7 lines,
  `authService/AuthService.ts` is 6,037 lines, and focused helper modules
  contain 7,198 lines total. `packages/sdk-server-ts` typecheck and build passed
  after the move.
- July 3, 2026: Email OTP challenge issuance moved into
  `core/authService/emailOtpChallenges.ts`. The helper now owns request-boundary
  parsing, active challenge reuse, challenge rate limiting, challenge record
  persistence, delivery rollback, and delivery result shaping through explicit
  operation ports. `AuthService` still owns stores, limiter caches, and the
  public method signatures. `packages/sdk-server-ts` typecheck passed after the
  move.
- July 3, 2026: Email OTP unlock challenge issuance and unlock-proof
  verification moved into `core/authService/emailOtpUnlock.ts`. The helper owns
  unlock challenge creation, secp256k1 unlock proof validation, challenge
  consumption, and Email OTP login auth-state marking through explicit operation
  ports. No route imports of helper internals were added. Line count:
  `authService/AuthService.ts` is now 5,509 lines and focused helper modules
  contain 7,905 lines total. `packages/sdk-server-ts` typecheck passed after the
  move.
- July 3, 2026: AuthService mechanical split checkpoint completed. The
  public barrel at `packages/sdk-server-ts/src/core/AuthService.ts` now
  re-exports the split facade from `core/authService/AuthService.ts`. Additional
  stateful slices moved behind explicit internal ports:
  `emailOtpChallengeVerification.ts`, `emailOtpRegistrationEnrollment.ts`,
  `emailOtpRecoveryKeys.ts`, `emailRecoveryAuthOperations.ts`,
  `nearAccountOperations.ts`, `identityOperations.ts`,
  `recoveryTrackingOperations.ts`, and the temporary assembly-only
  `storeRegistry.ts`. Route modules still import only the public facade, no
  `AuthServiceContext`/`AuthServiceDeps` bag was introduced, and the touched
  extracted modules contain no `any`. Line count: `core/authService/AuthService.ts`
  is now 1,999 lines, satisfying the Phase 2A pre-Phase-3 target.
- July 3, 2026: Follow-up AuthService split pass moved Google Email OTP/OIDC
  wallet-resolution facade logic into
  `core/authService/googleEmailOtpOperations.ts` and threshold ECDSA route-facing
  forwarding into `core/authService/thresholdEcdsaOperations.ts`. The public
  method names and route contracts stayed on `AuthService`; routes still have no
  direct imports of `core/authService/**`, no `AuthServiceContext`/`AuthServiceDeps`
  bag was introduced, and the new extracted modules contain no `any`. Line count:
  `core/authService/AuthService.ts` is now 1,908 lines.
- July 3, 2026: Email OTP public challenge composition moved into
  `core/authService/emailOtpChallengeOperations.ts`. `AuthService` now delegates
  login challenge issuing, enrollment challenge issuing, device-recovery
  challenge issuing, login grant minting, and device-recovery consume-grant
  minting through an explicit Email OTP challenge operation input. Route
  contracts stayed on the public `AuthService` facade; no route imports of
  `core/authService/**`, broad `AuthServiceContext`/`AuthServiceDeps` bag, or
  legacy compatibility path was introduced. Line count:
  `core/authService/AuthService.ts` is now 1,761 lines.
- July 3, 2026: AuthService runtime state moved into
  `core/authService/runtime.ts`. `AuthService` now keeps signer-WASM readiness,
  relayer public-key derivation, and service initialization state in one typed
  runtime state object while the facade still owns assembly. Route and app
  imports were audit-checked rather than guarded because this facade boundary is
  temporary. `core/authService/AuthService.ts` is now 1,751 lines.
- July 3, 2026: Phase 2A mechanical split closure review completed.
  Remaining methods in `core/authService/AuthService.ts` are constructor/config
  assembly, store wiring, runtime warm-up, or thin delegates whose next split
  belongs with Phase 3 route ports or Refactor 82B authority unions. Moving
  those now would require a broad context bag or route-contract churn, so the
  mechanical split stops here.
- Active Email OTP verification/recovery and WebAuthn helper clusters that
  can move without a broad dependency bag have moved. Remaining helper
  movement is deferred to route ports and typed authority cleanup.

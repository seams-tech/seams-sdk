# Modular Auth And Capability Refactor Plan

Date created: June 28, 2026
Reorganized: July 3, 2026 — horizontal layer phases (old Phases 1-14) were
restructured into vertical slices. See [Phase Mapping](#phase-mapping) for where
each old phase went.
Architecture hardening: July 10, 2026 — correlated capability operations,
factor-enrollment identity, verified evidence sets, session audience/device
binding, and atomic grant-use invariants were made canonical.
MPC preparation generalization: July 10, 2026 — EVM ECDSA lane identity,
material recovery, and authorization were made auth-factor agnostic.
YAOS and OTP recovery alignment: July 15, 2026 — the landed Ed25519 Yao and OTP
recovery work was reconciled into Slice B's canonical public locator,
capability-material-adapter-owned sealed and fresh recovery, non-secret recovery
commit journal and revocation outbox, volatile runtime publication lifecycle,
capability-local readiness, shared wallet signing quota, complete NEAR operation
family, refresh-safe server-verified export context, exact Yao lifecycle
continuity, worker-private rehydration/reseal lifecycle, fixed effect order, and
responsibility-local worker/package boundaries.
Lifecycle convergence review: July 16, 2026 — the review specified one target
hydration decision contract for post-registration, post-wallet-unlock, and
post-page-refresh capability material access. Active runtime use, active-session sealed
rehydration, and expired/exhausted public-reauth reprovisioning are distinct
closed branches shared by signing, step-up, and export.
ECDSA state convergence review: July 18, 2026 — replacement of the broad
`ThresholdEcdsaSessionRecordCore` aggregate, one durable ECDSA capability
manifest, one local commit protocol, and one exact transition path were added as
a Refactor 90 pre-phase.
Stable wallet lifecycle checkpoint reconciliation: July 20, 2026 — checkpoint
`f978ae98b` landed the production-shaped local topology, encrypted ECDSA
role-local material persistence and shared tactical resolution, repaired Email
OTP lifecycle continuity, and authenticated local rehydration of the activated
Passkey Ed25519 Yao Client. These are implementation groundwork for Foundations
A and B. The canonical hydration decision contract, ECDSA manifest, activation
journal, required-field record replacement, and full flow cutover remain open.

Status: Phases 1, 2, and 3 are complete. The lifecycle pre-phase is in progress,
and the ECDSA state/persistence pre-phase is in progress. Both gate Phase 4 and
Phase 5 closure plus Phases 19 and 23. Phases 4 and 5 are in progress. Phase 6
onward is planning.

Companion spec: [Modular Auth And Capability Refactor SPEC](./refactor-90-modular-auth-capabilities-SPEC.md).

Progress journal: [Refactor 90 Journal](./refactor-90-journal.md). Dated
progress entries live there, not here. Each phase in this plan carries only a
one-line status.

Companion plans:

- [Refactor 82B: Auth Authority Typing Cleanup](./refactor-82B.md)
- [Refactor 85: IndexedDB Minimization](./refactor-85-indexedDB.md)
- [Refactor 86: Static Wallet Assets And Vite Plugin Removal](./refactor-86-static-wallet-assets.md)
- [Streaming Yao for Deriver A and Deriver B](./router-ab/ed25519-yao/implementation-plan.md)

This document is the implementation checklist. Requirements, architecture
decisions, domain sketches, persistence defaults, and security model live in the
companion SPEC. Target domain types are SPEC-owned; phases in this plan may
sketch tactical types for in-flight work, but when a type appears in both
documents the SPEC version is authoritative.

Refactor 82B is a prerequisite typing cleanup for this plan. It separates stable
auth authority from one-time registration proof data so the modular auth-factor
and capability surfaces here can be implemented without carrying Passkey-specific
session assumptions into Email OTP and future auth factors.

`router-ab/ed25519-yao/implementation-plan.md` is authoritative for the Ed25519 cryptographic construction,
Deriver A/B and SigningWorker ownership, client lifecycle, recovery/refresh/export
protocols, deployment topology, security profile, and production-readiness gates.
Refactor 90 owns session, authorization, capability composition, policy, and the
public integration around that implementation. Refactor 90 cannot redefine the
Ed25519 backend or advance its production status ahead of the YAOS gates.

The July 15 alignment changes below require a matching companion-SPEC amendment.
Phase 4 cannot close, and Phases 7, 10, 12, 17, 19, 20, and 21 cannot begin, until
the SPEC distinguishes session state, capability readiness, live signing runtime,
exact operation grants, and the shared wallet signing quota with the same
invariants used here. The amendment must also define the discriminated
`sealed_source | fresh_acquisition` recovery source, recovery commit journal,
separate revocation outbox with local/server fences, committed
runtime-publication/durability proof,
pending-journal precedence, grant/quota-independent operation fingerprint, and
the generic authenticated `CapabilityOperationClaim` lookup, fenced execution,
terminal reconciliation, and `revoked_after_claim` lifecycle used from Phase 10
onward. MPC claims specialize that base with exact quota, cryptographic-phase, and
delivery bindings. The amendment must also distinguish affine browser
material-use leases from durable server execution leases and define the
auth-agnostic, refresh-safe `near.export_key` context described in Phase 19. That
context carries an exact Yao lifecycle reference, remains independent of normal
signing grant/quota/runtime readiness, and converges on one export operation and
one-use export session for every supported factor. The amended closed Near
operation union and policy table must also cover `near.sign_transaction`,
`near.sign_delegate_action`, `near.sign_nep413_message`, `near.export_key`, and
`mpc.produce_signer_proof` as distinct operation contracts. It must distinguish
stable pre-effect continuity refs from rotating grant, quota, session-transport,
and runtime/export-session state and require exact current-state resolution after
every recovery or reauthentication effect.

The July 16 lifecycle pre-phase adds one further SPEC gate. The SPEC must define
entry-point provenance separately from the canonical MPC capability hydration
plan.
Post-registration, post-wallet-unlock, and post-page-refresh callers resolve the
same closed `use_live_runtime`, `rehydrate_active_session`,
`reauthorize_public_anchor`, or `blocked` union. The entry point cannot select the
security branch. Current canonical runtime, session, sealed-material, and public-
reauth state select it. The public-anchor branch carries no reusable secret,
sealed ciphertext, bearer session authority, or live runtime handle.

The July 18 ECDSA state/persistence pre-phase adds a second gate. The SPEC must
replace `ThresholdEcdsaSessionRecordCore` with linked required-field aggregates
for registered signer identity, capability scope, exact wallet authority, active
material-session authority, durable material binding, volatile runtime
observation, retired public anchor, and exact operation lane. One durable active
capability manifest binds those facts. Registration and unlock publish it through
one commit protocol; refresh reads it through one exact parser. Core selection,
hydration, recovery, signing, and export cannot accept the old optional aggregate,
raw persistence rows, source-priority candidates, or entry-point-specific
reconstructions.

## Decided Architecture Points

Decisions made July 3, July 10, July 15, and July 16, 2026 during plan review. These are
settled; do not re-litigate them in later phases without a written reversal note
here.

1. **Execute vertically, not horizontally.** The old Phases 1-14 landed
   vocabulary, schema, ports, and modules layer-by-layer, so nothing worked
   end-to-end until vault integration. The plan now ships Slice A (a vault-only
   tenant, end to end: native provider session -> `SeamsSession` -> capability grant
   -> vault proxy use -> passkey grant evidence -> vault reveal -> audit) before
   any shared wallet vocabulary is renamed. Slice B then migrates MPC signing
   onto the proven layer. Most deletion happens in-slice, not in a final
   deletion phase.
2. **`CapabilityKind` and `CapabilityOperationKind` are closed unions.** They
   live in a small leaf module that both `seams-authorization` and capability
   modules import. No runtime kind registry. Capability packages still register
   operation descriptors and handlers at assembly time, but the kind vocabulary
   is compile-time closed and exhaustiveness-checked. Capability kind and
   operation kind travel together as a correlated `CapabilityOperationRef`;
   independent kind fields are forbidden in core policies, envelopes, grants,
   and route auth. If third-party capability
   extensibility ever becomes real, reopen via module augmentation or a generic
   parameter then. The SPEC's Target Domain Types section is amended to match.
3. **The route module manifest is defined early (Phase 9), not late.** The old
   plan defined runtime-neutral route manifests in Phase 11, after Phases 4-10
   had each rewired routes against ports. Manifest shape now lands with the
   service ports so later phases add modules instead of rewiring routes.
4. **Audit envelope writing lives in `seams-authorization`.** No separate
   `audit-core` package now; extract one later only if a non-authorization
   audit producer appears.
5. **The public SDK exposes `SeamsSession` as an opaque branded handle.** Its
   fields are not public API.
6. **`CapabilityGrant` records stay DB-backed.** One-use/short-TTL rows with
   replay checks, not stateless signed capability tokens. Revocation, replay
   detection, and audit are required anyway, and D1 is already in the hot path.
7. **Vocabulary and type-shape cleanup:** split pure `AuthFactorIdentity` from
   durable `AuthFactorRecord`, split factor manifests from runtime-specific
   server/browser modules, compose evidence-kind families, keep provider login
   sessions and deferred workload evidence kinds out of the closed
   `GrantEvidenceKind` union, and use entity-specific lifecycle unions plus the
   exact repeated `OperationDigestSet` cluster. The SPEC's Target Domain Types
   are authoritative.
8. **Client/server capability config mismatch fails early and typed.** Browser
   `authMethods`/`capabilities` config selects SDK modules only; server tenant
   runtime config is authoritative. When a client requests a capability the
   tenant has disabled, the SDK surfaces a typed error at session exchange or
   capability initialization, never a deep failure inside iframe/worker
   bootstrap.
9. **Document hygiene:** dated progress entries go to
   [refactor-90-journal.md](./refactor-90-journal.md); the plan holds one-line
   statuses. Line counts are progress telemetry, not phase goals — phase goals
   are stated in terms of ownership, boundaries, and behavior.
10. **Parallel implementations are deleted in the same change that replaces
    them.** The AuthService-era server stack and the D1 route services
    currently duplicate Email OTP, registration, and wallet-ID allocation
    logic. Every Phase 9 route port that lands deletes its `AuthService` facade
    method and its duplicated `core/authService/**` helper in the same
    commit. Phase 9 does not exit while the Phase 3 delete-candidate ledger has
    entries whose D1 owner is live. Route ports replace both layers; they
    must not become a third.
11. **One route-handler implementation; hosts are thin adapters.** The
    parallel Express route implementations are deleted at Phase 9. The Phase 9
    manifest/handler contract stays runtime-neutral (fetch-style
    request/response) so an Express adapter can be added later on demand as a
    thin wrapper — never as a second route implementation. The Node
    web-server consumes the same handlers through a thin Node adapter.
12. **Better Auth and native factors split by evidence grade; providers are
    interchangeable behind one port.** V1 ships on the Seams-native session
    provider (the existing passkey + Email OTP stack); the Better Auth
    adapter is a later compatibility milestone (Phase 25) behind the same
    port. Better Auth remains the permanent, optional provider for commodity
    auth (email+password, social login, organizations, enterprise SSO); Seams
    never rebuilds those natively. The Seams-native
    factor modules are exactly those that produce MPC-grade,
    operation-digest-bound evidence or drive the Seams confirmation UI —
    passkey and Email OTP for signing-grade flows, plus Slack OTP when tenant
    policy accepts Slack OTP as operation-bound grant evidence. They are never
    ported into Better Auth. Both
    normalize into `SeamsSession` through the same Phase 11 exchange boundary;
    Better Auth is optional at assembly (a signing-only tenant runs native
    factors alone). `seamsAuth({...})` is a composition layer wiring native
    factor modules plus an optional Better Auth instance — not a Better Auth
    reimplementation. Litmus test for any future factor:
    digest-bound/MPC-grade evidence or Seams confirm UI → native; otherwise →
    Better Auth.

    Interchangeability clause: Better Auth and the Seams-native session
    provider are two implementations of one session-provider port. Swapping
    one for the other is a config/assembly change only — no code outside the
    provider adapter may import or depend on provider specifics, grant-
    evidence endpoints are provider-neutral Seams manifest routes (Better
    Auth mounting is a thin bridge, not their home), and one provider
    conformance suite runs against both implementations. Feature sets may
    differ (commodity breadth is Better Auth's); the exchange boundary,
    authorization, capabilities, and UI behave identically over either.

    Interchangeability is a session-layer property; it does not extend to
    signing. MPC signing grant policies accept only native digest-bound grant
    evidence (`passkey_assertion`, `email_otp`) or `mpc_signer_proof` —
    provider-side passkey/OTP login evidence never authorizes signing. An
    existing provider passkey becomes wallet authority only through the Seams
    add-auth-method enrollment ceremony (one credential, two verifiers; see
    the SPEC's credential-adoption note).

13. **Operation authorization and aggregate signing quota are separate.**
    `CapabilityGrant` remains DB-backed, short-lived, and bound to one exact
    capability operation and digest set. `MpcWalletSigningQuota` owns the YAOS
    product invariant of one expiry and remaining-use counter shared across the
    wallet's exact NEAR Ed25519 and EVM-family ECDSA bindings. Each binding carries
    its own exact `WalletAuthAuthorityRef`, so one wallet quota can span capabilities
    owned by different enrolled authorities. Phase 20 replaces
    the old reserve/commit/release budget subsystem with one atomic claim that
    always consumes the exact grant use and, for `quota_use: required`, one quota
    use under the same operation fingerprint. The fingerprint excludes
    grant/quota IDs and survives their
    renewal. Grant or quota renewal never identifies or mutates live
    cryptographic material. Each MPC operation descriptor carries
    `quota_use: required(cost) | none`; normal signing costs one use, while key
    export uses its exact one-use operation grant and ceremony admission with
    `quota_use: none`. No `signingGrantId` survives in material identity.
14. **Bloat discipline.** Each slice exit records a deletion ledger and net
    non-doc line accounting in the journal; source guards and fixtures retire
    in the same slice that makes their invariant structural (closed unions,
    branded IDs, generic lanes). The chain-specific online signer fleet
    consolidates in Phase 21: `eth-signer` and `tempo-signer` merge into one
    EVM-family online signer because Phase 5 made role-local material
    chain-agnostic. ECDSA derivation, presign, and online signing remain
    responsibility-local workers and artifacts. Ed25519 uses a narrow Yao
    client-only package with no Deriver/server execution code.
15. **Exact factor enrollment is authority.** Factor identity is matching data;
    `factorId` identifies one enrollment. Wallet authority adds a durable
    wallet-auth-method binding and digest. Re-enrollment creates new IDs and
    cannot revive old signing, export, recovery, restore, or admission records.
16. **Verified evidence sets are the grant boundary.** Grant issuance never
    accepts a raw array of evidence. A boundary builder proves common tenant,
    principal, session/device context, correlated operation, and operation
    digests before policy evaluation.
17. **Grant use is atomically idempotent.** Every operation is keyed by a
    canonical authorization-resource-independent fingerprint with a database
    uniqueness constraint. It covers tenant, principal, capability, correlated
    operation, operation ID, and lane/intent/display digests; it excludes grant,
    quota, session, and material-handle IDs. Those component digest projections
    exclude the same rotating resource IDs transitively. Claim insertion and all
    applicable decrements happen in one transaction. Same-fingerprint retries
    never consume twice, including after grant, quota, or same-operation lane
    replacement. Authenticated lookup returns or reconciles an existing claim
    before fresh preparation. Every `claimed` row has a fenced execution lease,
    deadline, phase journal, and terminal reconciliation path. Server revocation
    fences an already consumed claim through one exact epoch-transition CAS and
    completes or reconciles it without refund.
18. **Sessions are audience- and device-bound.** Hosted wallet iframes use a
    one-time origin-bound exchange code redeemed by the iframe. Bearer tokens
    never cross `postMessage`, and session exchange does not trust a
    client-selected device ID.
19. **Deployment modules and tenant enablement are separate.** Deployment
    assembly determines which handlers are in a bundle. Tenant runtime config
    can deny a deployed capability per request; it cannot mutate route assembly
    or trigger dynamic imports.
20. **Auth factors do not define MPC signing lanes.** MPC capability code carries
    `WalletAuthAuthorityRef`, separates transaction targeting from exact
    signing-runtime ownership, and derives one action-oriented preparation state:
    `ready`, `recovery_required`, `authorization_required`, or `blocked`.
    Passkey, Email OTP, and future interaction protocols stay behind auth-factor
    adapters; sealed/root cryptography stays behind capability-local material
    adapters. Generic lane selection, preparation, restore coordination, and
    committed-lane construction contain no factor-kind control flow.
    Factor-specific cryptographic ingress exists only inside capability-local
    material adapters or responsibility-local secure workers and their Rust/WASM constructors. After
    an authority-bound one-use material handle is
    consumed, registration, recovery, export coordination, active runtime, and
    normal signing are factor-neutral. Generic capability code receives no factor
    discriminator or secret bytes. This rule applies equally to the Near Ed25519
    Yao active Client and EVM-family ECDSA material.
21. **Ed25519 durability, recoverability, and runtime readiness are separate.**
    The browser persists a minimal public `NearEd25519YaoCapabilityLocator` and
    an authenticated capability-local sealed activated-Client envelope for
    routine local rehydration. It may also persist a separate sealed
    root-material recovery record owned by the Near material adapter. It persists
    a non-secret capability-local
    recovery commit journal while promotion, local activation, or required reseal
    finalization is incomplete; lock/logout uses a separate non-secret revocation
    outbox. A valid active-Client envelope yields
    `rehydrate_active_session`; a matching root-recovery record yields same-root
    recovery availability. Normal signing requires both an exact
    active Rust/WASM `NearEd25519YaoRuntimeHandle` and a branded
    `committed_ready` publication/durability proof; an active handle with pending
    activation or durability finalization cannot sign. Export requires a correlated one-use export
    session and carries no runtime handle. A data-only, server-verified export
    context can be resolved after page refresh without constructing or recovering
    a signable Client. It binds the durable locator/root owner to an exact
    `NearEd25519YaoLifecycleRef`; normal-signing grant/quota exhaustion does not
    suppress that context. Root material stays inside the Near
    material adapter as an authority-bound, purpose-typed, one-use handle with an
    `owned -> consumed` lifecycle. Same-root recovery stages a candidate, promotes
    it only after server continuity succeeds, and disposes every failed or
    replaced candidate. Page lifecycle, explicit lock, and logout destroy the live
    runtime while the eligible sealed active-Client envelope remains durable.
    ECDSA sealed material remains an independent capability-local
    lifecycle.
22. **Session identity and capability readiness are independent.** A restored
    `SeamsSession` and public wallet identity do not imply a ready signing
    runtime. Each MPC capability reports `ready`, `recovery_required`,
    `authorization_required`, or `blocked` independently. Expiry, exhaustion,
    missing live Client state, and recoverable ECDSA material are typed
    capability conditions instead of login states.
23. **Authorization capabilities, protocol ceremonies, and runtime handles use
    distinct identities.** `CapabilityInstance`, `CapabilityGrant`, one-use Yao
    ceremony admission/ticket state, `NearEd25519YaoCapabilityLocator`, sealed
    root-recovery references, `NearEd25519YaoLifecycleRef`, verified export
    contexts, one-use root-material handles,
    `NearEd25519YaoRuntimeHandle`, ECDSA material handles, and
    `MpcWalletSigningQuota` have separate branded IDs and state machines. A grant
    or quota ID cannot become a signing key, threshold session, recovery
    reference, material handle, or runtime identity.
24. **Signing preparation is data-only and effects follow one order.** Pure lane
    selection, resolution, and challenge planning precede user approval. Approval
    and evidence completion precede authorized nonce recovery, material
    acquisition, candidate/session staging, recovery/activation commit, and any
    retention-policy-required durability finalization. Exact post-effect
    re-resolution follows that finalization and precedes the atomic operation claim and all
    descriptor-applicable debits, cryptographic execution, and finalization.
    Any recovery, transport reauthentication, or session replacement invalidates
    rotating fields captured by the pre-effect observation. Continuity compares
    only the exact stable authority, material-owner, signer, lifecycle, and policy
    refs. The post-effect resolution supplies the current session transport,
    operation grant, quota revision when applicable, runtime/export session, and
    lane/context. Core code never compares complete pre-effect and post-effect
    lane aggregates or reuses a stale grant or credential from the selected lane.
    Challenge creation, resend, and code collection stay inside the
    approval/evidence-completion stage and may precede prerequisite recovery.
    They mutate only ephemeral provider challenge state. Auth-factor adapters in
    that stage may receive a boundary-scoped immutable credential/reference for
    their own challenge protocol. They have no port for material or recovery
    persistence, material-recovery transport reauthentication/mutation, worker
    material, runtime activation, nonce, claim, grant, or quota. User cancellation
    during approval or evidence completion leaves all
    capability, material, persistence, transport, nonce, authorization, and quota
    domains unchanged.
    An authenticated existing-operation-claim lookup is a data-only idempotency
    read and may precede local preparation/approval. It cannot create, renew,
    execute, or mutate a claim or authorization resource.
25. **Sealed refresh is capability-material recovery.** A durable sealed record
    proves only that exact recovery may be attempted. Data-only inspection may
    happen before approval; server seal removal, transport reauthentication,
    worker rehydration, material binding, Client construction, promotion/local
    activation, replacement reseal, and persistence are effects and happen only
    after approval and required evidence. The persistence adapter owns source/
    replacement sealed refs and the non-secret commit journal. The worker-private
    segment is `pending factor -> purpose-bound root handle -> staged candidate ->
    retained reseal source -> candidate replacement ciphertext`.
    Fresh factor acquisition uses a distinct source branch in the same commit
    lifecycle. It has no source seal/unseal transition and may publish the first
    retained seal or finalize volatile retention. Lock/logout reconciliation uses
    a separate non-secret revocation outbox.
    Every transition is correlated to one exact authority, locator, recovery
    digest, material owner, and purpose. Recovery allowance and expiry are
    monotonic protocol limits; they never grant an operation or replenish
    `MpcWalletSigningQuota`. Partial commits such as server promotion without
    local activation, or activation without required reseal, are explicit
    resumable states. They never collapse into a boolean reauth decision or a
    ready lane.
26. **MPC entry point and hydration state are independent.** Registration, wallet
    unlock, and page refresh are provenance values. They never authorize an
    operation or choose a material path. Every successfully provisioned MPC
    capability resolves through one protocol-neutral hydration plan:
    `use_live_runtime`, `rehydrate_active_session`,
    `reauthorize_public_anchor`, or `blocked`. The active-session branch requires
    an unexpired, unexhausted exact session plus restorable sealed material. The
    public-anchor branch requires `expired | exhausted` plus an exact public
    reauth anchor and makes live runtime, sealed secret, and bearer session fields
    `never`. Reauthorization can provision a normal unlock session or an exact
    operation-scoped session; key export does not require a full wallet unlock.
    Each capability resolves independently, so one wallet may contain live,
    sealed-rehydratable, public-reauth, and blocked capability branches at the
    same time. Registration and unlock must publish the same canonical inventory
    that a subsequent page refresh reads.
27. **ECDSA capability state has one durable owner.** The browser persists one
    exact active ECDSA capability manifest beside its encrypted role-local
    material binding. The manifest contains required signer, scope, authority,
    material-session, server-generation, durable material ref, and binding-digest
    facts. It contains no bearer credential, operation grant, wallet quota, nonce,
    provenance source, diagnostics, or live worker handle. Runtime readiness is a
    separate volatile observation validated against the manifest revision and
    material binding. Registration, unlock, refresh, recovery, signing, and export
    consume boundary-parsed manifest state and fail closed on missing, ambiguous,
    corrupt, mismatched, or unavailable persistence. Cross-store publication uses
    one explicit commit journal and never treats a partial write as ready.

## Implementation Rules

- Keep the completed signer-set registration cut intact so local D1 registration
  does not revive the `ed25519_and_ecdsa` cross-product request shape. Then ship
  the Slice A vertical: native provider session -> `SeamsSession` -> vault
  proxy use -> passkey grant evidence -> vault reveal -> audit.
- V1 ships on the Seams-native session provider — the existing passkey and
  Email OTP stack, plus Slack OTP when enabled as operation-bound grant
  evidence — behind the session-provider port (Decided Point 12).
  Better Auth compatibility is a later milestone through the same port,
  gated on the provider conformance suite. Commodity auth is never rebuilt
  natively; when tenants need it, it arrives via the Better Auth adapter.
- Delete a parallel implementation in the same change that replaces it
  (Decided Point 10). New ports and modules must not become a third layer
  beside two live ones.
- Keep capability modules as typed route/service modules. Add only the small SDK
  runtime config surface needed to select hosted wallet iframe mode and requested
  browser capabilities; avoid a framework or bundler plugin registry.
- Keep `mpc_signer_proof` optional. Baseline vault access must work without MPC.
- Phase-one automation uses service-account API keys that can request narrow
  capability grants. Defer OIDC workload federation, mTLS, KMS-bound proof, and
  customer workload identity until the grant model is stable.
- Treat public exports, host apps, env vars, migrations, fixtures, and docs as
  refactor surfaces. A shared type rename is incomplete until those surfaces are
  inventoried and either moved, updated, or explicitly parked.
- Use static route assembly plus import guards for Cloudflare Workers.
- Keep compatibility logic at request and persistence boundaries, then delete it.
- Delete wallet-first fixtures when they only protect obsolete behavior.
- Reject `ed25519_only`, `ecdsa_only`, `ed25519_and_ecdsa`, and equivalent
  curve-combination mode tags in core registration, quota, session, and signing
  state. Model quota coverage as a nonempty collection of exact discriminated
  curve bindings.
- Use Router A/B ECDSA threshold-PRF derivation terminology in target
  architecture. YAOS Phase 14B completed the destructive rename; active plan
  tasks and implementation paths use derivation terminology. Retain HSS names
  only in historical context and explicit deleted-name guards.
- Treat browser `walletRuntime`, `authMethods`, and `capabilities` as SDK module
  selection only. Server tenant runtime config is authoritative for enabled auth
  methods, capabilities, and policies.
- New vocabulary lands in new modules first. Wallet-touching renames wait for
  Slice B, after Slice A has proven the model.
- Resolve MPC capability hydration from canonical current state through the
  Foundation A union and, for ECDSA, only from the Foundation B manifest
  plus runtime observation. Registration, unlock, and refresh may supply provenance to
  diagnostics and tests; they cannot select separate recovery implementations.
- When moving code, name the target owner from the Simplified End State tree so
  files land once. Do not create intermediate homes that a later phase must
  re-home.

## Simplified End State

Target source ownership:

```text
identity/
  tenants
  principals
  authAccounts
  providerIdentities
authFactor/
  passkey
  emailOtp
  slackOtp
  walletLogin
  recoveryCode

session/
  seamsSession
  providerSessionAdapters

authorization/
  capabilityKinds        <- closed unions; leaf module, no imports
  grantEvidence
  capabilityGrants
  policies
  audit

capability/
  mpcLifecycle
    hydrationPlan
    publicReauthAnchor
  mpcWalletAuthority
    signingQuota
  vault
  nearEd25519Mpc
    operationPreparation
    yaoRuntime
    yaoRecovery
    yaoRootMaterialAdapters
  evmEcdsaMpc
    capabilityManifest
    activationCommitJournal
    capabilityPersistence
    operationPreparation
    roleLocalMaterial
  idpAccess

idp/
  oidcProvider
  relyingParties

router/
  routeModules           <- runtime-neutral handlers; the only implementation
  cloudflareAdapter
  nodeAdapter
  (expressAdapter)       <- on-demand thin adapter if requested; never a second implementation

sdkWeb/
  config
  walletRuntime/hostedIframe
  authFactorUi
  capabilityUi
```

Use this as the implementation compass. Package extraction is deferred until
these internal module boundaries are stable.

## Execution Order

| Phase | Contents | Status |
| -------------- | --------------------------------------------------- | ----------- |
| Foundation A | Canonical MPC hydration decision contract          | In progress |
| Foundation B | Canonical ECDSA capability state and persistence   | In progress |
| Phase 1 | Signer-set registration cut | Complete |
| Phase 2 | Wallet-rooted confirmation subjects | Complete |
| Phase 3 | AuthService mechanical module split | Complete |
| Phase 4 | Exact capability subject type hardening | In progress |
| Phase 5 | ECDSA role-local material cache slimming | In progress |
| Phase 6 | Inventory and public-surface ledger | Planning |
| Phase 7 | Core vocabulary and closed capability kinds | Planning |
| Phase 8 | SDK runtime surface for hosted wallet capabilities | Planning |
| Phase 9 | Route service ports and route module manifest | Planning |
| Phase 10 | Slice A persistence and schema | Planning |
| Phase 11 | Session exchange and Seams Auth provider | Planning |
| Phase 12 | Seams authorization core | Planning |
| Phase 13 | Management and session route policy | Planning |
| Phase 14 | Generic client grant evidence and confirmation UI | Planning |
| Phase 15 | Service-account grant evidence | Planning |
| Phase 16 | Vault capability module and integration | Planning |
| Phase 17 | Wallet auth authority refs on signing lanes | Planning |
| Phase 18 | Wallet vocabulary and persistence migration | Planning |
| Phase 19 | MPC capability modules | Planning |
| Phase 20 | MPC route policy migration | Planning |
| Phase 21 | Client worker split and bundle boundaries | Planning |
| Phase 22 | Wallet UI adapter migration | Planning |
| Phase 23 | Auth-first registration and capability provisioning | Planning |
| Phase 24 | Host and example assembly migration | Planning |
| Phase 25 | Better Auth provider adapter | Planning |
| Phase 26 | IdP integration | Planning |
| Phase 27 | Final deletion and hardening | Planning |

Phases 4 and 5 are tactical fixes on the current wallet-first stack and can
proceed while Phase 6 builds the inventory ledger. Phase 7 must not start until
that ledger exists. Phase 8 consumes the Phase 7 vocabulary and therefore starts
after Phase 7; Refactor 86 hosted-asset work may proceed independently until the
SDK config cut is ready.
The lifecycle and ECDSA state/persistence pre-phases may proceed beside Phase 4
and Phase 5. Both must close before either tactical phase closes or Phase 19/23
begins. Foundation A defines the shared hydration outcome. Foundation B
defines the exact ECDSA inputs, persistence owner, and transitions that construct
that outcome.

## Phase Mapping

Where each phase of the pre-July-3 plan went, for cross-references from other
documents:

| Old phase | New home |
| ---------------------------------------------- | ------------------------------------------------------------------ |
| July 16 lifecycle convergence review           | Foundation A + Phases 4, 19, and 23                             |
| July 18 ECDSA state convergence review         | Foundation B + Phases 5, 17, 18, 19, and 23                     |
| Legacy 0A, 0B, 0D, 0F, 0E | Phases 1, 2, 4, 5, 8 |
| 0 (Inventory) | Phase 6 |
| 0C (Public surface and deployment inventory) | Phase 6 |
| 1 (Shared auth vocabulary) | Phase 7 (new vocabulary) + Phase 18 (wallet-touching renames) |
| 2 (Persistence and schema) | Phase 10 (new tables) + Phase 18 (wallet table remap) |
| Legacy 2A (AuthService split) | Phase 3 |
| New Slice B bridge: wallet auth authority refs | Phase 17 |
| 3 (Route and D1 ports) | Phase 9 |
| 4 (Seams authorization core) | Phase 12 |
| 5 (Seams auth provider) | Phase 11 |
| 6 (Route policy V2) | Phase 13 (management/session/grant planes) + Phase 20 (MPC planes) |
| 6A (Service-account grant evidence) | Phase 15 |
| 7 (Client grant evidence and worker split) | Phase 14 (generic confirmation) + Phase 21 (worker/bundle split) |
| 8 (React and Lit UI adapter) | Phase 14 (generic/vault UI) + Phase 22 (wallet UI, docs) |
| 9 (Capability modules) | Phase 16 (vault) + Phase 19 (MPC) |
| 10 (Registration and provisioning) | Phase 23 |
| 11 (Route module assembly) | Phase 9 (manifest) + Phase 24 (hosts/examples) |
| 12 (Vault integration) | Phase 16 |
| 13 (IdP integration) | Phase 26 |
| 14 (Deletion and hardening) | In-slice deletion + Phase 27 |

---

# Part 0: In-Flight Tactical Phases

These phases fix the current wallet-first stack. They are prerequisites or
parallel work, not part of the vertical slices.

## Foundation A: Canonical MPC Hydration Decision Contract

Status: in progress. The four-branch SPEC vocabulary is frozen. The shared leaf
contract, narrow proof constructors, and compile-time rejection fixtures are
absent at the July 20 checkpoint and must be implemented against canonical
protocol observations. The earlier adapter over
`ThresholdEcdsaSessionRecordCore` was deleted because it inferred lifecycle and
authority from optional legacy fields. The checkpoint's tactical ECDSA material
resolver and Ed25519 local active-Client rehydration provide protocol evidence;
canonical inventory publication and flow migration remain. This bounded
type-and-contract foundation gates Phase 4 closure and Phases 19 and 23.

Goal: make post-registration, post-wallet-unlock, and post-page-refresh callers
resolve the same MPC capability-material lifecycle. Entry-point provenance remains
observable for tests and diagnostics but cannot select authorization, material,
or recovery behavior.

Add the following SPEC-owned decision shape in a leaf capability lifecycle
module after each protocol exposes a precise observation union. Tactical
Ed25519 and ECDSA adapters consume those observations until Phase 19 deletes
the tactical orchestration.

```ts
type MpcCapabilityHydrationEntryPoint =
  | 'post_registration'
  | 'post_wallet_unlock'
  | 'post_page_refresh';

type MpcCapabilityHydrationResolution = {
  provenance: {
    entryPoint: MpcCapabilityHydrationEntryPoint;
  };
  plan: MpcCapabilityHydrationPlan;
};

type MpcCapabilityHydrationPlan =
  | {
      kind: 'use_live_runtime';
      capability: CapabilityInstanceRef;
      materialOwner: MpcMaterialOwnerRef;
      authority: WalletAuthAuthorityRef;
      runtime: MpcCapabilityRuntimeRef;
      activeMaterialSession: ActiveMpcMaterialSessionRef;
      sealedMaterial?: never;
      retirement?: never;
      publicReauthAnchor?: never;
    }
  | {
      kind: 'rehydrate_active_session';
      capability: CapabilityInstanceRef;
      materialOwner: MpcMaterialOwnerRef;
      authority: WalletAuthAuthorityRef;
      activeMaterialSession: ActiveMpcMaterialSessionRef;
      sealedMaterial: RestorableMpcMaterialRef;
      runtime?: never;
      retirement?: never;
      publicReauthAnchor?: never;
    }
  | {
      kind: 'reauthorize_public_anchor';
      capability: CapabilityInstanceRef;
      materialOwner: MpcMaterialOwnerRef;
      authority: WalletAuthAuthorityRef;
      retirement: 'expired' | 'exhausted';
      publicReauthAnchor: MpcCapabilityPublicReauthAnchor;
      runtime?: never;
      activeMaterialSession?: never;
      sealedMaterial?: never;
    }
  | {
      kind: 'blocked';
      capability: CapabilityInstanceRef | null;
      reason:
        | 'missing_capability'
        | 'missing_material'
        | 'revoked'
        | 'replaced'
        | 'authority_ambiguous'
        | 'binding_mismatch'
        | 'exact_record_conflict'
        | 'corrupt'
        | 'persistence_unavailable';
      runtime?: never;
      activeMaterialSession?: never;
      sealedMaterial?: never;
      retirement?: never;
      publicReauthAnchor?: never;
    };
```

The target names may change in the companion SPEC, but the four branches and
their `never` exclusions are fixed. This plan describes material access only.
Its `blocked` branch is distinct from the capability preparation `blocked`
state used by Phases 18-19; the two reason unions are separate vocabularies
and are not interchangeable.
Operation grants, signing quota, transaction nonce state, export admission, and
session transport remain independent preparation domains.
Entry-point provenance wraps the plan for diagnostics and tests; capability
authorization and material executors receive only `resolution.plan`.

Do:

- Keep the shared module limited to the closed union, narrow proof constructors,
  and precise branded references. Each persistence/runtime adapter parses its
  real external record once and constructs a branch from normalized facts.
  Avoid a second versioned observation wire format in the shared core.
- Define `MpcCapabilityPublicReauthAnchor` as public, exact-authority-bound data. It
  contains the stable capability, material-owner, key/lifecycle, policy, and
  registered-public-key facts needed for fresh authorization. Secret material,
  sealed ciphertext, bearer session credentials, live runtime handles, active
  material-session IDs, operation grants, quota state, and nonce state are
  impossible fields.
- Require `rehydrate_active_session` to prove an unexpired and unexhausted exact
  material session plus one exact durable active-session material reference.
  For ECDSA this is encrypted role-local material. For Near Ed25519 this is the
  authenticated sealed activated-Client envelope in `seams_wallet`. Root
  recovery material has a distinct type and lifecycle. Decision construction is
  data-only and requires proof that the exact material-unlock source is already
  available. If it is unavailable, the protocol adapter returns an explicit
  typed material-unlock requirement and cannot construct this branch. Execution
  consumes that source during local import.
- Require `reauthorize_public_anchor` to prove `expired | exhausted` and one
  exact public anchor. The resulting effect may provision a normal multi-use
  wallet-unlock session or an operation-scoped one-use session. Key export can
  use the latter and never requires an unrelated transaction or full unlock.
- Keep `use_live_runtime` capability-local. Ed25519 requires an active Client
  plus committed publication/durability; ECDSA requires exact ready role-local
  material. Capability adapters prove those protocol-specific facts before
  constructing the shared branch.
- Resolve every requested capability independently. Mixed wallets may return
  different branches for Near Ed25519 and EVM-family ECDSA without changing the
  `SeamsSession` or public wallet identity.
- Make registration and unlock publish the same canonical capability inventory
  that refresh reads. Remove entry-point-only shadow state and avoid separate
  post-registration or post-unlock shortcut resolvers.
- Preserve the checkpoint's routine Passkey Ed25519 rule: wallet unlock, page
  refresh, signing, and budget refresh import the exact locally sealed activated
  Client and make zero Deriver A/B calls. Phase 19 generalizes the adapter
  without assuming that every auth factor already persists this envelope.
  Device linking and explicit same-root recovery retain the root-recovery
  lifecycle; export retains its separate one-use material-acquisition ceremony.
- Require exact canonical re-resolution after rehydration, reauthorization,
  runtime publication, or session replacement. Stable authority/material-owner/
  signer/lifecycle facts must match; current rotating session transport,
  operation grant, quota revision, and runtime/export-session refs come only
  from the post-effect result.
- Replace the tactical ECDSA export `current session | public reauth authority`,
  ECDSA transaction public-reauth lane, and Near material-inspection unions when
  their capability modules start consuming the shared plan. Delete each replaced
  union, parser, fixture, and branch in the same change; retain no compatibility
  model.
- Treat `ExactEcdsaExportSession`, `EcdsaPublicReauthLane`,
  `EvmFamilySharedEcdsaState`, `EmailOtpEd25519YaoSilentRecoveryResultV1`, and
  their type fixtures as a deletion ledger for Phase 19. A retained
  operation-specific result may carry signing or export output, but it must not
  independently reclassify live, sealed-active, retired, or blocked material.
- Add source guards preventing factor-kind, curve-kind, entry-point, diagnostics,
  or persistence-source switches from authorizing or selecting a hydration
  branch in capability core.

Entry-point contract:

| Entry point        | Successful immediate state                                                                                                                           | Cold/retired alternatives                                                                                                                                         |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Post-registration  | Every successfully provisioned capability resolves to `use_live_runtime`, and its canonical durable inventory is readable.                           | Failed or rolled-back provisioning is `blocked`; no partial capability masquerades as ready.                                                                      |
| Post-wallet-unlock | A locally durable active session may first resolve to `rehydrate_active_session`; after its effect and exact re-resolution it resolves to `use_live_runtime`. Unrequested capabilities keep their independently resolved state. | Capability-local failure leaves session/public wallet identity active and returns the exact non-ready branch.                                                     |
| Post-page-refresh  | Volatile runtime handles are absent. A current exact material session with a valid seal resolves to `rehydrate_active_session`.                      | Expired/exhausted material authority resolves to `reauthorize_public_anchor`; missing, corrupt, conflicting, revoked, or unavailable state resolves to `blocked`. |

Check:

- [ ] The leaf lifecycle module owns the final union and this plan states that entry-point
      provenance cannot influence branch selection.
- [ ] Narrow proof constructors reject direct literals, broad spreads, optional identity
      bags, raw strings, and mixed live/sealed/public-anchor fields.
- [ ] `@ts-expect-error` fixtures reject expired/exhausted state without a public
      anchor, an active session with a public anchor, a sealed branch without an
      exact active material session, and a live branch without capability-local
      runtime readiness proof.
- [ ] Passkey, Email OTP, and a synthetic third factor produce identical plans
      for equivalent canonical observations.
- [ ] Near Ed25519 signing, ECDSA signing, and both key-export paths consume the
      same hydration-plan vocabulary while retaining operation-specific outputs.
- [ ] A table-driven test covers all three entry points against live, sealed-
      active, expired, exhausted, missing, corrupt, conflicting, revoked, and
      persistence-unavailable observations for both MPC capabilities.
- [ ] Post-registration -> refresh and post-unlock -> refresh transition tests
      prove that only volatile runtime state disappears and that exact durable
      authority/material continuity is preserved.
- [ ] Near Ed25519 routine unlock, page-refresh restoration, signing, and budget
      refresh rehydrate the sealed activated Client locally and make zero
      Deriver A/B calls.
- [ ] Public-anchor key export provisions one exact one-use export session after
      fresh authorization and requires no preceding transaction or full wallet
      unlock.

## Foundation B: Canonical ECDSA Capability State And Persistence

Status: in progress. This foundation folds the
`ThresholdEcdsaSessionRecordCore` replacement into Refactor 90. It must land
before Phase 4 or Phase 5 closes and before Phases 19 or 23 begin.

Checkpoint groundwork already landed: encrypted ECDSA role-local material and
presign records share `seams_wallet`; worker memory retains opaque runtime
handles; registration and Email OTP paths preserve durable material identity;
and the tactical role-local resolver is shared by registration, unlock, and
refresh-sensitive flows. The canonical active capability manifest, activation
journal, atomic manifest-plus-material commit, required-field core replacement,
and deletion of source-priority selection remain.

Prerequisites: Foundation A owns the shared hydration result. This foundation
may proceed while Phase 5 finalizes `EcdsaRoleLocalMaterialBinding`, then both
close together against the same SPEC-owned shape. Pull the existing exact
`WalletAuthAuthorityRef` leaf scaffold and its boundary builder forward; this
does not depend on the broader Phase 17/18 wallet vocabulary migration.

Goal: replace the optional, multi-lifecycle ECDSA session record with one
SPEC-owned set of linked required-field aggregates and one durable capability
manifest. Registration, wallet unlock, and page refresh may begin from different
external inputs, but they commit or read the same manifest and feed the same
hydration and exact-lane resolvers.

Canonical domains:

- `RegisteredEvmFamilySigner` owns durable public signer identity, registered
  public facts, exact authority, and explicit `evm_family | exact_target`
  capability scope. It contains no active session, bearer credential, material
  handle, operation grant, quota, or nonce.
- `ActiveEcdsaMaterialSession` owns the exact threshold-session ID,
  server-issued generation, lifecycle binding, material-use retention, expiry,
  and recovery policy. Operation grant and wallet signing quota remain separate
  domains.
- `DurableEcdsaMaterialBinding` owns the exact material owner, the nested
  role-local material binding (Phase 5's final `EcdsaRoleLocalMaterialBinding`,
  carried as `roleLocalBinding` per the SPEC), durable material ref, binding
  digest, lifecycle ID, authenticated ciphertext digest, activation digest, and
  material expiry. Every field is required.
- `ActiveEcdsaCapabilityManifest` binds one registered signer, one active
  material session, one durable material binding, one server activation receipt,
  and one manifest revision. It is the only persisted shape from which an active
  ECDSA capability can be constructed.
- `EcdsaRuntimeObservation` is a closed `absent | live | invalid` union. The
  `live` branch requires a worker-local handle plus a validation proof for the
  exact capability, manifest revision, material ref, and binding digest. It is
  volatile and never serializable.
- `RetiredEcdsaCapabilityManifest` is a closed reauthorizable-or-terminal union.
  `expired | exhausted` requires an exact public reauthorization anchor.
  `revoked | replaced` makes that anchor impossible. Active-session,
  durable-material, live-runtime, operation-grant, quota, bearer, and nonce
  fields are impossible in both branches.
- `EcdsaCapabilityManifestLookup` is a closed
  `active | retired | missing | exact_binding_mismatch |
  exact_record_conflict | corrupt | persistence_unavailable` result. No failure
  branch can be interpreted as absence or trigger source-priority fallback.
- `ExactEcdsaOperationLane` composes one exact active manifest reference with one
  target-specific operation envelope, current operation authorization, and
  current wallet quota when the operation descriptor requires it. Target
  projection can share only stable material-owner and signer facts.

Required-field rule:

- Core ECDSA identity, authority, material, session, persistence, recovery,
  signing, export, and lifecycle types use required fields.
- Mutually exclusive states use discriminated unions with `never` exclusions.
- Optional fields remain limited to raw boundary compatibility shapes,
  diagnostics, UI display data, truly optional configuration, and callbacks.
- Core builders accept the narrowest valid branch and use exhaustive switches.
  Persistence and request parsers validate raw rows once, then return canonical
  branches.
- A live state always carries its durable material identity. Runtime destruction
  therefore has one transition: `live -> durable`.

Persistence ownership:

| Store | Canonical responsibility | Forbidden responsibility |
| --- | --- | --- |
| Router D1/DO adapters | registered signer authority, active server generation, threshold-session lifecycle, activation/retirement receipts, idempotent correlation lookup | browser runtime readiness, local material presence, source-priority selection |
| ECDSA capability IndexedDB adapter | active or retired manifest, encrypted role-local material, sealing key, activation commit journal, exact revisions and digests | raw bearer credentials, live worker handles, grants, quotas, nonces, diagnostics |
| ECDSA derivation worker memory | live role-local material and exact runtime-validation proof | durable authority, persisted capability selection, recovery policy |
| Browser runtime registries | derived hot observations and in-flight coordination keyed by exact material owner | canonical persistence, newest-record selection, durable fallback authority |

Extend the current `seams_wallet` ECDSA material adapter into one capability
persistence adapter. The encrypted material row and active manifest row commit
in one IndexedDB transaction. The worker retains exclusive plaintext ownership;
the manifest contains only the encrypted material reference and authenticated
digests.

Cross-boundary activation commit:

1. Persist a non-secret `EcdsaCapabilityActivationCommitJournal` before the first
   consuming server activation or replacement call. It binds the exact
   capability, signer, authority, material owner, expected prior revision,
   server-generation expectation, and idempotency correlation.
2. Reconcile or perform the idempotent server activation. Advance the journal
   with the exact server receipt and generation before local publication.
3. In one IndexedDB transaction, persist the encrypted material record, persist
   the exact active manifest that references it, and advance the journal to
   `local_commit_readback_pending`.
4. Read back and authenticate the manifest, material ref, binding digest,
   ciphertext digest, server receipt, and revision.
5. Publish the runtime observation only after read-back succeeds. Exact
   re-resolution must return `use_live_runtime` before registration or unlock
   reports capability success.
6. Clear the journal after publication proof is committed. Reload first
   reconciles a pending journal by its exact idempotency correlation. It never
   repeats a consuming server effect or chooses another record by timestamp.

The activation journal is a closed union:

```ts
type EcdsaCapabilityActivationCommitJournal =
  | EcdsaActivationPrepared
  | EcdsaServerActivationCommitted
  | EcdsaLocalCommitReadbackPending
  | EcdsaRuntimePublicationPending;
```

Each branch requires every receipt and revision that exists at that stage and
makes later-stage fields `never`. Journal data is non-secret. Terminal rollback,
retirement, and orphan-material cleanup are explicit commands derived from exact
reconciliation; a partial commit never becomes a ready capability.

Flow cutover:

- Registration and wallet unlock call one
  `commitEcdsaCapabilityActivation(...)` boundary after their factor-specific
  protocols produce normalized activation input.
- Page refresh calls `readEcdsaCapabilityManifest(...)`, observes worker runtime
  independently, and passes those exact facts to the Foundation A hydration
  resolver.
- Recovery and reauthorization finish through the same activation commit and
  exact post-effect read. They cannot publish a shortcut runtime record.
- Signing and export call `selectExactEcdsaOperationLane(...)` once, then carry
  that lane through material preparation, authorization, quota claim, nonce,
  signing/export, and finalization.
- Shared EVM-family target projection requires explicit capability scope and
  projects only stable signer/material-owner facts. It never copies
  `thresholdSessionId`, operation grant, quota use, bearer credential, or runtime
  handle from another target.
- Expiry, exhaustion, revocation, or replacement calls
  `retireEcdsaCapability(...)`, writes a reauthorizable public anchor for
  expiry/exhaustion or a terminal tombstone for revocation/replacement, makes the
  active manifest ineligible, and schedules exact material cleanup.

Deletion ledger:

- Delete `ThresholdEcdsaSessionRecordCore`,
  `NormalizedThresholdEcdsaSessionRecordShared`,
  `ReadyPasskeyEcdsaSessionRecord`, `EmailOtpEcdsaSessionRecord`,
  `NormalizedThresholdEcdsaSessionRecord`,
  `ThresholdEcdsaSessionRecord`,
  `OperationUsableThresholdEcdsaSessionRecord`, and
  `buildOperationUsableThresholdEcdsaSessionRecord` after their consumers move.
- Delete authority and lifecycle inference from `source`, provider identity,
  optional field presence, record timestamps, and diagnostics.
- Delete `PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY`, Passkey material ranking,
  newest-record selection, and separate exact-lane/material searches.
- Delete ECDSA `restorable` as a core lifecycle label. Use exact
  `rehydrate_active_session` or `reauthorize_public_anchor` branches.
- Stop using `recordsByLane` and module-level record maps as persistence or
  selection authority. A runtime registry may retain exact manifest-keyed hot
  observations.
- Delete registration-only and unlock-only capability publication paths after
  both call the canonical commit API.
- Reject and clear obsolete IndexedDB ECDSA session records at the persistence
  boundary during the cutover. Do not add dual-schema readers or core
  compatibility types.

Check:

- [x] The companion SPEC owns every canonical ECDSA aggregate, journal branch,
      persistence lookup result, and transition named above.
- [x] Encrypted ECDSA role-local material and presign records use the
      `seams_wallet` database, while live cryptographic state remains
      worker-local.
- [x] Registration and Email OTP lifecycle repair preserve durable ECDSA
      material identity and use the shared tactical role-local resolver.
- [ ] `@ts-expect-error` fixtures reject active manifests without an exact
      authority, server generation, durable material ref, binding digest,
      ciphertext digest, or manifest revision.
- [ ] Fixtures reject persisted live handles, live observations without exact
      manifest validation, retired manifests with active material/session fields,
      public anchors with grants or bearer credentials, and target projections
      with copied operation authority.
- [ ] Persistence parsers distinguish missing, exact mismatch, exact conflict,
      corruption, and unavailable storage. Every switch is exhaustive.
- [ ] Registration and unlock use the same activation commit port and resolve the
      committed capability from the same read port used by refresh.
- [ ] Refresh after worker destruction preserves the exact manifest and material
      binding, observes runtime `absent`, and resolves
      `rehydrate_active_session`.
- [ ] Failure injection after every journal, server, IndexedDB, read-back, and
      runtime-publication step proves reload-safe idempotent convergence.
- [ ] Equivalent durable snapshots plus equivalent server authority produce the
      same hydration plan and exact operation lane for registration, unlock, and
      refresh provenance.
- [ ] Ambiguous current manifests fail closed before lane or material selection.
- [ ] Passkey, Email OTP, and a synthetic third factor construct the same
      canonical activation input for equivalent ECDSA facts.
- [ ] Source guards reject every deletion-ledger symbol and any core import of
      raw ECDSA persistence rows.
- [ ] End-to-end transition tests perform a real write, destroy browser and
      worker runtime, reopen persistence, hydrate exact material, and sign for
      one-target and shared EVM-family configurations.

## Phase 1: Signer-Set Registration Cut

Status: complete through Refactor 82 Phase 8.

Residual note: the NEAR and EVM branch helpers were extracted, but
`packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`
still carries the large registration orchestrator. Treat that slimming as Phase 9/Phase 23
follow-up work rather than reopening this completed tactical cut.

Goal: fix the registration request and D1 ceremony shape before staging or public
API hardening can normalize the two-signer cross-product model.

This is the tactical bridge from Refactor 82 into Refactor 83. It keeps the
current auth/session stack for now, but changes wallet registration to request a
set of signer capabilities instead of one mode enum.

Do:

- Replace the public registration request shape:

```ts
type RegistrationSignerSetSelection = {
  kind: 'signer_set';
  signers: readonly RegistrationSignerRequest[];
};

type RegistrationSignerRequest =
  | {
      kind: 'near_ed25519';
      accountProvisioning: RegistrationNearAccountProvisioning;
      signerSlot: SignerSlot;
      participantIds: readonly number[];
      derivationVersion: 1;
    }
  | {
      kind: 'evm_family_ecdsa';
      participantIds: readonly number[];
      chainTargets: readonly ThresholdEcdsaChainTarget[];
    };
```

- Delete `ed25519_only`, `ecdsa_only`, and `ed25519_and_ecdsa` from core
  registration logic. If a temporary request-boundary parser accepts old mode
  shapes while tests are updated, keep it outside core and delete it before this
  phase is marked complete.
- Normalize raw signer-set requests once into a `RegistrationSignerPlan`.
- Reject duplicate signer identities at the boundary. Examples: two
  `near_ed25519` entries with the same `signerSlot`, or two
  `evm_family_ecdsa` entries that resolve to the same wallet key.
- Replace D1 `combined_registration` ceremony state with branch-set state keyed
  by stable signer branch identity.
- Split the wallet-registration parts of
  `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts` into
  a registration orchestrator plus NEAR Ed25519 and EVM-family ECDSA branch
  helpers.
- Update SDK web defaults, iframe messages, wallet-registration RPC parsing,
  registration timing events, and type fixtures to use signer-set terminology.
- Update or delete fixtures that preserve the old mode enum behavior.

Check:

- Local D1 registration provisions both NEAR Ed25519 and EVM-family ECDSA from
  the signer-set request.
- Ed25519-only and ECDSA-only registration use the same signer-set machinery.
- D1 prepare/start/respond/finalize has targeted coverage for a two-signer set.
- Duplicate signer branches fail at the request boundary.
- Source guards reject production references to `ed25519_and_ecdsa`,
  `ed25519_only`, `ecdsa_only`, and `combined_registration` outside any
  temporary boundary parser named in this phase.
- `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir packages/sdk-web
  type-check`, focused D1 registration tests, registration intent allocation
  tests, and `git diff --check` pass.

Long-term path:

- Phase 1 is still wallet-registration work. Phase 23 promotes the same shape
  into auth-first capability provisioning where registration creates an auth
  account by default and provisions only requested `CapabilityInstance` records.
- `near_ed25519` becomes `near_ed25519_mpc_signing` capability provisioning.
- `evm_family_ecdsa` becomes `evm_ecdsa_mpc_signing` capability provisioning.
- The branch identity used by D1 ceremony state becomes the capability
  provisioning identity or `capabilityId` once Phase 23 lands.
- Vault-only, IdP-only, and auth-only registration paths must not create signer
  records or load MPC protocol, signer, Deriver, or WASM code.
- Capability policies bind requested signer capabilities to registered auth
  evidence kinds through Seams authorization, replacing the current wallet-first
  registration authority checks.

## Phase 2: Wallet-Rooted Confirmation Subjects

Status: complete.

Goal: align existing signing confirmation payloads with the modular capability
model before the larger auth/capability split lands.

Do:

- Treat `walletId` as the canonical wallet identity in sign-intent confirmation
  payloads.
- Represent NEAR signing as a wallet plus NEAR account metadata:

```ts
{
  kind: 'near_wallet';
  walletId: WalletId;
  nearAccountId: AccountId;
}
```

- Represent EVM-family and Tempo signing as wallet-scoped capability use:

```ts
{
  kind: 'evm_wallet';
  walletId: WalletId;
}
```

- Delete the ambiguous `near_account` / `wallet` sign-intent subject names from
  the intent-digest confirmation boundary.
- Add type fixtures that reject `nearAccountId` on EVM-family subjects and
  reject NEAR subjects without `walletId`.
- Keep chain-specific protocol identifiers as branch metadata. Do not use them
  as wallet identity.

Check:

- Passkey confirmation for EVM/Tempo no longer validates `walletId` as a NEAR
  account id.
- NEAR sign-intent confirmation has both `walletId` and `nearAccountId`, so
  split identity works for implicit accounts.
- `SignIntentDigestSubject` is a discriminated union with no compatibility
  branch for the old names.

## Phase 3: AuthService Mechanical Module Split

Status: complete (July 3, 2026). Dated progress entries:
[refactor-90-journal.md](./refactor-90-journal.md#phase-2a-authservice-mechanical-module-split).

Goal (achieved): split `packages/sdk-server-ts/src/core/AuthService.ts` into
smaller source modules without changing behavior, route contracts, storage
semantics, public exports, or runtime wiring.

Outcome:

- `packages/sdk-server-ts/src/core/AuthService.ts` is a 7-line public barrel.
- `core/authService/AuthService.ts` holds assembly/delegation at 1,751 lines
  (down from 11,769), meeting the below-2,000 pre-Phase 9 target. Remaining methods
  are constructor/config assembly, store wiring, runtime warm-up, or thin
  delegates whose next split belongs with Phase 9 route ports or Refactor 82B
  authority unions.
- 40+ focused helper modules under `core/authService/` with explicit store/port
  inputs; no `AuthServiceContext`/`AuthServiceDeps` bag exists.
- Route and app imports of `core/authService/**` internals are audit-checked
  each pass rather than source-guarded, because the facade boundary is
  temporary; Phase 9 route ports replace it.
- Routes import only the public `AuthService` facade; extracted modules import
  no Cloudflare D1 route adapters, Express handlers, React, browser SDK code,
  or tests.

Known debt accepted by this phase: the split grouped code by mechanical
extractability, not by the Simplified End State ownership tree. Phases 9, 11,
and 19 re-home these modules into `authFactor/`, `session/`, `authorization/`,
and `capability/` owners. When re-homing, name the final owner from the end-state
tree so each file moves once more, not twice.

Split inventory (final):

| Cluster | Current owner | Status | Next action |
| ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WebAuthn/OIDC boundary parsing and provider loading | `core/authService/webauthnOidcHelpers.ts` | Active provider helper | Keep behind `AuthService` facade until WebAuthn route ports land. |
| NEAR private-key transaction signing helpers | `core/authService/nearPrivateKeySigning.ts` | Active facade helper | Keep isolated from D1 route adapters; no route imports. |
| Random ID generation | `core/authService/bytes.ts` | Active facade helper | Reuse from remaining facade methods; move callers with owning domains later. |
| Boundary object guard | `core/authService/record.ts` | Active boundary helper | Replace only raw boundary checks; do not use for core domain objects. |
| Signer WASM URL resolution | `core/authService/signerWasmUrls.ts` | Active provider helper | Keep module-local source and built-package candidates. |
| Threshold store configuration summary | `core/authService/thresholdStoreSummary.ts` | Active diagnostics helper | Keep config diagnostics in helper; no service selection side effects. |
| WebAuthn login/listing helpers | `core/authService/webauthn.ts` | Active facade helper | Keep behind `AuthService` facade until WebAuthn route ports land. |
| WebAuthn sync-account helpers | `core/authService/AuthService.ts` | Active facade methods | Move only after the threshold/session dependencies are narrowed enough to avoid a broad context bag. |
| Email OTP challenge, enrollment, unlock, registration, recovery | `core/authService/emailOtp*` plus D1 route adapters | Active but duplicated ownership | Delete AuthService-era branches once D1 ports are canonical (Phase 9 or Slice B). |
| Wallet registration intent/ceremony/finalize helpers | `core/authService/**` plus D1 registration services | Active but duplicated ownership | Route through D1 canonical adapters, then delete old AuthService authority paths. |
| Ed25519 Yao registration, active Client, recovery, refresh, and export | `packages/sdk-web/src/core/signingEngine/threshold/ed25519/yao*`, `packages/sdk-server-ts/src/router/routerAbEd25519Yao*`, and `crates/router-ab-ed25519-yao*` | Active YAOS lifecycle with capability-local ownership | Move public orchestration behind `capability/nearEd25519Mpc`; preserve the YAOS protocol/runtime boundary and delete factor-specific capability resolvers in Phase 19. |
| Ed25519/ECDSA ordinary signing, replay, and shared-use accounting | `packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime.ts` plus signing routes/stores | Active shared runtime awaiting decomposition | Move curve policy/admission into each MPC capability, retain a narrow capability-neutral SigningWorker transport/replay port, and replace budget APIs with grant-plus-quota claiming in Phase 20. |
| Router A/B ECDSA derivation, role-local material, signing, recovery, and export | responsibility-local Router, SDK, WASM, and D1/DO owners | Active strict Router A/B implementation after the completed Phase 14B artifact split | Complete Phase 5 material slimming, preserve the three-worker ownership split, and migrate behind `capability/evmEcdsaMpc`. |
| NEAR account creation, funding, access-key checks, transactions | `core/authService/nearAccountOperations.ts`, `nearTransactions.ts` | Active facade helpers | Account creation and delegate execution stay in the facade until their queueing/registration coordination is split. |

Delete-candidate ledger:

| Candidate | Why it is stale or risky | Replacement | Delete phase |
| ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| AuthService-era wallet registration authority branches | D1 registration is the canonical registration owner; duplicate authority branches caused passkey-only and Email OTP drift. | D1 registration route services plus typed Router API adapter ports. | Refactor 82 Phase 12 / Refactor 82B authority cleanup. |
| Passkey-only Ed25519 authority checks inside shared session paths | Shared Ed25519 session code must require an exact durable authority ref and cannot assume `passkey_rp` or `rpId`. | Boundary factor parsers producing `WalletAuthAuthorityRef`; shared session and capability code consume only the ref. | Refactor 82B / Phase 17. |
| AuthService generic registration bootstrap/finalize surfaces used by Cloudflare D1 routes | They keep old AuthService request shapes alive beside D1 request models. | D1 route adapter boundary with raw parsing at route/persistence edges only. | Refactor 82 Phase 12. |
| Helper code that only supports removed registration diagnostics | The extracted diagnostics module had no active callers after import audit. | None; deleted instead of moved. | Completed July 3, 2026. |
| Parallel wallet-ID allocation copy in the D1 registration intent service | Router code must not import `core/authService/**` internals, so a local copy exists beside `walletRegistrationPlanning.ts`. | Collapse through the Refactor 82 route-port cleanup. | Phase 9 / Refactor 82 route-port cleanup. |

---

# Part 1: Foundations

## Phase 4: Exact Capability Subject Type Hardening

Status: in progress. Durable NEAR unlock-subject resolution is implemented;
full branch-specific `unlockCore(subject)` remains. Phase 5 exclusively owns
ECDSA role-local material identity and cache semantics.

Prerequisite to close: Foundations A and B are complete and the companion
SPEC owns the canonical capability hydration plan plus the ECDSA capability
manifest and persistence lifecycle.

Goal: close the type holes that let exact capability identity drift after
Refactor 79 and before the modular capability model lands.

This phase addresses the wallet-unlock bug found during local D1 testing:

- Wallet unlock was exposed as wallet-scoped, while the local unlock wrapper
  still required a NEAR binding before it could enter capability-specific logic.

Do:

- Keep capability-subject resolution separate from hydration resolution.
  `WalletUnlockSubjectSet` identifies requested capabilities; the Foundation A
  resolver determines `use_live_runtime`, `rehydrate_active_session`,
  `reauthorize_public_anchor`, or `blocked` from current canonical state. Unlock and
  page-refresh code may not construct readiness directly.

- Introduce branch-specific wallet unlock subjects:

```ts
type WalletUnlockSubject =
  | {
      kind: 'near_ed25519_wallet';
      walletId: WalletId;
      nearAccountId: NearAccountId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      signerSlot: SignerSlot;
    }
  | {
      kind: 'evm_family_ecdsa_wallet';
      walletId: WalletId;
      ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    };
```

- Use the same branch-specific subject model for capability-subject reads that
  accompany session restoration. Resolve a wallet into a
  `WalletUnlockSubjectSet` at the IndexedDB/request boundary, then compute each
  capability's preparation input from that set. Session/login state comes from
  the independent session boundary.
  Do not introduce a sibling `WalletSessionReadSubject` union that restates the
  same branch identities.

```ts
type WalletCapabilitySubjectResolution =
  | { kind: 'no_session_request' }
  | {
      kind: 'resolved';
      walletId: WalletId;
      subjectSet: WalletUnlockSubjectSet;
      source: 'runtime_session_record' | 'profile_projection' | 'host_last_used_profile';
    }
  | {
      kind: 'no_session_for_wallet';
      walletId: WalletId;
      reason: 'missing_requested_capability_subject';
      source: 'runtime_session_record' | 'profile_projection' | 'host_last_used_profile';
    }
  | {
      kind: 'unresolvable';
      walletId: WalletId;
      reason:
        | 'missing_wallet_profile'
        | 'ambiguous_wallet_profile'
        | 'missing_requested_capability_subject'
        | 'invalid_wallet_profile';
    };
```

- Replace local `unlock(walletId) -> requireNearAccountForWallet(walletId) ->
  unlockCore(nearAccountId)` with `resolveWalletUnlockSubject(walletId,
  requestedCapabilities) -> unlockCore(subject)`.
- Resolve `WalletUnlockSubject` once at the IndexedDB/request boundary from
  active wallet signers and auth-factor records. Core unlock code must receive
  the discriminated subject, not raw wallet strings, broad profile records, or
  optional identity bags.
- Keep `nearAccountId` required only for the `near_ed25519_wallet` branch.
- Let `evm_family_ecdsa_wallet` unlock, restore, and warm ECDSA material without
  reading or validating any NEAR account identity.
- When unlock requests both NEAR Ed25519 and EVM-family ECDSA, represent it as
  a set of exact `WalletUnlockSubject` branches rather than one flattened object.
- Update passkey and Email OTP unlock flows so auth prompts bind to wallet/auth
  subject identity, while capability warmup binds to the selected branch subject.
- Update `getWalletSession`/page-refresh restoration to call the same capability
  subject resolver after session/public identity resolution.
  `no_session_request` means there was no wallet to restore.
  `no_session_for_wallet` means a requested or selected wallet has no active
  capability subject. It does not determine whether the `SeamsSession` or public
  wallet identity is active.
  Corrupt or ambiguous durable identity is `unresolvable` and must remain
  observable in diagnostics/tests.
- After successful registration or wallet unlock, read the same canonical
  capability inventory used by page refresh and assert each successfully warmed
  requested branch resolves to `use_live_runtime`. Do not retain a registration-
  only or unlock-only readiness cache.
- Split session/login display from capability readiness. Session state reports
  the `SeamsSession` lifecycle and public wallet identity. Each requested MPC
  capability independently reports `ready`, `recovery_required`,
  `authorization_required`, or `blocked` with a typed reason. A page refresh may
  restore an active session and registered NEAR identity while the Ed25519 Yao
  runtime first attempts exact sealed active-Client rehydration, then reports
  same-root recovery or fresh authorization when local active-session material
  is unavailable. ECDSA sealed material may report exact recovery without
  changing login state.
- Preserve registered NEAR account identity and Ed25519 public key independently
  of lane, grant, quota, or live Client readiness. Session reads remain
  side-effect free; the first signing/export operation owns exact recovery or
  authorization.
- Amend the companion SPEC's `WalletSessionDisplayState` before this phase closes
  so `expired`, `exhausted`, material restoration, and missing live Client state
  cannot masquerade as login lifecycle branches.
- Keep resolver `source` fields diagnostic-only. Source must never select auth
  authority or authorize a capability.
- Move display names, recent unlock lists, and account picker labels to wallet
  identity plus auth-factor display data. Implicit NEAR account IDs remain
  capability metadata.
- Delete fallback paths that infer a wallet from `nearAccountId` in unlock or
  wallet-session reads, except request/persistence boundary parsers with
  explicit deletion notes.
- Delete the `login.publicKey ? 'passkey' : null` auth-method inference fallback
  from wallet-session reads. Auth method display comes from resolved
  wallet-auth-method bindings or session evidence only.
- Replace silent signer-slot defaults in restore/session-read paths with
  boundary parse failures. Invalid or missing `SignerSlot` cannot become slot
  `1` in core code.

Check:

- [ ] Wallet unlock for an ECDSA-only wallet does not call `toAccountId`, read NEAR
  projections, or require a NEAR operational key.
- [x] Wallet unlock for a NEAR Ed25519 wallet still requires
  `nearAccountId`, `nearEd25519SigningKeyId`, and positive `signerSlot`.
- [ ] Combined NEAR+ECDSA wallet unlock warms the requested branches from a typed
  subject set and does not flatten `walletId`, `nearAccountId`, and ECDSA key
  identity into one object.
- [ ] Page refresh wallet-session restoration uses `WalletUnlockSubjectSet`,
  supports NEAR-only, ECDSA-only, and combined wallets, and never mints a
  NEAR-only session-read subject.
- [ ] Post-registration, post-wallet-unlock, and post-page-refresh flows feed the
      same canonical hydration resolver; entry-point provenance changes no branch
      for an equivalent current-state observation.
- [ ] An active restored login can coexist with ECDSA `recovery_required` and
  Ed25519 `recovery_required` or `authorization_required`; capability recovery
  failure changes only that capability's preparation state.
- [ ] Registered NEAR identity remains available when the Ed25519 lane snapshot,
  grant, quota, or live Yao Client is absent, expired, exhausted, or disposed.
- [ ] Source guards reject:
  - optional `nearAccountId` in wallet unlock core subject types;
  - `wallet-scoped auth requires a resolved NEAR account binding` in
    wallet-scoped unlock code;
  - ECDSA unlock paths importing NEAR account validators.
  - new `WalletSessionReadSubject` or `wallet_near_subject` aliases outside
    tests that intentionally assert their absence;
  - `WalletSessionReadResolution` after
    `WalletCapabilitySubjectResolution` lands.
- [ ] Focused tests cover:
  - [ ] post-registration canonical inventory publication and immediate
        `use_live_runtime` resolution for every successfully provisioned capability;
  - [ ] ECDSA-only wallet unlock;
  - [x] NEAR Ed25519 wallet unlock;
  - [ ] combined wallet unlock with requested branch set;
  - [x] page-reload unlock where runtime session records are empty but durable wallet
    signer records exist.
  - [ ] page-reload session read for ECDSA-only and combined wallets;
  - [ ] missing-profile, ambiguous-profile, expired ECDSA sealed-session, and
    capability-local recovery/authorization demotion cases;
  - [ ] active login plus public NEAR identity after page reload with no live Yao
    Client.
  - [ ] post-registration -> page-refresh and post-wallet-unlock -> page-refresh
        transitions through the shared hydration plan for NEAR-only, ECDSA-only, and
        combined wallets.

Cross-plan notes:

- Refactor 79 remains the owner for `ExactSigningLaneIdentity` and exact signing
  lane mutation rules. Phase 5 owns worker material identity.
- Refactor 90 owns `WalletUnlockSubject` because unlock is an auth/capability
  entrypoint, not a NEAR account API.
- YAOS owns Ed25519 Client cryptography and same-root protocol continuity.
  Refactor 90 owns the public capability locator, sealed/fresh recovery-source
  model, non-secret recovery commit journal and revocation outbox, volatile
  runtime ownership/publication, and capability-readiness projection.
- ECDSA role-local derivation contexts remain digest-only; SDK capability
  subjects may include app-specific identity before digesting.

## Phase 5: ECDSA Role-Local Material Cache Slimming

Status: in progress. The `evmFamilySigningKeySlotId` role-local material-handle
slice is complete; broader Phase 5 slimming remains pending.

Prerequisite to close: Foundation B is complete. The final material binding
must land directly in the canonical ECDSA manifest and runtime-observation
model; do not add another tactical session-record representation. Where this
phase and Foundation B disagree, Foundation B is the newer model and wins.

> This phase's material-only `EcdsaRoleLocalMaterialBinding` is the
> authoritative target shape. It supersedes the wider Phase 4 field list.

Goal: replace the Phase 4 tactical chain-specific worker-material handle with a
smaller material-cache identity. Exact signing lanes and signed Router A/B
normal-signing state remain the authority for chain/session use.

Evidence from the current implementation:

- `activeStateId` (the renamed `routerAbStateSessionId`) is derived from
  `RouterAbEcdsaDerivationNormalSigningStateV1` key, signing-root, version, and
  `activation_epoch` facts, and that epoch is issued from
  `thresholdSessionId`, so it transitively carries session identity.
- Current ECDSA threshold session identifiers are generated as
  `secureRandomId('tecdsa-keygen', 32, ...)`; they serve as the unique live
  material-session identifier.
- `chainTarget` is required in exact signing lane/session-record identity. The
  derivation client worker opens a role-local state blob by material handle and
  binding digest; chain selection should be checked before the worker material
  is opened.
- `evmFamilySigningKeySlotId` currently behaves like a deterministic
  provisioning/key-allocation handle derived from wallet and signing-root scope.
  If it has no runtime semantics after ECDSA key material exists, keep it out of
  signing authority, worker material identity, and generic capability records.

Implementation inventory:

- Shared TS protocol and ID helpers:
  - `packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId.ts`
  - `packages/shared-ts/src/signing-lanes/index.ts`
  - `packages/shared-ts/src/threshold/ecdsaDerivationRoleLocalBootstrap.ts`
  - `packages/shared-ts/src/utils/routerAbEcdsaDerivation.ts`
  - `packages/shared-ts/src/utils/signingSessionSeal.ts`
- Rust Router A/B protocol and local smoke code:
  - `crates/router-ab-core/src/protocol/router_ab_ecdsa_derivation.rs`
  - `crates/router-ab-cloudflare/src/lib.rs`
  - `crates/router-ab-dev/src/bin/router_ab_local_smoke.rs`
- Server route, JWT, budget, and D1 ceremony surfaces:
  - `packages/sdk-server-ts/src/router/commonRouterUtils.ts`
  - `packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts`
  - `packages/sdk-server-ts/src/router/signingBudgetStatus.ts`
  - `packages/sdk-server-ts/src/router/verifiedWalletSessionAuth.ts`
  - `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`
  - `packages/sdk-server-ts/src/router/cloudflare/d1EvmFamilyEcdsaRegistrationBranch.ts`
  - `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords.ts`
  - `packages/sdk-server-ts/src/core/AuthService.ts`
  - `packages/sdk-server-ts/src/core/ThresholdService/**`
- Web protocol clients and registration/bootstrap adapters:
  - `packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts`
  - `packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts`
  - `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions.ts`
  - `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/**`
- Web runtime, persistence, worker, and lane authority surfaces:
  - `packages/sdk-web/src/core/indexedDB/schemaNames.ts`
  - `packages/sdk-web/src/core/indexedDB/seamsWalletDB/ecdsaPresignMaterialStore.ts`
  - `packages/sdk-web/src/core/platform/ecdsaRoleLocalRecords.ts`
  - `packages/sdk-web/src/core/platform/secretSources.ts`
  - `packages/sdk-web/src/core/platform/ports.ts`
  - `packages/sdk-web/src/core/indexedDB/seamsWalletDB/ecdsaRoleLocalSessionMaterialStore.ts`
  - `packages/sdk-web/src/core/signingEngine/session/material/ecdsaRoleLocalMaterialResolver.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
  - `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/ecdsaDerivationSigningMaterialHandle.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts`
  - `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/**`
  - `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/**`
  - `packages/sdk-web/src/core/signingEngine/workerManager/**`
- Tests and guards:
  - `tests/scripts/check-key-material-branding-boundaries.mjs`
  - `tests/scripts/check-exact-signing-lane-authority-boundaries.mjs`
  - `tests/scripts/check-registration-capability-subjects.mjs`
  - `tests/scripts/check-router-ab-ecdsa-derivation-boundaries.mjs`
  - `tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs`
  - `tests/unit/evmFamilyEcdsaIdentity.unit.test.ts`
  - `tests/unit/ecdsaRoleLocalRecords.unit.test.ts`
  - `tests/unit/indexedDBConsolidation.unit.test.ts`
  - `tests/unit/readySecp256k1Material.rehydration.unit.test.ts`
  - `tests/unit/postRegistrationSessionActivation.unit.test.ts`
  - `tests/unit/loginEcdsaInventoryProfileRepair.unit.test.ts`
  - `tests/unit/routerAbEcdsaDerivationNormalSigning.unit.test.ts`
  - `tests/unit/routerAbEcdsaDerivationBudgetRouteCore.unit.test.ts`
  - `tests/unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts`
  - `tests/unit/thresholdEcdsa.*.unit.test.ts`

Side effects to account for:

- Removing `wallet_key_id` from Router A/B ECDSA derivation normal-signing scope
  changes canonical scope bytes, budget request digests, admission lifecycle ids,
  Rust protocol structs, and TS route parsers together.
- Removing or renaming `evmFamilySigningKeySlotId` changes Wallet Session JWT
  claims, signing-session seal bindings, D1 ceremony records, IndexedDB session
  records, sealed recovery records, and source guards. In development, delete
  local D1 and IndexedDB state after this lands rather than preserving
  compatibility readers.
- If `ecdsaThresholdKeyId` derivation stops hashing
  `evmFamilySigningKeySlotId`, existing ECDSA key identities change. Update
  registration bootstrap, add-signer, export/recovery, and test fixtures in the
  same commit.
- A chain-agnostic role-local `materialHandle` must not be used as a per-chain
  authority key or UI/session identity. Any `workerSessionId` field populated
  from the material handle must be treated as a worker cache reference only.
- Rename only ECDSA role-local public verifier fields in this phase. Ed25519
  `clientVerifyingShareB64u` fields remain out of scope unless a separate
  Ed25519 naming cleanup is planned.

Do:

- Audit `evmFamilySigningKeySlotId` before changing runtime material identity:
  - if it is only a registration/bootstrap reservation id, rename it to
    `EvmFamilyEcdsaProvisioningReservationId` and keep it only in
    registration/bootstrap request, ceremony, and server validation code;
  - if it is intended to identify a durable EVM-family signing capability,
    replace it with a real capability identity such as
    `EvmFamilyEcdsaSignerId`, document the cardinality it represents, and stop
    deriving it as a cosmetic alias for wallet plus signing-root scope.
- Do not carry a provisioning reservation id in:
  - `ExactSigningLaneIdentity`;
  - `WalletUnlockSubject`;
  - Wallet Session claims;
  - Router A/B normal-signing scope;
  - `EcdsaRoleLocalPublicFacts`;
  - the legacy `ThresholdEcdsaSessionRecord` during the Foundation B cutover;
  - sealed recovery records;
  - role-local material handles or binding digests.
- If no multi-ECDSA-key-per-wallet use case exists today, use
  `ecdsaThresholdKeyId` plus wallet/signing-root facts as the durable signer
  identity and delete `evmFamilySigningKeySlotId` from runtime paths.
- Replace the current role-local material binding:

```ts
type EcdsaRoleLocalMaterialBinding = {
  thresholdSessionId: ThresholdEcdsaSessionId;
  signingGrantId: SigningGrantId;
  keyHandle: EcdsaKeyHandle;
  activeStateId: EcdsaActiveStateId;
  chainTarget: ThresholdEcdsaChainTarget;
  clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  participantIds: readonly number[];
  relayerKeyId: EcdsaRelayerKeyId;
};
```

  with a material-only binding:

```ts
type EcdsaRoleLocalMaterialBinding = {
  keyHandle: EcdsaKeyHandle;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
  participantIds: readonly number[];
  relayerKeyId: EcdsaRelayerKeyId;
};
```

  This binding is the shape the SPEC nests as
  `DurableEcdsaMaterialBinding.roleLocalBinding` inside the Foundation B
  manifest, and it carries material facts only. Session identity
  (`thresholdSessionId`) lives solely in the manifest's
  `ActiveEcdsaMaterialSession`; the manifest revision binds material to its
  session, and lane/session validation proves the threshold session before
  worker material is opened, mirroring the `chainTarget` rule.

- Remove `thresholdSessionId` from `EcdsaRoleLocalMaterialBinding`,
  `EcdsaRoleLocalBindingDigest`, and `EcdsaRoleLocalMaterialHandle`
  (Foundation B owns this cut). The active manifest links material to its
  exact `ActiveEcdsaMaterialSession`; selected lanes keep proving
  `thresholdSessionId` against the session record before worker material
  access.

- Remove `activeStateId` (the renamed `routerAbStateSessionId`) from
  `EcdsaRoleLocalMaterialBinding`, `EcdsaRoleLocalBindingDigest`,
  `EcdsaRoleLocalMaterialHandle`, worker-store payloads, runtime material
  validation keys, tests, and diagnostics.
- Remove `chainTarget` from `EcdsaRoleLocalMaterialBinding`,
  `EcdsaRoleLocalBindingDigest`, and `EcdsaRoleLocalMaterialHandle`.
- Remove `signingGrantId`, `CapabilityGrantId`, `MpcWalletSigningQuotaId`, and
  remaining-use/expiry fields from `EcdsaRoleLocalMaterialBinding`, its binding
  digest, material handle, worker-store key, and cryptographic runtime identity.
  Phase 20 validates authorization and quota independently immediately before
  material use.
- [x] Remove `evmFamilySigningKeySlotId` from `EcdsaRoleLocalMaterialBinding`,
  `EcdsaRoleLocalBindingDigest`, and `EcdsaRoleLocalMaterialHandle`.
- Rename `clientVerifyingShareB64u` to `clientVerifyingPublicKey33B64u` in
  ECDSA role-local material binding, public facts, worker payloads, diagnostics,
  tests, and type fixtures. This value is public verifier identity, not a masked
  or secret signing share.
- Keep `chainTarget` in `ExactSigningLaneIdentity`, canonical ECDSA capability
  scope, exact operation-lane selection, and signer-session validation. It does
  not belong in the role-local material binding or a replacement broad session
  record.
- Preserve the current `routerAbEcdsaDerivationNormalSigning` signed state in
  wallet-session claims and persisted session records. Use its active-state
  session helper only at Router A/B
  request/admission boundaries that need the canonical normal-signing state
  session key. YAOS Phase 14B already replaced the old target types, routes,
  records, helpers, domains, and tests with Router A/B ECDSA derivation names.
- Move lane/session chain checks before worker-material access. A selected ECDSA
  lane must prove:
  - lane signer `walletId` matches the session record wallet;
  - lane signer `chainTarget` matches the session record chain target;
  - lane `thresholdSessionId` matches the session record;
  - lane signer key handle and ECDSA threshold key match the session record.
- Validate the exact operation grant and wallet signing quota after lane/material
  identity is established. Their renewal or replacement cannot invalidate,
  rename, or re-key role-local material.
- Make `buildEcdsaRoleLocalMaterialIdentity()` accept only branded domain types.
  Parse raw strings in record/JWT/worker-response boundary builders before
  calling it.
- Delete the legacy regression test that expects Tempo and ARC to produce
  different role-local worker material handles for the same material. Replace it
  with a test proving a Tempo lane cannot open/sign through an ARC session
  record, even when the worker material handle is shared.
- Add a guard rejecting `chainTarget`, `thresholdSessionId`, and
  `activeStateId`/`routerAbStateSessionId` inside
  `EcdsaRoleLocalMaterialBinding` and the role-local material handle/digest
  builder.
- Add a guard rejecting `evmFamilySigningKeySlotId` in runtime authority types
  unless the audit proves it is a durable signer identity and renames it away
  from the provisioning/reservation vocabulary.
- Update diagnostics to report the exact lane/session mismatch that blocked
  signing instead of reporting a worker material binding mismatch for chain
  selection failures.

Check:

- [x] `buildEcdsaRoleLocalMaterialIdentity()` and
  `buildEcdsaRoleLocalSigningMaterialHandle()` have no
  `evmFamilySigningKeySlotId` / `wallet_key_id` input.
- [x] Role-local worker material-handle call sites no longer pass
  `evmFamilySigningKeySlotId`.
- [x] Focused regression test covers the narrowed material-handle API:
  `pnpm -C tests exec playwright test unit/evmFamilyEcdsaIdentity.unit.test.ts -g "without signing key slot identity"`.
- [ ] `buildEcdsaRoleLocalMaterialIdentity()` has no `chainTarget`,
  `walletId`, `evmFamilySigningKeySlotId`, `thresholdSessionId`,
  `activeStateId`, or `routerAbStateSessionId` input.
- [ ] `buildEcdsaRoleLocalMaterialIdentity()` and its handle/digest builders have
  no grant, quota, remaining-use, or expiry input.
- [ ] `evmFamilySigningKeySlotId` is either deleted from runtime paths or renamed
  to a provisioning-reservation id that appears only in registration/bootstrap
  code.
- [ ] ECDSA role-local and EVM-family signing paths no longer use
  `clientVerifyingShareB64u`; public verifier fields use
  `clientVerifyingPublicKey33B64u`. Ed25519 paths are out of scope for this
  rename unless a separate Ed25519 naming cleanup chooses the same vocabulary.
- [ ] ECDSA role-local material handles are stable for the same material across
  Tempo, ARC, and other EVM-family chain targets.
- [ ] Cross-chain signing still fails closed through exact lane/session-record
  validation before the worker material handle is opened.
- [ ] Router A/B signing requests carry and validate the signed ECDSA derivation
  normal-signing scope against Wallet Session claims and retain no active
  HSS-named fields.
- [ ] `activeStateId` (the renamed `routerAbStateSessionId`) appears only in
  Router A/B state/admission helpers, request builders, and diagnostics that
  describe the signed Router A/B scope.
- [ ] Focused ECDSA signing tests cover same-material cross-chain reuse,
  cross-chain lane mismatch rejection, page-reload restored material, and
  registration-created material.

## Phase 6: Inventory And Public-Surface Ledger

Status: planning. Merges the old Phase 0 (call-site inventory) and Phase 0C
(public surface and deployment inventory).

Goal: map current wallet-first coupling and make the repo-wide blast radius
concrete before any shared vocabulary changes land. Phase 7 must not start until the
ledger exists.

Do — call-site inventory:

- Inventory `signing-session`, `signingGrantId`, `thresholdSessionId`,
  `SigningAuthPlan`, `WalletAuthIntent`, `WalletAuthCurve`, `AuthMethod`,
  `user_session`, and `threshold_session` call sites.
- Classify each `signingGrantId` occurrence as exact operation authorization,
  aggregate wallet signing quota, threshold-session authorization, or obsolete
  data. The ledger must assign a distinct target type or deletion action; a
  mechanical rename is forbidden.
- Classify each route and method as identity, session/provider adapter, Seams
  authorization, auth factor, route assembly, vault, IdP, Ed25519 MPC, or ECDSA MPC.
- Inventory frontend demo and SDK surfaces, including `apps/seams-site`,
  `apps/docs`, `examples/*`, `packages/sdk-web/src/SeamsWeb`,
  `packages/sdk-web/src/react`, and
  `packages/sdk-web/src/core/signingEngine`.
- Inventory shared and public API surfaces, including `packages/shared-ts`,
  `packages/sdk-web/package.json`, `packages/sdk-server-ts/package.json`,
  package export maps, public README/docs snippets, generated `.d.ts` surfaces,
  and `advanced`/`threshold`/`worker`/`wasm` entrypoints.
- Inventory deployment hosts and examples, including `apps/web-server`,
  `examples/self-host-cloudflare-worker`, wrangler configs, startup scripts, env
  var names, and package scripts that construct `AuthService`, threshold stores,
  signing-session seal routes, console routers, or router API workers.
- Inventory console management surfaces, including RBAC roles, API key scopes,
  policy assignment scopes, wallet index, key exports, approvals, audit,
  webhooks, observability, and seed data.
- Inventory auth-factor runtimes and sealed storage, including Email OTP WASM,
  Ed25519 Yao factor-root recovery records, signing-session seal records, wallet
  session IndexedDB stores, combined cross-curve worker envelopes, and any HKDF
  salt/info labels that currently bind to wallet or threshold identities.
- Inventory the complete landed YAOS surface: `crates/ed25519-yao*`,
  `crates/router-ab-ed25519-yao*`, the client WASM package, `yaoClient.ts`,
  `yaoActiveClientRegistry.ts`, `yaoPublicCapabilityReferences.ts`,
  `yaoPageLifecycleOwner.ts`, registration/add-signer/recovery/refresh/export
  orchestration, normal Ed25519 signing, server admission/recovery/refresh
  routes, D1 capability replacement, source guards, and intended-behaviour
  tests.
- Inventory the tactical OTP repair symbols as Phase 19 deletion inputs:
  `NearEd25519YaoCapabilitySource`, `NearEd25519YaoSigningCapability`,
  `nearEd25519YaoCapabilitySource`,
  `emailOtpNearEd25519LaneRequiresFreshAuth`, the Passkey/Email OTP reconnect
  aggregates and hooks, `EmailOtpEd25519YaoSilentRecovery*`, the Email OTP
  budget/cold-recovery prepared states and entrypoints, factor-labelled
  rehydrate/root worker operations and handles, method-specific Browser recovery
  maps, factor-labelled Near assembly ports, persisted-record-as-runtime
  publication, combined cross-curve unlock envelopes, source-text ordering
  guards, and generic-named passkey-only WASM registration/recovery sessions.
- Inventory every sealed-refresh identity and policy field separately:
  locator/recovery binding, authority, factor/provider identity, material owner,
  threshold session, recovery-envelope allowance/expiry, session transport JWT
  and expiry, operation grant, wallet quota, signer slot/key, root/version,
  participants, worker, public key, seal version, and retention. Assign each to
  the Phase 18 schema, a boundary-only parser, or destructive deletion; an
  ambiguous `remainingUses`/`expiresAtMs` row cannot survive.
- Inventory `RouterAbNormalSigningRuntime`, its replay and SigningWorker
  transport ports, the current shared budget stores/routes, every
  `ed25519_only | ecdsa_only | ed25519_and_ecdsa` binding mode, and the exact
  authority/curve/session/participant facts that become
  `MpcWalletSigningQuota` bindings.
- Inventory the completed YAOS Phase 14B ECDSA derivation source, routes,
  records, three responsibility-local worker entrypoints, WASM packages,
  generated bindings, tests, and deleted-name guards. Target-owner rows use
  Router A/B ECDSA threshold-PRF derivation terminology.
- Inventory test helpers and tooling, including Playwright configs, setup
  scripts, source guards, helper flows, fake relayers, fixture imports, and
  generated test env files.
- Classify `voiceId`, native clients, Rust crates, and WASM packages as
  capability-local, future grant evidence, or explicitly out of scope for this
  refactor.
- Classify frontend call sites as auth UI, session exchange, grant-evidence
  confirmation, vault UI, IdP UI, wallet UI, MPC signing, worker/runtime, or demo
  glue.
- Record imports that pull threshold, Router A/B ECDSA derivation,
  Yao runtime, signer WASM, chain, wallet UI, or recovery code into generic
  auth/router/frontend paths.
- Mark tests to preserve, rewrite, or delete.

Do — public-surface ledger:

- Write an inventory ledger with rows for:
  - package exports and public entrypoints;
  - deployment hosts and examples;
  - D1 migrations and seed data;
  - console management services and dashboard API clients;
  - test helpers, source guards, and Playwright scripts;
  - docs and generated diagrams that teach the old model;
  - optional workspaces such as `voiceId`, native clients, Rust crates, and WASM
    packages.
- For each row, record current owner, target owner, phase, action
  (`keep_capability_local`, `move_to_identity`, `move_to_session`,
  `move_to_auth_factor`, `move_to_authorization`, `move_to_vault`, `delete`, or
  `park`), and validation check.
- Treat `apps/web-server` as a first-class deployment host. It must have the
  same module boundary decisions as Cloudflare through the thin Node adapter.
- Treat `packages/shared-ts` as the highest-risk vocabulary surface. Shared
  exports cannot mention wallet/signing concepts unless the file is explicitly
  capability-local.
- Treat `voiceId` as parked future grant evidence unless this refactor explicitly
  chooses to add `voice_id_owner_presence` to `GrantEvidenceKind`.

Check:

- Every current auth/wallet/signing route has one target owner.
- Every frontend demo, SDK component, React hook/context, SeamsWeb operation, and
  browser worker has one target owner.
- Every public package export either remains capability-local, moves behind an
  auth/capability-neutral entrypoint, or is scheduled for deletion.
- Every deployment host and example has a target assembly model: auth-only,
  vault-only, MPC-only, IdP-only, or full-platform.
- Every console table, role, API scope, policy scope, and seed fixture has a
  target owner or deletion note.
- Every non-test helper that manufactures signing sessions, signing grants,
  threshold sessions, wallet auth, or wallet policy has a target owner.
- Every shared type slated for deletion has a replacement.
- The ledger names all current `signingGrantId`, `thresholdSessionId`,
  `signing-session`, `AuthMethod`, `wallet_auth`, `wallet_session`,
  `user_session`, and `threshold_session` surfaces outside generated build
  output.
- Every YAOS row is classified as retained protocol owner, public locator,
  sealed active-Client owner, Near root-material adapter, sealed recovery owner,
  non-secret commit-journal owner, runtime-publication owner, volatile runtime
  owner, rename, or deletion. Every Ed25519 sealed record has a
  capability-local Near material adapter owner. A valid exact locator plus
  matching sealed active-Client record can produce
  `rehydrate_active_session`; a matching root-recovery record can produce
  `sealed_recovery_available`. Orphan, expired, exhausted,
  exact-binding-mismatched, corrupt, conflicting, and unavailable records retain
  their typed failure. No HSS target owner exists.
- The ledger proves each old curve-combination budget tag has a typed quota
  binding replacement and a deletion phase.
- Export maps for `@seams/sdk`, `@seams/sdk-server`, and
  `@seams-internal/shared-ts` have target shapes before Phase 7 type changes.
- Host assembly targets are recorded for Cloudflare, Node web server,
  self-hosted Worker examples, local test servers, and the on-demand Express
  adapter contract.
- Parked surfaces have explicit source guards or issue links so they do not
  silently become generic auth dependencies.

## Phase 7: Core Vocabulary And Closed Capability Kinds

Status: planning. This is the additive subset of the old Phase 1. New
vocabulary lands in new modules only; renames and deletions that touch wallet
code are deferred to Phase 18.

Goal: define auth and capability-grant vocabulary independent of wallets, with
compile-time-closed capability kinds.

Do:

- Create the SPEC-owned `authorization/capabilityKinds` leaf module (Decided
  Point 2), including `vault_access`, both MPC capabilities, `idp_access`, their
  complete operation families, and correlated `CapabilityOperationRef`.
  The leaf module imports nothing. Both `seams-authorization` and capability
  modules import it. Capability packages register operation descriptors and
  handlers at assembly time, keyed by these closed kinds. Extend the unions in
  place as capabilities land; exhaustiveness checks must break when a kind is
  added without a handler.
- Define the complete Near authorization operation family:
  `near.sign_transaction`, `near.sign_delegate_action`,
  `near.sign_nep413_message`, and `near.export_key`. Define
  `mpc.produce_signer_proof` as a separate correlated MPC operation whose owning
  capability is resolved before Phase 19. Keep Yao registration, same-root recovery,
  server-share refresh, activation, and one-use export ceremony commands in a
  separate capability-local lifecycle union. Boundary builders map an authorized
  export operation to its one-use Yao ceremony without merging normal signing
  and Deriver execution.
- Add `AuthFactorIdentity`, `AuthFactorRecord`, `AuthFactorKind`,
  `GrantEvidenceKind`, `VerifiedGrantEvidenceSet`,
  tenant/principal/session/capability/grant IDs, public opaque `SeamsSession`,
  internal `SeamsSessionRecord`,
  `GrantEvidenceRef`, `CapabilityGrantRequest`, `CapabilityOperationEnvelope`,
  `CapabilityGrant`, `CapabilityGrantPolicy`, and
  `CapabilityOperationGrantPolicyBinding`.
- Consume the Refactor 82B vocabulary mapping when defining auth factors:
  Refactor 90 `AuthFactorIdentity` maps one-to-one to 82B's `AuthFactorIdentity`
  (`WalletAuthAuthority.factor`); `rpId` is verifier context on the
  wallet-bound authority, not factor identity. Do not mint a third
  representation. See
  [refactor-82B.md](./refactor-82B.md#vocabulary-mapping-into-refactor-90).
  The 82B `WalletAuthAuthority` restructure is gated on this phase landing —
  coordinate the two changes as one cut.
- Stage the 82B side by landing its domain types and type fixtures dark first,
  then flip imports and delete the old wallet-auth shapes in the same PR that
  makes the new types authoritative.
- Model evidence kinds as composed family unions (Decided Point 7): auth-factor
  session evidence, provider session/assurance evidence, interactive grant
  evidence, service-account evidence, approval evidence, and MPC signer proof.
  Provider sessions normalize into `seams_session`; only separately verified
  provider assurance can enter `GrantEvidenceKind`.
- Make `VerifiedGrantEvidenceSet` the only grant-issuance input. Its builder
  rejects mixed tenant, principal, session/device, operation, and digest facts.
- Model evidence policy as one recursive `GrantEvidenceExpression`; do not use an
  outer array whose all/any semantics depend on convention.
- Model assurance as required properties, not an implied ordering over unrelated
  factor/provider evidence grades.
- Keep `oidc_workload_federation`, `mtls_client_certificate`, and
  `kms_bound_proof` out of `GrantEvidenceKind` until their provider phases land.
- Use plain records for single-shape domain objects: `IdpRelyingParty`,
  `CapabilityGrantRequest`, `CapabilityGrantPolicy`,
  `CapabilityOperationGrantPolicyBinding`, `CapabilityInstance`,
  `CapabilityBinding`, and `CapabilityOperationEnvelope`.
- Use entity-specific lifecycle unions and `OperationDigestSet` for
  `laneDigest`/`intentDigest`/`displayDigest`.
- Model `SeamsSessionRecord` as identity plus a `state` lifecycle union, with
  `ActiveSeamsSessionRecord` for active-session inputs.
- Collapse `MpcSignerProof` to one record with `signerKind: MpcCapabilityKind`
  and `operationDigests: OperationDigestSet`.
- Split `AuthFactorManifest`, `ServerAuthFactorModule`, and
  `BrowserAuthFactorModule` so a server route manifest cannot import a client
  loader and a browser factor cannot import server handlers.
- Keep `AuthPrincipal` as one record keyed by `PrincipalKind`; add a union only
  when a principal kind gains real branch-specific fields.
- Keep verified email/contact data outside `AuthPrincipal`; passkey-only human
  principals do not require an email address.
- Expose `SeamsSession` publicly as an opaque branded handle only (Decided
  Point 5).
- Keep the SPEC Target Domain Types and the Phase 7 implementation in lockstep with
  the simplified shape above.
- Leave wallet code untouched in this phase, with one named exception: the
  staged 82B `WalletAuthAuthority` flip above is 82B-owned wallet-auth work
  that lands as its own coordinated cut beside this phase. Otherwise
  `AuthMethod = SignerAuthMethod` stays; `SignerAuthMethod`/`WalletAuthMethod`
  move in Phase 18.

Check:

- The Phase 6 ledger is complete for shared exports, package exports, deployment
  hosts, console schemas, helper scripts, and parked workspaces before any type
  here merges.
- `capabilityKinds` has no imports; `seams-authorization` and capability
  modules both consume it; a switch over `CapabilityKind` without a `default`
  typechecks (exhaustive).
- Generic auth modules import no signer domain files.
- Type fixtures reject invalid sessions, grant evidence records, grants,
  single-shape objects with obsolete `kind` fields, and signer fields on auth
  records.
- Type fixtures reject mismatched capability/operation pairs, factor records
  without `factorId`, direct object-literal construction of branded
  `SessionProviderEvidence`, `SessionExchangeRequestContext`,
  `CapabilityOperationEnvelope`, `VerifiedGrantEvidenceSet`, or
  `CapabilityGrantRequest`, raw evidence arrays as grant inputs, and lifecycle
  states unsupported by their persistence records.
- Type fixtures reject a `CapabilityGrantPolicy` referencing a grant evidence
  kind that is not declared.
- Type fixtures reject deferred workload evidence kinds before their provider
  phases add them.
- No existing wallet-first test or fixture changes in this phase.

## Phase 8: SDK Runtime Surface For Hosted Wallet Capabilities

Status: planning. Starts after Phase 7 owns `AuthFactorKind`, `CapabilityKind`,
and the correlated capability-operation vocabulary.

Goal: make the wallet iframe an SDK-level runtime selection instead of an app
Vite/Next/build plugin. Application code should import the SDK, provide its
environment and publishable key, and opt into wallet capabilities with typed
runtime, auth-factor, and capability config.

Client config selects SDK modules and UI/runtime loading only. Server tenant
runtime config owns `authFactors`, enabled capabilities, and
capability policies (see the SPEC's `TenantRuntimeConfig`).

Validated against current code:

- `SeamsWebProvider` already accepts one `config` object.
- `SeamsConfigsInput.iframeWallet` already carries the required runtime fields:
  wallet origin, service path, SDK base path, wallet host variant, and RP ID
  override.
- `SeamsWalletConfig` already resolves into a discriminated runtime shape:
  `direct` or `iframe`.
- `WalletIframeRouter` already requires `walletOrigin` when iframe mode is used.

Target public API:

```ts
import {
  createSeamsConfig,
  hostedWalletIframe,
  passkeyAuth,
  nearEd25519MpcSigning,
  evmFamilyEcdsaMpcSigning,
} from '@seams/sdk';

const config = createSeamsConfig({
  environmentId: 'proj_...',
  publishableKey: 'pk_...',
  walletRuntime: hostedWalletIframe({
    origin: 'https://wallet.seams.sh',
    rpId: 'example.com',
  }),
  authMethods: [passkeyAuth()],
  capabilities: [nearEd25519MpcSigning(), evmFamilyEcdsaMpcSigning()],
});
```

React usage:

```tsx
<SeamsWebProvider config={config}>{children}</SeamsWebProvider>
```

Auth-only usage:

```ts
const config = createSeamsConfig({
  environmentId: 'proj_...',
  publishableKey: 'pk_...',
  authMethods: [passkeyAuth()],
});
```

Internal normalized shape:

```ts
type BrowserWalletRuntimeSelection =
  | { kind: 'none' }
  | {
      kind: 'hosted_wallet_iframe';
      origin: WalletOrigin;
      servicePath: WalletServicePath;
      sdkBasePath: WalletSdkBasePath;
      rpId?: WebAuthnRpId;
      walletHostVariant: WalletHostVariant;
    };

type BrowserCapabilitySelection = {
  capabilityKind: Extract<CapabilityKind, 'near_ed25519_mpc_signing' | 'evm_ecdsa_mpc_signing'>;
  walletRuntime: 'hosted_wallet_iframe';
};

type BrowserAuthFactorSelection = {
  factorKind: Extract<AuthFactorKind, 'passkey' | 'email_otp'>;
};
```

Do:

- Add builder functions for the three distinct config axes:
  - wallet runtime: `hostedWalletIframe`;
  - `authMethods` config builders: `passkeyAuth` and later `emailOtpAuth`;
  - capabilities: `nearEd25519MpcSigning` and `evmFamilyEcdsaMpcSigning`.
- Naming note (deliberate): the _public_ config key stays `authMethods` —
  customer-facing ergonomics — while all internal types use auth-factor
  vocabulary (`BrowserAuthFactorSelection`, `factorKind`). The boundary parser
  is the rename point. Do not "fix" one to match the other.
- Add `createSeamsConfig(...)` as the single public browser config constructor.
  It should parse raw config input once and return the existing
  `SeamsConfigsInput`/resolved config bridge only as an internal adapter while
  the old config shape is being removed.
- Parse `origin`, `servicePath`, `sdkBasePath`, and `rpId` at the config
  boundary into branded runtime types.
- Allow at most one wallet runtime selection at the config boundary.
- Reject duplicate auth factor kinds and duplicate capability kinds at the
  config boundary.
- Reject `nearEd25519MpcSigning()` or `evmFamilyEcdsaMpcSigning()` without
  `hostedWalletIframe(...)` for browser builds.
- Keep `passkeyAuth()` usable without a wallet iframe for auth-only customers.
- Keep passkey and OTP out of wallet runtime config; they are auth factors.
- Implement the SPEC's hosted-wallet session delivery: the app receives a
  one-time exchange code bound to tenant, source session, app origin, wallet
  origin, and nonce; the iframe redeems it directly for a wallet-audience
  session. Never send a bearer session token through `postMessage` and never
  rely on unrestricted third-party cookies.
- Authenticate the iframe channel before sending the exchange code. Reject
  source-origin, target-origin, nonce, expiry, and replay mismatches at the
  session boundary.
- Define the client/server mismatch behavior (Decided Point 8): when the client
  config selects a capability or auth factor the server tenant runtime config
  has disabled, surface one typed, named error at session exchange or capability
  initialization. Iframe and worker bootstrap must not be reachable for a
  capability the tenant has disabled.
- Replace app examples that set `iframeWallet.walletOrigin` with the
  `walletRuntime` API.
- Keep any temporary `iframeWallet` acceptance at the public config boundary
  only, then delete it before this phase is complete.
- Keep Vite/Next plugins out of the runtime API. Wallet runtime selection is a
  plain typed SDK config value.
- Update `SeamsWebProvider` examples to use `config={...}`.
- Add type fixtures for:
  - duplicate auth factor and capability rejection;
  - signer capability without hosted wallet runtime rejection;
  - auth-only config without hosted wallet runtime;
  - old `iframeWallet` public examples absent from docs and app examples.

Check:

- A minimal Vite React app can import `@seams/sdk/react` and use
  `SeamsWebProvider config={createSeamsConfig(...)}` with no SDK Vite plugin.
- Auth-only passkey login can initialize without wallet iframe code.
- Browser NEAR/EVM MPC signing refuses to initialize without
  `hostedWalletIframe(...)`.
- Browser NEAR/EVM MPC signing initializes the hosted wallet iframe and never
  requests app-origin `/sdk/*`.
- Hosted wallet startup succeeds with third-party cookies disabled; browser
  traces contain no bearer token in `postMessage`, logs, diagnostics, or URLs.
- Replayed, expired, wrong-app-origin, wrong-wallet-origin, and wrong-nonce
  hosted-wallet exchange codes fail through typed results.
- A client config requesting a tenant-disabled capability fails with the typed
  mismatch error before any iframe or worker code loads.
- `packages/sdk-web/src/plugins/vite.ts` is no longer part of any public
  browser wallet setup path.

## Phase 9: Route Service Ports And Route Module Manifest

Status: planning. Old Phase 3 plus the route-manifest definition pulled forward
from old Phase 11 (Decided Point 3), so Slice A and B phases add modules
instead of rewiring routes.

Goal: stop exposing monolithic service surfaces to routes, and define the
runtime-neutral route module contract once.

Do — service ports:

- Replace router-facing `Pick<AuthService, ...>` with a service map keyed by the
  same `RouteServiceKey` values declared by route modules (the SPEC's
  `SeamsRouteServices` shape).
- Split `CloudflareD1RouterApiAuthMetadataService` into D1-backed adapters for
  identity, session, auth provider, auth factors, authorization, wallet, recovery,
  Ed25519 MPC, and ECDSA MPC.
- Split Node `apps/web-server` assembly into the same narrow ports, consumed
  through a thin Node adapter over the runtime-neutral handlers. It should
  construct enabled modules from config rather than directly wiring wallet,
  threshold, signing-session seal, router, and console services together.
- Delete the parallel Express route implementations (Decided Point 11). The
  handler contract stays fetch-style request/response so an Express adapter
  can be added later on demand as a thin wrapper; no Express-specific route
  code survives this phase.
- Port `packages/sdk-server-ts/src/router/express/createConsoleRouter.ts` into
  management/session/capability manifest routes before deleting the Express
  source. Console-only closed-source behavior moves to management route modules
  behind the same service ports; product capability routes stay in capability
  modules.
- Keep `AuthService` and the old D1 facade as temporary assemblers only.
- Same-change deletion (Decided Point 10): each route port that lands deletes
  its `AuthService` facade method and its duplicated `core/authService/**`
  helper in the same commit. The port replaces both layers, never becomes a
  third.
- Work through the Phase 3 delete-candidate ledger as ports land; record
  each deletion against its ledger entry.
- Land Phase 9 in per-port waves. Each wave must move one route family to the
  manifest, delete the replaced facade/helper/Express path, update the ledger,
  and keep Cloudflare and Node adapters green. The phase exits only when every
  ledger row with a live D1 owner is cleared.
- When a `core/authService/**` helper moves behind a port, re-home it to its
  Simplified End State owner (`identity/`, `authFactor/`, `session/`,
  `authorization/`, or a capability module) in
  the same change — do not leave it in `core/authService/` with a port wrapper.

Do — route module manifest:

- Evolve `RouterApiModule` from extension-only modules into runtime-neutral
  route manifests.
- Add module-owned route definitions, required service ports (by
  `RouteServiceKey`), a discriminated `RouterModuleOwner` (`platform` or exact
  capability), import guards, and runtime-specific handler factories. A field
  named `capabilityKind` must never contain `session`, `management`, or auth
  module labels.
- Replace the static Cloudflare handler list with registered modules.
- Assemble modules through named builders such as
  `buildCloudflareRouteModules(...)` from a deployment-scoped module selection.
  Keep tenant runtime enablement at request admission. Tenant configuration
  cannot mutate the route table or trigger per-request imports.
- Later phases (Phases 11-16, Phases 19-23, Phase 24) add modules against this contract; they must
  not introduce a second registry or bypass the manifest.

Check:

- Route handlers can access only declared service methods.
- Changes to wallet/threshold services do not typecheck through unrelated auth,
  vault, IdP, or session routes.
- Node web-server, Cloudflare, and self-hosted Worker examples share the same
  route module manifest decisions through thin adapters over one handler
  implementation.
- Duplicate module registration is rejected.
- Disabled modules are absent from route tables and bundles.
- A capability compiled into a multi-tenant Worker remains unavailable to a
  tenant that has disabled it, while another tenant can use the same deployed
  handler through its own runtime config.
- No `router/express/routes/**` implementation files remain; the only Express
  artifact is the documented on-demand adapter contract.
- Every landed route port deleted its facade method and duplicated helper in
  the same change; the Phase 3 delete-candidate ledger has no entries whose
  D1 owner is live. Phase 9 does not exit otherwise.

---

# Part 2: Slice A — Vault-Only Tenant End To End

Goal: prove the entire new model on the one capability with no legacy coupling.
At slice exit, a vault-only tenant works end to end on new vocabulary confined
to new modules, while wallet/MPC code still runs on the old vocabulary,
untouched.

Slice exit criteria:

- Native provider session -> `SeamsSession` -> capability grant -> vault proxy
  use through the Phase 16 minimal broker/gateway adapter -> passkey grant evidence
  -> vault reveal -> audit works against local D1.
- A vault-only tenant persists principals, factors, sessions, grants, and vault
  items with zero signer tables touched and zero MPC protocol/signer/WASM code
  loaded.
- A service account can request, receive, and consume a `vault.proxy_use` grant.
- No wallet-path file was renamed or deleted for this slice.
- The slice's deletion ledger and net non-doc line accounting are recorded in
  the journal, and guards whose invariant this slice made structural are
  retired (Decided Point 14).

## Phase 10: Slice A Persistence And Schema

Status: planning. Subset of old Phase 2; wallet-table remapping moved to Phase 18.

Goal: make the SPEC persistence model concrete for auth, session,
authorization, and vault.

Do:

- Add migrations for identity/auth/authorization tables, session refresh tokens,
  hosted-wallet exchange codes, grant evidence, verified evidence sets and
  members, capability grants, capability grant uses, capability grant policies, capability
  instances, capability bindings, audit, and vault tables.
- Add `auth_devices` storage plus `device_id` on sessions, challenges, grant
  evidence, MPC signer proofs, and authorization audit rows.
- Add expiry indexes for session refresh tokens, grant challenges, grant
  evidence, and capability grants. Add rate-limit storage for session exchange,
  OTP challenges, WebAuthn grant-evidence challenges, and service-account grant
  requests.
- Expand or replace console tables for principals, agents, vault approvals,
  capability provisioning, audit, and new API scopes.
- Add row parsers at the adapter boundary.
- Expose domain store commands rather than a generic transaction/query object.
  D1 implements atomic commands with batch/CAS; SQL adapters may use native
  transactions behind the same command ports.
- Add the SPEC's exact tenant-scoped foreign keys, partial unique indexes, replay
  indexes, correlated capability-operation CHECK constraints, and seed policies.
- Add exact factor enrollment persistence: `factor_id`, canonical identity
  digest, lifecycle, and replacement-factor linkage. Re-enrollment replaces the
  prior factor and creates the new factor atomically.
- Persist session subject and audience bindings. A session row must reconstruct
  the exact `SessionSubjectRef`, `SessionAudience`, and assurance profile.
- Persist immutable evidence sets and their ordered evidence membership so a
  grant can be reconstructed without embedding a transient request object.
- Add `operation_fingerprint_digest` and a unique
  `capability_operation_claims` record independent of authorizing-resource IDs.
  Model `CapabilityOperationClaim<Descriptor>` as an exhaustive
  `claimed | completed` union whose Slice A descriptor links one grant use.
  `claimed` requires a server-owned `CapabilityOperationExecutionLease` with an
  exact execution owner, lease ID, monotonic fencing token, deadline, expected
  capability-revocation epoch, and the descriptor's closed execution-phase
  journal. `completed` makes active-lease fields `never` and requires the original
  claim identity, final fencing token, completion time, and a descriptor-valid
  terminal result. The base terminal union is `succeeded | failed_after_claim |
  executor_lost | outcome_unknown | delivery_unknown | revoked_after_claim`;
  descriptor builders make inapplicable outcome and delivery branches
  unconstructable and require exact result, attempt, delivery, reconciliation, or
  revocation references where applicable.
  Phase 20 adds an MPC union keyed by operation descriptor: `quota_use: required`
  links one grant use and one wallet-quota use, while `quota_use: none` links only
  the exact grant use and makes quota fields `never`.
  `CapabilityGrantUse` references the operation claim instead of owning the
  idempotency key.
  Canonicalize the fingerprint from tenant, principal, capability, correlated
  operation, operation ID, and lane/intent/display digests. Exclude grant tokens,
  grant IDs, quotas, sessions, and runtime/material handles so renewal cannot
  create a second identity for the same operation. Implement the SPEC's
  claim-plus-decrement transaction and adapter conformance suite before any
  capability consumes grants. New-claim insertion creates the initial fenced
  execution lease atomically with every applicable decrement and linked audit/use
  row. Completed uses persist an integrity-bound terminal result so
  same-fingerprint retries can return the protected result without repeating side
  effects.
- Store raw OTPs, grant tokens, refresh tokens, vault secrets, auth headers, and
  signer material only as hashes, sealed envelopes, or external references.
- Do not remap existing wallet/signer/WebAuthn/Email-OTP tables in this phase;
  record their remap targets in the Phase 6 ledger for Phase 18.

Check:

- A vault-only tenant can persist principals, factors, sessions, capability
  grants, capability instances, vaults, and vault items without signer material.
- A service-account principal can persist API credentials, grant-request scopes,
  capability bindings, and capability grant policy records.
- Console roles, API scopes, policy assignment scopes, and seed data can express
  vault-only and auth-only tenants without wallet-operation roles.
- Raw provider rows cannot enter core logic.
- Concurrent same-fingerprint operation claims consume once and return the same
  `completed | claimed_active | claimed_stale` state, including after grant
  renewal. Different fingerprints
  serialize against applicable balances; exhausted grants cannot create orphan
  claim or use rows.
- Claim schema/type fixtures reject missing lease facts, terminal fields on
  `claimed`, active-lease fields on `completed`, invalid descriptor phases,
  inapplicable delivery/outcome branches, missing revocation correlation, and
  broad-spread lifecycle construction. Indexes support lease expiry, exact
  fingerprint lookup, and terminal reconciliation.
- Persistence parsers reject mismatched capability/operation pairs, unsupported
  lifecycle strings, cross-tenant references, and grants whose evidence-set
  binding differs from the grant record.

## Phase 11: Session Exchange And Seams Auth Provider

Status: planning. Old Phase 5.

Goal: normalize external login evidence into `SeamsSession` through one
exchange boundary, with durable identity resolution in `identity/` and session
lifecycle in `session/`.

Do:

- Create the internal `identity/` and `session/` source modules (package
  extraction deferred). Identity owns tenants, principals, auth accounts,
  provider-identity links, and JIT policy; session owns devices, audiences,
  exchange, refresh, and revocation.
- Implement the Seams-native session provider against the port first (v1,
  Decided Point 12): the existing passkey and Email OTP stack emits exact
  factor evidence into the session owner,
  Slack OTP participates when enabled as operation-bound evidence, recovery
  codes exchange as session evidence, and the native factor modules feed the
  same exchange as evidence sources while staying bound to the Seams
  confirmation UI. `betterAuthSessionProvider(auth)` is the deferred second
  implementation of the same port (Phase 25); nothing in this phase may
  depend on Better Auth specifics.
- Define the session-provider port as the contract first (Decided Point 12
  interchangeability clause): `betterAuthSessionProvider(auth)` and the
  Seams-native session provider are two implementations of it. No code
  outside the provider adapters may import provider specifics.
- Provider adapters emit principal-unbound verified provider evidence. The
  identity port resolves the tenant/provider subject, applies JIT policy, and
  returns the exact principal/provider-identity binding before session evidence
  is constructed.
- Implement one provider-neutral `provider_session` exchange command consuming
  branded `SessionProviderEvidence`; Better Auth and OIDC adapters verify their
  protocol artifacts before constructing it. Add exact native-factor and refresh
  commands. Wallet-login proof exchange may be stubbed as unsupported until
  Phase 23; it must fail closed, not fall through.
- Native factor exchange commands require the exact active `factorId`; the
  factor kind is loaded from that enrollment and is not duplicated in the core
  command. Lookup by factor kind alone is forbidden. Created sessions carry a
  `SessionSubjectRef` for either that enrollment or the exact provider identity.
- Define the session context consumed by Phase 14 grant-evidence routes. Phase 11 does not
  implement operation-bound grant-evidence challenge/verify endpoints; those
  depend on Phase 12 challenge records, digest canonicalization, and the generic grant
  issuer.
- Mint and manage `auth_devices` records through the session exchange boundary.
  The HTTP/runtime adapter derives request hashes and validates a signed existing
  device claim or a new-device nonce. Core session and authorization code
  receives `DeviceId`; it never accepts a client-selected ID or raw fingerprint.
- Persist and enforce `SessionAudience`. Implement first-party web, hosted-wallet
  iframe, and API-client audience branches.
- Implement the one-time hosted-wallet exchange-code flow from Phase 8 and the
  SPEC. Code consumption and wallet-audience session creation are atomic.
- Add a provider conformance suite (session create/refresh/revoke/replay,
  evidence normalization, tenant isolation) and run it against the native
  provider now; it becomes the acceptance gate for the Better Auth adapter in
  Phase 25.
- Add `seamsAuth({ database, ... })` plus D1/PostgreSQL-compatible adapters, as
  a composition layer only: it wires native factor modules plus an optional
  Better Auth instance. Commodity options (email+password, social providers,
  organizations, enterprise SSO) are reachable only through the Better Auth
  provider config; they are not implemented natively.
- Keep Better Auth optional at assembly: a signing-only tenant runs native
  factors alone without the Better Auth dependency.
- Implement multi-session revoke, forced logout, refresh rotation, and refresh
  family replay handling.
- Add rate limiting for session exchange, refresh, OTP login challenge minting,
  and native factor verification attempts.
- Move `/session/exchange`, refresh, and revoke onto the new session exchange
  service as manifest route modules (Phase 9 contract).

Check:

- All login paths create `SeamsSession` through the same exchange boundary.
- Session exchange cannot mint grants, provision capabilities, or satisfy grant
  evidence requirements by itself.
- Session exchange creation, refresh, revoke, replay denial, and tenant
  isolation have targeted tests.
- Session construction rejects mixed tenant, principal, provider, subject,
  audience, device, and evidence bindings.
- Two passkeys on one principal and Email OTP re-enrollment resolve the exact
  factor enrollment; replaced factor IDs cannot create or refresh sessions.
- Cross-origin, cross-audience, cross-device, expired, and replayed hosted-wallet
  exchange codes fail closed, and bearer tokens never appear in iframe messages.
- The session-provider port is the only session surface routes and
  authorization consume; the conformance suite passes against the native
  provider, and a source guard rejects provider-specific imports outside
  adapter/bridge modules — so the Phase 25 Better Auth adapter can land as
  config/assembly wiring only.

## Phase 12: Seams Authorization Core

Status: planning. Old Phase 4. Audit lives here (Decided Point 4).

Goal: build the authorization module that owns grant evidence, grants, policy,
operation digests, grant-use limits, and audit envelopes. Session lifecycle
lives in `session/` (Phase 11) and feeds authorization as evidence.

Do:

- Create the internal `authorization/` source module around the Phase 7 vocabulary
  and the `capabilityKinds` leaf.
- Implement operation digest envelopes (`laneDigest`, `intentDigest`,
  `displayDigest`), policy evaluation, grant lifecycle, replay checks, and audit
  envelopes.
- Define `CapabilityOperationFingerprint` independently from the grant that
  authorizes it. A fresh grant for the same tenant/principal/capability,
  correlated operation, operation ID, and digest set resolves to the existing
  claim/result. A deliberate retry uses a new operation ID.
- Implement authenticated, data-only
  `CapabilityOperationClaimLookup<Descriptor>` before fresh capability
  preparation. Its request contains only the semantic operation envelope and
  claimed fingerprint. The server recomputes the fingerprint, verifies tenant,
  principal, capability, and descriptor ownership, and returns
  `absent | claimed_active | claimed_stale | completed`. `completed` returns the
  protected terminal result; `claimed_active` joins or polls the current
  execution and requires an unexpired lease whose expected revocation epoch equals
  the current capability epoch with no tombstone. `claimed_stale` is a nested
  `lease_expired | revocation_epoch_changed | terminalization_pending` union and
  enters the matching descriptor or server-only revocation reconciliation. Only
  `absent` may proceed to fresh grant preparation and claim creation. Lookup
  cannot create, renew, execute, or mutate a claim or authorization resource.
- Implement `authorization/digests` as the canonical byte encoder for lane,
  intent, display, challenge, evidence-set, and audit digests. Add TypeScript
  fixtures plus Rust parity vectors before a capability depends on a digest.
- Implement generic grant-challenge records, lifecycle, and one-use
  verification state. Phase 14 registers the interactive evidence providers against
  these records.
- Implement the `VerifiedGrantEvidenceSet` boundary builder and generic grant
  issuer: exact operation envelope + capability binding + verified evidence set
  - `CapabilityGrantPolicy` -> `CapabilityGrant`. Raw evidence arrays and
  diagnostics cannot reach policy evaluation.
- Implement recursive `GrantEvidenceExpression` evaluation and property-based
  assurance requirements. Add exhaustive evaluators; no implicit evidence-grade
  ordering or outer-array convention is allowed. Canonicalize policies and cap
  expression depth/node count at the request/persistence boundary.
- Derive assurance profiles from verified evidence, deduplicate/sort properties,
  and cap profile expiry at the earliest supporting evidence/session expiry.
- Grants are DB-backed one-use/short-TTL records (Decided Point 6).
- Implement `seams_session` grant evidence first. `service_account_api_key`
  lands in Phase 15; interactive challenge evidence lands in Phase 14.
- Implement one-way grant-use consumption through the Phase 10 atomic operation
  claim port. Add the generic execution coordinator for the Phase 10
  `claimed | completed` lifecycle: lease renewal and every descriptor-phase
  transition use compare-and-swap on the current fencing token and expected
  revocation epoch; an expired lease can be fenced and transferred to exactly one
  descriptor reconciler. The reconciler reads exact attempt/result/delivery
  references before resuming an idempotent effect or completing a terminal result.
  It never repeats delivery without a descriptor-owned status query. Success and
  every post-claim failure complete the existing consumed claim without refund.
  Replay denial before a claim is an authorization audit event and creates no
  consumed-use row.
- Add the server-only revocation transition for an already consumed claim. It is
  authorized by claim ID, current fencing token, the lease's expected epoch, and
  an observed newer capability-revocation epoch plus exact revocation receipt. One
  compare-and-swap fences the old executor and either completes
  `revoked_after_claim` when no external outcome is possible or enters a
  descriptor-specific revocation-reconciliation lease whose expected epoch is the
  observed newer epoch and whose phase retains the prior epoch/token plus receipt.
  That reconciler resolves
  cryptography/result/delivery uncertainty before completing `succeeded`,
  `failed_after_claim`, `outcome_unknown`, `delivery_unknown`, or
  `revoked_after_claim`. Every branch is non-refunding, and existing-claim lookup
  returns the final completed result.
- Delete the bare `result | operation_in_progress` response and every indefinite
  claimed-row fixture before Slice A releases. The fenced base lifecycle is the
  only claim contract; retain no compatibility branch.
- Implement fail-closed `mpc_signer_proof` evaluation. The proof _producer_
  lands with the MPC capability in Phase 19; until then any policy requiring
  `mpc_signer_proof` must deny.
- Add the pruning job interface for expired challenges, expired/consumed grant
  evidence, expired grants, and refresh-token retention windows.
- Add architecture guards proving auth provider adapters cannot mint grants.

Check:

- A synthetic capability operation can be authorized without vault or MPC
  imports.
- Missing/inactive/mismatched MPC proof-producing capability fails closed.
- Grant lifecycle, digest mismatch, expiry, replay, and consumption have
  targeted tests.
- Existing-claim tests prove lookup precedes fresh readiness, completed results
  replay without a current grant, active leases join, stale leases fence the old
  executor, and descriptor reconciliation reaches one terminal result. Crash
  tests cover every descriptor phase. Revocation tests cover pre-effect,
  effect-started, and delivery-started claims and prove the server-only epoch
  transition cannot strand or refund a consumed claim.
- Mixed tenant, principal, session, device, capability-operation, or digest
  evidence cannot build a `VerifiedGrantEvidenceSet`.
- Mismatched capability/operation pairs fail in the Phase 7 parser and cannot
  reach policy lookup, route auth, or persistence.
- Digest canonicalization has TypeScript fixtures and Rust parity vectors.

## Phase 13: Management And Session Route Policy

Status: planning. Old Phase 6 minus the MPC planes (those move in Phase 20).

Goal: make route auth speak management, session, and exact capability grants
for the surfaces Slice A needs. Signing routes keep `threshold_session` until
Phase 20.

Do:

- Introduce `management_console`, `management_api_key`, `session_principal`, and
  `capability_grant` route auth planes. Replace `console`, `api_credentials`,
  and `user_session` on non-signing routes; leave `threshold_session` in place
  on MPC routes for Phase 20.
- Add `ManagementOperationKind`, `ManagementResourceScope`, correlated
  `CapabilityOperationRef`, and grant use. Route policies cannot carry
  independent capability/operation fields.
- Resolve console users and API keys into tenant-scoped principals.
- Replace wallet-only API scopes with the management scope taxonomy from the
  SPEC.
- Split API credential scopes into management scopes and capability grant-request
  scopes. Operation grant-request scopes can ask for a grant; they cannot reveal
  secrets, inject credentials, export keys, or sign by themselves.
- Replace console RBAC role names that are wallet-operation-specific with
  management roles that can govern auth, vault, IdP, and MPC capabilities.

Check:

- Management roles and API scopes cannot satisfy capability-grant routes by
  themselves.
- Old wallet-only API scopes are gone from non-signing surfaces; remaining
  signing-route scopes are recorded in the ledger with a Phase 20 deletion note.
- Management route policy and API scope parsing have targeted tests.

## Phase 14: Generic Client Grant Evidence And Confirmation UI

Status: planning. The generic-confirmation subsets of old Phases 7 and 8. The
MPC worker split and wallet UI migration stay in Phase 21/Phase 22.

Goal: give vault/auth flows a browser confirmation path that never imports
signing-engine code, without touching the existing MPC worker.

Do:

- Add `CapabilityGrantPlan` and `CapabilityGrantChallenge`.
- Register interactive grant-evidence providers for `passkey_assertion`,
  `email_otp`, and `slack_otp` against the Phase 12 grant-challenge store. Slice A's
  required end-to-end reveal path uses `passkey_assertion`; Email OTP and Slack
  OTP route tests prove the provider boundary.
- Implement provider-neutral Seams manifest routes for challenge/verify. The
  native provider mounts them directly; `seamsPasskeyGrantEvidence()` and any
  Better Auth mounting bridge land in Phase 25 over the same routes.
- Add a generic auth confirmation worker that returns a boundary-only
  `GrantEvidenceProofResult`; the server verifies it, persists the evidence row,
  and returns `GrantEvidenceRef`. Client code cannot manufacture evidence IDs or
  verified evidence records. Build it beside the
  existing `passkey-confirm.worker.ts`, which keeps serving MPC flows until Phase 21
  splits it.
- Add generic confirmation coordination separate from MPC signing coordination
  (the `UiConfirmManager` split lands fully in Phase 21; here only the generic side
  is created).
- Point vault/IdP operation prompts at the generic confirmation worker.
- Hide wallet-only features behind capability checks so vault-only and IdP-only
  tenants do not see wallet controls.
- Add public browser entrypoints for auth-only and vault-only imports that do
  not traverse `./advanced`, `./threshold`, `./worker`, `./wasm`, wallet iframe
  signer hosts, or signing-engine modules.
- Add export-map source guards for the new entrypoints on `@seams/sdk`,
  `@seams/sdk-server`, and `@seams-internal/shared-ts`.
- Add rate limiting for grant-evidence challenge minting and verification
  attempts.

Check:

- Vault/IdP prompts use generic confirmation without signing-engine imports.
- Vault-only and IdP-only bundles exclude MPC worker chunks and signer WASM.
- Public auth/vault entrypoints compile without importing MPC workers, signer
  WASM, threshold stores, Router A/B derivation/Yao runtime, or chain adapters.
- Seams passkey, Email OTP, and Slack OTP grant-evidence challenge and verify
  have targeted tests.
- Cross-session, cross-device, cross-origin, cross-operation, and digest-mismatched
  proof results fail before evidence persistence or evidence-set construction.

## Phase 15: Service-Account Grant Evidence

Status: planning. Old Phase 6A.

Goal: support non-interactive automation as a first grant-evidence provider.

Do:

- Add service-account API keys that authenticate to `management_api_key`.
- Normalize a valid key into `GrantEvidenceRef` with
  `evidenceKind: "service_account_api_key"`.
- Build service-account evidence sets through the same
  `VerifiedGrantEvidenceSet` boundary using the `non_interactive` context branch.
- Add grant-request scopes:

```text
grants.request.vault_proxy_use
grants.request.vault_rotate
grants.request.mpc_sign
```

- Add `CapabilityGrantPolicy` records for service-account API-key evidence with
  service account, capability, operation kind, resource scope, max TTL, max
  uses, and environment limit.
- Require a matching `CapabilityBinding` before issuing a grant.
- Resolve policy server-side from service account, API key scope, capability
  binding, resource scope, operation kind, and environment.
- Mint one-use or short-TTL `CapabilityGrant` records.
- Add rate limiting and replay detection for service-account grant requests.
- Add service-account capability grant policies for phase-one automation:
  `vault.proxy_use`, `vault.rotate`, and optional non-production MPC signing
  operations.
- Defer OIDC workload federation, mTLS, KMS-bound proof, and customer workload
  identity adapters.

Check:

- A service-account API key with only management scopes cannot request
  capability grants.
- A service-account API key with grant-request scope still fails without a
  capability binding and capability grant policy.
- Service-account API keys cannot directly call capability-grant routes; they
  must request and consume a short-lived grant.
- Phase-one capability grants allow vault proxy use and rotation.
- Reveal, export, break-glass, key export, and production high-risk signing
  remain blocked unless an explicit later policy enables them.

## Phase 16: Vault Capability Module And Integration

Status: planning. Old Phase 9 (vault part) plus old Phase 12.

Goal: ship the first capability module end to end on the new layer.

Resolve before starting: should `vault_access` be provisioned automatically for
every tenant? (See Open Questions.)

Do:

- Define the `vault_access` capability module under `capability/vault`.
- Define vault operation lanes for proxy use, reveal, export, permission
  change, rotate, and break-glass reveal.
- Define Secret Broker and Egress Gateway adapter contracts plus a minimal local
  Worker-compatible adapter for Slice A proxy-use tests. Production separate
  Workers remain in the Centaur secrets-vault plan after the grant model is
  proven.
- Implement vault access through `SeamsSession`, `VerifiedGrantEvidenceSet`, and
  `CapabilityGrant`.
- Enforce vault operation lanes, `direct_member`, `delegate_member`, proxy-only
  use, reveal, export, permission change, and break-glass.
- Support service-account capability grants for vault proxy use and rotation.
- Add optional MPC-backed authorization for high-assurance tenants (policy
  hook only; denies until Phase 19 ships the proof producer).
- Audit tenant, principal, capability, operation, lane digest, intent digest,
  display digest, evidence, and device.
- Validate capability grant policies against registered grant evidence kinds
  and correlated capability operation descriptors.
- Mount vault routes as Phase 9 manifest modules.

Check:

- Humans and agents share the principal model.
- Delegate access can use secrets through proxy without receiving plaintext.
- Service accounts can use vault proxy and rotation grants through the minimal
  broker/gateway adapter without reveal/export authority.
- Vault-only compilation excludes MPC modules.
- Vault proxy use, rotate, reveal/export, permission change, break-glass, and
  delegate-member denial have targeted tests.

---

# Part 3: Slice B — Migrate MPC Signing

Goal: move wallet/MPC signing onto the layer Slice A proved. This is where the
shared wallet vocabulary renames finally happen — with a working reference
implementation to migrate toward, not a speculative one.

Slice exit criteria:

- NEAR Ed25519 and EVM-family ECDSA signing authorize through
  `CapabilityGrant`s minted by Seams authorization.
- `signingGrantId`, `SigningAuthPlan`, wallet-only `AuthMethod`, and
  `threshold_session` route planes are deleted, not aliased.
- Auth-only registration creates no signer records.
- Vault-only and auth-only bundles still exclude all MPC/worker/WASM chunks.
- `core/authService/` is empty: every helper is re-homed to its end-state
  owner or deleted, and the `AuthService` facade is gone.
- Exact operation grants and descriptor-applicable `MpcWalletSigningQuota` use
  authorize MPC operations (Decided Point 13). Normal signing requires both;
  key export is grant-only. The old signing-budget coordinator,
  reserve/commit/release lifecycle, ambiguous `signingGrantId`, and curve-mode
  cross-product tags are deleted.
- Current Ed25519 and EVM-family ECDSA signing lanes and signing-session records
  carry `WalletAuthAuthorityRef`; admission, export, recovery, and restore never
  identify authority from branch-specific strings.
- Near Ed25519 and EVM-family ECDSA lanes are independent of auth factor kind.
  Each capability exposes `ready`, `recovery_required`,
  `authorization_required`, or `blocked`; no passkey/Email OTP lane or resolver
  cross-product remains in signing core.
- Browser persistence separates six Ed25519 Yao domains: the public capability
  locator, authenticated sealed activated-Client envelope, optional sealed
  root-recovery record, non-secret recovery commit journal, separate non-secret
  revocation outbox, and volatile runtime. The Near material adapter owns the
  last five. A valid active-Client envelope yields local active-session
  rehydration; a matching root-recovery record yields same-root recovery
  availability. Typed lookup failures stay distinct.
  `normal_signing.ready` requires an exact active Client plus committed
  publication/durability proof, while `export.ready` requires a correlated
  one-use export session and forbids a runtime handle. Lock, logout, page hide,
  and owner disposal destroy the live Client. Same-root recovery promotes a
  replacement only after server continuity and disposes every failed candidate.
- Page-refresh export resolution loads an exact durable Near Ed25519 context,
  verifies its server-canonical Yao lifecycle, and remains available when normal
  signing authorization or shared quota is exhausted. It performs no signable
  capability recovery. The export operation still requires its own exact
  `near.export_key` grant, one-use admission, and material-owner proof.
- Normal NEAR transaction, delegate-action, NEP-413, and any Near-owned
  signer-proof signing use the active Client plus SigningWorker/FROST with zero
  Deriver calls.
- One EVM-family online signer replaces `eth-signer` and `tempo-signer` while
  ECDSA derivation, presign, and online-signing artifacts stay
  responsibility-local. The browser Yao package contains client protocol code
  only.
- The slice's deletion ledger and net non-doc line accounting are recorded in
  the journal, and guards watching surfaces this slice deleted are retired.

## Phase 17: Wallet Auth Authority Refs On Signing Lanes

Status: planning. The shared authority/ref scaffold exists; exact factor and
wallet-auth-method binding IDs, final persistence shape, and lane/runtime
migration remain. Start after Phase 7 lands the Refactor 82B vocabulary mapping.
This is the narrow bridge from Refactor 82B's stable `WalletAuthAuthority`
model into Slice B's auth/capability migration. Foundation B pulls the leaf
`WalletAuthAuthorityRef` and its exact boundary builder forward for the ECDSA
manifest; Phase 17 completes the cross-capability migration without changing
that identity.

Goal: make every remaining signing lane and canonical capability record carry a
stable wallet-auth authority reference before the old signing budget is replaced
by exact operation grants plus the shared wallet quota. Multi-factor wallets,
multiple passkeys, Email OTP
re-enrollment, and future auth factors identify authority by the durable
wallet-auth-method binding. Core lanes stop carrying branch-specific strings
such as `passkey:rpId:credentialIdB64u` or
`email_otp:providerSubjectId`.

Target owner: `capability/mpcWalletAuthority`. This shared capability-local
module contains no chain, curve protocol, signer-WASM, material, or
operation-lane code.

Do:

- Replace raw factor-bearing selected/committed signing lane auth bindings with
  `WalletAuthAuthorityRef` for Ed25519 and ECDSA. The ref is derived from the
  bound `WalletAuthAuthorityRecord` and carries wallet ID, wallet-auth-method
  binding ID, exact `factorId`, and authority digest. It is never reconstructed
  from display data or diagnostics.
- Resolve user preference and policy into `any_authority` or one exact authority
  reference before lane selection. Core selectors never accept `authMethod` as
  an independent identity input.
- Preserve the authority ref in the Foundation B ECDSA manifest, exact
  operation lanes, material, recovery, restore, and export records. Carry it
  through Ed25519 Yao
  registration/admission, active runtime binding, public capability locator,
  sealed active-Client envelope, sealed root-recovery and fresh-acquisition
  references, recovery commit journal, runtime-publication
  proof, revocation outbox, exact Yao lifecycle ref, one-use material handle,
  same-root candidate/promotion, add-signer, and export records. Each quota binding
  and its refresh request carry their own exact
  authority ref; the aggregate wallet quota has no single authority ref.
- Separate durable authority identity from transient session transport
  credentials. New Ed25519 locator, recovery, material, and runtime paths carry
  `WalletAuthAuthorityRef`; they acquire the current bearer credential through a
  narrow `SeamsSession` transport port when a Router call requires one. Generic
  capability records contain no provider subject, email hash, display email, or
  bearer JWT.
- Update lane builders and boundary parsers so core signing code requires an
  authority ref. Land a schema/version cut with the new shape; reject and clear
  old local signing records instead of adding dual authority parsers or aliases.
- Change operation-authorization action singleflight to use an
  `AuthorizationActionKey` composed of the operation fingerprint and exact
  requirement digest. The requirement digest binds
  `authorityRef.authorityDigest`, capability/operation identity, projection
  version, curve, target, and exact quota requirement where applicable. Exclude
  live grant IDs and factor display data; the operation fingerprint remains
  independent of grant and quota IDs.
- Define re-enrollment semantics explicitly: if a wallet-auth-method binding is
  re-minted, the new binding produces a new `WalletAuthAuthorityRef`; old
  signing/session/export records tied to the previous ref cannot satisfy new
  authority checks.
- Keep `AuthFactorIdentity` pure. Factor identity maps to
  `WalletAuthAuthority.factor`; verifier context and wallet binding stay in
  `WalletAuthAuthority`, and signing lanes carry only the authority ref plus
  any operation-local lane facts they already require.
- Make the durable wallet-authority record reference the exact `factorId` from
  Phase 7. Matching credential/provider identity cannot substitute for an active
  factor enrollment or wallet-auth-method binding.
- Add static fixtures rejecting selected/committed signing lanes, ECDSA sealed
  records, Ed25519 public locators, sealed active-Client records, sealed
  root-recovery and fresh-acquisition references, one-use
  material handles, recovery commit journals, revocation outboxes,
  runtime-publication proofs, live
  runtime bindings, quota bindings, and export/recovery authorization state
  without an authority ref. Add purpose-substitution fixtures for
  `registration | recovery | export` root-material handles.
- Delete the interim
  `signingGrantAdmissionAuthorityKeyFromAuth` adapter once all signing lanes
  carry authority refs.
- Add a Phase 19 deletion marker to the current Passkey/Email OTP committed-lane,
  material-selection, authority-resolver, reauth-builder, and restore-builder
  symbols. Phase 17 must not add new method-specific lane branches while the
  authority-ref bridge is in flight.

Check:

- A wallet with both Passkey and Email OTP has distinct authority refs and
  cannot coalesce admission, export, recovery, or restore state across methods.
- Two passkeys on the same wallet have distinct authority refs.
- Email OTP re-enrollment produces a new authority ref; old records fail at the
  boundary parser/build step instead of during signing.
- Authorization-action singleflight keys bind the operation fingerprint to an
  exact requirement digest containing `WalletAuthAuthorityRef.authorityDigest`;
  no core signing flow builds authority identity from `rpId`, credential id,
  provider subject id, email hash, or display email.
- Ed25519 public locators, sealed/fresh recovery references, recovery commit journals,
  revocation outboxes, runtime-publication proofs, one-use material handles,
  active runtime bindings, recovery promotion, refresh, and export carry the same exact authority ref
  without carrying an auth-factor discriminator into the Yao runtime.
- Ed25519 export context resolution preserves the same exact authority and Yao
  lifecycle refs across the durable record, server lookup, worker request, export
  admission, and one-use export session. Missing or substituted lifecycle facts
  fail at the first parser or continuity boundary.
- Transient provider credentials are acquired only at the Router transport
  boundary. Static and runtime substitution tests reject provider-subject,
  factor-enrollment, authority-ref, and root-purpose mismatches before material
  consumption.
- Exact lane identity, selection, admission, restore, and recovery source guards
  reject raw factor fields and independent `authMethod` identity parameters.
- The Refactor 82B Phase 10D tests keep passing after the branch-specific
  queue-key helper is deleted.

## Phase 18: Wallet Vocabulary And Persistence Migration

Status: planning. The wallet-touching remainders of old Phases 1 and 2.

Do:

- Turn the Phase 6 test inventory into a redundant-test ledger.
- Remove tests/fixtures that only assert obsolete wallet-first behavior.
- Adapt tests that still protect valid behavior so they use auth/capability
  terminology before changing shared types.
- Move `SignerAuthMethod` and `WalletAuthMethod` into capability-local code.
- Delete `AuthMethod = SignerAuthMethod`.
- Classify every `signingGrantId` field by semantics. Delete it where
  operation-bound `CapabilityGrant` admission replaces it; map current
  wallet-level shared-use identity to `MpcWalletSigningQuotaId`; assign any
  distinct threshold-session authorization a separate branded ID; delete every
  material-identity occurrence. Add `capabilityGrantId` only to capability
  grant, grant use, and authorized/claimed-operation records. A mechanical type
  alias or field rename is forbidden. Keep `thresholdSessionId` inside MPC
  branches only.
- Remap existing D1 console/signer migrations onto the Phase 10 schema:
  `api_keys`, `policies`, `policy_assignments`, `wallet_index`,
  `key_exports`, `approvals`, `audit_events`, webhook categories,
  observability tables, signer wallet tables, wallet auth methods, WebAuthn
  tables, Email OTP tables, and signing-root secret share tables.
- Map active wallet auth methods to capability-local
  `mpc_wallet_auth_authorities` rows referencing exact Phase 7 `factor_id`
  values. Replaced/revoked bindings remain explicit lifecycle rows and cannot be
  parsed as active authority.
- Preserve the Foundation B ECDSA manifest, activation journal, persistence
  lookup union, and commit/read API as the canonical ECDSA state boundary.
  Phase 18 migrates wallet vocabulary and server authority rows around that
  boundary; it cannot reintroduce a broad signing-session record or a second
  ECDSA persistence owner.
- Split remaining legacy signing-session storage facts into independent fields for provenance,
  retention, authority reference, material owner, and recovery capability.
  `email_otp` is an auth factor kind, never a storage provenance value. Session
  versus single-use retention remains explicit and exhaustive.
- Keep ECDSA sealed material and typed recovery records capability-local.
  Transaction target projections may reference a shared ECDSA material owner
  without rewriting its identity.
- Split Ed25519 persistence and runtime observation into six exact domains: a
  minimal public `NearEd25519YaoCapabilityLocator`, an optional capability-local
  `NearEd25519YaoSealedActiveClientRecord`, an optional capability-local sealed
  root-recovery record, an optional non-secret
  `NearEd25519YaoRecoveryCommitJournal`, an optional non-secret
  `NearEd25519YaoRevocationOutbox`, and a volatile Rust/WASM
  `NearEd25519YaoRuntimeHandle`. The Near material/runtime adapter owns the last
  five domains. The active-Client record carries authenticated ciphertext plus
  stable wallet, account, signer, authority, lifecycle, threshold-session,
  participant, SigningWorker, registered-public-key, epoch, transcript, and
  material-session bindings. Operation grant, quota, session transport, and
  refresh-request scope are impossible fields. The root-recovery record carries
  ciphertext plus a typed recovery reference and the exact public binding
  digests needed for same-root validation. Neither record contains a live Client
  scalar, raw factor root, role input, recipient plaintext, bearer credential,
  or operation authorization.
- Define a branded `NearEd25519YaoLifecycleRef` at the server-response boundary.
  It requires the canonical Yao lifecycle ID, root-share epoch, account ID,
  threshold/wallet-session ID, signer-set ID, and SigningWorker ID. The public
  locator, sealed/fresh recovery refs, recovery journal, server capability
  descriptors and receipts, export context, worker request, and export admission
  carry that same exact ref or a digest that transitively binds it. Raw lifecycle
  strings cannot cross more than one boundary, and no builder may reconstruct the
  ref from a subset of wallet/session fields.
- Add a data-only `NearEd25519YaoExportContextResolution` built on demand from the
  exact public locator/root owner and a server-canonical active-capability lookup.
  It is not another persistence domain. Its closed result is `available |
  session_transport_reauthentication_required | missing | exact_binding_mismatch |
  exact_record_conflict | corrupt | persistence_unavailable | server_unavailable`.
  `available` requires the exact authority ref, material owner, lifecycle ref,
  wallet/account, signer slot/key, threshold session, runtime-policy binding,
  participants, SigningWorker, registered public key, locator revision/digest, and
  server verification receipt/epoch. Active Client state, runtime publication,
  normal-signing grant/quota state, recovery allowance, raw provider identity, and
  bearer credentials are `never`. Recovery-envelope or normal-signing quota
  exhaustion therefore cannot hide a valid export context; `near.export_key`
  obtains its own operation authorization later.
- Persist the recovery commit journal before the first non-reversible server
  mutation. It carries only the recovery/idempotency correlation, authority and
  owner refs, locator digest, expected server revocation epoch, and a discriminated
  `NearEd25519YaoMaterialRecoverySource`. `sealed_source` requires the exact
  sealed-recovery ref, sealed-recovery requirement digest, authenticated
  ciphertext digest, and source revision; fresh-acquisition fields are `never`.
  `fresh_acquisition` requires an exact non-secret acquisition requirement ref
  and digest plus requested retention and initial recovery-envelope policy;
  sealed-record ID, ciphertext, revision, and current recovery-allowance fields
  are `never`. The journal has an exhaustive state:
  `recovery_material_acquisition_pending |
  material_acquisition_committed_promotion_pending |
  pre_promotion_cleanup_pending | promotion_prepared |
  promotion_committed_activation_pending |
  activation_committed_seal_pending |
  seal_persistence_pending |
  seal_committed_readback_pending |
  volatile_retention_persistence_pending |
  volatile_retention_committed_readback_pending`.
  Branch-specific builders make the exact material-acquisition/admission receipt,
  promotion receipt,
  active-publication facts, candidate seal digest/revision, committed seal
  digest/revision, and volatile-retention receipt required exactly
  where they exist and `never` everywhere else. Secret handles,
  factor data, bearer credentials, and Client state are always `never`.
  `pre_promotion_cleanup_pending` requires the exact cancellation correlation and
  an `admission_only | material_acquired` cleanup stage. `admission_only` requires
  the exact admission query/result and makes acquisition receipt/policy `never`;
  `material_acquired` requires the acquisition receipt and reconciled monotonic
  policy. Promotion, runtime, and seal fields are `never` in both. Server
  recovery admission, sealed-source removal/recovery-policy consumption, fresh
  acquisition admission, and Router promotion declare whether they consume state
  and are independently idempotent and queryable by the same recovery ID. Persist
  `recovery_material_acquisition_pending` before the first consuming call, so a
  crash can reconstruct each exact result without a second allowance decrement or
  promotion.
- Clear a journal before promotion only after exact reconciliation proves that no
  consuming call committed, or after every attempted consuming admission or
  material-acquisition result is reconciled, terminal worker cleanup completes,
  and one durable CAS
  records the stage-specific terminal result, any returned monotonic recovery
  policy, and either restored sealed-source eligibility/removal or the fresh
  acquisition's terminal receipt. No journal-owned quarantine survives journal deletion. Once the
  journal enters `promotion_prepared`, retain and advance every
  partial-commit journal until local publication/durability finalization succeeds
  or explicit lock/logout reconciliation revokes the remote state.
- Create `recovery_material_acquisition_pending` in one IndexedDB compare-and-swap.
  For `sealed_source`, it verifies the exact source digest/revision, rejects
  another active journal for that source, and reserves/quarantines the source to
  the recovery ID before admission or unseal. For `fresh_acquisition`, it verifies
  the exact acquisition requirement and rejects another active recovery for the
  same material owner; it reserves no sealed record. After material acquisition
  commits, advance the existing journal to
  `material_acquisition_committed_promotion_pending` with its exact idempotent
  result and monotonic recovery policy when applicable. A sealed source remains
  replayable only through that recovery's idempotent result for material
  reacquisition until replacement or volatile-retention CAS commits; every new or
  differently correlated recovery treats it as ineligible. Fresh acquisition
  never invokes sealed-source unseal or retirement and may create the first
  retained seal or finalize volatile retention.
- Bind every sealed recovery reference to a branded
  `NearEd25519YaoSealedRecoveryRequirementDigest`. The digest covers the public
  locator, authority ref, material owner, lifecycle ref, wallet/account, signer slot and key,
  threshold session, signing root/version, participants, SigningWorker, public
  key, server revocation epoch, exact source sealed-record ID, authenticated
  ciphertext digest, source record revision, seal version, retention policy, and recovery-envelope policy.
  The Near material adapter verifies that digest before any server unseal or
  worker rehydration. Provider subject, email hash, display email, registration
  authority strings, and stored bearer JWTs remain boundary migration inputs
  and are absent from the current schema.
- Bind fresh recovery to a branded
  `NearEd25519YaoFreshAcquisitionRequirementDigest` covering the same public
  capability bindings plus exact acquisition purpose, correlation, and requested
  retention and initial recovery-envelope policy. It contains no sealed-record
  identity, ciphertext, source revision, or current recovery allowance. The two
  source digests are not interchangeable.
- Classify every current `remainingUses` and expiry field before migrating it.
  A recovery-envelope allowance becomes branded `remainingRecoveryUses` and
  `recoveryExpiresAt`; threshold-session lifetime, `SeamsSession` transport
  lifetime, operation-grant expiry, and wallet-quota expiry remain separate
  domains. If a field authorizes signing spend, migrate it completely to
  `MpcWalletSigningQuota` and remove it from material recovery. Recovery policy
  reconciliation may only take the protocol-defined monotonic minimum of local
  and server recovery limits. It cannot increase an allowance, renew a grant,
  replenish quota, or identify live material.
- Parse the persisted Ed25519 locator, sealed active-Client record, and sealed
  root-recovery record independently as closed unions. The locator lookup is
  `available | missing | corrupt | exact_record_conflict |
  persistence_unavailable`. The active-Client lookup is
  `available | absent | exact_binding_mismatch | corrupt |
  persistence_unavailable`. The root-recovery lookup is
  `available | absent | expired | exhausted | exact_binding_mismatch | corrupt |
  persistence_unavailable`. A sealed record without its exact locator is
  `corrupt`; a well-formed record with the wrong exact
  authority/owner/signer/root/policy binding is `exact_binding_mismatch`. Parse
  volatile handle observation independently as `active | disposed | absent`.
  Compose it with the commit journal and retention result into a closed
  `NearEd25519YaoRuntimePublicationState`:
  `absent | disposed | promotion_pending | durability_pending | committed_ready`.
  Only `committed_ready` carries the active runtime ref, observed owner-fence
  generation, server revocation epoch/promotion receipt, and a branded
  `durability_finalized` proof. That proof is explicitly either finalized
  volatile retention or finalized sealed retention with the committed seal
  digest/revision. Pending branches carry the exact journal ref and make
  claim-ready fields `never`. No persistence/runtime lookup can construct an
  operation authorization; Phase 19 composes readiness only from
  `committed_ready` plus authorization/quota state. Duplicate exact rows remain
  `exact_record_conflict`, and storage I/O failure remains
  `persistence_unavailable`. A valid revocation outbox makes `committed_ready`
  unconstructable even if a stale active-handle observation exists.
- Parse the recovery journal independently as
  `absent | valid_pending | exact_binding_mismatch | stale_revision | corrupt |
  exact_record_conflict | persistence_unavailable`. A valid pending journal takes
  precedence over ordinary locator/seal recovery lookup. A `sealed_source` record
  is journal-owned and quarantined: generic lookup cannot expose it as
  `sealed_recovery_available`, while the exact reconciliation/finalization port
  may read it by journal and sealed-source requirement digest. A
  `fresh_acquisition` journal has no source record to expose or quarantine.
- Persist lock/logout reconciliation in a separate non-secret
  `NearEd25519YaoRevocationOutbox`, parsed as `absent | valid_pending |
  exact_binding_mismatch | stale_revision | corrupt | exact_record_conflict |
  persistence_unavailable`. `valid_pending` carries a `revocation_pending`
  outbox whose branch requires exact authority, locator,
  material owner, idempotency correlation, and a nonempty collection of
  discriminated `capability_locator | sealed_recovery | recovery_commit |
  runtime_publication | operation_claim` targets. Each target requires its exact
  IDs, revisions, and receipts and makes every other target's fields `never`. Locator-only and
  volatile-runtime states can therefore be revoked without inventing a sealed
  record.
  Only a proven `absent` parser result permits capability recovery or readiness.
  `valid_pending` is `blocked(wallet_locked)`; binding mismatch, stale revision,
  corruption, and exact conflict are terminal blocked states;
  `persistence_unavailable` is retryable blocked. No parser failure can be
  interpreted as absence.
- Store a monotonic `NearEd25519YaoOwnerFenceGeneration` with the public owner
  state. Lock/logout first advances the process-local fence and disposes local
  runtime/worker state. One IndexedDB transaction then increments the durable
  fence, marks locator/seal/journal state ineligible, and writes the revocation
  outbox. Runtime publication observes the fence mismatch and cannot remain ready;
  active tabs receive the local fence through the owner broadcast channel. The
  model claims no memory/IndexedDB distributed atomicity. Storage failure keeps
  the process locally locked, returns retryable `lock_persistence_pending`, and
  cannot report lock/logout completion.
  Every recovery admission, material acquisition, promotion, publication, claim,
  and signing boundary revalidates the observed fence inside the owner queue.
  Every owner-state IndexedDB CAS predicates on that expected generation. A stale
  lease cannot publish readiness or begin another consuming effect; a remote call
  already in flight is reconciled through the outbox target captured at lock.
- Give the Router a server-canonical capability/authority revocation epoch. Every
  recovery admission, material-acquisition admission, and promotion
  compare-and-swap requires the exact expected epoch. Revocation atomically
  advances the epoch or installs a terminal tombstone and issues an exact
  revocation receipt. It then queries every recovery and claimed-operation ID
  associated with the exact capability/authority, including races absent from the
  original outbox snapshot. An already consumed claim uses Phase 12's server-only
  revocation transition: the exact old epoch, current execution-fence token, new
  epoch, and revocation receipt fence the old executor before terminal or
  uncertainty reconciliation. Acknowledgement can clear local durable records
  only after the server fence is durable and every correlated recovery is terminal
  and every correlated claim is `completed`. A stale ordinary request that reaches
  the Router after the fence fails its compare-and-swap.
- Land the SPEC-owned `MpcWalletSigningQuota` domain, parser, and persistence with
  one tenant/wallet/policy scope, expiry, remaining-use count, and a nonempty
  collection of exact Ed25519/ECDSA authority/curve/session/participant bindings.
  Each binding carries its own `WalletAuthAuthorityRef`. Delete the
  `ed25519_only`, `ecdsa_only`, and `ed25519_and_ecdsa` core union and all data
  shaped for those modes.
- Add migration notes for wallet-scoped records that become capability-scoped,
  principal-scoped, tenant/project/environment-scoped, or capability-local MPC
  records.
- Replace persistence formats atomically at each migrated surface. Reject and
  clear obsolete local records; do not add dual-schema readers.

Check:

- Redundant wallet-first tests are deleted or adapted before shared renames
  land.
- Old wallet-session rows and raw provider rows cannot enter core logic.
- Persistence parsers reject records whose authority ref, exact material owner,
  retention, and recovery capability do not agree. Pending single-use ECDSA
  records cannot become silently restorable session material. Ed25519 sealed
  root records parse only into sealed-recovery lookup branches and never imply
  runtime readiness.
- Sealed-recovery parsers distinguish missing, expired, exhausted, corrupt,
  exact-record conflict, persistence unavailable, and exact binding mismatch.
  Wrong curve, authority, subject, key, root, or policy is a terminal typed
  mismatch rather than a missing record. Tests prove local/server recovery
  allowance and expiry reconciliation is monotonic and never changes an
  operation grant or `MpcWalletSigningQuota`.
- Lifecycle-ref fixtures reject missing/substituted lifecycle ID, root-share
  epoch, account, threshold session, signer set, or SigningWorker at server,
  browser, worker, admission, and persistence boundaries. Export-context parser
  tests also reject wallet/account, signer slot/key, runtime policy, participant,
  locator revision, and registered-public-key substitution.
- Export-context resolution is data-only and creates no additional durable export
  record. With an exact locator and server capability, it returns `available`
  after reload even when the active Client is absent and normal-signing grant,
  quota, or recovery allowance is exhausted. Typed tests cover transport
  reauthentication, missing context, exact mismatch/conflict, corruption, local
  persistence failure, and server unavailability. No branch changes recovery
  allowance, seal eligibility, journal state, runtime publication, grant, or quota.
- Browser persistence parsers accept only the public locator, exact sealed
  factor-root recovery schema, non-secret recovery commit journal, or non-secret
  revocation outbox. They reject live Client state, secret handles, raw root
  material, transport credentials, and authorization state. Page hide disposes
  the live owner while retaining durable recovery and partial-commit facts,
  including a quarantined source for a sealed-source journal only while that
  source still exists. Post-retirement pending journals retain the exact former
  source identity and finalization receipt. Explicit
  lock/logout disposes local runtime/worker secrets immediately, makes durable
  recovery state ineligible, and persists the revocation outbox before attempting
  server reconciliation. Network failure cannot leave local signing state usable.
- Journal/reconciliation tests terminate the worker or reload the page before
  material acquisition, after sealed-source unseal or fresh acquisition,
  before/after server promotion, after local activation, during seal generation,
  and after seal persistence. Each attempt
  resumes from server-canonical and journal state without decrementing recovery
  allowance twice or repeating promotion, a signing claim, a grant decrement, or
  a quota decrement.
- Journal `@ts-expect-error` fixtures reject direct literals/broad spreads,
  missing branch receipts/revisions, committed-seal fields before candidate seal
  creation, candidate fields after persistence commit, secret handles in every
  branch, sealed-source fields on fresh acquisition, fresh-acquisition fields on
  sealed recovery, cleanup state without an exact cancellation correlation/stage,
  admission/acquisition receipt substitution, cleanup state with promotion/seal
  fields, and an ordinary sealed-recovery lookup while a valid
  sealed-source journal owns the source record.
- Offline lock/logout tests dispose runtime and worker secrets immediately, mark
  all durable recovery state ineligible, and retain only the non-secret
  `revocation_pending` outbox until idempotent server acknowledgement. Type
  fixtures reject empty/duplicate revocation target collections, cross-target
  field combinations, and sealed fields on locator-only or volatile-runtime
  targets. Concurrency tests prove the owner-fence increment invalidates
  pre-lock recovery and claim leases before their next consuming boundary. Outbox
  parser tests prove only `absent` may proceed. Router tests prove a stale
  admission/promotion request cannot commit after the server revocation epoch and
  that acknowledgement waits for every correlated recovery ID to become terminal
  and every correlated operation claim to become `completed`. Claim revocation
  tests cover no-external-effect, outcome-uncertain, and delivery-uncertain phases
  through the exact fenced Phase 12 transition.
- Authority selection reports `authority_ambiguous` when `any_authority` matches
  multiple refs. Exact persistence resolvers distinguish `missing`,
  expired/exhausted recovery, exact binding mismatch, `corrupt`,
  `exact_record_conflict`, and `persistence_unavailable`. They never choose a
  newest or source-priority record when exact matches conflict.
- Quota parsers require a nonempty typed binding collection, reject duplicate or
  substituted authority/curve/session/participant bindings, and accept no legacy
  curve-combination mode. Distinct bindings in one wallet quota may carry
  different exact authority refs.
- Source guards reject wallet-only `AuthMethod` outside capability-local
  modules. The broader old-signing-symbol guard lands in Phase 19 when the old
  EVM preparation flow is deleted.

## Phase 19: MPC Capability Modules

Status: planning. Old Phase 9 (MPC part).

Prerequisites: Foundations A and B plus Phases 5, 12, 14, 17, and 18 are
complete, and
the companion SPEC contains the auth-agnostic Near preparation domain, public
locator, sealed active-Client ref and local import lifecycle, sealed and fresh
recovery source union, exact Yao lifecycle ref, refresh-safe verified
export context, recovery journal, separate revocation outbox and local/server fences,
and runtime-publication split, operation-versus-material authorization model,
complete Near operation union, fixed effect order, exact resolver failures, and
grant/quota amendment. It must also define the worker-private material-recovery
lifecycle, recovery-envelope policy, session-transport reauthentication,
pending-journal precedence, reseal finalization, and every post-commit recovery
state. Phase 19 defines the client/capability preparation domain, and Phase 20
completes server admission and
route cutover. Treat Phases 19 and 20 as one no-release migration tranche; no
supported build may expose both the old signing authorization flow and the new
capability-grant flow. YAOS production readiness remains gated by `router-ab/ed25519-yao/implementation-plan.md`.

Resolve before starting: which MPC capability produces `mpc_signer_proof` by
default? (See Open Questions.)

Do:

- Define `near_ed25519_mpc_signing` and `evm_ecdsa_mpc_signing` modules under
  `capability/`.
- Make both modules consume the Foundation A
  `MpcCapabilityHydrationPlan`. Registration
  finalization, wallet-unlock warmup, page-refresh restoration, signing, step-up,
  and export resolve the same plan from current canonical state. Protocol adapters
  construct live/sealed/public-anchor proofs; capability orchestration contains
  no entry-point-specific material branch.
- Move Ed25519 and ECDSA operation lane and intent construction into their
  capability modules.
- Use distinct names for the authorization resource, durable public Ed25519
  identity, sealed active-Client reference, sealed root-recovery reference, and
  live cryptographic runtime:
  `CapabilityInstance`,
  `NearEd25519YaoCapabilityLocator`,
  `NearEd25519YaoSealedActiveClientRef`,
  `NearEd25519YaoSealedRootRecoveryRef`, and
  `NearEd25519YaoRuntimeHandle`. Add
  `NearEd25519YaoLifecycleRef`,
  `VerifiedNearEd25519YaoExportContext`,
  `NearEd25519YaoMaterialRecoverySource`,
  `NearEd25519YaoRecoveryCommitJournal`,
  `NearEd25519YaoRevocationOutbox`, and
  `NearEd25519YaoRuntimePublicationState` for the non-secret partial-commit and
  signability lifecycle. The runtime handle has only `active | disposed`; it
  carries no grant, quota, persistence, or publication identity.
- Add one exact local active-Client material adapter. The checkpoint's Passkey
  envelope already authenticates wallet, account, signer, passkey credential,
  lifecycle, signing-root, signer-set, participant, SigningWorker, public-key,
  epoch, transcript, and activation bindings. The target adapter additionally
  verifies canonical `WalletAuthAuthorityRef` and active material-session
  continuity. A valid
  `NearEd25519YaoSealedActiveClientRef` constructs Foundation A's
  `rehydrate_active_session`; the effect imports the activated Client into the
  Rust/WASM registry, verifies its public identity, publishes the runtime, and
  then reruns exact resolution. It performs zero Deriver A/B calls. Envelope
  absence, corruption, or binding mismatch remains distinct from root recovery.
- Replace the tactical `PasskeyEd25519YaoLocalMaterialLocatorV1`. Its checkpoint
  shape still embeds `signingGrantId` and server refresh scope and compares
  rotating grant identity during import. The canonical sealed active-Client
  record binds stable authority, lifecycle, and material-session identity while
  operation grants, quota, refresh requests, and session transport remain
  separate. Registration publishes the record through the canonical
  journal/read-back transition; compensating delete around a pre-activation
  write is insufficient durability proof.
- Implement the SPEC's auth-agnostic Near Ed25519 Yao preparation domain as a
  union keyed by operation class. `normal_signing` carries one exact
  transaction/delegate/NEP-413/(Near-owned proof) envelope, stable signer/runtime
  identity, and `quota_use: required(cost)`. `export` carries one exact
  `near.export_key` envelope, exact root-material owner, verified durable export
  context, and `quota_use: none`;
  normal signing lane/runtime/quota fields are `never`. Both branches require
  `WalletAuthAuthorityRef`, validate the exact operation grant independently of
  cryptographic state, and return only `ready`, `recovery_required`,
  `authorization_required`, or `blocked` with branch-specific payloads.
- Add one auth-agnostic `NearEd25519YaoRootMaterialAdapter` with separate
  inspection and acquisition ports. The data-only inspection port returns
  `acquisition_ready | sealed_recovery_available | unlock_required |
  partial_commit_pending | unavailable`. Its acquisition/sealed branches
  carry only an exact non-secret acquisition or sealed-recovery ref.
  `partial_commit_pending` carries only the exact parsed journal ref and action;
  acquisition and ordinary sealed-recovery refs are `never`, and it takes
  precedence over a journal-owned sealed source. Inspect the revocation outbox
  independently and require a proven `absent` result before any other preparation
  branch. `revocation_pending` maps to `blocked(wallet_locked)` and is executable
  only by the revocation outbox owner; every parser error maps to its fail-closed
  typed blocked state.
  The effect-only port accepts an authorized, exact-purpose
  acquisition request plus Router admission, acquires an authority-bound
  `NearEd25519YaoRootMaterialHandle<Purpose>`, and immediately consumes it through
  the matching Rust/WASM constructor inside the Near material adapter or secure worker.
  The handle has an `owned -> consumed` lifecycle and is leaf-private: it is never
  returned through capability assembly or placed in preparation state. The port
  returns only a purpose-specific, correlated candidate-runtime or ceremony
  result.
- Implement material recovery across two explicit owners. The material-adapter
  persistence port supplies the exact discriminated recovery source and owns
  journal/source/seal eligibility and IndexedDB CAS. Inside the secure worker, the
  lifecycle is `pending factor -> authority/purpose/correlation-bound root handle
  -> consumed staged candidate -> volatile finalization | retained reseal source
  -> candidate seal ciphertext`. For sealed retention, the persistence port
  consumes the candidate ciphertext and publishes a new eligible sealed recovery
  ref; it replaces `sealed_source` and is the first seal for
  `fresh_acquisition`. Volatile retention has no seal branch. For
  `sealed_source`, the adapter
  checks the exact sealed-recovery requirement digest from Phase 18 before unseal.
  For `fresh_acquisition`, it checks the exact acquisition requirement digest and
  invokes no sealed-source operation. Rehydration returns only
  an opaque pending-factor handle plus branded monotonic recovery policy; root
  binding and constructor consumption happen in the same secure owner. Raw
  factor bytes, provider identity, and bearer credentials never return to the
  capability coordinator. Surviving candidate or reseal-source refs stay in the
  secure owner's private `resident` state keyed by recovery ID; public pending
  results carry only the exact journal action, and reload uses
  `reconstruction_required`. Every
  terminal failure, cancellation, expiry, supersession, and disposal zeroizes or
  disposes all pending factors, bound roots, staged Clients, retained reseal
  sources, and candidate ciphertext still owned by that attempt. The worker never
  owns, retires, or selects a durable sealed record.
- Make root-material purpose a closed discriminated union with branch-specific
  correlation and `never` fields: registration binds ceremony/admission identity;
  recovery binds recovery-requirement ID and digest; export binds operation
  fingerprint, envelope digest, and admission identity. Every branch carries the
  same exact `WalletAuthAuthorityRef`. Branch-specific builders are the only way
  to create acquisition requests and one-use handles.
- Implement one auth-agnostic, data-only Near export-context resolver. It parses
  the Phase 18 resolution union, verifies the exact locator/authority/material
  owner/lifecycle/server receipt, and returns only a branded
  `VerifiedNearEd25519YaoExportContext` or its typed unavailable branch. Page
  refresh, an absent/disposed active Client, exhausted normal-signing grant or
  wallet quota, and exhausted recovery allowance do not change a valid result.
  Resolution performs no seal unseal/removal, root acquisition, normal-signing
  recovery, journal transition, candidate construction, promotion, activation,
  publication, authorization claim, or quota mutation.
- Auth-factor adapters own WebAuthn/OTP interaction and verified evidence. The
  Near material adapter owns recovery-source/journal/revocation-outbox inspection
  and persistence CAS
  through its non-secret persistence port. Its responsibility-local secure-worker
  subport owns root acquisition, constructor invocation, immediate handle
  consumption, candidate state, and reseal-source zeroization. The capability
  coordinator and active runtime receive no factor-kind discriminator, raw root,
  provider credential, root-material handle, or secret-bearing record.
- Give the generic export coordinator one exact export material-acquisition port.
  Boundary assembly resolves the verified authority requirement to the registered
  factor/material adapter; capability core receives the opaque requirement and
  result. It contains no `auth.kind` switch, Passkey recovery callback, Email OTP
  context callback, or factor-labelled export function. Static adapter inputs
  reject a requirement for a different exact authority, while the operation and
  export-session lifecycle remain identical across factors.
- Keep factor-domain KDFs inside Rust/WASM. Each Near material adapter implementation invokes its
  factor-specific constructor, which derives the Client root before converging on
  the common activation lifecycle. No generic capability API accepts a
  pre-derived Client root.
- Give registration its own no-grant ceremony sequence: resolve the exact
  ceremony and authority, obtain Router admission, acquire the registration
  material handle and consume it into Rust/WASM inside the Near material adapter,
  execute, then complete. Admission failure leaves material unacquired and
  unconsumed.
- Resolve the revocation-outbox parser union and recovery commit journal before
  parent operation authorization and quota. Only a proven absent outbox proceeds;
  every other branch stays blocked. A pending recovery
  resumes through its existing recovery correlation and queries admission by
  recovery ID as `not_started | committed | terminal`. `not_started` obtains the
  exact admission once after its required recovery-specific approval/evidence or
  transport prerequisite; `committed` reuses the receipt; `terminal` maps to its
  exact blocked/revocation outcome. The resume path consumes no operation grant or quota. After it
  converges, rerun the complete normal operation resolution against current
  authorization, quota, runtime publication, and lane identity.
- When no journal is pending, sequence signing recovery as: inspect durable
  recovery data and validate the parent operation's grant and required quota
  readiness without effects; obtain approval and required evidence; reacquire a
  current session transport credential when required; allocate the exact
  recovery/idempotency ID and persist
  `recovery_material_acquisition_pending` with its sealed or fresh source; obtain
  exact recovery admission; idempotently unseal a sealed source or acquire fresh
  material, then consume the recovery material handle inside the Near material
  adapter; advance the journal through
  `material_acquisition_committed_promotion_pending` and `promotion_prepared`;
  verify and promote/activate the correlated candidate Client; complete the
  required retention finalization; then perform exact post-effect re-resolution.
  The parent signing operation claims grant and quota only after the re-resolved
  lane is `ready`.
- Sequence `near.export_key` as: perform authenticated existing-claim lookup;
  resolve the exact durable export context and export operation requirement using
  data-only reads; validate the exact export grant plan; obtain approval and
  policy-required evidence; reacquire session transport when required; obtain
  exact export admission; complete material unlock/acquisition; stage the one-use
  Rust/WASM export session; re-resolve the lifecycle/context exactly; atomically
  claim the grant-only export operation; execute export; then finalize and
  zeroize. Normal-signing authorization/quota state is absent from this sequence.
  The export operation's own grant remains mandatory. User cancellation before
  claim decrements no grant and zeroizes any acquired handle or staged export
  session.
- Sequence `evm.export_key` through the same hydration vocabulary. Live role-
  local material uses `use_live_runtime`; a current active material session with
  an exact sealed record uses `rehydrate_active_session`; an expired or exhausted
  material session with only durable public facts uses
  `reauthorize_public_anchor`. The public-anchor branch obtains fresh export-
  specific evidence and provisions one one-use export session. It never searches
  for a retired sealed secret record and requires no prior EVM/Tempo transaction
  or full wallet unlock.
- Treat the pre-effect export selection as a stable continuity request. It carries
  no executable grant, bearer credential, or runtime/export-session authority.
  After material acquisition, cold recovery, or transport reauthentication,
  compare exact wallet/account, signer key/slot, threshold session, lifecycle,
  runtime policy, and `WalletAuthAuthorityRef` continuity. Then discard every
  rotating field from the earlier observation and use the current canonical
  context, export grant, session transport, and one-use export session. Stable
  signer or authority drift fails closed; grant replacement or session-transport
  credential rotation is an expected successful transition. No transaction or
  normal-signing operation may be required to publish that current export state
  first.
- Consume or zeroize every one-use root-material handle on success, failure,
  cancellation, constructor error, supersession, and disposal. Staged candidate
  Clients follow the same terminal-path cleanup rule.
- Model operation authorization and root-material ownership as independent
  proofs. The operation grant may be satisfied by any policy-approved evidence;
  material recovery and export require the exact material owner's
  `WalletAuthAuthorityRef`. An adapter may reuse one interaction only after it
  proves exact authority, purpose, operation, and correlation. Export,
  registration, and recovery inputs cannot substitute for one another.
- Require `normal_signing.ready` to contain a validated active Client whose wallet,
  account, signer slot/key, threshold session, authority, signing root/version,
  epoch, participants, SigningWorker, runtime policy, and public key match the lane
  and public capability locator, plus a branded `durability_finalized` publication
  proof, current local owner-fence generation, current server revocation epoch/
  promotion receipt, branded operation authorization, and exact quota readiness.
  Require `export.ready` to contain the verified durable export context, exact
  export-grant readiness, `quota_use: none`, and a correlated one-use
  export-session reference. Runtime handle/publication, normal-signing lane/grant,
  nonce, recovery journal/result, and quota fields are `never`. Its post-effect
  resolution validates lifecycle, export-session, and root-owner correlation
  independently of active runtime.
  Resolve normal-signing action precedence explicitly: parse the revocation outbox
  first, and only `revocation_outbox.absent` may proceed. Parse and reconcile an
  exact journal next from its persisted locator/authority/source binding; a valid
  pending journal yields `recovery_required` with its exact action before generic
  authority selection, operation grant, or quota resolution. Journal binding,
  re-enrollment, conflict, corruption, and persistence failures yield their exact
  reconciliation/blocked state. Only after proving no outbox or journal pending
  does generic authority ambiguity exit before lane construction. Then missing
  operation authorization or replenishable quota produce
  `authorization_required` before fresh material access;
  an absent/disposed runtime plus a valid sealed active-Client reference produces
  Foundation A `rehydrate_active_session`; if that reference is absent, an
  `acquisition_ready` or `sealed_recovery_available` root-material observation
  produces `recovery_required`; `unlock_required`
  produces `authorization_required` with an exact material-unlock requirement;
  unavailable material, missing locator, schema corruption, exact conflict,
  binding mismatch, or terminal quota failure is terminal `blocked` with its
  typed reason. Pre-mutation storage unavailability is
  `blocked({ retryability: 'retryable', reason: 'persistence_unavailable' })` and
  performs no effect. Persistence CAS/read-back failure after a remote/local
  commit stays in its exact partial-commit journal branch.
- Treat a persisted Wallet Session only as a transport fact. An exact public
  locator plus sealed/fresh acquisition state or a pending commit journal with an
  absent/disposed/unobservable Client maps to `recovery_required` or a typed
  blocked state. An active Client with `promotion_pending` or `durability_pending` also remains
  `recovery_required`. A status-read failure cannot fall back to `ready`, and
  publishing a persisted record as runtime identity is forbidden. Only
  `committed_ready` publication, exact active-runtime observation, continuity
  validation, authorization, and quota readiness can establish normal-signing
  readiness.
- Keep preparation branches data-only. They carry verified requirements,
  correlation digests, and exact references; they contain no effect callbacks.
  Lifecycle/action/result unions and operation payloads cannot carry optional
  factor-specific reconnect, restore, or recovery hooks. Inject effect ports at
  execution assembly and require a data-only action reference to select them.
  Execute every Near and EVM-family signing operation in this order: pure
  selection/resolution/challenge planning, user approval and evidence completion,
  authorized prerequisite recovery (including Near nonce recovery when required),
  material acquisition, candidate/session staging, and applicable external
  promotion/local activation, retention-policy-required durability finalization,
  exact post-effect re-resolution, atomic operation claim and all
  descriptor-applicable debits, cryptographic execution, then finalization.
  Challenge creation, resend, and code collection remain ephemeral interactions
  inside the approval/evidence-completion stage and may precede prerequisite
  recovery. The adapter may receive a boundary-scoped immutable credential/ref
  for that challenge protocol and has no material, recovery-persistence,
  material-recovery transport reauthentication/mutation, worker-material,
  runtime, nonce, claim, grant, or quota mutation port. User
  cancellation during this stage leaves every one of those domains unchanged.
  A cancelled recovery disposes its staged candidate and leaves the active runtime
  unchanged.
- Model `cancelled` in the outer operation-executor result, outside the exhaustive
  recovery-result union. Before any consuming call, cancellation uses one CAS to
  clear the journal and, for `sealed_source`, unreserve the source;
  `fresh_acquisition` has no sealed source transition. After a consuming admission
  or material acquisition may have started, cancellation is accepted only when an
  owner-queue CAS advances the current pre-promotion state to
  `pre_promotion_cleanup_pending` with its exact cancellation correlation. That
  state maps to `recovery_required(cleanup_pending)` while the executor reconciles
  every exact server result, zeroizes worker-owned state, then uses one CAS to
  persist the stage-specific terminal admission/acquisition result, apply any
  returned monotonic policy, restore/remove the sealed source or record the
  fresh-acquisition terminal receipt, and clear the journal. It leaves no
  quarantined source without a journal owner. Only successful cleanup returns
  outer `cancelled`; failure remains `pre_promotion_cleanup_pending`. If
  `promotion_prepared` wins the CAS, cancellation is rejected and every later
  outcome remains an explicit non-cancellable partial-commit/finalization result
  until convergence.
- Keep a recovered Client staged through lifecycle continuity checks. Cancellation
  is allowed until the owner-queue CAS enters `promotion_prepared`; that transition
  is the non-cancellable cutoff. Persist `promotion_prepared` with the exact
  recovery/idempotency correlation before promotion. Server promotion uses compare-and-swap, is queryable by that
  correlation, and returns an exact promotion receipt.
  The browser then atomically swaps its active-runtime registry entry and disposes
  the superseded active handle. These are two sequential owner-local commits;
  the model claims no distributed atomicity. If server promotion succeeds and
  the local swap fails, return `promotion_committed_activation_pending` with the
  receipt, exact journal ref, and journal resume action; consume no grant/quota
  and resume or reconstruct the candidate through the runtime owner. When
  session-retained recovery requires a
  durable seal, successful local activation first returns
  `activation_committed_seal_pending` with the exact promotion receipt, journal
  ref, public activation facts, material-recovery source digest, and journal
  resume action. Runtime, candidate, and replacement fields are `never`.
  The runtime owner's private lookup is an exhaustive
  `resident | reconstruction_required` union. `resident` requires its opaque
  candidate or reseal-source ref; `reconstruction_required` makes those refs
  `never`. This private optimization never changes the public journal/result
  branch. Once the worker produces a
  candidate seal, advance to `seal_persistence_pending`, which
  requires its exact candidate digest/revision. Successful persistence advances
  to `seal_committed_readback_pending`, which requires the committed
  seal identity. Volatile retention uses its two explicit pending states.
  Resume each branch from journal and server-canonical state without repeating
  server promotion; consume no grant/quota before required durability
  finalization.
  Exact post-effect re-resolution follows successful local activation and the
  retention-policy-required finalization. A binding change returns a branded
  replacement lane and invalidates the old preparation before any claim. Failed,
  cancelled, superseded, abandoned, and unpromoted candidates are disposed.
  Candidate promotion uses the runtime-recovery singleflight scope defined below.
- Correlate every Near recovery/activation result to the original capability
  locator, discriminated material-recovery source, authority ref, and recovery
  digest. Exact post-effect resolution accepts only that correlated result and current runtime
  observation. The result union is exhaustive across `activated`,
  `replacement_lane_required`, `recovery_material_acquisition_pending`,
  `material_acquisition_committed_promotion_pending`,
  `pre_promotion_cleanup_pending`, `promotion_prepared`,
  `promotion_committed_activation_pending`,
  `activation_committed_seal_pending`,
  `seal_persistence_pending`,
  `seal_committed_readback_pending`,
  `volatile_retention_persistence_pending`,
  `volatile_retention_committed_readback_pending`, `authorization_required`,
  `retryable_failure`, and `blocked`. Branch-specific fields are required and
  invalid combinations are `never`. `activated` is constructible only after
  `committed_ready` publication and carries its `durability_finalized` proof.
  Raw Router and worker error strings are parsed once at their adapters and never
  enter capability core.
- Restrict recovery-result `authorization_required` to the pre-material,
  pre-journal state;
  pending-factor, root, candidate, active-runtime, and reseal-source refs are
  `never` in that branch. If recovery transport/evidence expires or material must
  be reacquired after acquisition begins, dispose or zeroize worker-owned state,
  retain/advance the non-secret journal, and return `recovery_required` with the
  exact `session_transport_reauthentication` or `material_unlock` prerequisite.
  Parent operation grant/quota expiry has no effect on this convergence path.
  After promotion, keep the corresponding promotion/activation/retention pending
  branch and attach the same exact recovery prerequisite; the partial commit never collapses to pre-material
  `authorization_required`. A pending branch carrying that prerequisite makes all
  process-local secret refs `never`. No secret-bearing attempt remains alive
  across human interaction.
- Construct `retryable_failure` only before journal creation or after exact
  reconciliation and atomic journal cleanup. Once a valid journal exists, every
  transport, Router, worker, persistence, reload, and cancellation interruption
  returns that exact pending journal branch with its resume/query action. Generic
  failure branches cannot hide durable partial state.
- Map that result union exhaustively back into preparation. `activated` triggers
  exact post-effect resolution. Each pre-promotion pending branch becomes
  `recovery_required` with only its exact journal query/resume action; it cannot
  become a generic retryable failure. `promotion_committed_activation_pending`
  becomes `recovery_required` with the exact promotion receipt and journal resume
  action and resumes local activation without repeating root unlock or server
  promotion; `activation_committed_seal_pending` becomes `recovery_required`
  with only its journal resume action and resumes without repeating activation.
  Seal-persistence/read-back and volatile-retention pending branches each
  become `recovery_required` with only their exact journal finalization action;
  `replacement_lane_required` returns only its branded replacement lane and
  invalidates the old preparation. Missing, expired, or exhausted sealed recovery
  maps to an exact material-unlock requirement when fresh acquisition is allowed.
  Expired session transport maps to
  `session_transport_reauthentication`; identity, authority, locator, key, root,
  public-key, or policy mismatch maps to `blocked`. Retryable worker, Router, and
  pre-commit transport failures remain correlated recovery actions. Pre-mutation
  persistence unavailability maps to retryable `blocked`; post-commit persistence
  failure maps to the exact retention-finalization-pending branch. No outcome
  becomes a planner boolean.
- For both MPC capabilities, preserve independently branded operation and quota
  readiness across recovery only when exact post-effect revalidation proves the
  same authority, threshold session, signing root, key, runtime/material binding,
  participants, and policy. Any binding change returns a branded replacement lane
  and invalidates the old preparation. Recovery alone never implies grant renewal,
  quota replenishment, or budget readmission; delete the transitional blanket
  readmission path.
- Keep grant/quota renewal separate from runtime replacement. Exhaustion refresh
  may replace operation authorization or replenish the wallet quota while
  retaining the active Client, threshold session, signing key, authority,
  participants, root/version, epoch, runtime policy, and public key.
- Keep normal Ed25519 transaction, delegate-action, NEP-413, and any Near-owned
  signer-proof signing outside the Yao Deriver path. They consume the active
  Client and SigningWorker through normal FROST signing with zero Deriver calls.
  Yao ceremonies remain registration, same-root recovery, server-share refresh,
  activation, add-signer, and explicit export.
- Route Near transaction, delegate-action, and NEP-413 operations through the same
  generic preparation/action loop, effect order, exact post-effect re-resolution,
  and runtime-owner material-use queue. Apply the same rule to signer proof if the
  Near capability becomes its owner. No operation may require a pre-existing
  active Client through an auth-method-specific shortcut.
- Publish a sealed recovery record after promotion only when it exactly matches the
  promoted authority, root, threshold session, key, and runtime binding. The
  worker first produces a candidate seal plus its digest/revision;
  the persistence port advances to `seal_persistence_pending`. One
  IndexedDB compare-and-swap transaction verifies the journal and recovery-source
  digest. For `sealed_source`, it also verifies the source revision, publishes the
  replacement as eligible, and retires the source record. For
  `fresh_acquisition`, it publishes the first eligible sealed record and performs
  no source retirement. The transaction advances to
  `seal_committed_readback_pending`. Exact read-back follows
  that transaction. A second journal CAS clears the completed journal, after
  which the runtime owner may construct sealed-retention `durability_finalized`
  and acknowledge the worker to zeroize its retained reseal source and candidate
  ciphertext. A mismatch or persistence failure leaves the exact pending journal
  branch and keeps every source/candidate/committed seal identity distinct.
- Finalize volatile retention explicitly. After local activation, advance to
  `volatile_retention_persistence_pending`; one persistence CAS verifies the
  recovery-source digest, atomically retires/removes a sealed source, performs no
  sealed-record transition for fresh acquisition, and advances to
  `volatile_retention_committed_readback_pending`. Exact read-back and a second
  CAS prove the sealed source absent and clear the journal before the runtime owner constructs volatile-retention
  `durability_finalized`. A crash at either step remains journal-pending and
  cannot publish readiness.
- The Near material-adapter persistence port owns both finalization effects. A
  session-retained attempt cannot report completion while seal persistence
  or read-back is pending or failed.
- Make page hide dispose the live Client while retaining the public capability
  and zeroize worker secrets while retaining the public capability locator, any
  ordinarily eligible sealed recovery reference, and any incomplete non-secret
  journal. A `sealed_source` journal retains its quarantined source record only
  while that record still exists. After sealed or volatile finalization has
  retired the source, the pending journal retains the exact former source
  identity/revision and replacement-seal or volatile-retirement receipt, with no
  live quarantined source. Reload reconciliation
  queries the server-canonical recovery ID, reacquires exact material when
  process-local handles were lost, and resumes activation or retention
  finalization without a second allowance decrement, promotion, or operation
  claim. Explicit wallet lock or logout immediately disposes/zeroizes local
  runtime and worker state and advances the process-local fence. One IndexedDB
  transaction increments the durable fence, marks locator/seal/journal state
  ineligible, and writes a separate non-secret `revocation_pending` outbox. Server reconciliation then
  idempotently advances the capability/authority revocation epoch or installs its
  tombstone before resolving every correlated in-flight recovery. Network failure
  leaves the wallet locally locked with no live secret. Acknowledgement clears
  durable records/outbox only after the server fence and terminal recovery states
  are durable.
- Implement the SPEC's auth-agnostic EVM ECDSA preparation domain. Transaction
  lanes carry a transaction target plus `ExactEcdsaMaterialIdentity`; the
  material owner composes `WalletAuthAuthorityRef` with Phase 5's final
  canonical `EcdsaRoleLocalMaterialBinding` and carries no raw factor identity
  or provisioning-only key-slot ID.
- Canonicalize exact ECDSA source material and recovery facts before EVM-family
  projection. Project only stable material-owner identity, exact authority,
  lifecycle, and recovery facts to requested chain targets; perform target-lane
  selection afterward. A target-local unusable observation cannot suppress a
  valid canonical shared-material projection. Target-specific operation grants,
  envelopes, authorization results, operation claims, and quota uses never
  project. Delete the legacy projection path that copies `signingGrantId` or
  other operation authorization across EVM and Tempo targets.
- Build lane selection from a branded EVM transaction request containing the
  parsed target and exact operation envelope. Its builder proves target/intent
  digests and operation fingerprint before the selector sees it.
- Add a separate EVM ECDSA export preparation/action path. Its branch-specific
  builder accepts only an `evm.export_key` envelope, exact material-owner identity,
  and `quota_use: none`; the transaction builder rejects export and the export
  builder rejects transaction. `export.ready` requires exact grant readiness and a
  correlated staged export-session ref; transaction target, nonce, signing lane,
  transaction material-readiness, and quota fields are `never`. Sequence export
  as exact operation authorization, material unlock/session staging inside the
  ECDSA material adapter, exact post-effect re-resolution of export correlation,
  atomic grant-only claim, export, then finalization/zeroization. The export path
  reuses no transaction authorization and serializes with other cryptographic uses
  of the same exact material owner.
- Add one exact capability resolver and one typed material-recovery port for the
  EVM ECDSA capability. Preparation returns only `ready`,
  `recovery_required`, `authorization_required`, or `blocked`.
- Make authority and persistence resolution fail explicitly. Multiple eligible
  authority refs under `any_authority` return `authority_ambiguous`; multiple
  durable rows matching one exact selected lane or recovery ref return
  `exact_record_conflict`; a zero match returns `missing`; malformed data returns
  `corrupt`; storage failure returns `persistence_unavailable`. Exact conflicts
  fail closed and never select by newest timestamp, source priority, or array
  order. The resolver leaves conflicting current-schema rows untouched; a
  separate explicit maintenance action owns conflict cleanup. Boundary migration
  may reject and clear obsolete-schema rows before they enter core parsing.
- Resolve EVM transaction preparation in this order: active authority, authorized
  operation-bound active grant, exact spendable wallet quota binding, then exact material.
  `recovery_required` carries branded operation and quota readiness so no signer
  material is unsealed before policy admission.
  Claim grant and quota use jointly only after preparation reaches `ready` and
  immediately before signing; failed material recovery consumes neither.
- Make `recovery_required` require a verified exact recovery reference. A
  `restorable` or `deferred` inventory label alone is insufficient authority to
  restore material.
- Make prerequisite action kind explicit:
  `operation_grant | quota_replenishment | material_unlock |
  threshold_session_replacement | session_transport_reauthentication`.
  Session transport reauthentication carries the exact authority, session
  audience/device binding, recovery ID, and recovery digest and returns only a
  fresh opaque transport reference. Operation grant policy may accept evidence
  from a different authority or factor; material unlock and transport
  reauthentication remain bound to the exact requirement that requested them.
- Correlate prerequisite action results with their requirement kind. Successful
  material unlock returns an upgraded recovery attempt bound to the original
  recovery ID/digest; successful threshold replacement returns a branded lane
  bound to its reauthorization anchor; successful session transport
  reauthentication returns an opaque transport ref bound to the exact recovery
  requirement and cannot satisfy operation authorization or material ownership.
- A threshold-session replacement returns a replacement lane through a
  reauthorization anchor. Never rerun resolution against the obsolete exact
  lane after its threshold-session identity changes.
- Use three independent concurrency scopes. Authorization actions are
  singleflight by operation fingerprint plus exact requirement and return
  `no_progress_after_action` when that requirement repeats. Runtime
  recovery/activation is singleflight by stable material/runtime owner plus exact
  recovery identity, authority ref, and discriminated recovery-source digest; a
  replaceable `thresholdSessionId` alone is never the key. Two attempts join only
  when all stable owner and recovery facts match. Authority re-enrollment, seal
  replacement/version change, or recovery-digest change creates a distinct
  flight. After approval/evidence, the flight leader acquires the stable
  runtime/root-owner material-use queue before journal creation, sealed-source
  reservation, exact recovery admission, material acquisition, or any owner
  mutation. It captures and revalidates the owner-fence generation before every
  consuming server or publication boundary and stops on mismatch while retaining
  the exact journal/outbox reconciliation state. Only the queue callback can
  construct the branded, non-serializable `MaterialUseLease<Owner>` union:
  `recovery_held | parent_held | transferred | released`. Both held branches
  require the exact owner key, underlying lease ID, acquisition generation,
  observed owner fence, and an opaque holder-specific token. Recovery coordination
  accepts only `RecoveryHeldMaterialUseLease<Owner>`; parent operation
  preparation, export, claim, and signing accept only
  `ParentHeldMaterialUseLease<Owner>`. A queue-owned runtime registry stores the
  sole current holder token for each underlying lease ID and validates it at every
  material, claim, and signing boundary. Transfer atomically invalidates the
  recovery holder token, records a transferred source receipt, and returns exactly
  one parent-held destination with a fresh token. Release invalidates either held
  token and records only `released`. TypeScript aliases to an old held value may
  still exist, so they fail the runtime token check and can perform no effect. The
  leader holds the queue through
  root consumption, candidate promotion/local activation, required retention
  finalization, and exact
  post-effect re-resolution. Distinct recovery flights for the same owner
  serialize even when their digests differ; identical flights join once. The
  recovery leader either moves its recovery-held lease exactly once into a
  parent-held lease for claim/signing or releases it. A repeated move with the old
  holder token fails closed. After release, the parent
  must reacquire the queue, receive a new parent-held lease, and rerun exact
  runtime/publication generation and durability-proof resolution immediately
  before claim. Cached generations or a ready proof observed outside a currently
  held lease can never authorize a claim. The lease is `never` in operation
  requests, durable claims, persistence, diagnostics, and logs.
  Cryptographic material use is queued by exact material/runtime owner, so EVM
  and Tempo projections and export operations sharing one owner share one queue.
  Never hold this queue during human interaction. Normal signing acquires a
  parent-held lease after
  exact post-effect re-resolution, revalidates the exact generation/proof inside
  the lease, and holds it around atomic claim and signing.
  Export acquires a parent-held lease after human interaction and initial
  authorization resolution,
  before material unlock/session staging, and holds it through exact re-resolution,
  grant-only claim, export, and zeroization. OTP resend/retry inside one auth-factor
  adapter interaction does not count as a repeated core authorization action.
- Encode generic material-use state: session-retained material may recover;
  pending single-use material is ready only while hot and bound to the same
  operation fingerprint; cold pending and consumed single-use material require
  threshold-session replacement and cannot enter recovery.
- Normalize Passkey, Email OTP, and future implementations behind auth-factor and
  capability-local material adapters at capability assembly. Auth-factor adapters
  own assertion/challenge protocols and verified evidence; Near and ECDSA material
  adapters own inspection, restore/acquisition, constructor invocation, and
  immediate secret consumption.
- Delete stale cross-curve companion envelopes at persistence boundaries. ECDSA
  recovery references and Ed25519 sealed root-recovery references remain
  disjoint; one capability recovery cannot enumerate, restore, or commit its
  companion as a hidden side effect. Replace the tactical
  `ecdsa_and_ed25519_yao_recovery` unlock envelope with capability-specific
  material requests. One verified factor interaction may satisfy two exact
  requirements through the auth-factor adapter, while each material adapter
  receives and commits only its own request.
- Replace method-specific signing step-up plans and retry branches with the
  SPEC's generic authorization requirements. Operation-grant evidence uses a
  branded exact operation requirement whose envelope matches the
  `grant_evidence_required` branch of `CapabilityGrantPlan`; root/material
  adapters return requirements and never construct authorization policy.
- Delete `PasskeyEcdsaCommittedLane`, `EmailOtpEcdsaCommittedLane`, their
  ready aliases, method-specific builders, `EmailOtpEcdsaCommittedLaneStateError`,
  `EvmFamilyEcdsaAuthMethod`, Passkey source-priority and material-selection
  types, the Email OTP ECDSA authority resolver, method-specific reauth and
  restore assembly ports, old signing step-up types/files, and the passkey-only
  restore branch once the exact resolver is live. Delete
  `reauth_required/missing_hot_material` as an implicit restore signal; remove
  obsolete fixtures and guards in the same change.
- Delete `NearPasskeyEd25519ReconnectHook`,
  `NearEmailOtpEd25519ReconnectHook`,
  `NearEd25519PasskeyReconnect`, `NearEd25519EmailOtpReconnect`,
  `recoverPasskeyEd25519YaoCapabilityForSigning`,
  `NearEd25519YaoCapabilitySource`, `nearEd25519YaoCapabilitySource`,
  `emailOtpNearEd25519LaneRequiresFreshAuth`,
  `RouterAbEd25519YaoClientRootFactorV1`,
  `RouterAbEd25519YaoBudgetRefreshAuthorizationV1`, factor-labelled Yao
  root/export transport unions, and passkey/Email OTP recovery/refresh assembly
  ports after the generic root and runtime ports are live. Keep factor protocol
  types inside their adapters. Replace `NearEd25519YaoSigningCapability` with the
  branded committed capability shape when its legacy session/grant/budget fields
  are removed; retain no broad source aggregate.
- Migrate the behavior and delete the landed sealed-refresh tactical surface:
  `EmailOtpEd25519YaoSilentRecoveryResultV1`,
  `EmailOtpEd25519YaoSilentRecoveryPorts`,
  `EmailOtpEd25519YaoBudgetRecoveryResult`,
  `PreparedEmailOtpEd25519YaoRecoveryV1`,
  `PreparedColdEmailOtpEd25519YaoRecoveryV1`,
  `recoverEmailOtpEd25519YaoFromSealedSessionV1`,
  `recoverEmailOtpEd25519CapabilityForSigningV1`,
  `recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning`,
  `requestRehydrateEmailOtpEd25519YaoFactor`, the
  `rehydrateEmailOtpEd25519YaoFactor` worker operation, current Email-OTP-specific
  Yao root purpose/scope/handle shapes, and method-specific Browser recovery
  singleflight maps. Replace them with the generic inspection, recovery action,
  material adapter, and worker-private handle lifecycle; retain no alias.
- Migrate the landed refresh-safe export behavior and delete its auth-specific
  coordinator surface: `Ed25519YaoExportFlowDeps.recoverPasskeyCapability`, the
  nested `emailOtp.resolveExportContext` callback bag,
  `exportEd25519YaoKeyWithFreshPasskey`,
  `exportEd25519YaoKeyWithFreshEmailOtp`,
  `ExactPasskeyEd25519SigningLaneIdentity`,
  `ExactEmailOtpEd25519SigningLaneIdentity`,
  `EmailOtpEd25519YaoExportSubjectV1`,
  `EmailOtpEd25519YaoExportContextV1`,
  `EmailOtpEd25519YaoExportContextPorts`,
  `recoverExactPasskeyEd25519YaoCapabilityForExport`,
  `resolveEmailOtpEd25519YaoExportContext`, and the matching Browser/assembly port
  aliases. Remove the `laneIdentity.auth.kind` export dispatch from
  `exportKeypairOperation.ts`. Replace it with the generic verified export-context
  resolver and exact export material-acquisition action. Preserve the regression
  invariant through exact-authority adapter fixtures; retain no method-labelled
  lane or shared recovery callback.
- Move `EmailOtpEd25519YaoActiveCapabilityDescriptorV1` into the generic Near
  lifecycle/export-context boundary and destructively replace the Email OTP worker
  export payload. Its final request requires the branded lifecycle ref, exact
  authority/material owner, export operation/admission correlation, runtime-policy
  binding, participant set, SigningWorker, and registered public key. Remove
  `signingGrantId`, raw provider subject, and bearer JWT from that payload. The
  Email OTP adapter may keep a responsibility-local OTP/export worker command;
  factor-specific types do not escape that adapter.
- Delete the factor-labelled Near assembly ports and Browser shortcuts:
  `refreshPasskeyEd25519CapabilityForSigning`,
  `requestEmailOtpEd25519SigningChallenge`,
  `recoverEmailOtpEd25519CapabilityForSigning`,
  `resolveAccountAuthMethodForSigning`,
  `ensureNearEd25519YaoCapabilityForSigning`,
  `resolveActiveNearEd25519YaoSigningLane`,
  `hasPasskeyAuthenticatorForNearEd25519Subject`,
  `recoverNearEd25519YaoCapabilityForSigning`,
  `recoverExactPasskeyEd25519YaoCapabilityForSigning`,
  `recoverExactEmailOtpEd25519YaoCapabilitySilentlyForSigning`,
  `recoverExactEd25519YaoCapability`,
  `hasNearEd25519YaoPublicReference`,
  `recoverNearEd25519YaoCapabilityFromSealedSession`,
  `recoverNearEd25519YaoCapabilityWithPasskey`,
  `readNearEd25519RuntimeRecordForSelectedLane`,
  `publishNearEd25519RuntimeIdentityForRecord`, the method-specific Browser
  recovery maps, `resolveNearTransactionPlannerReadiness`, the control-flow use
  of `getWarmThresholdEd25519SessionStatusForSession`,
  `resolveThresholdEd25519SessionIdForNearAccount`, the broad
  `resolveActiveEd25519YaoSigningCapability` port,
  `withThresholdEd25519CommitQueue`, `ThresholdEd25519CommitQueueByKey`,
  `resolveThresholdEd25519CommitQueueKey`, and the `forceFreshAuth` and
  `retryingFreshAuth` planner booleans. Delete all
  `CreateSigningEnginePortsArgs` aliases/wiring for those ports. Generic
  capability/runtime resolution accepts exact authority and runtime identity and
  contains no auth-method filter. Adapt valid fixtures in
  `nearSigning.typecheck.ts` to reject callback-bearing sources and factor-hook
  combinations, then delete its obsolete positive capability-source fixtures.
- Destructively migrate durable Ed25519 restore fields that currently carry
  `walletSessionJwt`, `providerSubjectId`, `emailHashHex`,
  `registrationAuthorityId`, `signingGrantId`, and ambiguous
  `remainingUses`/`expiresAtMs`. The current schema contains only exact authority,
  recovery digest, ciphertext/seal identity, retention, and the branded recovery
  policy selected in Phase 18.
- Delete `signingGrantId` from the current export subject/context and worker
  request when the generic context lands. The exact `near.export_key` grant exists
  only in operation authorization/claim state; normal-signing grant exhaustion is
  never an export-context lookup key.
- Replace factor-labelled diagnostics collections with exact lane, material,
  authority-ref, and recovery summaries. Diagnostics never select a branch.
- Register correlated operation kinds for `near.sign_transaction`,
  `near.sign_delegate_action`, `near.sign_nep413_message`, `near.export_key`,
  `evm.sign_transaction`, `evm.export_key`, and
  `mpc.produce_signer_proof`. Each operation has its own envelope, digest,
  result, policy descriptor, and invalid-pair fixtures.
- Treat `near.export_key` as one exact, one-use Yao export operation. Passkey,
  Email OTP, and future factors satisfy its policy through registered evidence
  and the Near material adapter; factor kind never changes the operation identity
  or export lifecycle type. Preserve and migrate the landed Email OTP export
  implementation, including page-refresh context resolution, server-canonical
  lifecycle lookup, one-use WASM ownership, worker-side exact continuity checks,
  and registered-public-key verification. Replace factor-kind pairing fixtures
  with exact authority-ref, lifecycle-ref, root-purpose, operation-envelope, and
  correlation fixtures.
  Update YAOS's stale Phase 9F follow-up note before Phase 19 starts. The companion
  SPEC must state explicitly whether Email OTP evidence is accepted by the
  default `near.export_key` policy or enabled through tenant policy.
- Add `produceMpcSignerProof` to the selected owning MPC capability as the
  implementation of the closed `mpc.produce_signer_proof` operation; connect it
  to the Phase 12 fail-closed `mpc_signer_proof` evaluator.
- Validate capability grant policies against registered grant evidence kinds and
  capability operation descriptors.
- Re-home the remaining threshold/wallet helpers from `core/authService/**`
  into these modules, guided by the Phase 3 split inventory.

Check:

- Vault-only compilation excludes MPC modules.
- Ed25519, ECDSA, and vault operation lanes are not interchangeable.
- Passkey, Email OTP, and a synthetic third factor drive the same Near Yao
  preparation transitions without changes to selection, recovery, refresh,
  committed-runtime construction, or normal signing.
- Post-registration and post-wallet-unlock success resolve each warmed capability
  to `use_live_runtime` from canonical inventory. Post-page-refresh starts with
  no volatile runtime and resolves only to `rehydrate_active_session`,
  `reauthorize_public_anchor`, or a typed `blocked` branch. Table-driven tests
  cover both MPC capabilities and mixed-wallet branch combinations.
- When exact active-session material exists, both MPC capabilities follow
  `rehydrate_active_session -> rehydrate exact -> resolve exact -> ready`.
  Genuine Near root recovery follows
  `recovery_required -> recover exact -> resolve exact -> ready`; direct EVM and
  shared Tempo material-owner cases have targeted coverage.
- A valid `NearEd25519YaoSealedActiveClientRef` plus an absent/disposed runtime
  rehydrates the activated Client locally, authenticates its full public
  binding, publishes it, and reaches `ready` with zero Deriver A/B calls.
- A valid exact locator plus sealed root-recovery ref and an absent/disposed
  runtime resolves to `recovery_required` when the Near material adapter reports
  `sealed_recovery_available`. Tests cover locator-only, successful refresh
  activation, fresh `acquisition_ready`, unlock-required, unavailable, missing, corrupt, expired,
  substituted, duplicate-exact, unavailable-storage, and authority re-enrollment
  states. Only `committed_ready` publication with a validated active Client and
  `durability_finalized` proof can construct `normal_signing.ready`; only a
  correlated one-use export session can construct `export.ready`.
- Page-refresh export tests start with no active Client and exhausted
  normal-signing grant/quota/recovery allowance. An exact locator plus
  server-verified lifecycle still resolves the export context, while the export
  operation requires its own fresh `near.export_key` grant. Context resolution
  performs zero Passkey recovery, Email OTP signable-capability recovery,
  promotion, activation, reseal, runtime publication, signing claim, or quota
  effects.
- Cold-recovery export tests begin with a selected observation carrying stale
  rotating authorization/session values. Recovery of the same exact authority,
  signer, threshold session, lifecycle, and policy returns the current canonical
  context; export uses only its current grant, session transport, and export
  session and succeeds without an intervening transaction. Signer, lifecycle,
  or authority drift fails before export. Whole-lane equality and reuse of the
  selected observation's grant or bearer credential are rejected by type fixtures
  and port-spy assertions.
- Server and worker continuity tests substitute wallet, account, signer slot/key,
  threshold session, lifecycle ID, root-share epoch, signer set, SigningWorker,
  runtime policy, participants, active-capability binding, state epoch, and
  registered public key one field at a time. Every mismatch fails closed before
  root material is exported. Missing lifecycle identity is rejected by static
  fixtures and boundary parsers.
- A restored login/session or persisted Wallet Session never chooses a capability
  action. With no exact locator, capability discovery returns absent; a request
  that requires an already-provisioned capability returns
  `blocked(missing_locator)`. An exact locator plus a valid sealed active-Client
  ref and no active Client yields `rehydrate_active_session`. After exact local
  import and publication it may become `ready`. An exact locator plus
  `sealed_recovery_available` or `acquisition_ready` and no active Client yields
  `recovery_required`; an exact active Client plus continuity, grant, and quota
  readiness plus `committed_ready` publication yields `ready`. Unavailable or
  pending runtime publication cannot become ready.
  Cancellation after data-only material inspection invokes zero server seal
  removal, fresh acquisition, warm bootstrap, worker rehydration, root binding,
  Client construction, activation, reseal, persistence, nonce recovery, claim, or
  quota effects.
- Sealed-recovery lifecycle tests cover exact rehydrate-digest substitution,
  local/server monotonic recovery policy, pending-factor and bound-root cleanup,
  candidate cleanup, worker-retained reseal-source cleanup, atomic replacement
  record read-back, stale-record ineligibility, and every terminal zeroization
  path. Reseal generation failure returns
  `activation_committed_seal_pending`; replacement CAS failure returns
  `seal_persistence_pending`; committed-record read-back failure returns
  `seal_committed_readback_pending`. None performs a signing claim.
- Commit-journal tests cover crash/worker termination before material acquisition,
  after sealed unseal or fresh acquisition, before promotion, between server
  promotion and local activation, after activation, during seal generation, and
  between seal persistence and read-back. Server-canonical reconciliation resumes
  by the same recovery ID, reacquires material when required, rejects stale-tab/
  source-revision CAS, and never repeats promotion or a signing claim.
  Admission reconstruction tests cover `not_started`, `committed`, and `terminal`
  from the initial journal branch without assuming a receipt exists.
- Cancellation tests race the `pre_promotion_cleanup_pending` transition against
  `promotion_prepared`, prove exactly one CAS wins, return outer `cancelled` only
  after durable cleanup, and keep cleanup pending across CAS failure/reload.
- Closed result fixtures distinguish transport reauthentication, material unlock,
  retryable Router/worker/storage failure, and terminal identity/authority/key/
  root/policy mismatch. `@ts-expect-error` fixtures reject direct literals, broad
  spreads, missing branch fields, callback-bearing actions, old-lane reuse after
  replacement, pending publication passed to ready/claim builders, and
  recovery/reason/sealed-source/fresh-source/seal-digest/receipt
  combinations from different branches. `authorization_required` rejects every pending-factor,
  root, candidate, runtime, and reseal-source field.
- Session-retained material can recover through its capability-local material adapter. Pending
  single-use material may sign once while hot and operation-bound; cold pending
  and consumed states require fresh threshold-session authorization. Type
  fixtures reject single-use recovery descriptors.
- Stale cross-curve companion records are rejected and cleared. Tests prove both
  ECDSA-to-Ed25519 and Ed25519-to-ECDSA recovery cannot create hidden material
  side effects.
- A synthetic third-factor adapter passes both MPC preparation conformance
  suites without changes to lane selection, preparation, recovery coordination,
  or committed runtime/material construction.
- Positive cross-factor tests allow policy-approved evidence from authority B to
  authorize an operation whose exact material owner is authority A, while root or
  ECDSA material acquisition still requires A. One interaction may satisfy both
  proofs only when authority, purpose, operation, and correlation all match.
- Source guards reject `passkey` and `email_otp` control-flow literals and
  imports from factor-specific modules inside generic Near Ed25519 Yao and EVM
  ECDSA selection/preparation/export coordination code. Runtime and export-context
  resolution contain no auth-method literal or filter. Adapter conformance tests
  prove Passkey, Email OTP, and a synthetic third factor consume the same generic
  export requirement and produce the same one-use export-session result.
- Source guards reject the deleted committed-lane/resolver/step-up symbols and
  every old `signingGrantId` semantic, broad Yao capability-source aggregate,
  auth-specific reconnect hook, and auth-labelled preparation-order assertion.
  Delete `nearRefreshYaoOrdering.guard.unit.test.ts`, whose substring checks
  preserve pre-confirmation silent recovery, and
  `ed25519YaoSealedRefreshWiring.guard.unit.test.ts`, whose factor-specific source
  ordering belongs to the tactical implementation. Replace them with port-spy
  behavior tests covering the complete effect boundary, worker-private lifecycle,
  retention finalization, and post-effect canonical re-resolution. Migrate the
  still-valid continuity, monotonic-policy, and cleanup assertions from
  `emailOtpEd25519YaoBudgetRecovery.unit.test.ts` into generic adapter/runtime
  conformance tests, then delete its old grant/budget fixtures and the tactical
  sealed-recovery typecheck fixture.
- Migrate the valid page-refresh, zero-Passkey-callback, exact durable context,
  lifecycle continuity, and worker zeroization assertions from
  `emailOtpEd25519YaoExportRefresh.unit.test.ts` into generic Near export-context
  and adapter conformance tests. Replace
  `ed25519YaoExportFlow.typecheck.ts` with fixtures that reject authority/adapter
  substitution without naming Passkey or Email OTP lanes, then delete the tactical
  files.
- Migrate the valid stale-selected-grant/current-recovered-grant, current Wallet
  Session credential, no-intervening-transaction, and authenticator-drift
  assertions from `passkeyEd25519YaoExportRefresh.unit.test.ts` into the generic
  continuity/post-effect-resolution suite. The generic fixtures use exact
  `WalletAuthAuthorityRef` continuity and contain no Passkey-specific lane type or
  callback. Delete the tactical test with the factor-labelled export flow.
- `@ts-expect-error` fixtures reject transaction lanes carrying export/proof
  operations, ready states with non-hot or mismatched material, unbranded
  recovery, single-use recovery, raw factor fields on material owners, raw
  active grants in ready state, mismatched authority/material/authorization
  aggregates, uncorrelated authorization result kinds, and unbranded replacement
  lanes.
- EVM export fixtures reject transaction envelopes/targets, quota readiness,
  unverified material unlock, cross-owner substitution, and transaction
  authorization reuse. Ordering tests require exact post-unlock re-resolution and
  a grant-only claim before export, with terminal zeroization.
- Ed25519 fixtures reject `normal_signing.ready` with a missing/disposed Client,
  pending promotion/seal publication, missing/mismatched durability proof,
  mismatched capability locator or sealed recovery ref, grant/quota identity
  embedded in runtime identity, factor-specific root type in capability core,
  cross-purpose root-material handle, or transaction/delegate/NEP-413 envelope
  substitution. They reject `export.ready` with a normal runtime/lane/nonce/quota
  field, missing export-session correlation, or a signing envelope.
- Root-material inspection fixtures reject a secret handle in every branch,
  acquisition refs on sealed/unlock/unavailable branches, sealed recovery refs on
  acquisition/unlock/unavailable branches, optional authority or purpose, and
  effect callbacks inside preparation state. Acquisition fixtures reject
  registration/recovery/export correlation substitution and consumed-handle
  reuse.
- Ceremony-order tests prove Router admission failure acquires or consumes no
  root-material handle, while every terminal path after acquisition consumes or
  zeroizes the handle and any staged Client.
- Export-order tests prove exact operation authorization and admission precede
  material acquisition, exact re-resolution precedes the grant-only claim, and
  the claim precedes export. Cancellation before claim consumes no grant and
  zeroizes acquired material/session state. Registration tests prove its ceremony
  uses no capability grant or wallet signing quota.
- Page-hide/lock disposal, pre-promotion candidate disposal,
  post-promotion activation-pending recovery, activation-committed seal
  finalization, failed-candidate disposal, refresh identity preservation,
  public-locator/sealed-recovery/commit-journal/revocation-outbox/
  runtime-publication separation, and zero signing-path Deriver calls have
  targeted tests.
- Factor-neutral preparation tests enforce the complete effect order for
  transaction, delegate-action, NEP-413, and any Near-owned signer-proof
  operation. Cancellation during approval/evidence completion leaves nonce,
  runtime, grant, and quota unchanged. Same-binding recovery preserves readiness
  only after exact revalidation; binding changes produce a replacement lane.
- Recovery-result tests cover server promotion CAS receipts, atomic local registry
  swap and superseded-handle disposal, resumable
  `recovery_material_acquisition_pending`, resumable
  `material_acquisition_committed_promotion_pending`, resumable
  `pre_promotion_cleanup_pending`, resumable
  `promotion_prepared`, resumable
  `promotion_committed_activation_pending`, resumable
  `activation_committed_seal_pending`, seal persistence/read-back
  pending, volatile-retention persistence/read-back pending, replacement lanes,
  transport reauthentication, retryable versus terminal failures, no-progress
  detection, and singleflight retries. Public pending branches carry only journal
  actions; private resident/reconstruction state never changes their shape. No
  branch claims grant/quota before final exact readiness. A pending journal takes
  precedence over expired or missing operation authorization/quota, and full
  authorization/quota resolution reruns after convergence. A journal bound to one
  exact authority also reconciles when generic `any_authority` selection would
  currently be ambiguous; re-enrollment is reported by the journal's exact
  binding outcome.
- Exact resolver tests distinguish authority ambiguity, duplicate exact records,
  missing records, corrupt records, and pre-mutation persistence unavailability.
  Projection tests
  prove EVM/Tempo project only stable material-owner identity, exact authority,
  lifecycle, and recovery facts and share one material-use queue; operation
  grants, envelopes, claims, and quota uses remain target-local.
- `mpc_signer_proof` missing capability, inactive capability, principal
  mismatch, target capability/operation mismatch, unsupported operation, and
  success have targeted tests.

## Phase 20: MPC Route Policy Migration

Status: planning. Old Phase 6 remainder.

Prerequisite: the companion SPEC must adopt Phase 10/12's generic authenticated
claim lookup, fenced execution/reconciliation lifecycle, and terminal result
contract. It must exclude grant, quota, threshold-session, and runtime/material
IDs transitively from the canonical operation fingerprint and uniqueness key, then
define the MPC quota, binding, cryptographic phase, and delivery specializations
below. Phase 20 cannot start while the SPEC retains an indefinite
`operation_in_progress` contract.

Do:

- Replace `threshold_session` route planes with `capability_grant` on every MPC
  capability-operation route: normal signing, the selected signer-proof owner,
  and explicit export.
- Parse threshold-session claims only inside the discriminated MPC operation
  branches that require them. Export branches carry no threshold-session or
  quota field.
- Specialize Phase 12's
  `CapabilityOperationClaimLookup<MpcOperationDescriptor>` with the MPC semantic
  envelope and fingerprint. Add no MPC-only lookup lifecycle. It runs before
  fresh grant/quota preparation, runtime recovery, user approval, or acquisition
  of a material-use lease. `completed` returns the protected terminal result;
  `claimed_active` joins or polls the current execution; `claimed_stale` enters
  MPC claim reconciliation. Only `absent` may enter new-claim preparation.
- Implement builders for branded authorized and claimed Near Ed25519 and EVM
  ECDSA operations on the lookup's `absent` branch. New authorization accepts only an active grant whose tenant,
  principal, capability, exact operation kind, and operation digests match the
  typed envelope. Claiming occurs after preparation reaches `ready` and always
  requires an operation-fingerprint-matched grant use. The `quota_use: required`
  builder also requires the exact wallet quota binding; the `quota_use: none`
  builder makes every quota field `never`. Before sending a Near normal-signing
  claim request, a client-side `ClaimableNearOperation` builder requires
  a current `ParentHeldMaterialUseLease<Owner>`, `committed_ready` matching that
  lease's exact owner/acquisition/fence generations, the exact server revocation
  epoch/promotion receipt, and its `durability_finalized` proof;
  promotion/durability-pending branches are
  unconstructable inputs. It emits only the semantic operation envelope,
  fingerprint, grant, and applicable quota data. Browser handles, journal refs,
  every `MaterialUseLease` branch, and local durability brands are `never` in the
  request and durable `MpcOperationClaim`; Phase 10's server-owned
  `CapabilityOperationExecutionLease<MpcOperationDescriptor>` is a distinct
  durable type. Server-side lifecycle
  enforcement loads the authenticated current promotion/capability receipt and
  revocation epoch by exact capability binding; it never trusts a client assertion
  about local IndexedDB or runtime state.
- Enforce the Phase 19 effect order at route and client boundaries. Runtime or
  material recovery and any retention-policy-required durability finalization
  complete before exact lane re-resolution; the applicable new claim begins only
  after that re-resolution returns `ready`. Existing-claim lookup precedes this
  sequence and has no mutation port. A cancelled approval, failed
  recovery/finalization, failed re-resolution, or replacement lane consumes no
  grant or applicable quota. Every post-claim failure is finalized against the
  existing operation claim.
- Implement claim and service adapters for Phase 18's SPEC-owned
  `MpcWalletSigningQuota` domain. It has one branded quota ID,
  tenant/wallet/policy scope, monotonic `quotaRevision`, and a nonempty collection
  of discriminated `near_ed25519 | evm_ecdsa` bindings. Each binding requires its
  exact `WalletAuthAuthorityRef`, capability, signing key, threshold session,
  SigningWorker, and nonempty participant set. The lifecycle is exhaustive:
  `active` carries positive `remainingUses` and expiry; `exhausted`, `expired`,
  and `revoked` carry only their branch-specific facts. Policy may transition
  exhausted or expired quota to a new active revision; revoked is terminal.
  ECDSA target projections may share one material binding while keeping their
  operation envelopes exact.
- Define `MpcOperationClaim` as a discriminated branch of the durable
  `CapabilityOperationClaim<MpcOperationDescriptor>` union. Both quota-use
  branches carry the
  authorization-resource-independent operation fingerprint, grant-use ID, and
  the Phase 10/12 `claimed | completed` lifecycle. Specialize
  `CapabilityOperationExecutionLease` with this closed MPC execution phase:
  `claim_committed | cryptography_started | result_materialized |
  delivery_started | delivery_observed | revocation_reconciliation`. Each ordinary
  phase requires its exact attempt, result, or idempotent delivery reference and
  makes later-phase and terminal fields `never`; operation descriptors make
  inapplicable delivery phases unconstructable. `revocation_reconciliation`
  requires the prior phase, old fencing token/epoch, observed newer epoch, exact
  revocation receipt, and every external reference required to determine the
  outcome. MPC completion uses the base closed terminal union, including
  `revoked_after_claim`, with branch-specific result/reconciliation references.
  Branch-specific builders are the only constructors. Every ordinary lease
  renewal and phase transition validates the expected server revocation epoch;
  Phase 12's server-only transition is the sole path across an epoch change.
  `quota_use: required` also requires quota ID/revision, exact quota-binding
  digest, and `quotaCost: PositiveInt`; `quota_use: none` makes those fields
  `never`. Current normal signing operations use cost `1`; Near and EVM key
  exports use `none`.
- Implement one database transaction keyed by the canonical operation
  fingerprint. It loads first: an existing claim returns its exact lifecycle
  branch without validating or consuming renewed grant/quota resources. Only the
  `absent` branch loads the current server promotion/revocation state, validates
  the exact active grant, and switches exhaustively on `quota_use` before inserting
  `claimed`. The `required` branch validates the quota
  revision and exact authority/curve/session/key/worker/participant binding and
  decrements grant and quota by their declared costs. The `none` branch validates
  that quota fields are absent and decrements only the exact grant. Both branches
  write linked use/audit state and the initial execution lease atomically. Any
  failed validation or compare-and-swap rolls back the transaction.
- Reconcile `claimed` operations with an idempotent watchdog and retry-triggered
  finalizer. An unexpired execution lease is `claimed_active` only when its expected
  revocation epoch equals the current server epoch and no tombstone exists. An
  epoch mismatch returns `claimed_stale(revocation_epoch_changed)` and enters the
  Phase 12 server-only transition. When a current-epoch lease expires, one
  compare-and-swap advances its fencing token and either transfers execution to a
  reconciler or completes a terminal result. The reconciler checks
  descriptor-specific attempt/result/delivery references before resuming. If
  external delivery may have occurred, it queries the chain/relayer by the exact
  idempotency or result reference before choosing `succeeded`, a typed failure, or
  `delivery_unknown`; it never blindly repeats delivery. If safe cryptographic
  resumption requires a disposed runtime, recovery runs under the existing claim
  and exact material-owner authority/recovery admission, without a new operation
  grant or quota decrement. The resumed executor enters the current owner queue.
  A required recovery subflow receives a recovery-held lease and affinely moves it
  to one parent-held lease before cryptographic continuation; an executor with no
  recovery receives a parent-held lease directly. Both paths revalidate the
  current local/server revocation fences before material or cryptographic work.
  Impossible resumption completes `executor_lost` or
  `outcome_unknown`. No reconciliation branch refunds authorization resources.
  Source guards reject any bare, unleased `operation_in_progress` response or
  indefinite claimed-row fixture that survived the Phase 12 cut.
- Delete the old signing-budget implementation after grant-plus-quota claiming
  lands (Decided Point 13): remove
  `BudgetCoordinator`, `budgetProjection`, `budgetFinalizer`,
  `budgetStatusReader`, `signingEngine/session/budget/**`,
  `DelegatedBudgetReservationStore`, and router reserve/commit/release budget
  methods. Build the quota store/claim transaction under its final name and
  schema; add no wrapper, alias, or dual-write path. Keep only client-side
  concurrent-operation fingerprinting from the old subsystem.
- Reject and clear old development `signingGrantId` budget rows at the
  persistence boundary. Provision new quota rows from exact current capability
  bindings; never fan one old remaining-use count into multiple quota or grant
  balances.
- Canonicalize the operation fingerprint from tenant, principal, capability,
  correlated operation, operation ID, and lane/intent/display digests. Exclude
  grant ID, quota ID/revision, threshold session, and runtime/material handles.
  The component digest projections also exclude those rotating resource IDs
  transitively. A replacement lane for the same semantic operation keeps one
  operation fingerprint while its new reauthorization anchor makes the old
  preparation unclaimable. The server recomputes and verifies the fingerprint at
  the capability boundary.
- Use the Phase 10 claim-plus-decrement transaction. Same-fingerprint retries
  return `completed`, join `claimed_active`, or reconcile `claimed_stale` without
  another grant or applicable quota decrement. They never create a second
  execution. Different fingerprints consume independently until an applicable
  grant or quota is exhausted.
- Apply the SPEC's one-way use rule to every applicable authorization resource:
  pre-claim failures leave grant and quota untouched; post-claim failures record
  a failed use and refund neither consumed resource. `quota_use: none` consumes
  only its grant. Replay of the same fingerprint follows its existing claim. A
  deliberate new attempt requires a new operation ID and fingerprint, then uses
  remaining applicable capacity or fresh authorization.
- Make grant renewal and quota replenishment explicit, independent actions.
  Quota refresh preserves its ID lineage, advances `quotaRevision` by one under
  compare-and-swap, and updates only lifecycle/expiry/balance. It cannot change
  an exact binding; binding changes require quota replacement/provisioning.
  Policy explicitly defines whether exhausted, expired, or active state may
  refresh; revoked state is terminal. Refresh serializes with in-flight claims
  and cannot overwrite a decrement. Grant renewal and quota refresh preserve the
  active Yao Client or ECDSA material identity when its exact stable bindings
  still match.
- Delete the wallet-only API scopes left on signing routes by Phase 13.
- Mount MPC routes as Phase 9 manifest modules.

Check:

- Old wallet-only API scopes are gone everywhere.
- Old wallet-operation console roles are gone or capability-local.
- Vault-only sessions cannot call MPC signing endpoints.
- Spend denial identifies exact grant or applicable quota state. No old budget
  subsystem remains. Quota-required operations atomically consume grant and quota;
  quota-none exports atomically consume only their grant. Both write audit under
  the exact operation fingerprint.
- Mid-flight operation failures after atomic claim are finalized or reconciled on
  that claim without refund or another decrement. A deliberate new operation ID/
  fingerprint requires remaining applicable capacity or fresh authorization; no
  reserve/commit/release path remains.
- Concurrent final-use tests cover two same-fingerprint requests, two different
  fingerprints on different curves, one request arriving during grant or quota
  refresh, and typed exhaustion that triggers one coordinated authorization or
  quota-replenishment flow.
- The canonical mixed-wallet regression preserves the exact cross-curve
  sequence: NEAR consumes `3 -> 2`, Tempo consumes `2 -> 1`, EVM consumes
  `1 -> 0`, and a fourth operation fails before signing. Every operation has its
  own exact `CapabilityGrant`; all three claims reference one quota.
- Near Ed25519 and ECDSA preparation receive the same active-grant shape
  regardless of whether Passkey, Email OTP, another interactive factor, or
  non-interactive evidence satisfied policy.
- Type fixtures and persistence parsers reject empty/duplicate quota bindings,
  `ed25519_only | ecdsa_only | ed25519_and_ecdsa`,
  authority/capability/session/key/worker substitution, partial grant-only or
  quota-only consumption for `quota_use: required`, quota fields on
  `quota_use: none`, and grant/quota IDs inside cryptographic runtime identity.
- Claim tests cover idempotent `required` and `none` branches, reject missing or
  extra quota fields, reject terminal fields on `claimed` and missing terminal
  fields on `completed`, and prove a key export never reads or decrements wallet
  signing quota. Existing-claim lookup tests run with no live runtime and an
  expired/replaced grant/quota: `completed` returns its protected result,
  `claimed_active` joins, `claimed_stale` reconciles, and only `absent` enters
  fresh preparation. An unexpired lease with a changed revocation epoch returns
  `claimed_stale(revocation_epoch_changed)` and cannot join ordinary execution.
- Lookup type fixtures make grant, quota, runtime, journal, durability, and held
  material-use lease fields `never`; new-claim fixtures require the exact absent
  lookup proof and reject reuse of a completed/active/stale lookup result.
- Client-side Near claimability fixtures reject `promotion_pending`,
  `durability_pending`, active handles without `durability_finalized`, stale queue
  generations, stale local/server fence generations or promotion receipts,
  missing/released/transferred held leases, double handoff, generation values
  presented without a live lease, and mismatched publication/journal revisions.
  Type fixtures reject recovery-held leases at claim/signing boundaries,
  parent-held leases at recovery-only boundaries, and transferred/released
  receipts at every effect boundary. Runtime queue tests retain aliases deliberately
  and prove an old recovery token fails after transfer, exactly one parent token is
  current, a repeated transfer fails, and release invalidates either held token.
  Server claim-request fixtures reject every local handle, journal ref,
  `MaterialUseLease` branch, and client durability brand.
  A same-operation replacement lane preserves the fingerprint while the old
  preparation and reauthorization anchor remain unclaimable.
- Claim-versus-refresh tests cover both transaction orderings, duplicate refresh,
  stale revision, active top-up policy, binding-change rejection, explicit
  operation cost, and same-operation replay after grant/quota renewal without a
  second decrement.
- Execution-reconciliation tests crash after claim insertion, cryptography start,
  result materialization, delivery start, delivery observation, and before final
  completion. Active leases join; stale leases fence the old executor and resume
  or terminate exactly once. Delivery reconciliation queries the exact external
  reference and never resends blindly. Revocation tests fence claims in
  `claim_committed`, `cryptography_started`, and `delivery_started`, then complete
  exactly once as `revoked_after_claim` or the reconciled outcome branch. Every
  terminal branch remains non-refunding, and no claim stays indefinitely
  `operation_in_progress`.
- Phase 20 deletes the last old route/auth wiring before the Phase 19/20 tranche
  can release; no compatibility route or dual admission model remains.

## Phase 21: Client Worker Split And Bundle Boundaries

Status: planning. Old Phase 7 remainder.

Prerequisites: Phase 5 must finish removing `chainTarget`,
`thresholdSessionId`, `activeStateId` (the renamed `routerAbStateSessionId`),
and authorization/quota identity from material-handle builders and role-local
material surfaces. The Phase 19/20 no-release tranche must
finish the material adapters, operation preparation/results, and discriminated
claim paths. The companion SPEC must carry the YAOS client/runtime and
responsibility-local ECDSA worker boundaries before this phase starts.

Do:

- Split `passkey-confirm.worker.ts` into generic auth confirmation and MPC
  capability workers; the generic worker from Phase 14 becomes the only generic path.
- Consolidate chain duplicates within responsibility-local workers (Decided
  Point 14). Merge `eth-signer` and `tempo-signer` into one EVM-family online
  signing worker and WASM artifact because Phase 5 made role-local material
  chain-agnostic with chain enforcement in lanes/session records.
- Preserve the completed YAOS Phase 14B ECDSA package/worker cut: one
  chain-agnostic Router A/B derivation-client worker, one presign-client worker,
  and one online-signing worker. Each owns only its lifecycle's secret material,
  sessions, loader, generated bindings, and package exports. Source guards keep
  every deleted ECDSA-HSS name, route, record, feature, vector domain, and worker
  discriminant from returning.
- Preserve the completed narrow Ed25519 Yao client-only protocol/WASM package.
  Its dependency
  and symbol closure contains client request/envelope/receipt types, recipient
  opening, active Client/FROST state, and verification for registration,
  same-root recovery, server-share refresh, activation, add-signer, and export.
  It contains no circuits, schedules, OT, garbling/evaluation, Deriver entrypoints,
  or local two-party execution.
- Destructively rename the passkey-only WASM sessions to
  `WasmPasskeyClientRegistrationSessionV1` and
  `WasmPasskeyClientRecoverySessionV1`. Their current generic names imply a
  factor-neutral constructor contract that they do not implement. Add no aliases.
- Finish the `UiConfirmManager` split into generic confirmation coordination
  and MPC signing coordination.
- Route WebAuthn assertion and OTP challenge/resend/code interaction through
  auth-factor adapters. Route only verified requirements and results to the Near
  material adapter; it owns authority-bound, purpose-typed, one-use Yao handles
  and their immediate Rust/WASM consumption. Route ECDSA material
  unlock/restore/consumption through the ECDSA material adapter. MPC preparation
  consumes only boundary-validated admission, authorization, and recovery results.
- Keep the sealed and fresh material-recovery handle lifecycle inside the
  capability-specific secure
  worker. Public/generic worker messages carry only exact data refs, admission,
  and closed results. Root binding and constructor consumption remain one
  uninterrupted worker-private operation; a root handle never crosses a public or
  generic message. A Near-adapter-private protocol may carry opaque pending,
  candidate, or finalization refs back to the same secure owner. Provider
  credentials are accepted only by the auth-factor or Router transport boundary;
  raw factor bytes, reconstructed roots, retained reseal sources, and Client
  scalars never cross into generic coordination.
- Make Near Yao export messages carry the exact
  `NearEd25519YaoLifecycleRef`, verified export-context ref, export operation ref,
  and admission. Generic coordinator and public worker messages carry no factor
  kind, raw provider credential, ordinary signing grant/quota, or signable-runtime
  recovery request. The selected auth-factor adapter turns verified factor
  evidence into a secure-worker-private material-acquisition command. Before
  constructing the one-use export session, that worker revalidates wallet,
  account, signer slot, key, threshold/wallet session, lifecycle, runtime policy,
  participants, SigningWorker, and registered public key against the exact
  context.
- Decompose combined ECDSA enrollment and
  `ecdsa_and_ed25519_yao_recovery` unlock requests into capability-specific
  worker requests. Preserve cross-curve restore isolation: an ECDSA restore
  request cannot enumerate or restore Ed25519 recovery state, and an Ed25519
  recovery request cannot inspect ECDSA material. Shared OTP/WebAuthn interaction
  is represented by verified evidence satisfying two exact requirements, never
  by a combined material envelope.
- Restrict one-use Yao WASM registration, recovery, and export constructors to
  the Near material adapter or its responsibility-local secure worker. UI code,
  selectors, capability coordinators, diagnostics, and normal signing cannot
  import those constructors or access factor secrets and reconstructed seeds.
  Retain the boundary guard until package exports make the restriction
  structurally unrepresentable, then replace the guard with export-map tests.
- Delete the replaced worker entrypoints, loaders, asset-manifest rows,
  `UiConfirmManager` factor branches, and adapter wrappers in the same change as
  the new split. No legacy worker alias or compatibility entrypoint survives.
- Move threshold warm-session cache, signer WASM, Router A/B ECDSA derivation,
  Yao client runtime, chain adapters, and wallet restore code out of generic
  confirmation paths.
- Load artifacts by operation. Normal NEAR signing cannot download a Deriver or
  Yao server artifact; Ed25519 registration, same-root recovery, server-share
  refresh, activation, add-signer, and export load only the client Yao package;
  ECDSA registration/derivation, role-local material recovery/refresh/reseal, and
  explicit export load the Router A/B derivation-client package; that package owns
  public-identity validation, additive-share mapping, client-state opening, and
  explicit export reconstruction. Presign creation, refill, and refresh load only
  the presign-client package. Normal ECDSA-family signing loads only the
  online-signing package. Keep the three artifacts separate unless measured
  first-use and repeat-use evidence justifies consolidation.
- Complete the public entrypoint split so auth-only and vault-only imports do
  not traverse `./advanced`, `./threshold`, `./worker`, `./wasm`, wallet iframe
  signer hosts, or signing-engine modules.
- Extend the export-map source guards from Phase 14 to cover the MPC entrypoints.

Check:

- Vault-only and IdP-only bundles exclude MPC worker chunks and signer WASM.
- MPC signing still works end to end through the split workers.
- Dependency/symbol guards prove the Ed25519 browser package contains no Yao
  server execution and each ECDSA worker contains only its lifecycle owner.
- Worker request/type fixtures reject combined cross-curve enrollment and restore
  envelopes, `ecdsa_and_ed25519_yao_recovery`, optional companion capability
  state, raw/provider fields in generic requests, and imports of one-use Yao
  constructors outside the Near material adapter or its secure worker. Export
  guards reject the old generic passkey WASM session names and prove ECDSA export
  resolves only through the derivation-client artifact.
- Browser waterfall checks cover registration, normal signing, same-root recovery,
  server-share refresh, activation, add-signer, and export and prove each operation
  downloads only its required artifacts.
- Bundle/dependency checks pass for vault-only, IdP-only, MPC-only, and
  full-platform browser runtimes.

## Phase 22: Wallet UI Adapter Migration

Status: planning. Old Phase 8 remainder.

Do:

- Keep `SeamsAuthMenu`, Lit transaction confirmation, theme scope, and layout.
- Replace runtime ports so the shell can use Better Auth or current `SeamsWeb`
  flows.
- Rename wallet/account UI fields to auth-account/principal fields at the UI
  boundary.
- Load transaction confirmers and signer bridges only through MPC adapters.
- Update dashboard API clients and routes for team RBAC, API keys, approvals,
  policies, audit, key exports, wallets, and future vault pages so each route is
  classified as management, session, capability grant, or capability-local MPC.
- Update docs app pages and diagrams that teach wallet sessions, signing
  sessions, and auth planes so public documentation matches the new vocabulary
  or is marked capability-local.

Check:

- Seams passkey grant evidence works without local wallet signer metadata.
- Docs and dashboard pages do not present wallet-only terms as generic auth.
- Frontend demo, SDK React components, SeamsWeb operations, and browser workers
  compile against the Phase 6 owner map.

## Phase 23: Auth-First Registration And Capability Provisioning

Status: planning. Old Phase 10.

Prerequisite: Foundations A and B are complete so capability
provisioning publishes the canonical inventory consumed by unlock and refresh.

Resolve before starting: are Ed25519 and ECDSA MPC capabilities provisioned
separately by default, and is embedded wallet login a default auth factor for
wallet customers? (See Open Questions.)

Do:

- Create only auth account, principal, factor, device, and session records by
  default.
- Create one exact `AuthFactorRecord` per enrollment. Passkey-only human
  registration does not require an email field on `AuthPrincipal`.
- Add explicit capability provisioning.
- Promote the Phase 1 signer-set request into protected capability
  provisioning. Wallet registration should request MPC capabilities through the
  same capability list used by vault and future capabilities.
- Support vault-only registration and wallet registration with requested
  capabilities.
- Keep embedded wallet login as an auth factor independent of signer material;
  replace the Phase 11 fail-closed stub with the real wallet-login proof exchange.
- Delete automatic signer provisioning from auth-only registration.
- When MPC capabilities are requested, create wallet-auth authority records that
  reference the exact enrollment `factorId`. Adding another passkey or Email OTP
  creates another binding; re-enrollment replaces IDs instead of mutating the
  old authority in place.
- Complete capability provisioning only after its live runtime/material,
  authority binding, public capability identity, and retention-policy-required
  durable inventory are committed and read back. Resolve the result through the
  shared hydration planner and require `use_live_runtime` before reporting that
  capability as registered. Roll back or return a typed partial-commit recovery
  state; never publish a ready registration backed only by page memory.

Check:

- New auth accounts do not create signer records unless provisioning requests
  them.
- Phase 1 signer-set branch identities map cleanly to protected capability
  records or capability provisioning identities.
- Multi-factor registration and re-enrollment cannot coalesce wallet authority,
  session, export, recovery, restore, or admission state by raw factor identity.
- A successfully provisioned MPC capability resolves to `use_live_runtime`
  immediately and to the correct sealed-active or public-anchor branch after a
  simulated page refresh. Registration-only readiness state is absent.
- Vault-only, IdP-only, and auth-only registration paths do not load
  MPC protocol/signer/WASM code.

---

# Part 4: Platform Completion

## Phase 24: Host And Example Assembly Migration

Status: planning. Old Phase 11 remainder (the manifest itself landed in Phase 9).

Do:

- Move Node web-server startup to the Phase 9 module manifest and runtime handler
  factory model, through the thin Node adapter.
- Verify the Express deletion from Phase 9 held: no parallel Express route
  implementations returned. Document the on-demand Express adapter contract —
  a thin wrapper over the runtime-neutral handlers that can be built if a
  customer requests Express hosting, never a second route implementation.
- Update self-hosted Cloudflare Worker examples to use capability modules and
  explicit MPC-only assembly instead of constructing `AuthService` directly.
- Keep self-hosted Worker examples capability-specific. A signing-only example
  should remain MPC-only, and a future vault example should omit signer WASM.
- Add modules for auth, session, IdP, vault, Ed25519 MPC, and ECDSA MPC where
  any are still missing from a host.

Check:

- Disabled capabilities are absent from route tables and bundles.
- Cloudflare bundles import no Express code; no parallel Express route
  implementations exist anywhere in the repo.
- The on-demand Express adapter contract is documented against the
  runtime-neutral handler signature.
- Node web-server and example Workers cannot mount disabled capability routes by
  accident.
- Router module construction, duplicate rejection, and Cloudflare/Node adapter
  manifest parity have targeted tests.

## Phase 25: Better Auth Provider Adapter

Status: planning. Deferred from Phase 11 (Decided Point 12): v1 ships on the
Seams-native session provider; this phase adds Better Auth as the second
implementation of the same session-provider port.

Do:

- Implement `betterAuthSessionProvider(auth)` against the Phase 11 port contract.
- Add `seamsPasskeyGrantEvidence()` as the thin Better Auth mounting bridge
  over the existing provider-neutral grant-evidence routes.
- The bridge cannot translate Better Auth login evidence into
  `passkey_assertion`. Before credential adoption, provider passkeys yield only
  provider session/assurance evidence; after adoption, the Seams-native factor
  route verifies its own operation-bound challenge against the exact `factorId`.
- Expose commodity auth (email+password, social providers, organizations,
  enterprise SSO) through the Better Auth composition in `seamsAuth({...})`;
  none of it is implemented natively.
- Document the credential-adoption flow (SPEC): a Better-Auth-registered
  passkey enrolls into wallet authority through the Seams add-auth-method
  ceremony.

Check:

- The provider conformance suite passes against the Better Auth adapter
  unchanged — the same suite the native provider passes.
- Swapping providers is config/assembly wiring only; the source guard against
  provider-specific imports outside adapter/bridge modules still passes.
- MPC signing grant policies remain unsatisfiable by provider login evidence
  (Decided Point 12 signing boundary).

## Phase 26: IdP Integration

Status: planning. Old Phase 13.

Resolve before starting: which IdP scopes require additional grant evidence by
default, and what customer signal triggers SAML work? (See Open Questions.)

Do:

- Implement tenant OIDC discovery, JWKS, authorization-code + PKCE, token issue,
  refresh rotation, reuse detection, revocation, relying-party config, and claim
  policies.
- Keep IdP tokens separate from Seams capability grants.
- Add `idp_access` and the correlated `idp.high_risk_scope.issue` operation.
  High-risk scope issuance resolves an exact capability instance, binding,
  operation policy, and verified evidence set before minting its internal grant.
- Put that authorization descriptor in `capability/idpAccess`; keep OIDC
  protocol state and token machinery in `idp/`.
- Provision `idp_access` only for tenants that enable IdP mode; ordinary OIDC
  token issuance remains session/relying-party policy and does not mint a
  capability grant unless the requested scope is classified high risk.

Check:

- Relying-party apps can use Seams login.
- Tokens never contain vault secrets, signer material, raw OTPs, raw auth
  headers, or operation-grant IDs.
- IdP OIDC flow, JWKS rotation, refresh-token rotation/replay, and claim policy
  have targeted tests.

## Phase 27: Final Deletion And Hardening

Status: planning. Old Phase 14, shrunk: most deletion happens in-slice (Phase 18, Phase 20,
Phase 21). This phase sweeps what remains.

Do:

- Delete any remaining old signing-session terminology and old route planes.
- Delete `SigningAuthPlan`, signer-auth aliases, auto-signer registration
  paths, and any remaining legacy fixtures.
- Delete or capability-localize old public exports whose names imply wallet-only
  auth, wallet sessions, signing sessions, threshold sessions, or signer grants.
- Delete generic imports of MPC confirmation workers, threshold stores, signer
  WASM, Router A/B derivation/Yao runtime, chain adapters, and wallet UI.
- Delete public docs, diagrams, source guards, and helper scripts that preserve
  obsolete generic terminology.
- Close out the Phase 3 delete-candidate ledger: every entry is deleted or has
  a written reason to survive.
- Run the guard-retirement sweep (Decided Point 14): delete source guards and
  type fixtures whose invariant became structural during the slices — guards
  that only watch for the return of names the type system now makes
  unrepresentable. Record retirements in
  `docs/refactor-89-clean-source-guards.md`.
- Record the final net non-doc line accounting for the whole refactor in the
  journal, per slice and total.

Check:

- Vault-only, IdP-only, wallet-only, and full-platform builds pass targeted
  tests.
- Import guards cover the intended boundaries; no guard remains whose
  invariant is structurally enforced.
- The Phase 6 ledger has no rows left in `move_*` or `delete` state.
- Net non-doc line change is recorded and explained; parallel-implementation
  deletions (AuthService stack, Express routes, old budget subsystem,
  factor-specific signing resolvers, chain-specific online signer workers, and
  retired ECDSA-HSS names/packages) appear in the accounting.

---

## Validation Plan

Checks are cumulative: Slice A checks must keep passing through Slice B and
Part 4.

Static checks:

- The Phase 6 inventory ledger exists and every row has an owner, phase, action,
  and validation check.
- Domain records require tenant, principal/session/capability IDs where
  applicable.
- Raw provider rows, decoded tokens, route bodies, and DB rows are parsed once at
  boundaries.
- Auth accounts cannot include signer material.
- `CapabilityKind`/`CapabilityOperationKind` are closed unions in the leaf
  module; `CapabilityOperationRef` correlates every pair; no runtime kind
  registry exists; kind switches are exhaustive.
- `AuthFactorIdentity`, `AuthFactorRecord`, and wallet-auth authority bindings
  remain distinct. Boundary authority builders require exact factor and binding
  IDs; core session/signing code requires only `WalletAuthAuthorityRef`.
- Session records require subject, audience, device, and assurance bindings;
  hosted-wallet exchange codes are single-use and origin-bound.
- Grant issuance accepts only `VerifiedGrantEvidenceSet`, and every persisted
  grant can reconstruct its evidence membership.
- `CapabilityOperationClaim` owns a unique fingerprint independent of grant,
  quota, session, and runtime IDs. Exact grant uses and descriptor-applicable MPC
  quota uses link to that claim and pass the atomic adapter conformance suite. Its
  base `claimed | completed` lifecycle requires a fenced execution lease, closed
  descriptor phase, deadline, expected revocation epoch, and exhaustive terminal
  result. Static fixtures reject invalid lease/phase/result combinations, including
  missing `revoked_after_claim` correlation and active fields on completion.
- `MpcOperationClaim` is exhaustive on `quota_use`. The `required` branch
  atomically claims one exact grant use and one exact `MpcWalletSigningQuota` use;
  the `none` branch atomically claims one exact grant use and makes quota fields
  `never`. Static fixtures reject terminal fields on `claimed`, missing terminal
  fields on `completed`, malformed MPC phase/reference specializations, and
  broad-spread lifecycle construction. Existing-claim lookup is
  constructible without runtime, material-use lease, or fresh grant/quota state;
  new-claim creation requires all of them according to its operation descriptor.
- `SeamsSession` state, public wallet identity, per-capability preparation,
  Ed25519 Yao ceremony state, live runtime handles, ECDSA material handles,
  exact grants, and wallet quotas use distinct branded IDs and exhaustive
  lifecycle unions.
- `MpcCapabilityHydrationPlan` is the only shared material-access lifecycle consumed
  by registration finalization, unlock, refresh, signing, step-up, and export.
  Its entry-point field is provenance only. Static fixtures prove equivalent
  canonical observations produce the same branch for every entry point.
- `use_live_runtime`, `rehydrate_active_session`,
  `reauthorize_public_anchor`, and `blocked` reject one another's fields. Public
  reauth anchors contain no secret material, sealed ciphertext, bearer session
  credential, runtime handle, active material-session identity, operation grant,
  quota, or nonce state.
- ECDSA material and Ed25519 live runtime identity contain no grant, quota,
  remaining-use, or expiry field.
- Ed25519 persistence distinguishes a public capability locator, a
  capability-local sealed active-Client record, a separate sealed root-recovery
  record, a non-secret recovery commit journal, a separate non-secret revocation
  outbox, volatile runtime observation, and closed runtime publication state.
  Static fixtures prevent sealed-only, promotion-pending, durability-pending, or
  active-without-durability-finalization state from constructing
  `normal_signing.ready` or a claim. Separate export fixtures require a correlated
  acquired export session and make normal runtime, lane, nonce, and quota fields
  `never`. Lookup fixtures map orphan/expired/exhausted/mismatched/corrupt/
  conflicting/unavailable states to typed failures. Source and
  generated-WASM guards reject live Client scalars, raw root material, Deriver
  execution code, transient bearer credentials, and recipient plaintext in
  persistence or generic bundles.
- `NearEd25519YaoLifecycleRef` is a precise required-field value shared by the
  locator, sealed active-Client record, sealed root-recovery record, journal,
  server descriptor/receipt, export
  context, worker request, and admission. Static fixtures reject lifecycle ID,
  root-share epoch, account, threshold/wallet session, signer-set, participant,
  SigningWorker, runtime-policy, or public-key substitution at every boundary.
  `VerifiedNearEd25519YaoExportContext` is data-only and cannot contain an active
  Client, normal signing lane/grant/quota, recovery allowance, raw provider
  credential, or provider token. Its available branch remains constructible when
  all ordinary signing resources are exhausted.
- Root-material inspection is data-only and carries no secret handle. Leaf-private
  root-material handles are exact-authority-bound, purpose/correlation-typed, and
  one-use. Type fixtures reject direct object-literal construction, broad spreads,
  unsafe casts, cross-purpose/correlation use, and operation-authorization/material-
  ownership substitution.
- Sealed recovery requires a branded digest over the complete locator, authority,
  material-owner, signer, root, participant, worker, public-key, seal, retention,
  source record ID/ciphertext digest/revision, and recovery-policy binding before
  unseal. Its closed lifecycle/result unions
  distinguish transport reauthentication, material unlock, pending activation,
  pending seal finalization, retryable failure, and terminal mismatch. Recovery policy is
  monotonic and carries no grant or wallet-quota authority.
- Fresh acquisition uses a distinct branded requirement digest with every sealed
  field `never`. Journal fixtures cover both source branches, reject cross-source
  field combinations, and prove that fresh acquisition can publish a first sealed
  record or finalize volatile retention without invoking unseal or source
  retirement. Revocation-outbox fixtures work for locator-only, sealed, journaled,
  and volatile-runtime states without requiring sealed-source fields.
- Authority selection has an explicit `authority_ambiguous` branch. Exact
  persistence result unions distinguish `missing`, expired/exhausted sealed
  recovery, `exact_binding_mismatch`, `corrupt`, `exact_record_conflict`, and
  `persistence_unavailable`; every switch is exhaustive and diagnostics cannot
  influence resolution.
- EVM-family projection begins from canonical source material facts and projects
  only stable material-owner identity, exact authority, lifecycle, and recovery
  facts. Target-specific operation grants, envelopes, claims, and quota uses remain
  unprojectable.
- Preparation states contain data-only requirements and exact references.
  Authorization-action singleflight, runtime recovery/activation singleflight,
  and material-owner cryptographic-use queues have separate branded keys.
- Pre-effect continuity requests and post-effect current resolutions are distinct
  domain branches. Static fixtures reject executable grants, bearer credentials,
  quota revisions, runtime handles, and export-session refs in the pre-effect
  branch; they also reject post-effect readiness built from a selected lane or
  context without exact current resolution. Recovery and reauthentication result
  builders require stable continuity and supply only current rotating resources.
- Capability grant policies cannot reference unregistered grant evidence.
- Vault-only/IdP-only entry points cannot import MPC workers, signer WASM,
  Router A/B derivation/Yao runtime, threshold stores, chain adapters, or wallet
  UI.
- Management/API-key principals cannot satisfy capability-grant routes
  without short-lived grants.
- Public export maps expose auth/vault entrypoints that stay free of MPC imports.
- Source guards reject old generic terms after their owning Slice B cutovers:
  `signing-session`, obsolete `signingGrantId` semantics, generic
  `thresholdSessionId`, `threshold_session`, `user_session`, wallet-only
  `AuthMethod`, and wallet-only API credential scopes. Phase 17 guards migrated
  exact-identity inputs; Phase 19 guards client preparation symbols; Phase 20
  guards route and grant-admission symbols.
- Source guards reject `ed25519_only`, `ecdsa_only`,
  `ed25519_and_ecdsa`, factor-specific Yao resolvers/hooks in capability core,
  and every ECDSA-HSS name deleted by YAOS Phase 14B.
- Parked workspaces such as `voiceId` cannot import auth core internals unless
  a future phase promotes them to `GrantEvidenceKind`.

Targeted tests (owning phase in parentheses):

- Refactor 88 lifecycle contract gate: `pnpm test:intended` before merging any
  slice that touches auth, session exchange, signing, export, wallet iframe
  routing, warm sessions, D1/DO state, or grant-spend replacement paths. Until
  CI owns startup, Email OTP rows require `SEAMS_INTENDED_GOOGLE_ID_TOKEN`.
- Exact capability subject and session-read boundary tests: ECDSA-only unlock,
  combined unlock subject sets, cold page-refresh session reads from
  `WalletUnlockSubjectSet`, missing-profile denial, ambiguous-profile denial,
  active login plus public NEAR identity with no live Yao Client, expired ECDSA
  sealed-session denial, capability-local recovery state, and recovery failure
  that leaves login identity unchanged (Phase 4).
- Shared hydration lifecycle matrix: post-registration, post-wallet-unlock, and
  post-page-refresh against live, sealed-active, expired, exhausted, revoked,
  missing, corrupt, conflicting, and unavailable states for Near Ed25519 and
  EVM-family ECDSA. Include post-registration -> refresh and post-unlock ->
  refresh transitions, mixed-wallet independent branches, operation-scoped
  public-anchor step-up/export, and absence of entry-point-specific recovery
  implementations. Near sealed-active cases verify authenticated local Client
  import, stable-binding substitution rejection, and zero Deriver A/B calls
  (Foundation A; Phases 4, 19, and 23).
- Canonical ECDSA capability-state transition matrix: registration and unlock
  activation commits, refresh/runtime destruction, durable rehydration,
  public-anchor reauthorization, retirement, exact conflict, corruption,
  unavailable persistence, and failure after every commit stage. Tests assert
  one manifest and exact lane across Passkey, Email OTP, and a synthetic third
  factor (Foundation B; Phases 5, 19, and 23).
- Wallet auth authority refs on Ed25519/ECDSA signing lanes, multi-factor
  collision and re-enrollment fixtures, and deletion of the interim admission
  authority-key helper (Phase 17).
- EVM ECDSA preparation matrix covering ready, exact recovery, authorization,
  and blocked states across active/consumed/expired/revoked grants,
  active/expired/exhausted threshold sessions, and
  hot/sealed/missing/invalid material (Phase 19).
- Static ECDSA preparation fixtures reject transaction lanes with export/proof
  operations, non-hot ready material, unverified or single-use recovery,
  mismatched material owner/authority/operation authorization, and raw active
  grants in ready state (Phase 19).
- Passkey and Email OTP cold-refresh recovery for direct EVM and shared Tempo
  material owners; restored, already-ready, authorization-required, unavailable,
  duplicate, corrupt, identity-mismatch, and no-progress recovery results
  (Phase 19).
- Near Ed25519 Yao preparation matrix covering active Client with committed
  publication, active Client with pending seal finalization, disposed or missing Client,
  sealed-only recovery, fresh acquisition, exact same-root recovery,
  authorization/quota renewal, pre-promotion candidate disposal,
  post-promotion activation-pending recovery, activation-committed seal
  finalization, seal-persistence/read-back pending, volatile-retention
  finalization, replacement-lane invalidation, pre-mutation storage unavailability,
  and terminal binding failures (Phase 19).
- Passkey, Email OTP, and synthetic third-factor adapters proving that generic
  Near Ed25519 and ECDSA selection/preparation require no new factor-kind branch
  (Phase 19).
- Cross-factor authorization/material tests prove policy-approved evidence from
  authority B can authorize an operation over authority A's material, while A is
  still required for material acquisition. Reusing one interaction requires exact
  authority, purpose, operation, and correlation (Phase 19).
- Page-hide disposal with retained public locator and any matching optional
  sealed recovery record and incomplete non-secret journal with an optional
  quarantined sealed source; explicit lock/logout
  immediate local zeroization, ineligibility, offline revocation outbox, and
  eventual reconciliation/removal; failed Yao candidate disposal; recovery substitution
  denial; refresh identity preservation; server promotion CAS receipt; atomic
  local registry swap and superseded-handle disposal; reload-resumable
  `promotion_committed_activation_pending`; and reload-resumable
  `activation_committed_seal_pending` with no grant/quota claim before final
  readiness (Phase 19).
- Factor-neutral effect-order tests for all Near signing operations: approval
  follows data-only durable inspection and precedes nonce recovery, session
  transport reauthentication, sealed-source unseal or fresh acquisition, worker
  rehydration, Client
  construction, activation, and retention-policy-required durability
  finalization; completed recovery precedes exact canonical re-resolution;
  re-resolution precedes joint claim; and claim precedes signing. Cancellation
  during approval/evidence completion invokes none of those effects. Replace the
  obsolete source-text ordering guard with behavioral port spies (Phase 19/Phase
  20).
- Sealed-refresh tests cover missing/expired/exhausted recovery policy,
  transport expiry, monotonic local/server allowance reconciliation, exact
  recovery-digest substitution, pending/root/candidate/reseal-source cleanup,
  stale-seal quarantine/ineligibility, replacement-record read-back, reseal
  generation failure, replacement CAS failure, and post-commit read-back failure.
  Reload/worker-termination cases cover every
  journal transition, idempotent seal-removal and promotion-result
  reconstruction, exact material reacquisition, source/replacement revision CAS,
  and stale-tab denial (Phase 18/Phase 19).
- Fresh-acquisition tests cover the distinct source digest, absence of unseal and
  source-record effects, first-seal publication, volatile retention, reload before
  and after material acquisition, and cross-source substitution denial. Pending
  journal tests prove expired or missing operation grant/quota cannot hide
  reconciliation and that grant/quota resolution reruns only after convergence
  (Phase 18/Phase 19).
- Exact resolver tests cover authority ambiguity, duplicate exact durable rows,
  missing rows, corrupt rows, and storage failure without newest/source-priority
  fallback. Current-schema conflicts remain untouched until a separate explicit
  maintenance action cleans them; obsolete-schema cleanup occurs only at the
  migration boundary. EVM-family projection tests cover valid shared material in the
  presence of target-local unusable observations and reject projected operation
  authorization (Phase 18/Phase 19).
- Concurrency tests prove distinct authorization requirement digests do not
  coalesce; identical operation/requirement pairs do. Runtime recovery joins only
  for the same stable owner, authority, and exact discriminated recovery-source digest,
  including when the threshold session is replaced; re-enrollment or reseal
  version changes do not join. EVM, Tempo, and ECDSA export operations sharing
  one ECDSA material owner serialize together; Near recovery, signing, and export
  serialize on their exact Near runtime/root owner as applicable. Distinct owners
  progress independently. No material-use queue is held during human interaction.
  A Near recovery leader acquires it before journal creation, sealed-source
  reservation, recovery admission, or material acquisition and holds it through durability persistence/read-back,
  cleanup, and exact re-resolution. Normal signing
  receives a direct lease handoff or reacquires and revalidates exact generation/
  publication/durability plus the owner fence inside the lease before claim.
  Lock/logout increments the fence and makes every pre-lock lease fail at its next
  consuming boundary. Export acquires it before
  material unlock/session staging and holds it through zeroization (Phase 19).
- Separate grant/envelope/digest/result tests for `near.sign_transaction`,
  `near.sign_delegate_action`, `near.sign_nep413_message`, and
  `near.export_key`; normal signing asserts zero Deriver calls (Phase 7/Phase 19).
- Passkey, Email OTP, and a synthetic third-factor Ed25519 export satisfy the
  same `near.export_key` operation contract. Cold-refresh coverage resolves the
  exact server-verified context with no active Client and with ordinary signing
  grant, quota, and recovery allowance exhausted; it invokes no Passkey recovery
  or signable Email OTP recovery. Tests require a fresh export-specific grant,
  separate operation authorization from exact root ownership, reject every
  authority/lifecycle/root-purpose/envelope substitution, consume one-use Yao
  admission and material handles, verify registered-public-key continuity, and
  clean up secret state on every terminal path. A stale pre-recovery authorization
  observation followed by same-owner recovery uses the current context, grant,
  and session transport and succeeds without a prior NEAR transaction; stable
  identity drift fails closed (Phase 19).
- EVM ECDSA export uses its own `evm.export_key` envelope and preparation/action
  path, exact material unlock, post-unlock re-resolution, grant-only operation
  claim, material-owner serialization, and terminal zeroization. Transaction
  lanes and authorization cannot substitute for export (Phase 19).
- Native provider session -> `SeamsSession` (Phase 11); Better Auth session ->
  `SeamsSession` through the same port (Phase 25).
- Session exchange creation, refresh, revoke, replay denial, and tenant
  isolation (Phase 11).
- Hosted-wallet exchange-code redemption with third-party cookies disabled,
  origin/audience/device mismatch denial, and no bearer token in iframe messages
  (Phase 8/Phase 11).
- Device minting, revoked-device denial, and device IDs on sessions, grant
  evidence, MPC signer proofs, and audit rows
  (Phase 11/Phase 12/Phase 14/Phase 16).
- Seams passkey, Email OTP, and Slack OTP grant-evidence challenge and verify
  (Phase 14).
- Digest canonicalization TypeScript fixtures and Rust parity vectors for lane,
  intent, display, challenge, evidence-set, and audit digests (Phase 12).
- Grant lifecycle, digest mismatch, expiry, replay, one-way consumption, failed
  consumed operation audit, existing-claim lookup before fresh readiness,
  execution-lease fencing/expiry, crash reconciliation across crypto/delivery
  phases, protected completed-result replay, and no refund after post-consumption failure
  (Phase 12/Phase 20).
- Wallet signing quota lifecycle, per-binding exact
  authority/curve/session/key/worker/participant identity, mixed-authority
  bindings in one wallet quota, `3 -> 2 -> 1 -> 0` NEAR/Tempo/EVM sequence, cross-curve final-use
  concurrency, monotonic revision, refresh during claim, stale/duplicate refresh,
  same-operation replay after authorization renewal, explicit operation cost,
  and no balance multiplication during the destructive cutover
  (Phase 18/Phase 20).
- Correlated capability-operation rejection, verified evidence-set mixed-binding
  rejection, same-fingerprint idempotency, different-fingerprint final-use
  concurrency, and exhaustion-to-step-up coordination (Phase 7/Phase 10/Phase 12/Phase 20).
- Management route policy and API scope parsing (Phase 13).
- Service-account API key grant request: management-only denial, missing binding
  denial, missing capability grant policy denial, successful vault proxy-use
  grant, and reveal/export denial (Phase 15).
- Vault proxy use through the minimal broker/gateway adapter, rotate,
  reveal/export, permission change, break-glass, and delegate-member denial
  (Phase 16).
- Retention pruning for expired challenges/evidence/grants and rate-limit denial
  for session exchange, OTP, WebAuthn challenge, verification, and
  service-account grant request paths (Phase 11/Phase 12/Phase 14/Phase 15).
- `mpc_signer_proof` missing capability, inactive capability, principal
  mismatch, unsupported operation, and success (Phase 19).
- Frontend demo, SDK React components, SeamsWeb operations, and browser workers
  compile against the new owner map (Phase 22).
- Console RBAC, API keys, policies, approvals, key exports, audit, webhooks, and
  wallet index routes compile against the new management/capability owner map
  (Phase 13/Phase 22).
- Router module construction, duplicate rejection, Cloudflare/Node adapter
  manifest parity, and the documented on-demand Express adapter contract
  (Phase 9/Phase 24).
- Node web-server startup, self-hosted Worker examples, and local test servers
  mount only enabled capability modules (Phase 24).
- IdP OIDC flow, JWKS rotation, refresh-token rotation/replay, and claim policy
  (Phase 26).
- Bundle/dependency checks for vault-only, IdP-only, MPC-only, and full-platform
  browser runtimes (Phase 14/Phase 21).
- Package export smoke tests for `@seams/sdk`, `@seams/sdk-server`, and
  `@seams-internal/shared-ts` auth-only, vault-only, MPC-only, and full-platform
  imports (Phase 14/Phase 21).

Security tests:

- Auth provider outputs, IdP tokens, refresh tokens, and session exchange cannot
  mint Seams grants.
- Reused, expired, cross-session, cross-tenant, cross-origin, cross-device, and
  digest-mismatched challenges fail closed.
- Raw provider sessions cannot enter `GrantEvidenceKind`, satisfy provider
  assurance, or authorize MPC signing.
- Replaced factor enrollments and wallet-auth bindings cannot reactivate through
  matching credential/provider identity.
- Exact ECDSA recovery cannot cross authority refs, material owners, threshold
  sessions, canonical material bindings, recovery IDs, or capability
  operations. EVM and Tempo targets may reference one material owner only when
  each transaction envelope independently authorizes its target projection.
- Pending single-use material is signable only while hot and bound to the same
  operation fingerprint. Cold pending and consumed material cannot enter the
  session-retained recovery path.
- Ed25519 Yao recovery cannot cross authority refs, wallets/accounts, signer
  keys/slots, threshold sessions, roots/epochs, participants, SigningWorkers,
  public keys, runtime policies, capability locators, sealed recovery refs, or
  root-handle purposes. Failed candidates never replace the active runtime.
- ECDSA recovery references and Ed25519 sealed root-recovery references cannot
  enumerate, restore, or commit the other capability as a hidden side effect.
- Browser persistence may contain authenticated ciphertext in separate
  capability-local Ed25519 sealed active-Client and sealed root-recovery records,
  plus non-secret correlation/receipt/revision facts in its recovery commit
  journal. Persistence, logs, diagnostics, and route bodies contain no plaintext
  Yao Client scalar, secret handle, raw authority-bound factor root,
  reconstructed seed, transient bearer credential, role input, or recipient
  plaintext. Stale journals, stale tabs, and pending publication cannot
  construct readiness or a claim.
- Operation authorization evidence cannot substitute for exact Ed25519 root
  ownership. Root-material handles cannot cross authority, purpose, operation,
  recovery-correlation, or consumed-state boundaries.
- UI, lane selection, capability coordination, diagnostics, and normal signing
  cannot import one-use factor-specific Yao WASM constructors or access factor
  secret bytes.
- Normal Ed25519 transaction, delegate-action, NEP-413, and any Near-owned
  signer-proof path make zero Deriver calls.
- A quota use cannot be claimed without the matching exact grant use. A
  `quota_use: required` grant cannot bypass quota exhaustion;
  `quota_use: none` makes every quota field absent. Same-fingerprint replay never
  consumes an applicable resource twice or starts a second execution; it returns,
  joins, or reconciles the existing claim.
- Cross-capability operation pairs and evidence sets bound to a different exact
  operation fail before grant lookup or use consumption.
- Vault-only sessions cannot call MPC signing endpoints.
- Delegates cannot reveal or export vault secrets.
- Audit records omit signer secrets, vault secrets, raw OTPs, and raw auth
  headers.
- Sealed session, Email OTP, and grant-evidence records do not reuse wallet or
  threshold identifiers as generic auth identifiers.

## Resolved Questions

Resolved July 3, 2026 (see Decided Architecture Points for rationale):

- Should the public SDK expose `SeamsSession`? **Yes, as an opaque branded
  handle; its fields are not public API.**
- Should audit writing live in `seams-authorization` or `audit-core`? **In
  `seams-authorization`. No separate audit package until a non-authorization
  audit producer exists.**
- Are capability kinds a runtime registry or closed union? **Closed union in a
  leaf module.**
- Are capability grants DB-backed records or stateless signed tokens?
  **DB-backed one-use/short-TTL records.**
- How are capability and operation kinds paired? **Through one correlated
  `CapabilityOperationRef`; independent pairs are invalid.**
- What identifies a factor for multi-factor and re-enrollment? **Pure
  `AuthFactorIdentity` is matching data; `factorId` identifies an enrollment and
  wallet authority adds its own durable binding ID/digest.**
- How does a hosted wallet iframe receive a session? **A short-lived,
  single-use, app-origin/wallet-origin-bound exchange code redeemed directly by
  the iframe. Bearer tokens never cross `postMessage`.**
- How are concurrent grant uses coordinated? **A canonical operation fingerprint
  independent of rotating authorization resources plus one atomic
  claim-and-decrement transaction, followed by a fenced execution lease and
  terminal reconciler.**

Resolved July 15, 2026 through YAOS alignment:

- Which document owns the Ed25519 cryptographic lifecycle and production gates?
  **`router-ab/ed25519-yao/implementation-plan.md`; Refactor 90 owns session, authorization, and capability
  integration.**
- Does login/session restoration imply MPC readiness? **No. Session/public
  identity and each capability's preparation state are independent domains.**
- How do registration, wallet unlock, and page refresh relate to material
  lifecycle? **They are entry-point provenance for one canonical hydration plan.
  Current state selects live-runtime use, active-session sealed rehydration,
  expired/exhausted public-anchor reauthorization, or a typed blocked result.**
- What persists for Ed25519 in the browser? **A minimal public Yao capability
  locator, an authenticated sealed activated-Client envelope for routine local
  rehydration, and an exact capability-local sealed root-recovery record when
  same-root recovery is retained. An incomplete promotion, activation, or reseal
  also persists a non-secret recovery commit journal. The two sealed records
  have distinct references, bindings, parsers, and effects. The live Client
  remains volatile Rust/WASM state, and signing requires a separate committed
  publication/durability proof.**
- Does `CapabilityGrant` carry the wallet-wide signing limit? **No. Exact
  operation grants and `MpcWalletSigningQuota` are distinct; signing atomically
  claims both, while key export declares `quota_use: none` and claims only its
  exact grant.**
- How are EVM-family workers consolidated? **Chain duplicates merge within each
  responsibility-local derivation, presign, or online-signing role. Explicit
  ECDSA export reconstruction belongs to the derivation-client role. Those roles
  and their artifacts remain separate.**

## Open Questions

Each question now has a resolve-by gate. A phase must not start while a
question gating it is open.

| Question | Resolve by | Current lean |
| -------------------------------------------------------------------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------- |
| Should `vault_access` be provisioned automatically for every tenant? | Before Phase 16 starts | Auto-provision; it is the baseline capability. |
| Should Ed25519 and ECDSA MPC capabilities be provisioned separately by default? | Before Phase 23 starts | Separately; the Phase 1 signer-set shape already models them as independent branches. |
| Which MPC capability should produce `mpc_signer_proof` by default? | Before Phase 19 starts | — |
| Should the default `near.export_key` policy accept Email OTP evidence, or should tenants enable it explicitly? | Before Phase 19 starts | Runtime support is landed; keep the policy choice explicit. |
| Should embedded wallet login be a default auth factor for wallet customers? | Before Phase 23 starts | — |
| Should VoiceID become a future `GrantEvidenceKind`, or remain a separate optional workspace? | Revisit at Slice B exit | Parked workspace with source guards. |
| Which customer signal should trigger SAML support after the OIDC IdP path ships? | Before Phase 26 scoping | — |
| Which IdP scopes require additional grant evidence by default? | Before Phase 26 starts | — |

## Related Docs

- [Modular Auth And Capability Refactor SPEC](./refactor-90-modular-auth-capabilities-SPEC.md)
- [Refactor 90 Progress Journal](./refactor-90-journal.md)
- [Centaur Secrets Vault Architecture Plan](./centaur-secrets-vault.md)
- [Slack OTP Step-Up Spec](./otp-slack.md)
- [Streaming Yao for Deriver A and Deriver B](./router-ab/ed25519-yao/implementation-plan.md)
- [Router A/B Solution Refactor](./router-a-b-sol-refactor.md)
- [Router A/B Specification](./router-ab/protocol.md)
- [Step-Up Adaptor Refactor Plan](./refactor-34b-stepup-adaptor.md)

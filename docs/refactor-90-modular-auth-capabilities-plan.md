# Modular Auth And Capability Refactor Plan

Date created: June 28, 2026
Reorganized: July 3, 2026 — horizontal layer phases (old Phases 1-14) were
restructured into vertical slices. See [Phase Mapping](#phase-mapping) for where
each old phase went.

Status: Phases 0A, 0B, and 2A are complete. Phases 0D and 0F are in progress.
Phase 0E and everything from Part 1 onward are planning.

Companion spec: [Modular Auth And Capability Refactor SPEC](./refactor-90-modular-auth-capabilities-SPEC.md).

Progress journal: [Refactor 90 Journal](./refactor-90-journal.md). Dated
progress entries live there, not here. Each phase in this plan carries only a
one-line status.

Companion plans:

- [Refactor 82B: Auth Authority Typing Cleanup](./refactor-82B.md)
- [Refactor 85: IndexedDB Minimization](./refactor-85-indexedDB.md)
- [Refactor 86: Static Wallet Assets And Vite Plugin Removal](./refactor-86-static-wallet-assets.md)

This document is the implementation checklist. Requirements, architecture
decisions, domain sketches, persistence defaults, and security model live in the
companion SPEC. Target domain types are SPEC-owned; phases in this plan may
sketch tactical types for in-flight work, but when a type appears in both
documents the SPEC version is authoritative.

Refactor 82B is a prerequisite typing cleanup for this plan. It separates stable
auth authority from one-time registration proof data so the modular auth-factor
and capability surfaces here can be implemented without carrying Passkey-specific
session assumptions into Email OTP and future auth factors.

## Decided Architecture Points

Decisions made July 3, 2026 during plan review. These are settled; do not
re-litigate them in later phases without a written reversal note here.

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
   is compile-time closed and exhaustiveness-checked. If third-party capability
   extensibility ever becomes real, reopen via module augmentation or a generic
   parameter then. The SPEC's Target Domain Types section is amended to match.
3. **The route module manifest is defined early (Phase F3), not late.** The old
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
7. **Vocabulary and type-shape cleanup:** rename `AuthMethodModule` to
   `AuthFactorModule` (its discriminant is already `factorKind`), compose
   evidence-kind families, keep deferred workload evidence kinds out of the
   closed `GrantEvidenceKind` union, collapse repeated branch payloads, and use
   small shared clusters such as `RecordStatus` and `OperationDigestSet`. The
   SPEC's Target Domain Types already reflect this F2 shape.
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
    logic. Every F3 route port that lands deletes its `AuthService` facade
    method and its duplicated `core/authService/**` helper in the same
    commit. F3 does not exit while the Phase 2A delete-candidate ledger has
    entries whose D1 owner is live. Route ports replace both layers; they
    must not become a third.
11. **One route-handler implementation; hosts are thin adapters.** The
    parallel Express route implementations are deleted at F3, not P1. The F3
    manifest/handler contract stays runtime-neutral (fetch-style
    request/response) so an Express adapter can be added later on demand as a
    thin wrapper — never as a second route implementation. The Node
    web-server consumes the same handlers through a thin Node adapter.
12. **Better Auth and native factors split by evidence grade; providers are
    interchangeable behind one port.** V1 ships on the Seams-native session
    provider (the existing passkey + Email OTP stack); the Better Auth
    adapter is a later compatibility milestone (Phase P1B) behind the same
    port. Better Auth remains the permanent, optional provider for commodity
    auth (email+password, social login, organizations, enterprise SSO); Seams
    never rebuilds those natively. The Seams-native
    factor modules are exactly those that produce MPC-grade,
    operation-digest-bound evidence or drive the Seams confirmation UI —
    passkey and Email OTP for signing-grade flows, plus Slack OTP when tenant
    policy accepts Slack OTP as operation-bound grant evidence. They are never
    ported into Better Auth. Both
    normalize into `SeamsSession` through the same A2 exchange boundary;
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
13. **`CapabilityGrant` subsumes the signing budget subsystem in Slice B.**
    DB-backed grants already carry `maxUses`, TTL, one-use consumption, and
    replay checks; B3 maps spend control onto atomic grant-use consumption
    instead of porting the budget reservation subsystem. Only the client-side
    concurrent-operation fingerprinting survives.
14. **Bloat discipline.** Each slice exit records a deletion ledger and net
    non-doc line accounting in the journal; source guards and fixtures retire
    in the same slice that makes their invariant structural (closed unions,
    branded IDs, generic lanes). The worker fleet consolidates in B4:
    `eth-signer` and `tempo-signer` merge into one EVM-family worker — 90
    Phase 0F made role-local material chain-agnostic, removing the reason for
    the split.

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
- Treat browser `walletRuntime`, `authMethods`, and `capabilities` as SDK module
  selection only. Server tenant runtime config is authoritative for enabled auth
  methods, capabilities, and policies.
- New vocabulary lands in new modules first. Wallet-touching renames wait for
  Slice B, after Slice A has proven the model.
- When moving code, name the target owner from the Simplified End State tree so
  files land once. Do not create intermediate homes that a later phase must
  re-home.

## Simplified End State

Target source ownership:

```text
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
  vault
  nearEd25519Mpc
  evmEcdsaMpc

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

| Order | Phase | Contents | Status |
| --- | --- | --- | --- |
| — | 0A | Signer-set registration cut | Complete |
| — | 0B | Wallet-rooted confirmation subjects | Complete |
| — | 2A | AuthService mechanical module split | Complete |
| 1 | 0D | Exact capability subject type hardening | In progress |
| 2 | 0F | ECDSA role-local material cache slimming | In progress |
| 3 | 0E | SDK runtime surface for hosted wallet capabilities | Planning |
| 4 | F1 | Inventory and public-surface ledger | Planning |
| 5 | F2 | Core vocabulary and closed capability kinds | Planning |
| 6 | F3 | Route service ports and route module manifest | Planning |
| 7 | A1-A7 | Slice A: vault-only tenant end to end | Planning |
| 8 | B0-B6 | Slice B: migrate MPC signing | Planning |
| 9 | P1, P1B, P2, P3 | Platform completion: hosts, Better Auth adapter, IdP, final hardening | Planning |

Phases 0D/0F/0E are tactical fixes on the current wallet-first stack and can
proceed in parallel with F1. F2 must not start until F1's ledger exists.

## Phase Mapping

Where each phase of the pre-July-3 plan went, for cross-references from other
documents:

| Old phase | New home |
| --- | --- |
| 0A, 0B, 0D, 0E, 0F | Unchanged (Part 0) |
| 0 (Inventory) | F1 |
| 0C (Public surface and deployment inventory) | F1 |
| 1 (Shared auth vocabulary) | F2 (new vocabulary) + B1 (wallet-touching renames) |
| 2 (Persistence and schema) | A1 (new tables) + B1 (wallet table remap) |
| 2A (AuthService split) | Complete (Part 0) |
| New Slice B bridge: wallet auth authority refs | B0 |
| 3 (Route and D1 ports) | F3 |
| 4 (Seams authorization core) | A3 |
| 5 (Seams auth provider) | A2 |
| 6 (Route policy V2) | A4 (management/session/grant planes) + B3 (MPC planes) |
| 6A (Service-account grant evidence) | A7 |
| 7 (Client grant evidence and worker split) | A6 (generic confirmation) + B4 (worker/bundle split) |
| 8 (React and Lit UI adapter) | A6 (generic/vault UI) + B5 (wallet UI, docs) |
| 9 (Capability modules) | A5 (vault) + B2 (MPC) |
| 10 (Registration and provisioning) | B6 |
| 11 (Route module assembly) | F3 (manifest) + P1 (hosts/examples) |
| 12 (Vault integration) | A5 |
| 13 (IdP integration) | P2 |
| 14 (Deletion and hardening) | In-slice deletion + P3 |

---

# Part 0: In-Flight Tactical Phases

These phases fix the current wallet-first stack. They are prerequisites or
parallel work, not part of the vertical slices.

## Phase 0A: Signer-Set Registration Cut

Status: complete through Refactor 82 Phase 8.

Residual note: the NEAR and EVM branch helpers were extracted, but
`packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`
still carries the large registration orchestrator. Treat that slimming as F3/B6
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
      signerSlot: PositiveSignerSlot;
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

- Phase 0A is still wallet-registration work. Phase B6 promotes the same shape
  into auth-first capability provisioning where registration creates an auth
  account by default and provisions only requested `CapabilityInstance` records.
- `near_ed25519` becomes `near_ed25519_mpc_signing` capability provisioning.
- `evm_family_ecdsa` becomes `evm_ecdsa_mpc_signing` capability provisioning.
- The branch identity used by D1 ceremony state becomes the capability
  provisioning identity or `capabilityId` once Phase B6 lands.
- Vault-only, IdP-only, and auth-only registration paths must not create signer
  records or load signer/HSS/WASM code.
- Capability policies bind requested signer capabilities to registered auth
  evidence kinds through Seams authorization, replacing the current wallet-first
  registration authority checks.

## Phase 0B: Wallet-Rooted Confirmation Subjects

Status: complete.

Goal: align existing signing confirmation payloads with the modular capability
model before the larger auth/capability split lands.

Do:

- Treat `walletId` as the canonical wallet identity in sign-intent confirmation
  payloads.
- Represent NEAR signing as a wallet plus NEAR account metadata:

```ts
{ kind: 'near_wallet'; walletId: WalletId; nearAccountId: AccountId }
```

- Represent EVM-family and Tempo signing as wallet-scoped capability use:

```ts
{ kind: 'evm_wallet'; walletId: WalletId }
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

## Phase 0D: Exact Capability Subject Type Hardening

Status: in progress. Phase 0D.1 exact ECDSA material identity and durable NEAR
unlock subject resolution is implemented; Phase 0D.2 full branch-specific
`unlockCore(subject)` remains.

> **Supersession note (July 3, 2026):** Phase 0F supersedes the
> `EcdsaRoleLocalMaterialBinding` field list sketched below. The single-builder
> API, the branded handle/digest types, and the `WalletUnlockSubject` work in
> this phase remain authoritative; the binding's *field list* is historical and
> Phase 0F's material-only binding is the target shape.

Goal: close the type holes that let exact capability identity drift after
Refactor 79 and before the modular capability model lands.

This phase addresses two concrete bug classes found during local D1 testing:

- EVM-family role-local material was exact in its binding digest, while the
  worker cache key was narrower than that digest. Tempo and ARC could reuse one
  `materialHandle` while expecting different chain-bound material.
- Wallet unlock was exposed as wallet-scoped, while the local unlock wrapper
  still required a NEAR binding before it could enter capability-specific logic.

Do:

- Add a single ECDSA role-local material identity builder. It must derive the
  binding digest and worker material handle from the same typed input:

```ts
type EcdsaRoleLocalMaterialBinding = {
  walletId: WalletId;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  chainTarget: EvmFamilyChainTarget;
  routerAbStateSessionId: RouterAbStateSessionId;
}; // historical field list — see supersession note; Phase 0F narrows this

type EcdsaRoleLocalMaterialHandle = Brand<string, 'EcdsaRoleLocalMaterialHandle'>;
type EcdsaRoleLocalBindingDigest = Brand<string, 'EcdsaRoleLocalBindingDigest'>;

function buildEcdsaRoleLocalMaterialIdentity(
  binding: EcdsaRoleLocalMaterialBinding,
): {
  bindingDigest: EcdsaRoleLocalBindingDigest;
  materialHandle: EcdsaRoleLocalMaterialHandle;
};
```

- Delete direct string construction of ECDSA role-local `materialHandle` values
  outside the identity module.
- Make worker storage, parser output, runtime records, tests, and diagnostics
  accept the branded `EcdsaRoleLocalMaterialHandle`.
- Add type fixtures that reject a material handle built from
  `{ thresholdSessionId, keyHandle }` without `chainTarget` and
  `evmFamilySigningKeySlotId`.
- Add a source guard that rejects `router-ab-ecdsa-role-local:` string
  interpolation outside the identity builder.
- Add a chain-split regression test proving Tempo and ARC with the same wallet,
  session, and router state produce different `bindingDigest` and
  `materialHandle` values.
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
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
    };
```

- Use the same branch-specific subject model for wallet-session reads. Session
  restoration must resolve a wallet into a `WalletUnlockSubjectSet` at the
  IndexedDB/request boundary, then compute session display state from that set.
  Do not introduce a sibling `WalletSessionReadSubject` union that restates the
  same branch identities.

```ts
type WalletSessionReadResolution =
  | { kind: 'no_session_request' }
  | {
      kind: 'resolved';
      walletId: WalletId;
      subjectSet: WalletUnlockSubjectSet;
      source:
        | 'runtime_session_record'
        | 'profile_projection'
        | 'host_last_used_profile';
    }
  | {
      kind: 'no_session_for_wallet';
      walletId: WalletId;
      reason: 'missing_requested_capability_subject';
      source:
        | 'runtime_session_record'
        | 'profile_projection'
        | 'host_last_used_profile';
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
- Update `getWalletSession`/page-refresh restoration to call the same resolver.
  `no_session_request` means there was no wallet to restore.
  `no_session_for_wallet` means a requested or selected wallet has no active
  capability subject and should read as logged out without warning noise.
  Corrupt or ambiguous durable identity is `unresolvable` and must remain
  observable in diagnostics/tests.
- Model sealed-session display state as `active_warm`, `active_restorable`,
  `expired`, `exhausted`, or `unavailable`. A restorable sealed session may make
  the wallet look unlockable in UI, but the first signing/export operation still
  performs exact material restore and can demote to re-auth on typed restore
  failure.
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

- [x] EVM-family signing cannot compile when a call site constructs role-local
  material from a cache key narrower than the binding digest.
- [x] Tempo and ARC signing share no role-local worker material handle unless their
  full material binding is identical.
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
- [ ] Restorable sealed sessions report `active_restorable`, not plain `active`,
  and restore failure transitions to a typed re-auth requirement.
- [ ] Source guards reject:
  - direct `materialHandle` string interpolation for role-local ECDSA;
  - optional `nearAccountId` in wallet unlock core subject types;
  - `wallet-scoped auth requires a resolved NEAR account binding` in
    wallet-scoped unlock code;
  - ECDSA unlock paths importing NEAR account validators.
  - new `WalletSessionReadSubject` or `wallet_near_subject` aliases outside
    tests that intentionally assert their absence.
- [ ] Focused tests cover:
  - [x] chain-specific ECDSA role-local material identity;
  - [ ] ECDSA-only wallet unlock;
  - [x] NEAR Ed25519 wallet unlock;
  - [ ] combined wallet unlock with requested branch set;
  - [x] page-reload unlock where runtime session records are empty but durable wallet
    signer records exist.
  - [ ] page-reload session read for ECDSA-only and combined wallets;
  - [ ] missing-profile, ambiguous-profile, expired sealed-session, and
    restorable-sealed-session demotion cases.

Implementation progress:

- [x] Added branded `EcdsaRoleLocalMaterialHandle` and
  `EcdsaRoleLocalBindingDigest`.
- [x] Moved ECDSA role-local handle construction behind a single typed builder
  that includes `walletId`, `evmFamilySigningKeySlotId`, `thresholdSessionId`,
  `signingGrantId`, `chainTarget`, and Router A/B state session identity.
- [x] Made `ThresholdEcdsaSecp256k1KeyRef` carry
  `evmFamilySigningKeySlotId` explicitly.
- [x] Added `WalletUnlockSubject` and durable wallet-signer resolution for the
  NEAR Ed25519 unlock branch.
- [ ] Replace local `unlockCore(nearAccountId)` with a branch-aware
  `unlockCore(subject)` flow that can authenticate and warm ECDSA-only wallets
  without NEAR account identity.
- [ ] Replace wallet-session read fallback logic with a boundary
  `WalletSessionReadResolution` that composes `WalletUnlockSubjectSet`.

Cross-plan notes:

- Refactor 79 remains the owner for `ExactSigningLaneIdentity` and exact signing
  lane mutation rules. This phase uses the same authority model for worker
  material handles.
- Refactor 90 owns `WalletUnlockSubject` because unlock is an auth/capability
  entrypoint, not a NEAR account API.
- Refactor 84b HSS slimming must keep HSS crate contexts digest-only; SDK
  capability subjects may include app-specific identity before digesting.

## Phase 0F: ECDSA Role-Local Material Cache Slimming

Status: in progress. The `evmFamilySigningKeySlotId` role-local material-handle
slice is complete; broader Phase 0F slimming remains pending.

> This phase's material-only `EcdsaRoleLocalMaterialBinding` is the
> authoritative target shape. It supersedes the wider Phase 0D field list.

Goal: replace the Phase 0D tactical chain-specific worker-material handle with a
smaller material-cache identity. Exact signing lanes and signed Router A/B
normal-signing state remain the authority for chain/session use.

Evidence from the current implementation:

- `routerAbStateSessionId` is derived from
  `RouterAbEcdsaHssNormalSigningStateV1.scope` and the state's
  `activation_epoch` is issued from `thresholdSessionId`.
- ECDSA `thresholdSessionId` values are generated with the `tehss_` prefix and
  24 random bytes, so they can serve as the unique live session identifier.
- `chainTarget` is required in exact signing lane/session-record identity. The
  HSS worker opens a role-local state blob by material handle and binding digest;
  chain selection should be checked before the worker material is opened.
- `evmFamilySigningKeySlotId` currently behaves like a deterministic
  provisioning/key-allocation handle derived from wallet and signing-root scope.
  If it has no runtime semantics after ECDSA key material exists, keep it out of
  signing authority, worker material identity, and generic capability records.

Implementation inventory:

- Shared TS protocol and ID helpers:
  - `packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId.ts`
  - `packages/shared-ts/src/signing-lanes/index.ts`
  - `packages/shared-ts/src/threshold/ecdsaHssRoleLocalBootstrap.ts`
  - `packages/shared-ts/src/utils/routerAbEcdsaHss.ts`
  - `packages/shared-ts/src/utils/signingSessionSeal.ts`
- Rust Router A/B protocol and local smoke code:
  - `crates/router-ab-core/src/protocol/ecdsa_hss.rs`
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
  - `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap.ts`
  - `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/**`
- Web runtime, persistence, worker, and lane authority surfaces:
  - `packages/sdk-web/src/core/platform/ecdsaRoleLocalRecords.ts`
  - `packages/sdk-web/src/core/platform/secretSources.ts`
  - `packages/sdk-web/src/core/platform/ports.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
  - `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/ecdsaHssSigningMaterialHandle.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts`
  - `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/**`
  - `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/**`
  - `packages/sdk-web/src/core/signingEngine/workerManager/**`
- Tests and guards:
  - `tests/unit/evmFamilyEcdsaIdentity.unit.test.ts`
  - `tests/unit/ecdsaRoleLocalRecords.unit.test.ts`
  - `tests/unit/routerAbEcdsaHssNormalSigning.unit.test.ts`
  - `tests/unit/routerAbEcdsaHssBudgetRouteCore.unit.test.ts`
  - `tests/unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts`
  - `tests/unit/thresholdEcdsa.*.unit.test.ts`
  - `tests/unit/refactor76BrandedKeys.guard.unit.test.ts`
  - `tests/unit/refactor79ExactSigningLane.guard.unit.test.ts`
  - `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts`
  - `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`
  - `tests/relayer/threshold-ecdsa.signature-harness.test.ts`

Side effects to account for:

- Removing `wallet_key_id` from Router A/B ECDSA-HSS normal-signing scope
  changes canonical scope bytes, budget request digests, admission lifecycle ids,
  Rust protocol structs, and TS route parsers together.
- Removing or renaming `evmFamilySigningKeySlotId` changes Wallet Session JWT
  claims, signing-session seal bindings, D1 ceremony records, IndexedDB session
  records, sealed recovery records, and source guards. In development, delete
  local D1 and IndexedDB state after this lands rather than preserving
  compatibility readers.
- If `ecdsaThresholdKeyId` derivation stops hashing
  `evmFamilySigningKeySlotId`, existing ECDSA-HSS key identities change. Update
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
  - `ThresholdEcdsaSessionRecord`;
  - sealed recovery records;
  - role-local material handles or binding digests.
- If no multi-ECDSA-key-per-wallet use case exists today, use
  `ecdsaThresholdKeyId` plus wallet/signing-root facts as the durable signer
  identity and delete `evmFamilySigningKeySlotId` from runtime paths.
- Replace the current role-local material binding:

```ts
type EcdsaRoleLocalMaterialBinding = {
  walletId: WalletId;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  signingGrantId: SigningGrantId;
  keyHandle: EcdsaKeyHandle;
  routerAbStateSessionId: RouterAbStateSessionId;
  chainTarget: EvmFamilyChainTarget;
  clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  participantIds: readonly number[];
  relayerKeyId: EcdsaRelayerKeyId;
};
```

  with a material-only binding:

```ts
type EcdsaRoleLocalMaterialBinding = {
  thresholdSessionId: ThresholdEcdsaSessionId;
  signingGrantId: SigningGrantId;
  keyHandle: EcdsaKeyHandle;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
  participantIds: readonly number[];
  relayerKeyId: EcdsaRelayerKeyId;
};
```

- Remove `routerAbStateSessionId` from `EcdsaRoleLocalMaterialBinding`,
  `EcdsaRoleLocalBindingDigest`, `EcdsaRoleLocalMaterialHandle`, worker-store
  payloads, runtime material validation keys, tests, and diagnostics.
- Remove `chainTarget` from `EcdsaRoleLocalMaterialBinding`,
  `EcdsaRoleLocalBindingDigest`, and `EcdsaRoleLocalMaterialHandle`.
- [x] Remove `evmFamilySigningKeySlotId` from `EcdsaRoleLocalMaterialBinding`,
  `EcdsaRoleLocalBindingDigest`, and `EcdsaRoleLocalMaterialHandle`.
- Rename `clientVerifyingShareB64u` to `clientVerifyingPublicKey33B64u` in
  ECDSA role-local material binding, public facts, worker payloads, diagnostics,
  tests, and type fixtures. This value is public verifier identity, not a masked
  or secret signing share.
- Keep `chainTarget` in `ExactSigningLaneIdentity`,
  `ThresholdEcdsaSessionRecord`, ECDSA lane selection, ready-record lookup, and
  signer-session validation.
- Keep `routerAbEcdsaHssNormalSigning` as signed state in wallet-session claims
  and persisted session records. Use `routerAbEcdsaHssActiveStateSessionId()`
  only at Router A/B request/admission boundaries that need the canonical
  normal-signing state session key.
- Move lane/session chain checks before worker-material access. A selected ECDSA
  lane must prove:
  - lane signer `walletId` matches the session record wallet;
  - lane signer `chainTarget` matches the session record chain target;
  - lane `thresholdSessionId` and `signingGrantId` match the session record;
  - lane signer key handle and ECDSA threshold key match the session record.
- Make `buildEcdsaRoleLocalMaterialIdentity()` accept only branded domain types.
  Parse raw strings in record/JWT/worker-response boundary builders before
  calling it.
- Delete the Phase 0D regression test that expects Tempo and ARC to produce
  different role-local worker material handles for the same material. Replace it
  with a test proving a Tempo lane cannot open/sign through an ARC session
  record, even when the worker material handle is shared.
- Add a guard rejecting `chainTarget` and `routerAbStateSessionId` inside
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
  `walletId`, `evmFamilySigningKeySlotId`, or `routerAbStateSessionId` input.
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
- [ ] Router A/B signing requests still carry and validate the signed
  `routerAbEcdsaHssNormalSigning.scope` against Wallet Session claims.
- [ ] `routerAbStateSessionId` appears only in Router A/B state/admission
  helpers, request builders, and diagnostics that describe the signed Router A/B
  scope.
- [ ] Focused ECDSA signing tests cover same-material cross-chain reuse,
  cross-chain lane mismatch rejection, page-reload restored material, and
  registration-created material.

## Phase 0E: SDK Runtime Surface For Hosted Wallet Capabilities

Status: planning.

Goal: make the wallet iframe an SDK-level runtime selection instead of an app
Vite/Next/build plugin. Application code should import the SDK, provide its
environment and publishable key, and opt into wallet capabilities with typed
runtime, auth-factor, and capability config.

Client config selects SDK modules and UI/runtime loading only. Server tenant
runtime config owns the enabled auth factors, enabled capabilities, and
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
  authMethods: [
    passkeyAuth(),
  ],
  capabilities: [
    nearEd25519MpcSigning(),
    evmFamilyEcdsaMpcSigning(),
  ],
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
  capabilityKind: Extract<
    CapabilityKind,
    'near_ed25519_mpc_signing' | 'evm_ecdsa_mpc_signing'
  >;
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
- Naming note (deliberate): the *public* config key stays `authMethods` —
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
- A client config requesting a tenant-disabled capability fails with the typed
  mismatch error before any iframe or worker code loads.
- `packages/sdk-web/src/plugins/vite.ts` is no longer part of any public
  browser wallet setup path.

## Phase 2A: AuthService Mechanical Module Split

Status: complete (July 3, 2026). Dated progress entries:
[refactor-90-journal.md](./refactor-90-journal.md#phase-2a-authservice-mechanical-module-split).

Goal (achieved): split `packages/sdk-server-ts/src/core/AuthService.ts` into
smaller source modules without changing behavior, route contracts, storage
semantics, public exports, or runtime wiring.

Outcome:

- `packages/sdk-server-ts/src/core/AuthService.ts` is a 7-line public barrel.
- `core/authService/AuthService.ts` holds assembly/delegation at 1,751 lines
  (down from 11,769), meeting the below-2,000 pre-F3 target. Remaining methods
  are constructor/config assembly, store wiring, runtime warm-up, or thin
  delegates whose next split belongs with Phase F3 route ports or Refactor 82B
  authority unions.
- 40+ focused helper modules under `core/authService/` with explicit store/port
  inputs; no `AuthServiceContext`/`AuthServiceDeps` bag exists.
- Route and app imports of `core/authService/**` internals are audit-checked
  each pass rather than source-guarded, because the facade boundary is
  temporary; F3 route ports replace it.
- Routes import only the public `AuthService` facade; extracted modules import
  no Cloudflare D1 route adapters, Express handlers, React, browser SDK code,
  or tests.

Known debt accepted by this phase: the split grouped code by mechanical
extractability, not by the Simplified End State ownership tree. Phases F3, A2,
and B2 re-home these modules into `authFactor/`, `session/`, `authorization/`,
and `capability/` owners. When re-homing, name the final owner from the end-state
tree so each file moves once more, not twice.

Split inventory (final):

| Cluster | Current owner | Status | Next action |
| --- | --- | --- | --- |
| WebAuthn/OIDC boundary parsing and provider loading | `core/authService/webauthnOidcHelpers.ts` | Active provider helper | Keep behind `AuthService` facade until WebAuthn route ports land. |
| NEAR private-key transaction signing helpers | `core/authService/nearPrivateKeySigning.ts` | Active facade helper | Keep isolated from D1 route adapters; no route imports. |
| Random ID generation | `core/authService/bytes.ts` | Active facade helper | Reuse from remaining facade methods; move callers with owning domains later. |
| Boundary object guard | `core/authService/record.ts` | Active boundary helper | Replace only raw boundary checks; do not use for core domain objects. |
| Signer WASM URL resolution | `core/authService/signerWasmUrls.ts` | Active provider helper | Keep module-local source and built-package candidates. |
| Threshold store configuration summary | `core/authService/thresholdStoreSummary.ts` | Active diagnostics helper | Keep config diagnostics in helper; no service selection side effects. |
| WebAuthn login/listing helpers | `core/authService/webauthn.ts` | Active facade helper | Keep behind `AuthService` facade until WebAuthn route ports land. |
| WebAuthn sync-account helpers | `core/authService/AuthService.ts` | Active facade methods | Move only after the threshold/session dependencies are narrowed enough to avoid a broad context bag. |
| Email OTP challenge, enrollment, unlock, registration, recovery | `core/authService/emailOtp*` plus D1 route adapters | Active but duplicated ownership | Delete AuthService-era branches once D1 ports are canonical (F3/Slice B). |
| Wallet registration intent/ceremony/finalize helpers | `core/authService/**` plus D1 registration services | Active but duplicated ownership | Route through D1 canonical adapters, then delete old AuthService authority paths. |
| Threshold Ed25519/ECDSA bootstrap, inventory, export | `core/authService/**` plus threshold services and D1/DO stores | Active but too broad | Defer stateful split until 82B authority unions are stable. |
| NEAR account creation, funding, access-key checks, transactions | `core/authService/nearAccountOperations.ts`, `nearTransactions.ts` | Active facade helpers | Account creation and delegate execution stay in the facade until their queueing/registration coordination is split. |

Delete-candidate ledger:

| Candidate | Why it is stale or risky | Replacement | Delete phase |
| --- | --- | --- | --- |
| AuthService-era wallet registration authority branches | D1 registration is the canonical registration owner; duplicate authority branches caused passkey-only and Email OTP drift. | D1 registration route services plus typed Router API adapter ports. | Refactor 82 Phase 12 / Refactor 82B authority cleanup. |
| Passkey-only Ed25519 authority checks inside shared session paths | Shared Ed25519 session code must accept the discriminated auth authority, not assume `passkey_rp` or `rpId`. | `WalletAuthAuthority` / auth-specific authority unions from Refactor 82B. | Refactor 82B. |
| AuthService generic registration bootstrap/finalize surfaces used by Cloudflare D1 routes | They keep old AuthService request shapes alive beside D1 request models. | D1 route adapter boundary with raw parsing at route/persistence edges only. | Refactor 82 Phase 12. |
| Helper code that only supports removed registration diagnostics | The extracted diagnostics module had no active callers after import audit. | None; deleted instead of moved. | Completed July 3, 2026. |
| Parallel wallet-ID allocation copy in the D1 registration intent service | Router code must not import `core/authService/**` internals, so a local copy exists beside `walletRegistrationPlanning.ts`. | Collapse through the Refactor 82 route-port cleanup. | F3 / Refactor 82 route-port cleanup. |

---

# Part 1: Foundations

## Phase F1: Inventory And Public-Surface Ledger

Status: planning. Merges the old Phase 0 (call-site inventory) and Phase 0C
(public surface and deployment inventory).

Goal: map current wallet-first coupling and make the repo-wide blast radius
concrete before any shared vocabulary changes land. F2 must not start until the
ledger exists.

Do — call-site inventory:

- Inventory `signing-session`, `signingGrantId`, `thresholdSessionId`,
  `SigningAuthPlan`, `WalletAuthIntent`, `WalletAuthCurve`, `AuthMethod`,
  `user_session`, and `threshold_session` call sites.
- Classify each route and method as auth provider, Seams authorization, auth
  factor, route assembly, vault, IdP, Ed25519 MPC, or ECDSA MPC.
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
  signing-session seal records, wallet session IndexedDB stores, and any HKDF
  salt/info labels that currently bind to wallet or threshold identities.
- Inventory test helpers and tooling, including Playwright configs, setup
  scripts, source guards, helper flows, fake relayers, fixture imports, and
  generated test env files.
- Classify `voiceId`, native clients, Rust crates, and WASM packages as
  capability-local, future grant evidence, or explicitly out of scope for this
  refactor.
- Classify frontend call sites as auth UI, session exchange, grant-evidence
  confirmation, vault UI, IdP UI, wallet UI, MPC signing, worker/runtime, or demo
  glue.
- Record imports that pull threshold, HSS, signer WASM, chain, wallet UI, or
  recovery code into generic auth/router/frontend paths.
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
  (`keep_capability_local`, `move_to_auth`, `move_to_authorization`,
  `move_to_vault`, `delete`, or `park`), and validation check.
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
- Export maps for `@seams/sdk`, `@seams/sdk-server`, and
  `@seams-internal/shared-ts` have target shapes before F2 type changes.
- Host assembly targets are recorded for Cloudflare, Node web server,
  self-hosted Worker examples, local test servers, and the on-demand Express
  adapter contract.
- Parked surfaces have explicit source guards or issue links so they do not
  silently become generic auth dependencies.

## Phase F2: Core Vocabulary And Closed Capability Kinds

Status: planning. This is the additive subset of the old Phase 1. New
vocabulary lands in new modules only; renames and deletions that touch wallet
code are deferred to Phase B1.

Goal: define auth and capability-grant vocabulary independent of wallets, with
compile-time-closed capability kinds.

Do:

- Create the `authorization/capabilityKinds` leaf module (Decided Point 2):

```ts
type CapabilityKind =
  | 'vault_access'
  | 'near_ed25519_mpc_signing'
  | 'evm_ecdsa_mpc_signing';

type CapabilityOperationKind =
  | 'vault.proxy_use'
  | 'vault.reveal'
  | 'vault.export'
  | 'vault.rotate'
  | 'vault.permission_change'
  | 'vault.break_glass_reveal'
  | 'near.sign_transaction'
  | 'evm.sign_transaction'
  | 'mpc.produce_signer_proof';
```

  The leaf module imports nothing. Both `seams-authorization` and capability
  modules import it. Capability packages register operation descriptors and
  handlers at assembly time, keyed by these closed kinds. Extend the unions in
  place as capabilities land; exhaustiveness checks must break when a kind is
  added without a handler.
- Add `AuthFactorKind`, `GrantEvidenceKind`,
  tenant/principal/session/capability/grant IDs, public opaque `SeamsSession`,
  internal `SeamsSessionRecord`,
  `GrantEvidenceRef`, `CapabilityGrantRequest`, `CapabilityOperationEnvelope`,
  `CapabilityGrant`, `CapabilityGrantPolicy`, and
  `CapabilityOperationGrantPolicyBinding`.
- Consume the Refactor 82B vocabulary mapping when defining `AuthFactor`:
  `AuthFactor` identity maps one-to-one to 82B's `AuthFactorIdentity`
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
  Grant evidence branches carry the family union directly.
- Keep `oidc_workload_federation`, `mtls_client_certificate`, and
  `kms_bound_proof` out of `GrantEvidenceKind` until their provider phases land.
- Use plain records for single-shape domain objects: `IdpRelyingParty`,
  `CapabilityGrantRequest`, `CapabilityGrantPolicy`,
  `CapabilityOperationGrantPolicyBinding`, `CapabilityInstance`,
  `CapabilityBinding`, and `CapabilityOperationEnvelope`.
- Extract `RecordStatus` for active/suspended/deleted records and
  `OperationDigestSet` for `laneDigest`/`intentDigest`/`displayDigest`.
- Model `SeamsSessionRecord` as identity plus a `state` lifecycle union, with
  `ActiveSeamsSessionRecord` for active-session inputs.
- Collapse `MpcSignerProof` to one record with `signerKind: MpcCapabilityKind`
  and `operationDigests: OperationDigestSet`.
- Define `AuthFactorModule` as one record keyed by `factorKind` until
  factor-specific module payloads diverge.
- Collapse `AuthPrincipal` to human plus non-human branches.
- Expose `SeamsSession` publicly as an opaque branded handle only (Decided
  Point 5).
- Keep the SPEC Target Domain Types and the F2 implementation in lockstep with
  the simplified shape above.
- Leave wallet code untouched in this phase: `AuthMethod = SignerAuthMethod`
  stays; `SignerAuthMethod`/`WalletAuthMethod` move in B1.

Check:

- The F1 ledger is complete for shared exports, package exports, deployment
  hosts, console schemas, helper scripts, and parked workspaces before any type
  here merges.
- `capabilityKinds` has no imports; `seams-authorization` and capability
  modules both consume it; a switch over `CapabilityKind` without a `default`
  typechecks (exhaustive).
- Generic auth modules import no signer domain files.
- Type fixtures reject invalid sessions, grant evidence records, grants,
  single-shape objects with obsolete `kind` fields, and signer fields on auth
  records.
- Type fixtures reject a `CapabilityGrantPolicy` referencing a grant evidence
  kind that is not declared.
- Type fixtures reject deferred workload evidence kinds before their provider
  phases add them.
- No existing wallet-first test or fixture changes in this phase.

## Phase F3: Route Service Ports And Route Module Manifest

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
  session, auth provider, auth factors, authorization, wallet, recovery,
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
- Work through the Phase 2A delete-candidate ledger as ports land; record
  each deletion against its ledger entry.
- Land F3 in per-port waves. Each wave must move one route family to the
  manifest, delete the replaced facade/helper/Express path, update the ledger,
  and keep Cloudflare and Node adapters green. The phase exits only when every
  ledger row with a live D1 owner is cleared.
- When a `core/authService/**` helper moves behind a port, re-home it to its
  Simplified End State owner (`authFactor/`, `session/`, capability module) in
  the same change — do not leave it in `core/authService/` with a port wrapper.

Do — route module manifest:

- Evolve `RouterApiModule` from extension-only modules into runtime-neutral
  route manifests.
- Add module-owned route definitions, required service ports (by
  `RouteServiceKey`), capability metadata, import guards, and runtime-specific
  handler factories.
- Replace the static Cloudflare handler list with registered modules.
- Assemble modules through named builders such as
  `buildCloudflareRouteModules(...)`. The builder may use normal `if` blocks
  and a final spread to combine base and optional module lists; do not use
  spread-plus-ternary arrays for optional modules.
- Later phases (A2-A7, B2-B6, P1) add modules against this contract; they must
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
- No `router/express/routes/**` implementation files remain; the only Express
  artifact is the documented on-demand adapter contract.
- Every landed route port deleted its facade method and duplicated helper in
  the same change; the Phase 2A delete-candidate ledger has no entries whose
  D1 owner is live. F3 does not exit otherwise.

---

# Part 2: Slice A — Vault-Only Tenant End To End

Goal: prove the entire new model on the one capability with no legacy coupling.
At slice exit, a vault-only tenant works end to end on new vocabulary confined
to new modules, while wallet/MPC code still runs on the old vocabulary,
untouched.

Slice exit criteria:

- Native provider session -> `SeamsSession` -> capability grant -> vault proxy
  use through the A5 minimal broker/gateway adapter -> passkey grant evidence
  -> vault reveal -> audit works against local D1.
- A vault-only tenant persists principals, factors, sessions, grants, and vault
  items with zero signer tables touched and zero signer/HSS/WASM code loaded.
- A service account can request, receive, and consume a `vault.proxy_use` grant.
- No wallet-path file was renamed or deleted for this slice.
- The slice's deletion ledger and net non-doc line accounting are recorded in
  the journal, and guards whose invariant this slice made structural are
  retired (Decided Point 14).

## Phase A1: Slice A Persistence And Schema

Status: planning. Subset of old Phase 2; wallet-table remapping moved to B1.

Goal: make the SPEC persistence model concrete for auth, session,
authorization, and vault.

Do:

- Add migrations for shared auth/authorization tables, session refresh tokens,
  grant evidence, capability grants, capability grant policies, capability
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
- Add tenant indexes, replay indexes, CHECK constraints, and seed policies.
- Store raw OTPs, grant tokens, refresh tokens, vault secrets, auth headers, and
  signer material only as hashes, sealed envelopes, or external references.
- Do not remap existing wallet/signer/WebAuthn/Email-OTP tables in this phase;
  record their remap targets in the F1 ledger for B1.

Check:

- A vault-only tenant can persist principals, factors, sessions, capability
  grants, capability instances, vaults, and vault items without signer material.
- A service-account principal can persist API credentials, grant-request scopes,
  capability bindings, and capability grant policy records.
- Console roles, API scopes, policy assignment scopes, and seed data can express
  vault-only and auth-only tenants without wallet-operation roles.
- Raw provider rows cannot enter core logic.

## Phase A2: Session Exchange And Seams Auth Provider

Status: planning. Old Phase 5.

Goal: normalize external login evidence into `SeamsSession` through one
exchange boundary, in the new `session/` module.

Do:

- Create the internal `session/` source module (package extraction deferred).
- Implement the Seams-native session provider against the port first (v1,
  Decided Point 12): the existing passkey and Email OTP stack owns sessions,
  Slack OTP participates when enabled as operation-bound evidence, recovery
  codes exchange as session evidence, and the native factor modules feed the
  same exchange as evidence sources while staying bound to the Seams
  confirmation UI. `betterAuthSessionProvider(auth)` is the deferred second
  implementation of the same port (Phase P1B); nothing in this phase may
  depend on Better Auth specifics.
- Define the session-provider port as the contract first (Decided Point 12
  interchangeability clause): `betterAuthSessionProvider(auth)` and the
  Seams-native session provider are two implementations of it. No code
  outside the provider adapters may import provider specifics.
- Implement `exchangeAuthProviderEvidence(command)` for Better Auth, Seams
  native factors, OIDC, and refresh. Wallet-login proof exchange may be stubbed
  as unsupported until B6; it must fail closed, not fall through.
- Define the session context consumed by A6 grant-evidence routes. A2 does not
  implement operation-bound grant-evidence challenge/verify endpoints; those
  depend on A3 challenge records, digest canonicalization, and the generic grant
  issuer.
- Mint and manage `auth_devices` records through the session exchange boundary.
  Core session and authorization code receives `DeviceId`, never raw
  fingerprints.
- Add a provider conformance suite (session create/refresh/revoke/replay,
  evidence normalization, tenant isolation) and run it against the native
  provider now; it becomes the acceptance gate for the Better Auth adapter in
  Phase P1B.
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
  service as manifest route modules (F3 contract).

Check:

- All login paths create `SeamsSession` through the same exchange boundary.
- Session exchange cannot mint grants, provision capabilities, or satisfy grant
  evidence requirements by itself.
- Session exchange creation, refresh, revoke, replay denial, and tenant
  isolation have targeted tests.
- The session-provider port is the only session surface routes and
  authorization consume; the conformance suite passes against the native
  provider, and a source guard rejects provider-specific imports outside
  adapter/bridge modules — so the Phase P1B Better Auth adapter can land as
  config/assembly wiring only.

## Phase A3: Seams Authorization Core

Status: planning. Old Phase 4. Audit lives here (Decided Point 4).

Goal: build the authorization module that owns grant evidence, grants, policy,
operation digests, grant-use limits, and audit envelopes. Session lifecycle
lives in `session/` (A2) and feeds authorization as evidence.

Do:

- Create the internal `authorization/` source module around the F2 vocabulary
  and the `capabilityKinds` leaf.
- Implement operation digest envelopes (`laneDigest`, `intentDigest`,
  `displayDigest`), policy evaluation, grant lifecycle, replay checks, and audit
  envelopes.
- Implement `authorization/digests` as the canonical byte encoder for lane,
  intent, display, challenge, evidence-set, and audit digests. Add TypeScript
  fixtures plus Rust parity vectors before a capability depends on a digest.
- Implement generic grant-challenge records, lifecycle, and one-use
  verification state. A6 registers the interactive evidence providers against
  these records.
- Implement the generic grant issuer:
  `CapabilityGrantRequest` + `GrantEvidenceRef[]` + capability binding + operation
  envelope + `CapabilityGrantPolicy` -> `CapabilityGrant`.
- Grants are DB-backed one-use/short-TTL records (Decided Point 6).
- Implement `seams_session` grant evidence first. `service_account_api_key`
  lands in A7; interactive challenge evidence lands in A6.
- Implement one-way grant-use consumption with result rows for success,
  pre-side-effect failure, post-side-effect failure, and replay denial.
- Implement fail-closed `mpc_signer_proof` evaluation. The proof *producer*
  lands with the MPC capability in B2; until then any policy requiring
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
- Digest canonicalization has TypeScript fixtures and Rust parity vectors.

## Phase A4: Management And Session Route Policy

Status: planning. Old Phase 6 minus the MPC planes (those move in B3).

Goal: make route auth speak management, session, and exact capability grants
for the surfaces Slice A needs. Signing routes keep `threshold_session` until
B3.

Do:

- Introduce `management_console`, `management_api_key`, `session_principal`, and
  `capability_grant` route auth planes. Replace `console`, `api_credentials`,
  and `user_session` on non-signing routes; leave `threshold_session` in place
  on MPC routes for B3.
- Add `ManagementOperationKind`, `ManagementResourceScope`, capability kind,
  operation kind, and grant use.
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
  signing-route scopes are recorded in the ledger with a B3 deletion note.
- Management route policy and API scope parsing have targeted tests.

## Phase A5: Vault Capability Module And Integration

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
- Implement vault access through `SeamsSession`, `GrantEvidenceRef`, and
  `CapabilityGrant`.
- Enforce vault operation lanes, `direct_member`, `delegate_member`, proxy-only
  use, reveal, export, permission change, and break-glass.
- Support service-account capability grants for vault proxy use and rotation.
- Add optional MPC-backed authorization for high-assurance tenants (policy
  hook only; denies until B2 ships the proof producer).
- Audit tenant, principal, capability, operation, lane digest, intent digest,
  display digest, evidence, and device.
- Validate capability grant policies against registered grant evidence kinds
  and capability operation descriptors.
- Mount vault routes as F3 manifest modules.

Check:

- Humans and agents share the principal model.
- Delegate access can use secrets through proxy without receiving plaintext.
- Service accounts can use vault proxy and rotation grants through the minimal
  broker/gateway adapter without reveal/export authority.
- Vault-only compilation excludes MPC modules.
- Vault proxy use, rotate, reveal/export, permission change, break-glass, and
  delegate-member denial have targeted tests.

## Phase A6: Generic Client Grant Evidence And Confirmation UI

Status: planning. The generic-confirmation subsets of old Phases 7 and 8. The
MPC worker split and wallet UI migration stay in B4/B5.

Goal: give vault/auth flows a browser confirmation path that never imports
signing-engine code, without touching the existing MPC worker.

Do:

- Add `CapabilityGrantPlan` and `CapabilityGrantChallenge`.
- Register interactive grant-evidence providers for `passkey_assertion`,
  `email_otp`, and `slack_otp` against the A3 grant-challenge store. Slice A's
  required end-to-end reveal path uses `passkey_assertion`; Email OTP and Slack
  OTP route tests prove the provider boundary.
- Implement provider-neutral Seams manifest routes for challenge/verify. The
  native provider mounts them directly; `seamsPasskeyGrantEvidence()` and any
  Better Auth mounting bridge land in P1B over the same routes.
- Add a generic auth confirmation worker that returns `GrantEvidenceRef`
  records; Seams authorization mints grants server-side. Build it beside the
  existing `passkey-confirm.worker.ts`, which keeps serving MPC flows until B4
  splits it.
- Add generic confirmation coordination separate from MPC signing coordination
  (the `UiConfirmManager` split lands fully in B4; here only the generic side
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
  WASM, threshold stores, HSS, or chain adapters.
- Seams passkey, Email OTP, and Slack OTP grant-evidence challenge and verify
  have targeted tests.

## Phase A7: Service-Account Grant Evidence

Status: planning. Old Phase 6A.

Goal: support non-interactive automation as a first grant-evidence provider.

Do:

- Add service-account API keys that authenticate to `management_api_key`.
- Normalize a valid key into `GrantEvidenceRef` with
  `evidenceKind: "service_account_api_key"`.
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
- The signing budget subsystem is subsumed by grant-use consumption (Decided
  Point 13); only client-side concurrent-operation fingerprinting survives.
- Current Ed25519 and EVM-family ECDSA signing lanes and signing-session records
  carry `WalletAuthAuthorityRef`; admission, export, recovery, and restore never
  identify authority from branch-specific strings.
- The worker fleet is consolidated (Decided Point 14): one EVM-family worker
  replaces `eth-signer` and `tempo-signer`.
- The slice's deletion ledger and net non-doc line accounting are recorded in
  the journal, and guards watching surfaces this slice deleted are retired.

## Phase B0: Wallet Auth Authority Refs On Signing Lanes

Status: planning. Start after F2 lands the Refactor 82B vocabulary mapping.
This is the narrow bridge from Refactor 82B's stable `WalletAuthAuthority`
model into Slice B's auth/capability migration.

Goal: make every current signing lane and signing-session record carry a stable
wallet-auth authority reference before spend control moves from signing budgets
to capability grants. Multi-factor wallets, multiple passkeys, Email OTP
re-enrollment, and future auth factors must identify authority by the durable
wallet-auth-method binding, not by branch-specific strings such as
`passkey:rpId:credentialIdB64u` or `email_otp:providerSubjectId`.

Do:

- Add `WalletAuthAuthorityRef` to current selected/committed signing lane auth
  bindings for Ed25519 and ECDSA. The ref is derived from the bound
  `WalletAuthAuthority`, not reconstructed from display data or diagnostics.
- Persist the authority ref in Ed25519 and ECDSA session records at the
  registration, unlock, step-up, recovery, export, durable restore, and sealed
  material boundaries.
- Update lane builders and boundary parsers so core signing code requires an
  authority ref. Raw compatibility parsing remains only at request/persistence
  boundaries and carries a named B1 deletion condition.
- Change signing-grant admission queue keys to use
  `authorityRef.authorityDigest` instead of the interim branch-specific
  authority-key helper. Keep wallet id, signing grant id, projection version,
  curve, and target in the key.
- Define re-enrollment semantics explicitly: if a wallet-auth-method binding is
  re-minted, the new binding produces a new `WalletAuthAuthorityRef`; old
  signing/session/export records tied to the previous ref cannot satisfy new
  authority checks.
- Keep `AuthFactorIdentity` pure. Factor identity maps to
  `WalletAuthAuthority.factor`; verifier context and wallet binding stay in
  `WalletAuthAuthority`, and signing lanes carry only the authority ref plus
  any operation-local lane facts they already require.
- Add static fixtures rejecting selected/committed signing lanes, sealed session
  records, warm capability records, and export/recovery grant state without an
  authority ref.
- Delete the interim
  `signingGrantAdmissionAuthorityKeyFromAuth` adapter once all signing lanes
  carry authority refs.

Check:

- A wallet with both Passkey and Email OTP has distinct authority refs and
  cannot coalesce admission, export, recovery, or restore state across methods.
- Two passkeys on the same wallet have distinct authority refs.
- Email OTP re-enrollment produces a new authority ref; old records fail at the
  boundary parser/build step instead of during signing.
- Admission queue keys use `WalletAuthAuthorityRef.authorityDigest`; no core
  signing flow builds authority identity from `rpId`, credential id,
  provider subject id, email hash, or display email.
- The Refactor 82B Phase 10D tests keep passing after the branch-specific
  queue-key helper is deleted.

## Phase B1: Wallet Vocabulary And Persistence Migration

Status: planning. The wallet-touching remainders of old Phases 1 and 2.

Do:

- Turn the F1 test inventory into a redundant-test ledger.
- Remove tests/fixtures that only assert obsolete wallet-first behavior.
- Adapt tests that still protect valid behavior so they use auth/capability
  terminology before changing shared types.
- Move `SignerAuthMethod` and `WalletAuthMethod` into capability-local code.
- Delete `AuthMethod = SignerAuthMethod`.
- Replace shared `signingGrantId` fields with `capabilityGrantId`. Keep
  `thresholdSessionId` inside MPC branches only.
- Remap existing D1 console/signer migrations onto the A1 schema:
  `api_keys`, `policies`, `policy_assignments`, `wallet_index`,
  `key_exports`, `approvals`, `audit_events`, webhook categories,
  observability tables, signer wallet tables, wallet auth methods, WebAuthn
  tables, Email OTP tables, and signing-root secret share tables.
- Add migration notes for wallet-scoped records that become capability-scoped,
  principal-scoped, tenant/project/environment-scoped, or capability-local MPC
  records.
- Delete compatibility parsers at request/persistence boundaries as each
  surface moves; each temporary parser carries a named deletion condition.

Check:

- Redundant wallet-first tests are deleted or adapted before shared renames
  land.
- Old wallet-session rows and raw provider rows cannot enter core logic.
- Source guards reject `signingGrantId` and wallet-only `AuthMethod` outside
  capability-local modules.

## Phase B2: MPC Capability Modules

Status: planning. Old Phase 9 (MPC part).

Resolve before starting: which MPC capability produces `mpc_signer_proof` by
default? (See Open Questions.)

Do:

- Define `near_ed25519_mpc_signing` and `evm_ecdsa_mpc_signing` modules under
  `capability/`.
- Move Ed25519 and ECDSA operation lane and intent construction into their
  capability modules.
- Add `produceMpcSignerProof` to MPC capabilities as the implementation of the
  closed `mpc.produce_signer_proof` operation; connect it to the A3 fail-closed
  `mpc_signer_proof` evaluator.
- Validate capability grant policies against registered grant evidence kinds and
  capability operation descriptors.
- Re-home the remaining threshold/wallet helpers from `core/authService/**`
  into these modules, guided by the Phase 2A split inventory.

Check:

- Vault-only compilation excludes MPC modules.
- Ed25519, ECDSA, and vault operation lanes are not interchangeable.
- `mpc_signer_proof` missing capability, inactive capability, principal
  mismatch, unsupported operation, and success have targeted tests.

## Phase B3: MPC Route Policy Migration

Status: planning. Old Phase 6 remainder.

Do:

- Replace `threshold_session` route planes with `capability_grant` on signing
  routes.
- Move threshold-session claim parsing into MPC route handlers.
- Map spend control onto grant-use consumption (Decided Point 13): atomic
  DB-backed grant `maxUses`/TTL consumption keyed by grant id and operation
  fingerprint replaces the signing-budget reservation subsystem. Delete
  `BudgetCoordinator`, `budgetProjection`, `budgetFinalizer`,
  `budgetStatusReader`, `signingEngine/session/budget/**`,
  `DelegatedBudgetReservationStore`, and router reserve/commit/release budget
  methods from capability-grant routes; keep only the client-side
  concurrent-operation fingerprinting.
- Apply the SPEC's one-way grant-use rule: pre-consumption failures leave the
  grant untouched, and post-consumption failures record a failed use without
  refunding it. Retry uses a remaining use or a fresh grant.
- Delete the wallet-only API scopes left on signing routes by A4.
- Mount MPC routes as F3 manifest modules.

Check:

- Old wallet-only API scopes are gone everywhere.
- Old wallet-operation console roles are gone or capability-local.
- Vault-only sessions cannot call MPC signing endpoints.
- Spend denial comes from grant state; no separate budget subsystem remains on
  capability-grant routes, and concurrent signing operations carry distinct
  operation fingerprints into grant-use consumption and audit.
- Mid-flight signing failures after grant-use consumption require re-auth or a
  grant with remaining uses; no reserve/commit/release path remains.

## Phase B4: Client Worker Split And Bundle Boundaries

Status: planning. Old Phase 7 remainder.

Prerequisite: Phase 0F must finish removing `chainTarget` and
`routerAbStateSessionId` from material-handle builders and role-local material
surfaces before this phase starts.

Do:

- Split `passkey-confirm.worker.ts` into generic auth confirmation and MPC
  capability workers; the generic worker from A6 becomes the only generic path.
- Consolidate the worker fleet (Decided Point 14): merge `eth-signer` and
  `tempo-signer` into one EVM-family worker. 0F made role-local material
  chain-agnostic with chain enforcement in lanes/session records, so the
  per-chain worker split has no remaining reason. Merge the two Rust WASM
  crates (`wasm/eth_signer`, `wasm/tempo_signer`), loaders, rolldown inputs,
  package exports, and Refactor 86 asset manifest/smoke list.
- Finish the `UiConfirmManager` split into generic confirmation coordination
  and MPC signing coordination.
- Move threshold warm-session cache, signer WASM, HSS, chain adapters, and
  wallet restore code out of generic confirmation paths.
- Complete the public entrypoint split so auth-only and vault-only imports do
  not traverse `./advanced`, `./threshold`, `./worker`, `./wasm`, wallet iframe
  signer hosts, or signing-engine modules.
- Extend the export-map source guards from A6 to cover the MPC entrypoints.

Check:

- Vault-only and IdP-only bundles exclude MPC worker chunks and signer WASM.
- MPC signing still works end to end through the split workers.
- Bundle/dependency checks pass for vault-only, IdP-only, MPC-only, and
  full-platform browser runtimes.

## Phase B5: Wallet UI Adapter Migration

Status: planning. Old Phase 8 remainder.

Do:

- Keep `PasskeyAuthMenu`, Lit transaction confirmation, theme scope, and layout.
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
  compile against the F1 owner map.

## Phase B6: Auth-First Registration And Capability Provisioning

Status: planning. Old Phase 10.

Resolve before starting: are Ed25519 and ECDSA MPC capabilities provisioned
separately by default, and is embedded wallet login a default auth factor for
wallet customers? (See Open Questions.)

Do:

- Create only auth account, principal, factor, device, and session records by
  default.
- Add explicit capability provisioning.
- Promote the Phase 0A signer-set request into protected capability
  provisioning. Wallet registration should request MPC capabilities through the
  same capability list used by vault and future capabilities.
- Support vault-only registration and wallet registration with requested
  capabilities.
- Keep embedded wallet login as an auth factor independent of signer material;
  replace the A2 fail-closed stub with the real wallet-login proof exchange.
- Delete automatic signer provisioning from auth-only registration.

Check:

- New auth accounts do not create signer records unless provisioning requests
  them.
- Phase 0A signer-set branch identities map cleanly to protected capability
  records or capability provisioning identities.
- Vault-only, IdP-only, and auth-only registration paths do not load
  signer/HSS/WASM code.

---

# Part 4: Platform Completion

## Phase P1: Host And Example Assembly Migration

Status: planning. Old Phase 11 remainder (the manifest itself landed in F3).

Do:

- Move Node web-server startup to the F3 module manifest and runtime handler
  factory model, through the thin Node adapter.
- Verify the Express deletion from F3 held: no parallel Express route
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

## Phase P1B: Better Auth Provider Adapter

Status: planning. Deferred from A2 (Decided Point 12): v1 ships on the
Seams-native session provider; this phase adds Better Auth as the second
implementation of the same session-provider port.

Do:

- Implement `betterAuthSessionProvider(auth)` against the A2 port contract.
- Add `seamsPasskeyGrantEvidence()` as the thin Better Auth mounting bridge
  over the existing provider-neutral grant-evidence routes.
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

## Phase P2: IdP Integration

Status: planning. Old Phase 13.

Resolve before starting: which IdP scopes require additional grant evidence by
default, and what customer signal triggers SAML work? (See Open Questions.)

Do:

- Implement tenant OIDC discovery, JWKS, authorization-code + PKCE, token issue,
  refresh rotation, reuse detection, revocation, relying-party config, and claim
  policies.
- Keep IdP tokens separate from Seams capability grants.
- Add optional grant evidence requirements for high-risk scopes.

Check:

- Relying-party apps can use Seams login.
- Tokens never contain vault secrets, signer material, raw OTPs, raw auth
  headers, or operation-grant IDs.
- IdP OIDC flow, JWKS rotation, refresh-token rotation/replay, and claim policy
  have targeted tests.

## Phase P3: Final Deletion And Hardening

Status: planning. Old Phase 14, shrunk: most deletion happens in-slice (B1, B3,
B4). This phase sweeps what remains.

Do:

- Delete any remaining old signing-session terminology and old route planes.
- Delete `SigningAuthPlan`, signer-auth aliases, auto-signer registration
  paths, and any remaining legacy fixtures.
- Delete or capability-localize old public exports whose names imply wallet-only
  auth, wallet sessions, signing sessions, threshold sessions, or signer grants.
- Delete generic imports of MPC confirmation workers, threshold stores, signer
  WASM, HSS, chain adapters, and wallet UI.
- Delete public docs, diagrams, source guards, and helper scripts that preserve
  obsolete generic terminology.
- Close out the Phase 2A delete-candidate ledger: every entry is deleted or has
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
- The F1 ledger has no rows left in `move_*` or `delete` state.
- Net non-doc line change is recorded and explained; parallel-implementation
  deletions (AuthService stack, Express routes, budget subsystem, worker
  merge) appear in the accounting.

---

## Validation Plan

Checks are cumulative: Slice A checks must keep passing through Slice B and
Part 4.

Static checks:

- The F1 inventory ledger exists and every row has an owner, phase, action,
  and validation check.
- Domain records require tenant, principal/session/capability IDs where
  applicable.
- Raw provider rows, decoded tokens, route bodies, and DB rows are parsed once at
  boundaries.
- Auth accounts cannot include signer material.
- `CapabilityKind`/`CapabilityOperationKind` are closed unions in the leaf
  module; no runtime kind registry exists; kind switches are exhaustive.
- Capability grant policies cannot reference unregistered grant evidence.
- Vault-only/IdP-only entry points cannot import MPC workers, signer WASM, HSS,
  threshold stores, chain adapters, or wallet UI.
- Management/API-key principals cannot satisfy capability-grant routes
  without short-lived grants.
- Public export maps expose auth/vault entrypoints that stay free of MPC imports.
- Source guards reject old generic terms outside capability-local modules
  (from B1 onward): `signing-session`, `signingGrantId`, `thresholdSessionId`,
  `threshold_session`, `user_session`, wallet-only `AuthMethod`, and wallet-only
  API credential scopes.
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
  expired sealed-session denial, `active_restorable` display state, and
  restorable-session demotion to re-auth on restore failure (0D).
- Wallet auth authority refs on Ed25519/ECDSA signing lanes, multi-factor
  collision and re-enrollment fixtures, and deletion of the interim admission
  authority-key helper (B0).
- Native provider session -> `SeamsSession` (A2); Better Auth session ->
  `SeamsSession` through the same port (P1B).
- Session exchange creation, refresh, revoke, replay denial, and tenant
  isolation (A2).
- Device minting, revoked-device denial, and device IDs on sessions, grant
  evidence, MPC signer proofs, and audit rows (A2/A3/A5).
- Seams passkey, Email OTP, and Slack OTP grant-evidence challenge and verify
  (A6).
- Digest canonicalization TypeScript fixtures and Rust parity vectors for lane,
  intent, display, challenge, evidence-set, and audit digests (A3).
- Grant lifecycle, digest mismatch, expiry, replay, one-way consumption, failed
  consumed operation audit, and no refund after post-consumption failure (A3/B3).
- Management route policy and API scope parsing (A4).
- Service-account API key grant request: management-only denial, missing binding
  denial, missing capability grant policy denial, successful vault proxy-use
  grant, and reveal/export denial (A7).
- Vault proxy use through the minimal broker/gateway adapter, rotate,
  reveal/export, permission change, break-glass, and delegate-member denial
  (A5).
- Retention pruning for expired challenges/evidence/grants and rate-limit denial
  for session exchange, OTP, WebAuthn challenge, verification, and
  service-account grant request paths (A2/A3/A6/A7).
- `mpc_signer_proof` missing capability, inactive capability, principal
  mismatch, unsupported operation, and success (B2).
- Frontend demo, SDK React components, SeamsWeb operations, and browser workers
  compile against the new owner map (B5).
- Console RBAC, API keys, policies, approvals, key exports, audit, webhooks, and
  wallet index routes compile against the new management/capability owner map
  (A4/B5).
- Router module construction, duplicate rejection, Cloudflare/Node adapter
  manifest parity, and the documented on-demand Express adapter contract
  (F3/P1).
- Node web-server startup, self-hosted Worker examples, and local test servers
  mount only enabled capability modules (P1).
- IdP OIDC flow, JWKS rotation, refresh-token rotation/replay, and claim policy
  (P2).
- Bundle/dependency checks for vault-only, IdP-only, MPC-only, and full-platform
  browser runtimes (A6/B4).
- Package export smoke tests for `@seams/sdk`, `@seams/sdk-server`, and
  `@seams-internal/shared-ts` auth-only, vault-only, MPC-only, and full-platform
  imports (A6/B4).

Security tests:

- Auth provider outputs, IdP tokens, refresh tokens, and session exchange cannot
  mint Seams grants.
- Reused, expired, cross-session, cross-tenant, cross-origin, cross-device, and
  digest-mismatched challenges fail closed.
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

## Open Questions

Each question now has a resolve-by gate. A phase must not start while a
question gating it is open.

| Question | Resolve by | Current lean |
| --- | --- | --- |
| Should `vault_access` be provisioned automatically for every tenant? | Before A5 starts | Auto-provision; it is the baseline capability. |
| Should Ed25519 and ECDSA MPC capabilities be provisioned separately by default? | Before B6 starts | Separately; the Phase 0A signer-set shape already models them as independent branches. |
| Which MPC capability should produce `mpc_signer_proof` by default? | Before B2 starts | — |
| Should embedded wallet login be a default auth factor for wallet customers? | Before B6 starts | — |
| Should VoiceID become a future `GrantEvidenceKind`, or remain a separate optional workspace? | Revisit at Slice B exit | Parked workspace with source guards. |
| Which customer signal should trigger SAML support after the OIDC IdP path ships? | Before P2 scoping | — |
| Which IdP scopes require additional grant evidence by default? | Before P2 starts | — |

## Related Docs

- [Modular Auth And Capability Refactor SPEC](./refactor-90-modular-auth-capabilities-SPEC.md)
- [Refactor 90 Progress Journal](./refactor-90-journal.md)
- [Centaur Secrets Vault Architecture Plan](./centaur-secrets-vault.md)
- [Slack OTP Step-Up Spec](./otp-slack.md)
- [Optional HSS Bootstrap Profiles](./refactor-8X-hss-optional.md)
- [Step-Up Adaptor Refactor Plan](./refactor-34b-stepup-adaptor.md)

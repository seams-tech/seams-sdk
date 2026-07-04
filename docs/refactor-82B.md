# Refactor 82B: Auth Authority Typing Cleanup

Date created: July 2, 2026
Reorganized: July 3, 2026 — dated progress entries and validation evidence
moved to [refactor-82B-journal.md](./refactor-82B-journal.md); phase sections
reordered into implementation-priority order (numbering unchanged); the July 3
second-review type simplifications are recorded in
[Decided Type Simplifications](#decided-type-simplifications) and tracked in
their owning phases.

Status: implementation complete for Phases 1-9. Phase 10 runtime validation is
in progress; Passkey registration/unlock/sign/export browser contracts pass
locally. Runtime validation opened Phase 10A for canonical lane inventory and
selection cleanup, then Phase 10B for extracting the shared typed
canonicalization kernel across ECDSA and Ed25519. Deployment and
CI/intended-behavior gating are deferred to Phase 11 until manual runtime
testing is complete.

Parent plan: [Cloudflare D1 Migration Plan](./refactor-82-cloudflare-D1-migration.md)

Related plan: [Modular Auth And Capability Refactor Plan](./refactor-90-modular-auth-capabilities-plan.md)

Progress journal: [Refactor 82B Journal](./refactor-82B-journal.md). Dated
progress entries, validation evidence, and long tracking notes live there; this
plan carries statuses and open tasks only.

## Relationship To Refactor 90

This plan is a prerequisite cleanup for Refactor 90. Refactor 90 splits auth
methods and capabilities into modular surfaces; Refactor 82B first makes the
current D1 registration, unlock, signing, export, sealed-session, and warm-session
authority types explicit enough that the later module split does not inherit
Passkey-specific assumptions.

Refactor 82B should finish before broad Refactor 90 implementation work touches
auth-method capability boundaries. The expected handoff is:

- `AuthFactorIdentity` maps one-to-one to Refactor 90 `AuthFactor`.
- `WalletAuthAuthority` is capability-local wallet-bound verifier authority:
  `walletId` + `factor` + `verifier` + binding reference as one object.
- Boundary proofs are `AuthMethodProof` plus `AuthOperationPurpose` at
  Refactor 90 grant-evidence producer boundaries.
- Signer capability modules consume wallet-bound authority plus capability
  identity, never one-time proof IDs.
- Email OTP and Passkey paths are represented as peer factor branches before
  capability-specific registration, unlock, signing, and export code is split.

### Ownership Split With Refactor 90 In-Flight Phases

Refactor 82B and Refactor 90 Phases 0D/0F are editing adjacent type surfaces in
parallel. The split is:

- **Refactor 82B owns:** `WalletAuthAuthority` and boundary proofs,
  `Ed25519WorkerMaterialState` and Ed25519 material-state conversion,
  `RegistrationWalletCandidate`/`ActiveWalletSession`, `SigningBudgetAuthority`/
  `SigningBudgetStatus`, committed lanes, the ECDSA lane-inventory read model,
  and sealed-session authority cleanup.
- **Refactor 90 Phase 0D/0F own:** ECDSA role-local material identity and
  worker-cache slimming (`EcdsaRoleLocalMaterialBinding`, handles, digests) and
  `WalletUnlockSubject`.

Neither plan changes the other's types without a cross-plan note in both
documents.

Refactor 85's `LocalCapabilityMaterial` storage boundary consumes canonical
material / committed-lane outputs from Phase 10A/10B/10C. If it needs inventory
facts at a persistence boundary, it consumes the typed canonical facts from this
plan. It should not introduce a fourth runtime/sealed/warm inventory
representation for the same ECDSA material.

### Vocabulary Mapping Into Refactor 90

This table is the handoff contract. Refactor 90 Phase F2 must consume it
instead of minting a third representation of the same concepts.

| Refactor 82B type                             | Refactor 90 target                                             | Notes                                                                                                                                                                                                                                                                           |
| --------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AuthFactorIdentity`                          | `AuthFactor`                                                   | Pure identity, maps one-to-one: passkey `credentialId`; email OTP `provider` + `providerUserId`. `rpId` is not identity. Email address stays display/enrollment metadata in both plans.                                                                                         |
| `WalletAuthAuthority`                         | Capability-local wallet-bound verifier authority               | `walletId` + `factor` + `verifier` + `bindingId` as one atomic object; what signing/export/session lanes consume. Refactor 90 auth modules see only `factor`; `rpId` lives in the `verifier` branch — see [Decided Type Simplifications](#decided-type-simplifications) item 4. |
| Boundary proofs (`AuthMethodProof` + purpose) | Grant-evidence challenge inputs (`GrantEvidenceRef` producers) | Purpose binding stays server-side in the challenge record in both plans.                                                                                                                                                                                                        |
| `SigningBudgetAuthority.signingGrantId`       | `capabilityGrantId`                                            | Renamed in Refactor 90 Phase B1; do not introduce new `signingGrantId` surfaces.                                                                                                                                                                                                |
| `ActiveWalletSession`                         | Capability-local wallet session                                | NOT `SeamsSession`. Wallet sessions become capability-local state under the MPC modules.                                                                                                                                                                                        |
| `EmailOtpAuthUse`                             | Capability-local lifecycle state                               | Stays inside MPC capability modules.                                                                                                                                                                                                                                            |
| `WalletUnlockSubject` (90-owned)              | Consumes `WalletAuthAuthority` branches                        | Unlock subject resolution reads stable authority; it does not redefine it.                                                                                                                                                                                                      |

## Goal

Make Passkey and Email OTP authority explicit across registration, wallet
unlock, signing, key export, sealed sessions, and warm sessions.

The current D1/DO runtime has the correct broad architecture, but several shared
session paths still model Passkey as the default authority and bolt Email OTP
onto that shape. This created repeated regressions:

- Email OTP registration/unlock rejected by `passkey_rp` checks.
- Email OTP ECDSA signing failing with missing signing-session authority.
- Email OTP key export failing provider-user matching.
- OTP registration reroll blocked by app-session wallet binding checks.
- Long-lived session identity polluted by one-time registration proof IDs.

## Current Regression Notes

The July 2026 OTP registration/signing regressions were hard to fix because the
same ECDSA signing session state was represented through several parallel shapes:

- registration bootstrap output;
- runtime session records;
- durable sealed session records;
- warm capability records;
- exact lane candidates;
- wallet-session authority records.

Those shapes were individually typed, but the bridge functions allowed partial
success states such as "session record exists, worker material exists, authority
JWT missing". The signing selector then collapsed distinct failures into one
generic "Email OTP signing-session authority is unavailable" error.

Refactor 82B must make that state atomic:

- Email OTP ECDSA registration, unlock, recovery, export, and step-up all commit
  through the same `EmailOtpEcdsaSessionCommit` path.
- A committed Email OTP ECDSA lane must contain session identity, key identity,
  wallet-session authority, warm material status, and durable restore metadata as
  one strict object.
- Selection must consume the strict committed lane object. It should not rebuild
  authority by probing multiple stores.
- Diagnostics may report which strict object failed to parse, but diagnostics
  must not influence control flow.

## Review Findings Incorporated

The first plan review found these design issues, and this document treats them
as scope constraints:

- The canonical `EcdsaCommittedLane` must be introduced before companion-lane
  work. Companion selection must consume committed lanes, rather than creating a
  temporary `ReadyEmailOtpEcdsaSessionRecord` selector that Phase 7 later deletes.
- Registration proof is only one boundary. Unlock, step-up, recovery, and key
  export also need explicit request-boundary proof unions that resolve to stable
  `WalletAuthAuthority` before core code runs.
- AuthService cleanup must name the public adapter boundary. Routes keep using
  the public facade during the mechanical split, and stale AuthService internals
  become delete candidates for the D1/AuthService cleanup phase.
- Compatibility parsing must list exact accepted legacy fields at each boundary
  and must have deletion tasks. Compatibility parsing cannot become a permanent
  shadow API.
- `WalletAuthAuthorityDigest` must define canonical serialization, digest
  algorithm, and whether `walletId` is part of the digest input.

The second review (July 3, 2026) found that the type _encoding_ multiplies
where it should parameterize, and that the 90 handoff vocabulary was
unmapped. A third review round (July 3, Codex) upgraded the `rpId` split into
the three-layer factor/verifier authority model and defended real
operation-specific invariants against over-collapsing — both are folded into
the [Decided Type Simplifications](#decided-type-simplifications) below.

## Decided Type Simplifications

Decisions from the July 3, 2026 review. Current code implements the
pre-review shapes; each decision has a migration task in its owning phase.
The unifying rule: **the authority factor branch is the discriminant.** Do not
pre-split types by auth method, encode the method into `kind` strings, or
carry a second discriminant that restates the authority factor branch.

1. **Committed lanes are generic over authority, with no top-level `kind`.**
   `kind: 'email_otp_ecdsa_committed_lane'` restated the auth-method branch —
   a double discriminant that fixtures then had to keep consistent. The named
   `RecordBacked{Method}{Curve}{Operation}CommittedLane` types were growing a
   {method} × {curve} × {operation} × {record-backed} cross-product — the same
   disease Refactor 82 Phase 0A deleted from registration. Target: one
   `EcdsaCommittedLane<A extends WalletAuthAuthority>` (and the Ed25519
   equivalent), narrowed via `lane.authority.factor.kind`, with `RecordBacked<L>` as
   a single extension. Operation-specific invariants are real and stay —
   export lanes and signing lanes legitimately require different facts — but
   they are expressed as generic composition
   (`EcdsaCommittedLane<A> & EcdsaExportFacts`), not as new named types per
   auth method, curve, operation, and backing record. Collapse the naming
   cross-product; keep the invariants. Migration: Phase 7.
2. **One proof union, purpose-bound.** `WalletUnlockAuthProof`,
   `StepUpAuthProof`, and `KeyExportAuthProof` were structurally identical;
   `RecoveryAuthProof` was one branch of the same shape. Encoding the
   operation into the type name never enforced the real security property —
   that a proof minted for unlock cannot authorize export — because that
   binding lives server-side in the challenge record. Target: one
   `AuthMethodProof` union plus `AuthOperationPurpose`, with the
   proof-to-purpose check in the boundary verifier where it actually executes.
   Callers that want compile-time operation separation use a phantom brand.
   Migration: Phase 1 follow-ups.
3. **Authority digest gets domain separation and an honest name.** The digest
   input gains a versioned domain-separation prefix
   (`seams:wallet-authority-binding:v1|`) so future authority branches
   (Refactor 90 adds `slack_otp`, `wallet_login`) cannot silently collide in
   the same hash domain. Because `walletId` is part of the preimage, the type
   is renamed `WalletAuthorityBindingDigest` — it binds an authority to a
   wallet; it is not a digest of authority alone. Development state is deleted
   rather than migrated, per the standing Refactor 82 convention. Migration:
   Phase 1 follow-ups.
4. **Three-layer authority: pure factor identity, then wallet-bound verifier
   authority.** Signing, export, and session lanes need authority _to a
   specific wallet_, not just knowledge of a factor — pure identity alone
   reintroduces the loose-pairing problem (a credential or Gmail subject
   exists while the wallet binding, `rpId`, enrollment, or session authority
   is missing or mismatched). And WebAuthn verification is RP-bound, so the
   committed authority must retain that binding somewhere trustworthy. The
   model:
   - **`AuthFactorIdentity`** — pure identity (passkey `credentialId`; email
     OTP `provider` + `providerUserId`). Maps one-to-one to Refactor 90's
     `AuthFactor`. Consumed by registration resolution (which runs before a
     wallet exists) and cross-wallet factor matching. `rpId` is not identity.
   - **`WalletAuthAuthority`** — the wallet-bound verifier authority core code
     consumes after finalize: `walletId` + `factor` + `verifier` + `bindingId`
     as one atomic object, so the pairing cannot drift. `rpId` lives in
     `verifier: { kind: 'webauthn', rpId }` — retained exactly where
     verification needs it. No outer `kind`: branches discriminate on
     `factor.kind`.
   - The wallet-auth-method binding minted at registration finalize is the
     upgrade point from factor identity to wallet authority.

   The Phase 2 audit keeps `bindingId: WalletAuthMethodId`: wallet-auth-method
   rows are durable and unique for the binding identity. Passkey ids are
   `passkey:{rpId}:{credentialIdB64u}`; Email OTP ids are
   `email_otp:{walletId}:{emailHashHex}`. Enrollment ids stay in
   recovery/enrollment material because they can rotate independently. Gated
   on 90 F2 in one cut with the digest recomputation. Migration: Phase 2
   follow-ups.

5. **No double discriminants anywhere.** `RegistrationAuthorityResolution`
   drops its `resolved_*_authority` kinds and discriminates on
   `factor.kind` (the email branch adds `proofAuditRef`).
   `EmailOtpFactorProfile` (formerly `EmailOtpAuthorityProfile`) drops its
   self-labeling `kind` and attaches email to the factor identity. Migration:
   Phase 3 / Phase 1 follow-ups.
6. **Lifecycle unions carry no constant fields.** `EmailOtpAuthUse`
   single-use branches drop `reason: 'sign'` (a field with one possible value
   carries no information). Migration: Phase 4 follow-ups.
7. **Record inventory is separate from committed lane selection.** Runtime
   validation showed that `duplicate_records` is overloaded: repeated Email OTP
   step-up can leave old exhausted records, current active records, durable
   restore records, and EVM-family shared projections for the same authority
   and key. Those are record facts about one lane, not separate authority
   candidates. Target: parse raw records into one generic record-fact union,
   group by wallet authority plus stable ECDSA key identity, check public facts
   inside the group, select one canonical committed lane per operation target,
   and expose stale/superseded facts as diagnostics. Avoid new `{method} ×
{curve} × {operation} × {source}` named type families; parameterize the group
   and lane objects over authority. Migration: Phase 10A.

## Core Rule

Long-lived authority is stable auth identity. One-time proof data stays at the
request boundary.

Core session, key, and lane objects carry `WalletAuthAuthority` or a narrowed
branch of it. Budget and sealed material objects carry `WalletAuthAuthorityRef`
when they only need to bind back to the stable authority. Route parsers and
request services consume boundary proofs, validate them once against the
minted purpose, then emit stable authority. All type definitions live in
[Target Types](#target-types) — they are defined once in this document.

Canonical home:

- Brands and primitive IDs live in `packages/shared-ts/src/utils/domainIds.ts`.
- `WalletAuthAuthority`, `WalletAuthAuthorityRef`, parsers, builders, and digest
  helpers live in one shared authority module
  (`packages/shared-ts/src/utils/walletAuthAuthority.ts`).
- The authority binding digest uses deterministic JSON over the wallet-bound
  `WalletAuthAuthority` (`walletId` is inside the bound object) with sorted
  object keys, a versioned domain-separation prefix
  (`seams:wallet-authority-binding:v1|`), base64url SHA-256 output, and no
  display fields such as email address.

## Typing Constraints

These are non-negotiable for this refactor:

- `WalletAuthAuthority` is the only long-lived auth identity in session, key,
  lane, and export state.
- `WalletAuthAuthorityRef` is the only long-lived auth reference in budget and
  sealed material state.
- Email address is display/enrollment metadata. Core authority matching uses
  `provider` and `providerUserId`.
- Registration proof is request-boundary data. Proof IDs must not appear in
  persisted key identity, threshold session policy, signing lanes, sealed
  sessions, budget records, or export records.
- Unlock, step-up, recovery, and key export proofs are request-boundary data.
  They resolve to `WalletAuthAuthority` or a branch-specific authenticated use
  object before core code runs.
- Core types must not carry loose sibling fields such as `rpId`,
  `providerUserId`, `authSubjectId`, `challengeId`, or
  `googleEmailOtpRegistrationAttemptId` when those fields are part of an auth
  authority or boundary proof.
- Raw request, D1, IndexedDB, worker, and token shapes are parsed once into
  strict internal types. Core functions receive branch-specific domain objects.
- Material, budget, registration candidate, and auth-use lifecycle state must be
  discriminated unions. Optional identity/auth/session fields are boundary-only.
- Generic helpers must switch exhaustively on the authority's factor branch
  (`authority.factor.kind` once the bound shape lands; `authority.kind` in
  current code). Helpers that require `rpId` or WebAuthn credential data must
  be named `Passkey`.
- Registration and factor-matching paths consume `AuthFactorIdentity`;
  post-finalize session, signing, export, sealed, and warm paths consume the
  wallet-bound `WalletAuthAuthority`. Neither type appears where the other
  belongs.
- Record inventory facts are read-model inputs only. Signing, step-up, and
  export core code consume canonical committed lanes or precise lane-selection
  failures; they do not branch on raw record counts.
- The authority branch is the only auth-method discriminant. No type carries a
  `kind` that restates the authority factor branch, and no new type is
  pre-split by auth method when its branches would be structurally identical —
  parameterize over the authority branch instead.
- Type fixtures must reject every known escape hatch from the regressions that
  triggered this plan.

## Compatibility Boundary Inventory

These are the exact compatibility shapes accepted during the remaining cleanup.
All entries are boundary-only and must be deleted from core selectors after the
owning reader is strict.

- [x] Shared authority parser:
  - Accepted legacy provider values: none.
  - Accepted canonical provider values: `google`, `email`.
  - Canonical output before the Phase 2 bound-authority follow-up:
    `{ kind: 'email_otp', provider, providerUserId }`; after the follow-up,
    `WalletAuthAuthority.factor.kind === 'email_otp'` with a canonical provider.
  - July 3 coverage: `parseWalletAuthAuthority` now rejects mixed
    Passkey/Email OTP sibling fields, and
    `walletAuthAuthority.shared.unit.test.ts` proves the deleted Google provider
    aliases are rejected by the shared parser.
  - [x] Delete shared-parser `google_oidc` compatibility. D1/worker request
        compatibility remains tracked under its owning boundary below.
  - [x] Delete shared-parser `google_sso_email_otp` compatibility. D1/worker
        request compatibility remains tracked under its owning boundary below.
- [x] Email OTP ECDSA session record parser:
  - Accepted legacy fields: none for `emailOtpAuthContext`.
  - Rejected deleted fields: `emailOtpAuthContext.authSubjectId`,
    `emailOtpAuthContext.retention`, `emailOtpAuthContext.reason`, and
    `emailOtpAuthContext.consumedAtMs`.
  - Canonical input before the Phase 2 bound-authority follow-up:
    `emailOtpAuthContext.authority.provider` and
    `emailOtpAuthContext.authority.providerUserId` plus
    `emailOtpAuthContext.use`; after the follow-up, provider identity lives
    under `emailOtpAuthContext.authority.factor`.
- [x] Sealed session store readers:
  - Accepted legacy fields: none for Email OTP provider identity.
  - Canonical field: `providerSubjectId`.
  - Deleted alias: `authSubjectId`.
- [x] Sealed recovery record reader:
  - Accepted legacy fields: none for Email OTP provider identity.
  - Canonical field: `providerSubjectId`.
  - Deleted alias: `authSubjectId`.
- [x] Available-lane sealed recovery projection:
  - Accepted legacy fields: none for Email OTP provider identity.
  - Canonical field: `providerSubjectId`.
  - Deleted alias: `authSubjectId`.
- [x] Ed25519 authority-scope parser:
  - Accepted legacy fields: none.
  - Canonical Email OTP branch:
    `{ kind: 'email_otp', provider, providerUserId }`.
  - Deleted proof fields: `proofKind`, `challengeId`,
    `googleEmailOtpRegistrationAttemptId`, `googleEmailOtpRegistrationOfferId`,
    `googleEmailOtpRegistrationCandidateId`, and display `email`.
- [x] D1 Google Email OTP request/persistence boundary:
  - Accepted legacy method/provider values: none in the D1 Google registration
    attempt boundary.
  - Canonical authority output: Email OTP provider `google` plus stable provider
    user ID.
  - [x] Delete `google_oidc` request/persistence compatibility. The D1 Google
        registration attempt writer now emits `authProvider: 'google'`, and the
        D1 parser rejects `google_oidc`.
  - [x] Delete `google_sso_email_otp` request/persistence compatibility. The D1
        Google Email OTP registration attempt parser accepts only
        `authProvider: 'google'`; active `google_sso_email_otp` hits are
        AuthService/core-store legacy shapes outside this D1 boundary.
- [x] AuthService monolith:
  - Accepted obsolete fields: `sessionHash` and `appSessionVersion` in Email OTP
    recovery-grant binding checks.
  - Canonical binding: stable Email OTP authority plus `walletId`, `userId`,
    channel, and org.
  - [x] Delete `sessionHash` recovery-grant binding compatibility. Store-backed
        Email OTP grant consumption now ignores rotated app-session hashes and
        binds grants to stable Email OTP authority fields only.
  - [x] Delete `appSessionVersion` recovery-grant binding compatibility. Route
        port contracts and Email OTP recovery-key helpers no longer accept
        app-session version for grant consumption or recovery-key attempt
        reporting.

## Inventory

This is the working inventory for implementation. Update it as files are edited.

### Shared Authority And Registration Types

Update:

- `packages/sdk-server-ts/src/core/types.ts`
  - `ThresholdEd25519AuthorityScope`
  - session/key record types carrying `authorityScope`
  - `WalletRegistrationStartAuthority`
  - `AddAuthMethodAuthority`
- `packages/shared-ts/src/utils/registrationIntent.ts`
  - `RegistrationAuthority`
  - `RegistrationEd25519AuthorityScope`
  - `registrationEd25519AuthorityScope`
  - registration intent parser branches carrying `challengeId` or
    `googleEmailOtpRegistration*` IDs
- `packages/sdk-server-ts/src/core/ThresholdService/validation.ts`
  - `parseThresholdEd25519AuthorityScope`
  - `thresholdEd25519AuthorityScopesMatch`
  - key/session parsers that currently parse `authorityScope`
- `packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts`
  - `Ed25519AuthorityScope`
  - `Ed25519SessionPolicyAuthority`
  - `ed25519AuthorityScopeFromPolicyAuthority`
  - `buildThresholdEd25519WalletSessionPolicy`
  - `buildThresholdEcdsaWalletSessionPolicy`

Target:

- Add the shared stable `WalletAuthAuthority`.
- Add request-boundary boundary proofs.
- Replace `authorityScope` in core session/key/lane policy with `authority`.
- Keep proof IDs inside registration/request parsers and audit records only.

### Server Registration And D1 Boundary

Update:

- `packages/sdk-server-ts/src/router/cloudflare/d1NearEd25519RegistrationBranch.ts`
  - `d1ThresholdEd25519AuthorityScopeFromRegistrationScope`
  - `d1RegistrationIntentThresholdEd25519AuthorityScope`
  - `validateD1WalletRegistrationRequestedSessionPolicy`
  - `parseD1WalletRegistrationReadyEd25519Session`
- `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`
  - Ed25519 authority construction around registration prepare/start/finalize
  - `walletRegistrationFinalizeAuthMethodFromAuthority` call sites
  - candidate wallet validation for OTP reroll
- `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords.ts`
  - `parseD1RegistrationAuthority`
  - `parseD1PasskeyRegistrationAuthority`
  - `parseD1EmailOtpRegistrationAuthority`
  - `parseD1GoogleSsoEmailOtpRegistrationAuthority`
  - ceremony record parsing that currently stores `authorityScope`
- `packages/sdk-server-ts/src/core/RegistrationCeremonyStore.ts`
  - legacy ceremony parsing and equality helpers using
    `RegistrationEd25519AuthorityScope`
- `packages/sdk-server-ts/src/core/AuthService.ts`
  - stale AuthService registration authority helpers
  - passkey-only session-policy validation still reachable from current tests

Target:

- D1 registration resolves registration proof into `WalletAuthAuthority` once.
- OTP wallet-name reroll validates `RegistrationWalletCandidate`.
- AuthService-era paths are deleted or owned by the public AuthService facade
  until route ports replace that facade. Routes must not import split
  `authService/*` internals during the mechanical module split.

### Server Session, Route, And Store Boundary

Update:

- `packages/sdk-server-ts/src/router/thresholdEd25519RequestValidation.ts`
  - `parseEd25519AuthorityScope`
  - `parseThresholdEd25519SessionPolicyBody`
- `packages/sdk-server-ts/src/router/commonRouterUtils.ts`
  - wallet session auth parsing and session policy builders
- `packages/sdk-server-ts/src/router/verifiedWalletSessionAuth.ts`
  - `VerifiedWalletSessionAuth.authorityScope`
- `packages/sdk-server-ts/src/router/routerApi.ts`
  - Router API request/response types carrying `rpId`, `authorityScope`, or
    optional Email OTP subject fields
- `packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts`
  - private worker request types carrying `authorityScope`
- `packages/sdk-server-ts/src/router/routerAbNormalSigningAdmissionCore.ts`
  - `ed25519AdmissionAuthorityScopeKey`
- `packages/sdk-server-ts/src/router/bootstrapGrantBroker.ts`
  - bootstrap grant authority payload parsing
  - July 3 progress: bootstrap grant issue parsing now requires an explicit
    authority branch. Passkey grants carry `rpId` only inside
    `authority: { kind: 'passkey_rp', rpId }`; wallet-auth grants carry
    `authority: { kind: 'wallet_auth' }`, and stale root `rpId` request bodies
    are rejected at the route boundary.
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts`
  - Ed25519 route session policy parsing
- `packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts`
  - Express equivalent
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`
  - passkey-only authority checks at ECDSA inventory/session routes
- `packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts`
  - Express equivalent
- `packages/sdk-server-ts/src/router/cloudflare/routes/syncAccount.ts`
  - passkey authority construction
- `packages/sdk-server-ts/src/router/express/routes/syncAccount.ts`
  - Express equivalent
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/signingSessionSeal.types.ts`
  - sealed session policy authority branch
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/policy/sessionPolicy.ts`
  - sealed session policy parser
- `packages/sdk-server-ts/src/core/EmailRecoveryPreparationStore.ts`
  - persisted recovery authority parsing
- `packages/sdk-server-ts/src/core/ThresholdService/stores/KeyStore.ts`
  - stored key identity shape
- `packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore.ts`
  - stored threshold session identity shape
- `packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore.ts`
  - wallet budget/session authority shape
- `packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore.ts`
  - DO persisted session and budget projection authority fields

Target:

- Route parsers accept raw/compatibility shapes and emit strict authority.
- Durable records persist stable authority, with compatibility readers confined
  to persistence boundaries.
- Shared routes switch on `authority.factor.kind` once the bound authority shape
  lands; passkey-only routes say `Passkey`.

### Web Registration And Warm Session Boundary

Update:

- `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
  - `thresholdEd25519AuthorityScopeFromRegistrationScope`
  - `registrationEd25519SessionPolicyAuthority`
  - `registrationAuthorityScopeKey`
  - `registrationBootstrapGrantAuthority`
  - registration finalize payload construction
- `packages/sdk-web/src/SeamsWeb/operations/registration/createAccountRouterApiServer.ts`
  - managed bootstrap grant payload identity
- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts`
  - Email OTP/Passkey login wallet binding authority
  - Ed25519 login material resolution
- `packages/sdk-web/src/SeamsWeb/operations/recovery/syncAccount.ts`
  - passkey authority assumptions
- `packages/sdk-web/src/SeamsWeb/operations/recovery/emailRecovery.ts`
  - recovery authority session construction
- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
  - `ThresholdEd25519WorkerMaterialRestoreContext`
  - `ThresholdEd25519LoginMaterialPendingSessionRecord`
  - `Ed25519ReusableWorkerMaterialSelector`
  - `resolveReusableEd25519WorkerMaterialForLoginSession`
  - `persistEd25519LoginSessionFromReusableWorkerMaterial`
  - `persistEmailOtpRegisteredThresholdEd25519WorkerMaterial`
  - `reconstructThresholdEd25519SigningMaterialFromWarmSession`

Target:

- Registration creates proof data at the boundary and stable authority in core.
- Warm-session bootstrap consumes `WalletAuthAuthority` and material state
  unions.
- Login resolution returns a branch of `Ed25519LoginMaterialResolution`, with no
  fallback hydration path hidden behind nullable records.

### Web ECDSA Email OTP Authority

Update:

- `packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity.ts`
  - `ThresholdEcdsaEmailOtpAuthContext`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
  - `EmailOtpEcdsaSessionRecord`
  - `thresholdEcdsaEmailOtpAuthContext`
  - `normalizeThresholdEcdsaEmailOtpAuthContext`
  - `toEcdsaEmailOtpRuntimeLaneRef`
  - `EmailOtpEcdsaPostSignMaterial`
  - `consumeSingleUseEmailOtpEcdsaLane`
  - `markThresholdEd25519EmailOtpSessionConsumedForWallet`
  - ECDSA session upsert/restore helpers carrying `emailOtpAuthContext`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit.ts`
  - `CommitEmailOtpThresholdEcdsaSessionArgs`
  - `CommitEmailOtpEvmFamilyThresholdEcdsaSessionsArgs`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts`
  - `EmailOtpEcdsaLoginReconnectInput`
  - `EmailOtpEcdsaTransactionStepUpInput`
  - login/step-up context builders
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts`
  - `EmailOtpEcdsaSealedRecoveryRecordInput`
  - restore source selection
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Recovery.ts`
  - companion ECDSA context copy
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.ts`
  - fresh export step-up inputs
  - `resolveEmailOtpEcdsaFreshLoginExportStepUpInput`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecoveryRuntime.ts`
  - `ExportEcdsaKeyWithFreshEmailOtpLaneArgs`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ports.ts`
  - `EmailOtpEcdsaSessionPorts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/emailOtpPublic.ts`
  - public Email OTP ECDSA login/enroll bridge functions
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/readySecp256k1Material.ts`
  - single-use consumed checks
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts`
  - Email OTP ECDSA step-up and post-sign consumption
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts`
  - budget readiness and auth planning inputs
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts`
  - prepared budget/auth state
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/clientSecretSource.ts`
  - `authSubjectId` digest inputs
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
  - worker-local Email OTP handle authority fields

Target:

- Replace loose `authSubjectId` with
  `authority: Extract<WalletAuthAuthority, { factor: { kind: 'email_otp' } }>`
  where the value is long-lived.
- Keep `challengeId` and registration attempt IDs in route/worker proof
  messages.
- Model Email OTP use with `EmailOtpAuthUse`.

### Web Ed25519 Worker Material State

Update:

- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
  - `RouterAbEd25519RestorableWorkerMaterialIdentity`
  - `Ed25519WorkerMaterialValidationKey`
  - `routerAbEd25519WorkerMaterialIdentityFromPersistedState`
  - `classifyRouterAbEd25519PersistedSigningRecord`
  - `hasEd25519SealedWorkerMaterial`
  - runtime validation helpers
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
  - `ThresholdEd25519SessionRecord`
  - `ThresholdEd25519MaterialReadySessionRecord`
  - `ThresholdEd25519MaterialPendingSessionRecord`
  - material field normalizers and upsert helpers
- `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
  - `CurrentEd25519RestoreMetadata`
  - `CurrentEd25519SealedSessionRecord`
  - `CurrentEcdsaSealedSessionRecord`
  - sealed restore parsing/building
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts`
  - `RouterAbEd25519WorkerMaterialRestoreAuthorization`
  - `RouterAbEd25519ReadySigningMaterialState`
  - `requireLoadedOrRestoreRouterAbEd25519SigningMaterial`
  - `tryRequireLoadedRouterAbEd25519SigningMaterial`
  - `restoreRouterAbEd25519SigningMaterial`
  - `buildExpectedWorkerMaterialBindingForRestore`
  - `sealedMaterialTransportFromRecord`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts`
  - `resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForPasskeyCredential`
  - `resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForStepUp`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`
  - selected exact lane material checks
- `packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts`
  - `ed25519MaterialRestoreIdentityForExportLane`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts`
  - material availability in lane candidates
- `packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts`
  - persisted Ed25519 lane construction
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/readModel.ts`
  - warm-session material state projection
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts`
  - warm capability persistence builders
- `packages/sdk-web/src/core/signingEngine/interfaces/near.ts`
  - Ed25519 session/material public internal interface

Target:

- Replace flat material fields with `Ed25519WorkerMaterialState`.
- Make lane selection consume material state instead of parallel predicates.
- Keep flat IndexedDB columns only at persistence read/write boundaries.

### Budget And First Step-Up Signing

Update:

- `packages/sdk-server-ts/src/router/signingBudgetStatus.ts`
  - `WalletSigningBudgetStatusRequest`
  - `parseWalletSigningBudgetStatusExpectations`
  - `parseEcdsaWalletSigningBudgetStatusRequest`
  - `parseEd25519WalletSigningBudgetStatusRequest`
  - `parseWalletSigningBudgetStatusRequest`
- `packages/sdk-server-ts/src/router/cloudflare/routes/sessions.ts`
  - `handleSigningBudgetStatus`
  - `VerifiedSigningBudgetStatus`
- `packages/sdk-server-ts/src/router/express/routes/sessions.ts`
  - Express equivalent
- `packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore.ts`
  - `authBudgetProjection`
  - `parseAuthBudgetReserveInput`
  - `parseAuthBudgetCommitInput`
  - reserve/commit/release handlers
- `packages/sdk-web/src/core/signingEngine/session/budget/budget.ts`
  - `SigningBudgetFinalizationResult`
  - `SigningSessionBudgetReserveResult`
  - `SigningSessionBudgetStatusCheck`
  - `SigningSessionBudgetStatusReader`
  - `SigningSessionBudgetStatusAuth`
- `packages/sdk-web/src/core/signingEngine/session/budget/BudgetCoordinator.ts`
  - `reserve`
  - `getAvailableStatus`
  - `recordSuccess`
  - `syncStatusForSuccessfulSpend`
  - `budgetStatusUnavailable`
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts`
  - HTTP response parser
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetProjection.ts`
  - client-side projection state
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts`
  - `EcdsaBudgetAdmissionAuthority`
  - `trustedBudgetStatusAuthFromBudgetAdmissionAuthority`
  - `trustedBudgetStatusAuthForEcdsaBudgetOperation`
  - `assertPreparedEcdsaBudgetAdmitted`
  - budget reservation and finalization call sites
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/budgetSpending.ts`
  - `reserveEvmFamilySigningGrantBudget`
  - `createEvmFamilyTransactionBudgetFinalizer`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts`
  - prepared budget state and `budget_unknown` branches
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts`
  - Ed25519 budget readiness state
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts`
  - Ed25519 transaction budget finalizer

Target:

- Parse budget status once into `SigningBudgetStatus`.
- Budget records and budget APIs carry `SigningBudgetAuthority`.
- Budget records and budget APIs do not carry `ThresholdEcdsaEmailOtpAuthContext`
  or Email OTP proof fields.
- Signing paths branch on `available`, `exhausted`, `requires_step_up`, or
  `unavailable`.
- First transaction after step-up must receive trusted status auth from the new
  session before signing starts.
- Concurrent EVM operations reserve independent operation IDs and do not reject
  because another operation is in flight.

### Tests And Type Fixtures

Update or add:

- Server authority/type fixtures:
  - `packages/sdk-server-ts/src/core/ThresholdService/thresholdEd25519AuthorityScope.typecheck.ts`
  - `packages/sdk-server-ts/src/router/verifiedWalletSessionAuth.typecheck.ts`
  - `packages/sdk-server-ts/src/router/signingBudgetStatus.typecheck.ts`
  - `packages/sdk-server-ts/src/core/RegistrationCeremonyStore.typecheck.ts`
  - `packages/sdk-server-ts/src/core/registrationRequests.typecheck.ts`
- Web authority/session fixtures:
  - `packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.typecheck.ts` if
    absent, add it.
  - `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/emailOtpHssIdentity.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/records.typecheck.ts` if
    absent, add it.
  - `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/budget/budget.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/budget/budgetFinalizer.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/budget/budgetProjection.typecheck.ts`
- Runtime regression tests:
  - `tests/unit/registrationIntentDigest.unit.test.ts`
  - `tests/unit/relayWalletRegistration.boundary.unit.test.ts`
  - `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts`
  - `tests/unit/emailOtpWalletSessionCoordinator.unit.test.ts`
  - `tests/unit/persistedAvailableSigningLanes.emailOtpEd25519.unit.test.ts`
  - `tests/unit/ed25519TransactionLaneSelection.unit.test.ts`
  - `tests/unit/exportLaneSelection.unit.test.ts`
  - `tests/unit/sealedSessionStore.unit.test.ts`
  - `tests/unit/signingSessionCoordinator.ecdsaStepUp.unit.test.ts`
  - `tests/unit/evmFamilyBudgetSpending.unit.test.ts`
  - `tests/unit/walletSessionBudgetReservation.store.unit.test.ts`
  - `tests/relayer/cloudflare-router.test.ts`
  - `tests/relayer/express-router.test.ts`
- Deferred Refactor 88 intended lifecycle gate:
  - `pnpm test:intended`

Delete stale tests that only preserve:

- `authorityScope` proof IDs in core session policy.
- Passkey-only ECDSA session inventory.
- Optional Email OTP provider subject in ECDSA session records.
- Flat optional Ed25519 material bags in lane selection.

## Target Types

Types are defined once, here. Where current code differs (pre-review shapes),
the migration task is named.

### Stable Auth Authority

Three layers (Decided Simplification 4): pure factor identity, the
wallet-bound verifier authority that core code consumes, and boundary proofs
(next section). The shared authority module now implements the factor/verifier
shape for Passkey and Email OTP; remaining 90 F2 work is vocabulary landing
across non-wallet-session route and session surfaces.

```ts
// Layer 1: pure identity. Maps one-to-one to Refactor 90's AuthFactor.
// Consumed by registration resolution (which runs before a wallet exists)
// and cross-wallet factor matching. rpId is NOT identity.
type EmailOtpEmailHashHex = string & { readonly __brand: 'EmailOtpEmailHashHex' };

type AuthFactorIdentity =
  | { kind: 'passkey'; credentialIdB64u: WebAuthnCredentialIdB64u }
  | {
      kind: 'email_otp';
      provider: EmailOtpProvider;
      providerUserId: EmailOtpProviderUserId;
    };

type PasskeyFactorIdentity = Extract<AuthFactorIdentity, { kind: 'passkey' }>;
type EmailOtpFactorIdentity = Extract<AuthFactorIdentity, { kind: 'email_otp' }>;

// Layer 2: wallet-bound verifier authority — what session, key, lane, and
// export state carries. One atomic object: wallet binding, factor identity,
// and verification context cannot drift apart. No outer kind; branches
// discriminate on factor.kind.
type WalletAuthAuthority =
  | {
      walletId: WalletId;
      factor: PasskeyFactorIdentity;
      verifier: { kind: 'webauthn'; rpId: WebAuthnRpId };
      bindingId: WalletAuthMethodId;
    }
  | {
      walletId: WalletId;
      factor: EmailOtpFactorIdentity;
      verifier: { kind: 'email_otp_wallet_auth_method'; emailHashHex: EmailOtpEmailHashHex };
      bindingId: WalletAuthMethodId;
    };

type PasskeyAuthority = Extract<WalletAuthAuthority, { factor: { kind: 'passkey' } }>;
type EmailOtpAuthority = Extract<WalletAuthAuthority, { factor: { kind: 'email_otp' } }>;

// Email address is display and enrollment metadata, not identity.
type EmailOtpFactorProfile = {
  factor: EmailOtpFactorIdentity;
  email: VerifiedEmailAddress;
};

// Compact projection of a bound authority for budget and sealed material
// state. Derivable from WalletAuthAuthority; carries no raw authority data.
type WalletAuthAuthorityRef = {
  walletId: WalletId;
  authorityDigest: WalletAuthorityBindingDigest;
};
```

Consumption rule: registration and factor-matching paths consume
`AuthFactorIdentity`; post-finalize session, signing, export, sealed, and
warm paths consume `WalletAuthAuthority`. The wallet-auth-method binding
minted at registration finalize is the upgrade point from factor identity to
wallet authority.

`bindingId` is kept because the Phase 2 audit found wallet-auth-method rows are
durable and unique per wallet/factor: D1 pins Passkey ids to
`passkey:{rpId}:{credentialIdB64u}` and Email OTP ids to
`email_otp:{walletId}:{emailHashHex}`. The Email OTP verifier carries the
wallet-auth-method email hash, not an enrollment id; enrollment ids belong to
recovery/enrollment material and can rotate independently.

`WalletAuthorityBindingDigest` (rename from `WalletAuthAuthorityDigest`;
Decided Simplification 3): deterministic JSON over the wallet-bound
`WalletAuthAuthority` (`walletId` is inside the bound object, so it is in the
preimage) with sorted keys, prefixed with
`seams:wallet-authority-binding:v1|`, hashed with SHA-256, base64url output.
Wallet scoping is deliberate — the same provider subject across different
wallets must not collide. `WalletAuthAuthorityRef` pairs the digest with
`walletId` for cheap indexing only.

### Boundary Proofs

One proof union, purpose-bound (Decided Simplification 2; supersedes the five
per-operation unions `RegistrationAuthProof`, `WalletUnlockAuthProof`,
`StepUpAuthProof`, `RecoveryAuthProof`, and `KeyExportAuthProof` — migration
tracked in Phase 1 follow-ups).

```ts
type AuthOperationPurpose = 'registration' | 'unlock' | 'step_up' | 'recovery' | 'key_export';

type AuthMethodProof =
  | {
      kind: 'passkey_registration_credential';
      webauthnRegistration: WebAuthnRegistrationCredential;
    }
  | {
      kind: 'passkey_assertion';
      assertion: WebAuthnAuthenticationAssertion;
    }
  | {
      kind: 'email_otp_challenge';
      challengeId: EmailOtpChallengeId;
      otpCode: EmailOtpCode;
      appSessionJwt: AppSessionJwt;
    }
  | {
      kind: 'google_sso_registration';
      registrationAttemptId: GoogleEmailOtpRegistrationAttemptId;
      registrationOfferId: GoogleEmailOtpRegistrationOfferId;
      registrationCandidateId: GoogleEmailOtpRegistrationCandidateId;
      appSessionJwt: AppSessionJwt;
    };

type AuthBoundaryProof = {
  purpose: AuthOperationPurpose;
  proof: AuthMethodProof;
};
```

The boundary verifier enforces proof-to-purpose validity: the challenge or
assertion must have been minted for `purpose` (this check lives server-side in
the challenge record — the old five-union encoding never enforced it), and
invalid combinations (e.g. `passkey_assertion` for `recovery`,
`passkey_registration_credential` for anything but `registration`) are
rejected there. Call sites that want compile-time operation separation use a
phantom brand: `type ProofFor<P extends AuthOperationPurpose> =
Brand<AuthBoundaryProof, P>`.

### Registration Authority Resolution

Registration resolution runs before a wallet exists, so it emits pure
`AuthFactorIdentity`, discriminated on the factor branch — not a parallel
kind string and not a wallet-bound authority (Decided Simplifications 4
and 5; migration in Phase 3).

```ts
type RegistrationAuthorityResolution =
  | { factor: PasskeyFactorIdentity }
  | { factor: EmailOtpFactorIdentity; proofAuditRef: RegistrationAuthProofAuditRef };
```

Route handlers, D1 registration services, and worker messages may carry
`AuthBoundaryProof`. Registration builders receive the resolved factor
identity; finalize mints the wallet-auth-method binding and upgrades it to
`WalletAuthAuthority`, which is what post-finalize session builders receive.

### Registration Candidate Wallet

Registration candidates are separate from active wallet sessions. OTP wallet
name reroll uses this type until finalize mints the wallet.

```ts
type RegistrationWalletCandidate = {
  kind: 'registration_wallet_candidate';
  walletId: WalletId;
  registrationAttemptId: RegistrationAttemptId;
};

type ActiveWalletSession = {
  kind: 'active_wallet_session';
  // The bound authority carries walletId — no duplicate sibling field.
  authority: WalletAuthAuthority;
  walletSessionJwt: WalletSessionJwt;
};
```

### Ed25519 Authority

```ts
type ThresholdEd25519Authority = WalletAuthAuthority;

type ThresholdEd25519SessionPolicy = {
  version: 'threshold_session_v1';
  nearAccountId: NearAccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  authority: ThresholdEd25519Authority;
  routerKeyId: RouterEd25519KeyId;
  thresholdSessionId: ThresholdEd25519SessionId;
  signingGrantId: SigningGrantId;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  participantIds: readonly ParticipantId[];
  ttlMs: PositiveMilliseconds;
  remainingUses: PositiveUseCount;
};
```

### ECDSA Authority

```ts
type ThresholdEcdsaSessionAuthority = WalletAuthAuthority;

// Decided Simplification 6: no constant `reason` on single-use branches.
type EmailOtpAuthUse =
  | { kind: 'session'; reason: 'login' | 'sign' }
  | { kind: 'single_use_pending' }
  | { kind: 'single_use_consumed'; consumedAtMs: UnixMilliseconds };

type ThresholdEcdsaEmailOtpAuthContext = {
  policy: EmailOtpAuthPolicy;
  authority: EmailOtpAuthority;
  use: EmailOtpAuthUse;
};
```

`authority.factor.providerUserId` is the stable match key used by runtime warm
sessions, sealed sessions, key export, and signing-session auth lanes.

### Committed Lane

Generic over the authority branch; no top-level `kind` (Decided Simplification
1; migration in Phase 7 — current code has kinded branches and named
`RecordBacked*` variants).

```ts
type EcdsaCommittedLane<A extends WalletAuthAuthority = WalletAuthAuthority> = {
  chainTarget: ThresholdEcdsaChainTarget;
  // Wallet-bound: authority.walletId is the lane's wallet. No duplicate
  // sibling walletId field once the bound authority shape lands.
  authority: A;
  key: EcdsaKeyIdentity;
  session: SigningSessionAuthority;
  material: EcdsaReadyMaterial;
  durableRestore: EcdsaDurableRestoreRef;
};

type PasskeyEcdsaCommittedLane = EcdsaCommittedLane<PasskeyAuthority>;
type EmailOtpEcdsaCommittedLane = EcdsaCommittedLane<EmailOtpAuthority>;

// One record-backed extension, not one named type per method × curve × operation.
type RecordBacked<L> = L & { record: CommittedLaneSourceRecord };
type RecordBackedEcdsaCommittedLane<A extends WalletAuthAuthority = WalletAuthAuthority> =
  RecordBacked<EcdsaCommittedLane<A>>;

// Operation-specific invariants are real and stay — expressed as composition,
// not as named cross-product types. Export genuinely requires facts signing
// does not:
type EcdsaExportFacts = {
  participantIds: readonly ParticipantId[];
  relayerKeyId: EcdsaRelayerKeyId;
  expectedPublicKey: EcdsaPublicKeyB64u;
};

type EcdsaExportLane<A extends WalletAuthAuthority = WalletAuthAuthority> =
  RecordBackedEcdsaCommittedLane<A> & EcdsaExportFacts;
```

Narrowing works through the factor branch: `lane.authority.factor.kind ===
'email_otp'` narrows `A`, branch-specific functions declare the parameter
(`fn(lane: EcdsaCommittedLane<EmailOtpAuthority>)`), and mixed-auth lanes are
unrepresentable without fixtures. The Ed25519 committed signing/export lanes
follow the same generic pattern. Two orthogonal rules keep this honest:
required operation facts live in one composed extension per operation (so the
export invariants stay compile-enforced), and no new _named_ type is minted
per auth method × curve × operation × backing-record cell.

### Canonical Lane Inventory

Record inventory is a read-model layer that feeds committed-lane builders. It
does not replace `EcdsaCommittedLane`, and signing/export code should not accept
these raw fact groups directly.

```ts
type EcdsaLaneRecordFact<A extends WalletAuthAuthority = WalletAuthAuthority> =
  | {
      source: 'runtime_session_record';
      authority: A;
      key: EcdsaKeyIdentity;
      publicFacts: VerifiedEcdsaPublicFacts;
      chainTarget: ThresholdEcdsaChainTarget;
      session: SigningSessionAuthority;
      material: EcdsaMaterialRef;
      status: SigningSessionStatus;
      updatedAtMs: UnixMilliseconds;
    }
  | {
      source: 'sealed_restore_record';
      authority: A;
      key: EcdsaKeyIdentity;
      publicFacts: VerifiedEcdsaPublicFacts;
      chainTarget: ThresholdEcdsaChainTarget;
      session: SigningSessionAuthority;
      durableRestore: EcdsaDurableRestoreRef;
      status: SigningSessionStatus;
      updatedAtMs: UnixMilliseconds;
    }
  | {
      source: 'evm_family_shared_projection';
      authority: A;
      key: EcdsaKeyIdentity;
      publicFacts: VerifiedEcdsaPublicFacts;
      chainTarget: ThresholdEcdsaChainTarget;
      sourceChainTarget: ThresholdEcdsaChainTarget;
      session: SigningSessionAuthority;
      material: EcdsaMaterialRef;
      status: SigningSessionStatus;
      updatedAtMs: UnixMilliseconds;
    };

type EcdsaLaneGroupKeyFields = Pick<
  EcdsaKeyIdentity,
  'evmFamilySigningKeySlotId' | 'ecdsaThresholdKeyId' | 'signingRootId' | 'signingRootVersion'
>;

type EcdsaLaneGroupKey<A extends WalletAuthAuthority = WalletAuthAuthority> = {
  authority: A;
  key: EcdsaLaneGroupKeyFields;
};

type EcdsaLaneGroup<A extends WalletAuthAuthority = WalletAuthAuthority> = {
  key: EcdsaLaneGroupKey<A>;
  facts: NonEmptyArray<EcdsaLaneRecordFact<A>>;
};

type EcdsaCanonicalLaneSelection<A extends WalletAuthAuthority = WalletAuthAuthority> =
  | {
      kind: 'selected';
      lane: EcdsaCommittedLane<A>;
      supersededFacts: readonly EcdsaLaneRecordFact<A>[];
    }
  | { kind: 'no_current_lane' }
  | { kind: 'conflicting_key_material'; conflicts: readonly EcdsaLaneConflict[] }
  | { kind: 'ambiguous_material'; candidates: readonly EcdsaLaneGroupKey<A>[] };
```

`duplicate_records` remains a persistence/read-model diagnostic. Core signing
failures should name the domain failure: conflicting key material, ambiguous
material, or no current lane. Multiple facts in one group are expected after
repeated Email OTP step-up and should collapse to one canonical lane when
authority and material agree.

The group key intentionally excludes `VerifiedEcdsaPublicFacts`. Owner address,
key handle, public key, and participant-set drift are intra-group integrity
checks. A fact with the same authority and key slot but different public facts
fails as `conflicting_key_material`; it does not silently become a second
`ambiguous_material` group.

`requires_step_up` is a policy result derived after canonical lane selection.
The inventory selector returns a canonical current lane or an inventory-integrity
verdict; the caller's policy layer decides whether a selected lane's
spend/freshness state requires step-up.

### Companion Lane Selection

```ts
type EmailOtpEcdsaCompanionForEd25519Signing =
  | {
      kind: 'single_companion_lane';
      lane: EmailOtpEcdsaCommittedLane;
    }
  | {
      kind: 'chain_distinct_companion_lanes';
      primaryLane: EmailOtpEcdsaCommittedLane;
      lanes: readonly EmailOtpEcdsaCommittedLane[];
    };

type EmailOtpEcdsaCompanionSelection =
  | { kind: 'ready'; companion: EmailOtpEcdsaCompanionForEd25519Signing }
  | { kind: 'not_found' }
  | { kind: 'duplicate_chain_lanes'; chainTargetKey: string; count: number };
```

### Worker Material State

Material identity must move as one object. Core code should never read
`materialKeyId`, `bindingDigest`, or sealed refs independently from a flat
optional bag.

```ts
type Ed25519WorkerMaterialIdentity = {
  materialKeyId: Ed25519WorkerMaterialKeyId;
  bindingDigest: Ed25519WorkerMaterialBindingDigest;
  clientVerifyingShareB64u: Ed25519ClientVerifyingShareB64u;
};

type Ed25519WorkerMaterialState =
  | { kind: 'material_pending' }
  | {
      kind: 'sealed_material';
      identity: Ed25519WorkerMaterialIdentity;
      sealed: Ed25519SealedWorkerMaterial;
    }
  | {
      kind: 'loaded_material';
      identity: Ed25519WorkerMaterialIdentity;
      handle: Ed25519WorkerMaterialHandle;
    };
```

### Signing Budget State

Signing code should consume a parsed budget state. It must not proceed from
`budget_unknown`.

Budget state models whether an already-authorized session can spend. It does
not model Email OTP proof, provider user matching, or ECDSA auth lane selection.

```ts
type SigningBudgetAuthority =
  | {
      kind: 'ed25519_budget_authority';
      walletId: WalletId;
      thresholdSessionId: ThresholdEd25519SessionId;
      signingGrantId: SigningGrantId; // becomes capabilityGrantId in 90 B1
      authorityRef: WalletAuthAuthorityRef;
    }
  | {
      kind: 'ecdsa_budget_authority';
      walletId: WalletId;
      thresholdSessionId: ThresholdEcdsaSessionId;
      signingGrantId: SigningGrantId; // becomes capabilityGrantId in 90 B1
      chainTarget: EvmFamilyChainTarget;
      authorityRef: WalletAuthAuthorityRef;
    };

type SigningBudgetStatus =
  | { kind: 'available'; remainingUses: PositiveUseCount }
  | { kind: 'exhausted' }
  | { kind: 'requires_step_up' }
  | { kind: 'unavailable'; reason: SigningBudgetUnavailableReason };
```

---

Phase sections below are ordered by implementation priority (1, 7, 2, 3, 4,
4B, 4C, 5, 6, 8, 9, 10, 10A, 10B, 11). Numbering stays stable for
cross-reference history. Each phase carries its own tracking checklist; dated
notes live in the [journal](./refactor-82B-journal.md).

## Phase 1: Inventory And Type Boundary

Status: complete for the shared boundary model, compatibility inventory, and
July 3 review follow-ups.

Do:

- Inventory every `passkey_rp`, `rpId`, `authorityScope`, `emailOtpAuthContext`,
  `authSubjectId`, `googleEmailOtpRegistrationAttemptId`, and
  `challengeId` use in auth/session/signing code.
- Classify each use as one of:
  - boundary proof
  - stable authority
  - display data
  - legacy/obsolete
- Add `WalletAuthAuthority` and branch-specific parser/builders in shared
  domain code.
- Add request-boundary proofs for registration, unlock, step-up, recovery,
  and key export.
- Add `RegistrationWalletCandidate` and `ActiveWalletSession` so registration
  reroll cannot be validated as an active wallet session.
- Define the authority binding digest canonical serialization and hash
  algorithm.
- Document exact compatibility fields accepted at each request/persistence
  boundary, with a deletion task for every field.
- Add type fixtures rejecting proof IDs inside session/key/lane policy objects.
- Add type fixtures rejecting loose auth fields beside `WalletAuthAuthority`.

Exit criteria:

- The inventory is documented in this file.
- Boundary proofs and stable authority have separate exported types.
- Compatibility field lists exist only under boundary parser tasks.
- Static checks reject proof IDs in long-lived session policy objects.
- Static checks reject direct object-literal construction of session policies
  with `rpId`, `authSubjectId`, or provider proof fields outside authority
  branches.

Tracking:

- [x] Inventory all Passkey-specific shared authority assumptions.
- [x] Inventory all Email OTP proof shapes used past the proof boundary.
- [x] Inventory all wallet-session, signing-session, and recovery-grant
      identity fields.
- [x] Classify each raw/persistence/request shape as boundary-only or core.
- [x] Add request-boundary proof unions for registration, unlock, step-up,
      recovery, and key export.
- [x] Define the authority digest canonical serialization and hash algorithm.
- [x] List exact compatibility fields accepted at each boundary parser.

July 3 review follow-ups (Decided Simplifications 2, 3, 5):

- [x] Collapse the five per-operation proof unions into `AuthMethodProof` +
      `AuthOperationPurpose`, moving the proof-to-purpose check into the
      boundary verifier. Keep per-purpose phantom brands only where a call
      site genuinely needs compile-time separation.
- [x] Add the `seams:wallet-authority-binding:v1|` domain-separation prefix to
      the authority digest input and rename `WalletAuthAuthorityDigest` to
      `WalletAuthorityBindingDigest`. Delete local dev D1/IndexedDB state
      after the digest change instead of writing compatibility readers.
- [x] Rename `EmailOtpAuthorityProfile` to `EmailOtpFactorProfile`, drop its
      self-labeling `kind` field, and attach `email` to
      `EmailOtpFactorIdentity` rather than the wallet-bound authority.

## Phase 7: Replace Loose Session Shapes With One Canonical Committed Lane

Status: complete for the 82B implementation scope. Detailed threading notes:
[journal](./refactor-82B-journal.md#phase-7-committed-lane-threading-july-3-2026).

Implementation note: this phase runs immediately after Phase 1 creates shared
authority types. Phase 4, Phase 4B, and Phase 4C consume this object instead of
creating temporary selectors that later need deletion.

Do:

- Make `EcdsaCommittedLane` the single canonical authority object for ECDSA
  signing, export, step-up, and restore. The committed lane is created once from
  boundary data and then passed through core flows directly.
- Delete loose ECDSA session-authority shapes after the committed lane owns the
  signing path:
  - registration bootstrap-as-authority objects;
  - runtime session records used directly as authority;
  - durable sealed records used directly as authority;
  - warm capability records used directly as authority;
  - exact lane candidates that rebuild wallet-session authority;
  - wallet-session authority probes that search multiple stores.
- Replace all ECDSA signing/export/step-up inputs with the strict committed
  lane (see [Committed Lane](#committed-lane)).
- Move compatibility parsing into boundary readers only:
  - D1 route parsers;
  - IndexedDB record readers;
  - worker response parsers;
  - sealed-session readers.
- In each boundary reader, list the exact compatibility fields accepted and the
  planned deletion checkpoint for those fields.
- Delete core helpers that independently answer the same authority question:
  - `resolveEmailOtpSigningSessionAuthLane` style probing in signing flows;
  - broad `get*SessionRecordForSigning` authority reads;
  - candidate-to-authority rebuild helpers;
  - wallet-session JWT fallback readers;
  - runtime/warm-capability authority selectors.
- Keep diagnostics as observability only. Diagnostics must report why boundary
  parsing failed and must not drive signing control flow.
- Add source guards that fail on new authority-path imports of loose shapes once
  the committed-lane builder is in place.

Exit criteria:

- ECDSA signing/export/step-up functions accept `EcdsaCommittedLane`, not
  session records, sealed records, warm capability records, or lane candidates.
- Exactly one builder creates `EcdsaCommittedLane` from boundary data.
- `EcdsaCommittedLane` is the only object that combines auth authority, key
  identity, session authority, material readiness, and durable restore identity.
- No core authority path probes multiple stores to reconstruct wallet-session
  authority.
- Loose persistence/request shapes appear only in boundary parser files.
- Each loose persistence/request field has an explicit deletion checkbox in this
  plan.
- The generic error `Email OTP signing-session authority is unavailable` is
  replaced by typed boundary parse failures or committed-lane state failures.
- The committed-lane type surface is generic over authority: no top-level lane
  `kind` strings, and no named `RecordBacked{Method}{Curve}{Operation}` types.

Tracking:

- [x] Add the Email OTP committed-lane branch used by EVM/Tempo signing
      selection.
- [x] Add the Email OTP committed-lane builder from boundary-normalized signing
      selector data.
- [x] Make Email OTP EVM/Tempo ready selections branch-specific so a ready
      Email OTP selection cannot exist without its committed lane.
- [x] Rebuild the committed Email OTP lane after ECDSA reauth and same-operation
      record refresh, and reject stale committed-lane/material mismatches at
      the prepare boundary.
- [x] Move Email OTP ECDSA reauth/step-up selection onto committed lanes so
      core reauth state carries wallet-session authority, selected lane,
      candidate identity, material state, and durable/source metadata together.
- [x] Add the Passkey ECDSA committed-lane branch to the canonical
      `EcdsaCommittedLane` union.
- [x] Make all ECDSA signing/export/step-up functions accept
      `EcdsaCommittedLane` (threading details in the journal).
- [x] Delete runtime session records as authority inputs (see
      journal for the completed export/step-up slices).
  - Partial July 3 export-boundary slice complete: Email OTP key-export
    challenge requests now distinguish explicit fresh-login ECDSA export from
    committed signing-session export. ECDSA/Ed25519 committed export and
    transaction challenge surfaces require branch-specific
    `EmailOtpSigningSessionAuthLane` and no longer accept loose root
    `routeAuth` / optional `authLane` inputs.
  - Partial July 3 Ed25519 export-boundary slice complete: the Email OTP
    Ed25519 export committed lane no longer requires or compares a
    `record.walletSessionJwt` after wallet-session authority has been resolved;
    worker export uses `committedLane.walletSessionAuthority`.
  - Partial July 3 NEAR step-up slice complete: `signNear` builds
    `Ed25519SigningLane` from `EmailOtpEd25519SigningSessionAuthority` and the
    persisted record, with authority/session drift rejected at the builder
    boundary. NEAR transaction challenge preparation now carries the committed
    lane through signing and port assembly; only the final Email OTP session
    adapter extracts `committedLane.authLane`. The old
    `emailOtpEd25519AuthLaneFromRecord` fallback is deleted.
  - Partial July 3 NEAR execution-boundary slice complete: Email OTP NEAR
    transaction execution reads the Wallet Session bearer JWT from
    `Ed25519SigningLane.walletSessionAuthority`, not from the persisted
    Ed25519 session record.
  - Partial July 3 NEAR budget-status slice complete: NEAR pre-confirm
    budget-status auth now consumes `ResolvedRouterAbEd25519WalletSessionState`
    from the Router A/B Ed25519 wallet-session boundary instead of rebuilding
    Wallet Session JWT auth directly from the persisted Ed25519 record.
  - Partial July 3 Ed25519 Wallet Session authority slice complete:
    public NEAR funding, NEAR transaction execution, Email OTP ECDSA recovery
    companion lookup, and Ed25519 export now consume
    `parseRouterAbEd25519WalletSessionAuthorityFromRecord` instead of the
    deleted `walletSessionJwtFromPersistedEd25519Record` /
    `walletSessionAuthFromPersistedEd25519Record` helpers.
  - Partial July 3 Email OTP ECDSA signing-session slice complete: the public
    transaction challenge/refresh boundary now resolves a full
    `EmailOtpEcdsaSigningSessionAuthority` (`authLane` + bound authority) from
    the exact session record before core challenge/refresh logic runs, instead
    of passing a naked record-derived auth lane forward. The old
    `emailOtpEcdsaAuthLaneFromRecord` convenience wrapper is deleted; boundary
    code must consume the structured resolution result.
  - Partial July 3 EVM-family selection slice complete: normal Email OTP ECDSA
    selection keeps exact runtime records only as material/restore metadata and
    obtains signing-session authority through the injected authority resolver.
  - Partial July 3 ECDSA auth-lane helper deletion complete: the old
    `resolveEmailOtpEcdsaAuthLaneFromRecord` runtime-record helper is deleted.
    Remaining record-boundary consumers call
    `resolveEmailOtpEcdsaSigningSessionAuthorityFromRecord`, which returns the
    bound authority atomically or a typed rejection.
  - Partial July 3 ECDSA key-ref authority cleanup complete:
    `buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord` no longer copies a
    persisted `record.walletSessionJwt` into the key ref. Ready signer sessions
    now receive Wallet Session bearer auth from the committed lane or the
    explicit signing-wallet-session authority path only.
  - Partial July 3 ECDSA ready-material cleanup complete:
    `resolveReadyEvmFamilyEcdsaMaterial` now uses the already parsed
    Router A/B ECDSA signing-wallet session authority from the
    `runtime_validated` material branch instead of independently rebuilding
    Wallet Session auth from `input.record.walletSessionJwt`.
  - Complete July 3 final runtime-record slice: the ECDSA read model now builds
    lane auth through `resolveRouterAbEcdsaWalletSessionAuthFromRecord`, the
    deleted `walletSessionAuthInputFromPersistedThresholdSession` helper has no
    production references, and bootstrap persistence reads Wallet Session JWT
    authority only from `bootstrap.session.jwt`.
  - Partial July 3 bootstrap-as-authority cleanup complete:
    ECDSA activation now rejects bootstrap responses without `session.jwt` and
    no longer mirrors that JWT onto `thresholdEcdsaKeyRef`. Passkey bootstrap,
    login runtime-scope parsing, and registration sealing consume the session
    authority field directly instead of falling back to key-ref authority.
- [x] Delete durable sealed records as authority inputs.
  - Partial July 3 slice complete: sealed Email OTP ECDSA recovery metadata is
    normalized at the sealed-session boundary into
    `EmailOtpEcdsaSigningSessionAuthority` (`authLane` + bound
    `EmailOtpWalletAuthAuthority`). ECDSA selection consumes that authority
    result and no longer accepts durable auth-lane-only state as a committed
    lane.
  - Partial July 3 sealed-authority carrier slice complete: accepted sealed
    recovery records now carry branch-specific `WalletAuthAuthority` built at
    the sealed-record parser boundary. Email OTP sealed signing-session auth,
    sealed Email OTP restore contexts, and exact sealed-record lookup consume
    the normalized authority instead of rebuilding identity from loose
    `providerSubjectId` / `credentialIdB64u` sibling fields.
  - Complete July 3 final durable-authority slice: reusable Ed25519 durable
    material restore now resolves Wallet Session authority through
    `parseRouterAbEd25519WalletSessionAuthorityFromRecord` before exposing
    bearer auth to login warm-session material.
- [x] Delete warm capability records as authority inputs.
  - Partial July 3 slice complete: warm Email OTP ECDSA capability reads now
    return `EmailOtpEcdsaSigningSessionAuthority` from the warm-capability
    boundary. ECDSA selection consumes the bound authority result instead of a
    warm record or naked auth lane.
  - Partial July 3 Ed25519 slice complete: warm Email OTP Ed25519 capability
    reads now return `EmailOtpEd25519SigningSessionAuthority`; the warm reader
    no longer exposes the generic `resolveEmailOtpSigningSessionAuthLane`
    surface.
  - Partial July 3 Router A/B ECDSA cleanup complete: the wallet-session auth
    resolver no longer treats warm capability records as an alternate authority
    source when a selected session record is stale.
  - Partial July 3 ECDSA seal-transport hardening complete:
    `resolveEcdsaSealTransport` now rejects Email OTP ECDSA records unless the
    warm read model resolved record-owned Wallet Session JWT auth first.
  - Partial July 3 warm authority resolver cleanup complete: warm Email OTP
    Ed25519/ECDSA signing-session authority resolvers now extract JWTs only
    through record-owned auth guards instead of optional auth projections.
  - Partial July 3 warm Wallet Session parser slice complete: warm capability
    read/status/provisioning code now consumes
    `parseRouterAbEd25519WalletSessionAuthorityFromRecord` and
    `resolveRouterAbEcdsaWalletSessionAuthFromRecord`; the raw
    `warmCapabilities/walletSessionAuthBoundary.ts` JWT helper is deleted.
  - Partial July 3 reusable ECDSA bootstrap slice complete:
    `buildReusableEcdsaBootstrapResult` now requires the warm ECDSA capability
    auth branch to be `ready` and uses that resolved Wallet Session JWT
    directly. A persisted ECDSA record JWT can no longer backfill reusable
    bootstrap auth when warm capability auth is missing.
  - Partial July 3 bootstrap persistence cleanup complete:
    ECDSA signer-row persistence no longer reads the obsolete
    `keyRef.walletSessionJwt` fallback while deriving signer identity from the
    role-local ready record.
  - Partial July 3 Ed25519 warm-authorization cleanup complete:
    `parseWarmEd25519SigningSessionAuthorizationFromRecord` now consumes
    `parseRouterAbEd25519WalletSessionAuthorityFromRecord` instead of reading
    `record.walletSessionJwt`, `thresholdSessionId`, and `signingGrantId`
    independently. Focused coverage rejects JWT claims that do not match the
    Ed25519 record identity.
  - Complete July 3 final warm-record audit: warm Ed25519/ECDSA capability
    paths expose parsed record-owned authority or an unavailable branch; no
    production helper remains that backfills Wallet Session auth from a warm
    record as a fallback source.
- [x] Delete exact lane candidate authority rebuilders.
  - Complete July 3 slice: Passkey ECDSA committed-lane authority is rebuilt
    from the selected session record's role-local auth method, not from the
    selected lane candidate. Source guards reject reintroducing
    `passkeyAuthorityFromCandidate`; Email OTP resolver-backed lanes obtain
    bound authority from warm/sealed boundaries rather than candidate auth.
- [x] Delete wallet-session authority probes across multiple stores (see
      journal).
  - Partial July 3 NEAR step-up slice complete: NEAR signing resolves
    wallet-session authority through the Ed25519 committed-authority resolver
    instead of probing the record for a naked wallet-session JWT auth lane, and
    challenge issuance receives a committed lane until the adapter boundary.
  - Partial July 3 NEAR execution-boundary slice complete: the final NEAR
    transaction signing boundary now uses the prepared Email OTP committed lane
    as its wallet-session authority source, so a refreshed or stale persisted
    record cannot silently replace the authority selected for step-up.
  - Partial July 3 seal-transport slice complete: `UiConfirmManager` no longer
    probes sealed/session records for fallback Wallet Session JWTs when building
    warm-session seal transport. Email OTP transport requires an explicit
    wallet-session JWT at the boundary; Passkey transport falls back to cookie
    auth without reading persisted JWT siblings.
  - Partial July 3 sealed metadata authority slice complete: passkey sealed
    restore metadata construction now derives JWT restore auth through the
    Ed25519/ECDSA record-owned Wallet Session authority parsers instead of
    reading raw `walletSessionJwt` siblings directly from runtime records.
  - Partial July 3 route-plan boundary slice complete:
    `buildEmailOtpRoutePlan` now requires a concrete `EmailOtpAuthLane` at the
    type boundary, and app/cookie callers must resolve the lane before route
    plan construction.
  - Partial July 3 Ed25519 export-boundary slice complete: Email OTP Ed25519
    export no longer treats `record.walletSessionJwt` as a second authority
    fact inside the committed export lane after the wallet-session authority
    resolver has built the lane.
  - Partial July 3 auth-projection slice complete: Email OTP app-session JWT
    and route-auth projection helpers now require a concrete
    `EmailOtpAuthLane`; missing auth is rejected by type fixtures instead of
    being treated as an empty JWT or missing bearer route auth.
  - Partial July 3 seal-transport slice complete: warm-session seal transports
    now branch on auth method; Email OTP transport requires an explicit
    `walletSessionJwt` at the type boundary, and `UiConfirmManager` refuses
    persisted sealed/runtime record JWT fallback whenever the transport is
    Email OTP. Passkey restore keeps the existing explicit-or-persisted path.
  - Partial July 3 seal-transport read-model slice complete: Email OTP ECDSA
    seal transport resolution returns `null` when the selected warm record does
    not carry record-owned Wallet Session JWT auth, so missing authority is
    rejected before sealed-session application.
  - Partial July 3 ECDSA reconnect slice complete: reconnect material now
    carries verified ECDSA wallet-session auth from the boundary builder, and
    reconnect planning consumes that material instead of selecting a JWT from
    the persisted record.
  - Partial July 3 ECDSA login route-plan slice complete: core Email OTP ECDSA
    login now requires a committed `EmailOtpRoutePlan` and rejects raw
    `appSessionJwt`, loose `routeAuth`, and `sessionKind` inputs. The
    `emailOtpPublic` facade is the boundary adapter that builds the plan for
    public unlock flows before calling the coordinator.
  - Partial July 3 Router A/B ECDSA single-record slice complete:
    `resolveRouterAbEcdsaWalletSessionAuthFromRecord` now resolves JWT
    authority only from the selected record's explicit `walletSessionJwt`.
    It no longer probes the warm capability store, stale records without a JWT
    fail as `missing_wallet_session_jwt`, and type fixtures reject
    `source: 'warm_capability'`.
  - Partial July 3 Router A/B ECDSA authority-identity slice complete:
    `resolveRouterAbEcdsaWalletSessionAuthFromRecord` now returns an atomic
    `RouterAbEcdsaWalletSessionAuthority` carrying the wallet-session JWT and
    exact `EcdsaSessionIdentity`. Passkey committed-lane authority, Email OTP
    auth-lane resolution, and Router A/B ECDSA HSS session parsing consume that
    identity instead of recombining JWT authority with sibling record fields.
  - Partial July 3 warm authority missing-JWT slice complete: a matching warm
    Email OTP ECDSA lane with no record-owned Wallet Session JWT no longer
    resolves to signing-session authority.
  - Partial July 3 EVM-family exact-record selection slice complete:
    record-backed Email OTP ECDSA selection no longer builds its
    wallet-session authority directly from the runtime record.
  - Partial July 3 runtime-record ECDSA authority slice complete: EVM-family
    selection and public signing-session refresh no longer pass a naked
    `EmailOtpAuthLane` rebuilt from a runtime ECDSA record.
  - Partial July 3 ECDSA key-ref authority cleanup complete: runtime ECDSA
    session records can still build key/material refs, but those refs no longer
    carry a duplicate Wallet Session JWT authority field.
  - Partial July 3 ECDSA ready-material authority cleanup complete: ready
    EVM-family material resolution now consumes parsed Router A/B ECDSA
    signing-wallet session auth from runtime-validated material rather than
    probing the runtime record for a Wallet Session JWT sibling.
  - Partial July 3 ECDSA bootstrap JWT fallback cleanup complete: clean
    bootstrap consumers now read Wallet Session JWT authority from
    `bootstrap.session.jwt`; `thresholdEcdsaKeyRef.walletSessionJwt` is no
    longer a fallback authority source in activation, Passkey bootstrap, login,
    or registration sealing.
  - Partial July 3 Ed25519 login route-plan slice complete: core Email OTP
    Ed25519 fresh login now follows the same rule. Raw unlock auth is accepted
    only by the `emailOtpPublic` facade and converted into `EmailOtpRoutePlan`
    before reaching `EmailOtpEd25519Warmup`.
  - Partial July 3 ECDSA registration route-plan slice complete: core Email
    OTP ECDSA registration/enroll now requires a committed registration
    `EmailOtpRoutePlan` and rejects raw `appSessionJwt`, loose `routeAuth`,
    and `sessionKind` inputs. Public iframe/SDK registration calls still enter
    through `emailOtpPublic`, which builds the registration route plan before
    invoking the coordinator.
  - Partial July 3 Ed25519 HSS ownership slice complete: finalization request
    boundaries now keep client-owned staged evaluator artifacts limited to
    `contextBindingB64u` and `stagedEvaluatorArtifactB64u`; responded server
    sessions carry server eval state through persisted and durable storage
    before finalization.
  - Partial July 3 Ed25519 Wallet Session parser slice complete: the remaining
    SDK Ed25519 callers no longer read Wallet Session JWTs through
    `walletSessionAuthBoundary.ts`; parsed Router A/B wallet-session authority
    validates the JWT claims against the selected Ed25519 record before any
    signer, funding, export, or recovery path receives the bearer token.
  - Partial July 3 warm capability Wallet Session parser slice complete: warm
    Ed25519/ECDSA capability readers and reconnect planning no longer use a
    raw persisted warm-record JWT accessor. They resolve Wallet Session
    authority through the curve-specific Router A/B boundary parsers before
    exposing bearer auth to downstream signing/provisioning code.
  - Partial July 3 seal-transport curve-local slice complete: passkey
    persisted seal transport no longer probes both Ed25519 and ECDSA records
    for a Wallet Session JWT. `UiConfirmManager` resolves persisted transport
    auth through a curve-local helper, while Email OTP transport remains
    explicit Wallet Session JWT only.
  - Complete July 3 final authority-probe audit: the remaining direct
    `record.walletSessionJwt` reads are boundary parsers/classifiers,
    diagnostics, or persistence writes. Core signing/export/read-model paths
    consume committed lanes or parsed Router A/B authority.
- [x] Delete the Email OTP ECDSA wallet+chain session-record getter from the
      EVM-family dependency surface and browser assembly.
- [x] Move Email OTP ECDSA export authority onto record-backed committed lanes.
- [x] Remove loose `record` + `authLane` from the ECDSA export recovery-flow
      dependency surface.
- [x] Add deletion checkpoints for every accepted loose compatibility field.
- [x] Keep diagnostics observability-only.
      `ecdsaSelection.typecheck.ts` and `thresholdAdmission.typecheck.ts` reject
      diagnostics as ready signer material.

July 3 review follow-ups (Decided Simplification 1):

- [x] Convert `EcdsaCommittedLane` from a kinded two-branch union to the
      generic `EcdsaCommittedLane<A extends WalletAuthAuthority>`; delete the
      top-level `passkey_ecdsa_committed_lane` /
      `email_otp_ecdsa_committed_lane` kind strings and discriminate on
      `authority.factor.kind`.
  - Partial July 3 slice complete: the exported `EcdsaCommittedLane` type is
    authority-parameterized, and the ECDSA committed-lane objects no longer
    carry the top-level method-kind strings.
  - Partial July 3 direct-authority slice complete: Passkey and record-backed
    Email OTP ECDSA committed lanes now carry direct bound `authority` fields,
    and type fixtures reject committed Email OTP lanes without bound authority
    or stale durable-exact auth-lane-only state.
  - Partial July 3 resolver-backed authority slice complete: Email OTP ECDSA
    reauth lanes can be committed from a boundary-resolved
    `EmailOtpEcdsaSigningSessionAuthority` when the exact runtime record is
    unavailable. That authority object carries both the wallet-session auth
    lane and bound `EmailOtpWalletAuthAuthority`; candidate auth is not used as
    an authority source.
  - Partial July 3 selected-path slice complete: ready/reauth EVM-family ECDSA
    signing selection constructors and prepared-signing metadata derive the
    selected auth method from `committedLane.authority.factor.kind`, with
    fixtures rejecting mismatched `authMethod`/committed-lane pairs.
  - July 3 generic-shape slice complete: the exported committed-lane, ready-lane,
    and record-backed lane aliases now compose from the same
    `EcdsaCommittedLane<A extends WalletAuthAuthority>` shape. Type fixtures
    reject assigning an Email OTP committed lane to a Passkey-parametrized lane.
- [x] Collapse the named `RecordBacked*CommittedLane` types (Email OTP/Passkey
      × ECDSA/Ed25519 × signing/export) into one `RecordBacked<L>` extension
      plus one composed operation-facts extension per operation
      (`EcdsaExportLane<A>`). Operation invariants stay compile-enforced; only
      the per-cell named types go.
  - Complete July 3 slice: ECDSA selection now defines the generic
    `RecordBacked<L>` primitive plus `RecordBackedEcdsaCommittedLane<A>`. ECDSA
    export material composes `EcdsaExportLane<A>` from that helper, ECDSA key
    export ports consume `EcdsaExportLane<EmailOtpWalletAuthAuthority>` and
    `ReadyEcdsaExportLane<PasskeyWalletAuthAuthority>` directly, and Email OTP
    companion selection consumes
    `RecordBackedEcdsaCommittedLane<EmailOtpWalletAuthAuthority>`.
- [x] Apply the same generic pattern to the Ed25519 committed signing/export
      lanes before any new named variant is added.
  - Complete July 3 slice: Ed25519 signing/export committed-lane objects no
    longer carry top-level method-kind strings, and the old
    `RecordBackedEmailOtpEd25519*CommittedLane` aliases are replaced by
    `RecordBackedEd25519CommittedLane<Record, Facts>`, `Ed25519SigningLane`, and
    `Ed25519ExportLane`.
  - July 3 bound-authority slice complete: Email OTP Ed25519 signing/export
    committed lanes now carry the bound `EmailOtpWalletAuthAuthority` from the
    normalized session record, and type fixtures reject record-backed Ed25519
    committed lanes without authority.
  - July 3 signing-session authority slice complete: `buildEd25519SigningLane`
    now requires `EmailOtpEd25519SigningSessionAuthority`, rejects authority
    drift against the normalized record, and type fixtures reject loose
    `authLane` construction.
- [x] Update fixtures and source guards to reject reintroduction of
      method-kinded lane types and deleted per-cell record-backed committed-lane
      aliases.
- [x] Delete duplicated `walletId` sibling fields from remaining objects that
      carry a bound authority (`EcdsaCommittedLane`, remaining lane/read-model
      projections); the bound authority is the single
      source of truth. Lane builders validate nested lane/key/candidate wallet
      facts against the authority binding before committed objects are built.
  - Partial July 3 slice complete: `ActiveWalletSession` no longer carries a
    sibling `walletId`, and shared type fixtures reject adding it back.
  - Partial July 3 authority-ref API slice complete: shared digest/ref builders
    derive `walletId` from the bound `WalletAuthAuthority` and type fixtures
    reject the old sibling helper input.
  - Partial July 3 ECDSA lane slice complete: committed ECDSA lanes now carry
    direct bound authority, and ready/reauth selected-path metadata derives the
    auth method from `committedLane.authority.factor.kind`.
  - Partial July 3 validation slice complete: ECDSA committed-lane builders now
    reject mismatches between `committedLane.authority.walletId`,
    `committedLane.lane.key.walletId`, and the selected candidate `walletId`
    before the candidate is discarded at the builder boundary. Source guards
    keep the assertion in place.
  - Complete July 3 guard slice: `EcdsaCommittedLane` has no direct sibling
    `walletId`, shared authority refs/digests derive wallet identity from the
    bound authority, and type fixtures reject reintroducing duplicate wallet
    facts on active wallet sessions, authority helpers, and ECDSA committed
    lanes.
  - July 3 ECDSA candidate-copy slice complete: committed ECDSA lanes no
    longer carry the selected lane candidate as a stored field. Builders still
    validate candidate/authority/lane agreement at the boundary, while
    committed-lane consumers read auth method from `authority.factor.kind` and
    selected identity from the committed lane itself.
  - July 3 sealed-recovery authority slice complete: normalized sealed recovery
    records no longer carry duplicate Passkey `rpId`/`credentialIdB64u` or
    Email OTP `providerSubjectId`/`emailHashHex` siblings beside their bound
    authority. Durable available-lane auth binding and sealed restore writers
    now derive those facts from `record.authority`; raw persisted fields remain
    accepted only in the sealed-record normalization boundary.
  - July 3 Ed25519 policy slice complete: SDK and server wallet-session
    `ThresholdEd25519SessionPolicy`/`Ed25519SessionPolicy` now serialize a
    bound `WalletAuthAuthority` as the single wallet-binding source; root
    `walletId` and reusable `authorityScope` are removed from the wallet-session
    policy shape. Registration Ed25519 session-policy request boundaries now
    reject `authorityScope` and require the bound authority object, while
    threshold persistence still derives legacy `authorityScope` from the bound
    authority where token claims require it.

## Phase 2: Ed25519 Session Policy Conversion

Status: complete for wallet-session policy conversion. Registration Ed25519
session-policy request boundaries now require bound `WalletAuthAuthority`;
remaining registration work is deleting obsolete AuthService-era authority
branches rather than supporting old request shapes.

Do:

- Replace `ThresholdEd25519AuthorityScope` in Ed25519 session policy with stable
  `ThresholdEd25519Authority`.
- Delete or boundary-confine `authorityScope` once equivalent stable authority
  parsing exists.
- Keep request compatibility parsing at route/persistence boundaries only.
- Update:
  - `packages/sdk-server-ts/src/core/types.ts`
  - `packages/sdk-server-ts/src/core/ThresholdService/validation.ts`
  - `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
  - `packages/sdk-server-ts/src/router/thresholdEd25519RequestValidation.ts`
  - `packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts`
  - `packages/sdk-web/src/core/signingEngine/threshold/ed25519/connectSession.ts`
  - Ed25519 warm-session bootstrap and recovery callers.
- Replace "passkey authority" checks with exhaustive switches over authority.
- Rename passkey-only helpers so their names say `Passkey`.

Exit criteria:

- Ed25519 session policy has one authority field.
- OTP session policy never contains `rpId`.
- Passkey code accesses `rpId` only inside
  `authority.factor.kind === 'passkey'`.
- Email OTP code accesses provider identity only inside
  `authority.factor.kind === 'email_otp'`.

Tracking:

- [x] Replace Passkey-only Ed25519 session policy inputs with
      `WalletAuthAuthority`.
- [x] Move `rpId` to the Passkey authority branch only, with type fixtures
      rejecting root `rpId` fields in session, wallet-session, MPC, key, and
      presign state.
- [x] Move Email OTP proof IDs out of reusable session policy state.
- [x] Add branch-specific Ed25519 session policy builders.
- [x] Delete the method-tagged Ed25519 wallet-auth proof projection from the
      session mint path (`AuthorizedThresholdEd25519SessionAuth` union).
- [x] Replace SDK and server Ed25519 wallet-session policy wire shape
      `walletId + authorityScope` with one bound `WalletAuthAuthority`.
- [x] Update wallet-session route parsers and threshold session minting to
      derive stored Ed25519 `authorityScope` from the bound authority at the
      persistence boundary.
- [x] Upgrade D1 wallet-registration finalized session policies from
      registration authority to bound `WalletAuthAuthority` before session mint.
- [x] Thread the bound `WalletAuthAuthority` through Ed25519 HSS registration
      finalize, registration keygen, and registration-session minting. These
      boundaries now reject the old loose `authorityScope` input and derive
      threshold-store/admission `authorityScope` projections only after the full
      wallet authority has been validated.
- [x] Reject `authorityScope` in D1 and AuthService-era Ed25519 registration
      session-policy request validators; require the requested bound
      `WalletAuthAuthority` to match the authority resolved from the finalized
      registration or verified wallet binding.
- [x] Delete the duplicated AuthService-era
      `validateThresholdEd25519SessionPolicyBindings` authority validator; the
      passkey wallet-binding session-policy resolver now validates the raw
      policy authority before building `Ed25519SessionPolicy`.

July 3 review follow-ups (Decided Simplification 4, gated on 90 F2):

- [x] Audit `WalletAuthMethodId` durability before the restructure:
      wallet-auth-method rows must be durable and unique per (wallet, factor)
      across re-enrollment for `bindingId` to enter the atomic authority
      object; otherwise drop the field from the target shape.
- [x] Inventory the shapes that currently read `authority.rpId` and classify
      each as verifier (reads `authority.verifier.rpId` after the
      restructure) or identity-only (loses the field), before the
      restructure lands.
  - Audit result: keep `bindingId`. `WalletAuthMethodId` is now a shared
    domain brand, and the server D1/in-memory store derives it through the
    shared `walletAuthMethodRecordId` helper. The D1 schema already pins
    passkey ids to `passkey:{rpId}:{credentialIdB64u}` and Email OTP ids to
    `email_otp:{walletId}:{emailHashHex}`, with matching unique indexes.
    Passkey reuse across wallets is rejected at the tenant store; Email OTP
    ids are wallet-scoped and survive registration/enrollment refreshes.
  - July 3 supporting SDK slice complete: public `WalletAuthMethodBinding`
    values now derive ids through `walletAuthMethodBindingId`, and unit
    coverage compares that formula against the server D1 store helper.
  - Verifier reads moved to `authority.verifier.rpId` for SDK Ed25519
    wallet-session policy and passkey warmup/reauth builders. Boundary and
    pre-finalize verifier reads that stay outside `WalletAuthAuthority`:
    registration intent passkey authority scopes and Router API bootstrap
    grants. These are request/proof boundary shapes, not post-finalize wallet
    authority.
  - Identity-only consumers: none of the current `authority.rpId` reads. Pure
    identity consumers must use `AuthFactorIdentity`.
- [x] Restructure `WalletAuthAuthority` into the wallet-bound
      factor/verifier shape and add `AuthFactorIdentity`; 90 F2 owns any
      follow-up vocabulary alignment, while 82B owns the bound authority shape,
      digest preimage, and strict parser behavior.
  - Partial July 3 slice complete: the Passkey branch is now wallet-bound
    (`walletId` + `factor` + `verifier.rpId` + `bindingId`), flat Passkey
    authorities are rejected by the shared parser, and SDK Passkey Ed25519
    session policy/warmup code reads `authority.verifier.rpId`.
  - Partial July 3 guard complete: authority-ref/digest construction now
    rejects a sibling `walletId` that disagrees with a bound Passkey
    authority's `walletId`, and the shared Passkey parser rejects missing or
    mismatched `bindingId` values instead of deriving over bad raw input.
  - Partial July 3 access cleanup complete: SDK signing/session consumers no
    longer read flat Email OTP authority `provider` or `providerUserId`
    fields directly; they use shared authority/context accessors so the Email
    OTP branch can move under `authority.factor` without another consumer
    sweep.
  - July 3 Email OTP bound-authority slice complete: the Email OTP branch is
    now `walletId` + `factor` + `verifier.emailHashHex` + `bindingId`;
    `parseEmailOtpWalletAuthAuthority` rejects the old flat provider shape;
    Email OTP registration, unlock, ECDSA login/enroll, Ed25519 warm-up,
    sealed restore, EVM/Tempo signing refresh, and ECDSA export flows carry
    `emailHashHex` from the wallet-auth-method binding or sealed metadata.
  - July 3 digest slice complete: the binding digest preimage is the bound
    `WalletAuthAuthority` object itself, with the bound `walletId` inside the
    preimage and the `seams:wallet-authority-binding:v1|` prefix.
  - July 3 authority-ref API slice complete: shared digest/ref builders now
    accept only the bound `WalletAuthAuthority` and derive `walletId` from it;
    type fixtures reject the old sibling `walletId + authority` helper input.
  - July 3 Ed25519 policy slice complete: wallet-session policies consume the
    bound authority on both SDK and server route boundaries; registration
    pre-finalize request scopes remain boundary-only.
  - Still open: remove sibling `walletId` duplication from authority consumers
    where the bound object is authoritative, delete local dev persisted state
    created with the old digest input, and finish the 90 F2 vocabulary landing
    across remaining non-wallet-session route/session surfaces.
- [x] Enforce the consumption rule with fixtures: reject `AuthFactorIdentity`
      in post-finalize session/lane/export state, and reject wallet-bound
      `WalletAuthAuthority` in pre-finalize registration state.
  - Partial July 3 slice complete: shared type fixtures reject flat Passkey and
    Email OTP authorities, missing Passkey authority `bindingId`, mixed
    Passkey/Email OTP sibling fields, and wallet-bound verifier fields on pure
    factor identities.
  - July 3 fixture slice complete: ECDSA committed-lane and export-lane
    typechecks reject pure `AuthFactorIdentity` / `EmailOtpFactorIdentity` in
    post-finalize state, and registration ceremony typechecks reject
    wallet-bound `WalletAuthAuthority` in pre-finalize registration state.

## Phase 3: Registration Authority Resolution

Status: implemented for the authority-resolution cleanup tracked in 82B. Notes:
[journal](./refactor-82B-journal.md#phase-3-registration-authority-july-3-2026).

Do:

- Convert registration intent auth proof into stable authority once in D1
  registration services.
- Move these fields out of long-lived registration/session identity:
  - `challengeId`
  - `googleEmailOtpRegistrationAttemptId`
  - `googleEmailOtpRegistrationOfferId`
  - `googleEmailOtpRegistrationCandidateId`
- Store proof/audit references separately from session/key identity.
- Update registration signing-key derivation so `nearEd25519SigningKeyId` is
  derived from stable authority.
- Preserve wallet-name reroll for OTP registration by validating candidate
  ownership against the registration attempt, then minting the chosen wallet ID.
- Make registration services accept `RegistrationWalletCandidate` for candidate
  validation and `ActiveWalletSession` only after finalize.

Exit criteria:

- OTP registration can reroll wallet IDs before finalization.
- Stable Email OTP authority survives unlock and step-up auth.
- Registration attempt IDs never appear in Ed25519 session policy digests.
- No registration candidate path calls an active-wallet-session validator.

Tracking:

- [x] Normalize registration authority once at D1/router request boundaries.
- [x] Keep Email OTP registration proof data at the registration-proof
      boundary; the only pre-proof cache key is the separate
      `email_otp_pre_auth` selector.
- [x] Persist stable Email OTP provider subject identity for later sessions.
- [x] Delete AuthService-era registration authority branches (delete
      candidates listed below). Focused guard evidence on July 3:
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts
./unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --grep
"Cloudflare D1 runtime does not revive legacy registration
modes|AuthService wallet registration does not revive legacy
registration modes|AuthService-backed Router API route harnesses stay
deleted|D1 Router API service factory does not revive a flat
AuthService-shaped facade" --reporter=line` passes.
- [x] Delete the AuthService-era Ed25519 registration session-policy authority
      validator duplicate; remaining AuthService-era modules listed below still
      need deletion or public-facade ownership review.
- [x] Keep routes on the public AuthService facade during the mechanical
      module split; route-source scan for `core/authService/*` imports under
      `packages/sdk-server-ts/src/router` returns no hits.
- [x] Record split AuthService internals that remain as D1 cleanup delete
      candidates: `authService/walletRegistrationPlanning.ts`,
      `authService/registrationThresholdHelpers.ts`,
      `authService/emailOtpChallengeProof.ts`,
      `authService/emailOtpChallengeVerification.ts`,
      `authService/emailOtpRegistrationEnrollment.ts`,
      `authService/googleEmailOtpRegistration.ts`,
      `authService/emailOtpUnlock.ts`,
      `authService/thresholdEcdsaOperations.ts`, and
      `authService/thresholdEcdsaKeyInventory.ts`. Tests may still cover
      AuthService-owned behavior directly, but route code must not import
      these modules.

July 3 review follow-ups (Decided Simplifications 4 and 5):

- [x] Re-discriminate `RegistrationAuthorityResolution` on the factor branch
      and emit pure `AuthFactorIdentity` (resolution runs pre-wallet); delete
      the `resolved_passkey_authority` / `resolved_email_otp_authority` kind
      strings. Finalize upgrades the factor identity to `WalletAuthAuthority`
      when the wallet-auth-method binding is minted.
  - July 3 source audit complete: the stale `resolved_passkey_authority` and
    `resolved_email_otp_authority` discriminants have no code hits, and the
    target type is documented as `{ factor: AuthFactorIdentity }` with the
    Email OTP proof audit reference on the email branch only.

## Phase 4: ECDSA Email OTP Session Authority

Status: complete for the web Email OTP ECDSA authority slice. Broader
end-to-end registration, unlock, sign, and export coverage is deferred to
Phase 10.

Do:

- Replace `ThresholdEcdsaEmailOtpAuthContext.authSubjectId` with
  `authority: EmailOtpAuthority` and `use: EmailOtpAuthUse`.
- Make `EmailOtpEcdsaSessionRecord` require:
  - `source: 'email_otp'`
  - `thresholdSessionKind: 'jwt'`
  - `walletSessionJwt`
  - `emailOtpAuthContext.authority`
  - `emailOtpAuthContext.use`
- Keep `EmailOtpEcdsaSigningSessionAuthLaneResolver` required for ECDSA
  selection.
- Update sealed-session records so Email OTP ECDSA restore always contains
  provider subject identity and wallet-auth-method email hash identity.
- Add tests for:
  - runtime session auth lane resolution
  - durable sealed auth lane resolution
  - missing provider subject rejected at parse time

Exit criteria:

- Tempo and EVM signing after OTP unlock use the same Email OTP stable authority
  as registration.
- ECDSA Email OTP authority never carries budget status, budget reservations, or
  budget finalization state.

Tracking:

- [x] Remove the OTP registration ECDSA manual persistence bypass and route
      registration through the canonical Email OTP ECDSA commit path.
- [x] Rename the Email OTP ECDSA commit input from `primaryChain` to
      `chainTarget`.
- [x] Add diagnostics for Email OTP ECDSA commit and exact authority
      resolution failures.
- [x] Make Email OTP ECDSA registration, unlock, recovery, export, and step-up
      carry the same stable authority context.
- [x] Delete multi-store ECDSA authority probing from the EVM/Tempo signing
      lane path by committing the selected Email OTP lane before signing.
- [x] Replace generic EVM/Tempo Email OTP committed-lane selector errors with
      typed `EmailOtpEcdsaCommittedLaneStateError` parse/state failures.
- [x] Replace remaining generic Email OTP signing-session errors in route-plan
      and export helpers with branch-specific signing-session state failures.
- [x] Rename fresh Email OTP ECDSA export domain state to `providerUserId`,
      with `authSubjectId` confined to the worker-command boundary.
- [x] Require ECDSA login callers to choose an `EmailOtpEcdsaProviderIdentity`
      branch, with record-backed refresh/export/companion flows carrying an
      explicit provider user and stale `authSubjectId` rejected.
- [x] Normalize Email OTP recovery-code rotation and device-escrow worker
      results at the SDK boundary so public/core material uses
      `providerUserId`, while worker wire payloads still parse
      `authSubjectId` only inside response parsers.
- [x] Require Email OTP sealed ECDSA/Ed25519 restore metadata and fresh ECDSA
      export material to carry `emailHashHex`, sourced from the bound
      wallet-auth-method authority or durable sealed restore metadata.
  - Partial July 3 export-grant slice complete: `ExportKeysAuthorization` now
    keeps `rpId` only on the Passkey branch. Email OTP key export
    authorization is wallet/challenge/scope bound, while Passkey export remains
    wallet/RP scoped.
  - Partial July 3 Ed25519 recovery-code digest slice complete:
    `recoveryCodeBindingDigestForEmailOtpMaterial` now uses a v2 digest domain
    and `providerUserId` in its canonical input; stale `authSubjectId` remains
    only on worker wire commands.
  - Partial July 3 Ed25519 warm-session provider identity slice complete:
    Email OTP Ed25519 login now derives a trimmed `providerUserId` directly
    from the committed route plan/session instead of branding it through the
    stale `AuthSubjectId` helper.

July 3 review follow-ups (Decided Simplification 6):

- [x] Drop the constant `reason: 'sign'` field from the
      `single_use_pending` and `single_use_consumed` branches of
      `EmailOtpAuthUse`; update the persisted-record parser and fixtures.

## Phase 4B: Exact Companion Lane Typing

Status: complete for the Email OTP Ed25519 companion-selection path. Broader
Passkey companion-lane reuse remains out of this slice unless a Passkey flow
starts sharing this selector.

Recent OTP step-up signing exposed a missing type distinction: Ed25519 reauth
needs the current concrete ECDSA companion for the same wallet-bound Email OTP
authority. The stale Ed25519 signing grant is no longer part of companion lane
identity. A wallet can have multiple ECDSA companion lanes for one authority
when those lanes represent different chain targets. That is valid. Multiple
canonical groups for the same chain target are ambiguous material and must fail
closed. Phase 10A narrows this rule to canonical lane groups: multiple raw
records inside one same-authority/same-key group canonicalize, while multiple
canonical groups for the same chain target still fail closed.

Do:

- Replace overloaded `exact_match` companion-selection results with the domain
  union in [Companion Lane Selection](#companion-lane-selection), which
  distinguishes one companion lane, a chain-distinct companion lane set,
  duplicate canonical groups for the same chain target, and missing companion
  lanes.
- Model the selected companion lane as a wallet-scoped capability, not as a
  provider-subject lookup result.
- Consume `EcdsaCommittedLane` directly. Do not introduce a
  `ReadyEmailOtpEcdsaSessionRecord` companion selector as an intermediate core
  authority shape.
- Update `EmailOtpEd25519Warmup.loginForSigning` to consume the `ready`
  companion branch explicitly.
- Keep `signingGrantId` and `walletId` required selector inputs.
- Keep `chainTarget` inside ECDSA capability identity; do not use provider
  subject identity as the lane selector.
- Add type fixtures proving callers cannot treat multi-chain companion sets as
  a single exact lane without selecting `primaryLane`.
- Add type fixtures proving Email OTP companion lanes cannot carry Passkey auth
  or Passkey record material.
- Add unit coverage for:
  - same wallet, same grant, Tempo + Arc lanes: succeeds
  - same wallet, same grant, duplicate Tempo lanes: fails closed
  - same Gmail/provider subject across different wallet IDs: does not collide

Exit criteria:

- The OTP Ed25519 step-up path has no `exact_match` branch that hides
  multi-lane state.
- Duplicate detection is chain-target-specific.
- Shared Email OTP authority is stable across wallets, while wallet capability
  selection remains wallet-scoped.
- Companion selection never accepts session records, sealed records, warm
  capability records, or exact lane candidates as authority inputs.

Tracking:

- [x] Define the Email OTP companion-lane subject union over committed
      companion lanes.
- [x] Make Email OTP companion-lane identity branch-specific and reject
      Passkey material in the Email OTP branch.
- [x] Remove duplicate exact-match companion-lane candidate records from Email
      OTP Ed25519 warm-up selection.
- [x] Add type fixtures for invalid mixed-auth and single-vs-chain-distinct
      lane state.
- [x] Add runtime unit coverage for same-grant Tempo + Arc success,
      duplicate-chain failure, and same-provider-subject wallet isolation.

## Phase 4C: Budget Authority And First Step-Up Signing

Status: complete for the SDK signing slice. Broad end-to-end flow coverage is
deferred to Phase 10.

Budget state answers one question: whether an authorized signing session has
usable remaining spend. It must not encode Email OTP provider identity,
challenge proof state, or ECDSA auth-lane resolution.

Do:

- Replace `budget_unknown` control flow with `SigningBudgetStatus` parsing at
  the budget-status response boundary.
- Introduce `SigningBudgetAuthority` as a separate domain object (see
  [Signing Budget State](#signing-budget-state)).
- Keep `ThresholdEcdsaEmailOtpAuthContext` out of budget admission, reservation,
  and finalization APIs.
- Make ECDSA first step-up signing consume:
  - `ThresholdEcdsaEmailOtpAuthContext` for auth authority
  - `SigningBudgetAuthority` for budget binding
  - `SigningBudgetStatus` for spend state
- Remove any code path where `budget_unknown` triggers Email OTP step-up
  behavior by inference.
- Add tests for:
  - first EVM/Tempo transaction immediately after step-up succeeds
  - concurrent EVM submissions reserve distinct budget operations
  - budget unavailable does not mutate Email OTP auth context
  - Email OTP auth unavailable does not produce `budget_unknown`

Exit criteria:

- The first step-up transaction after budget exhaustion succeeds.
- Concurrent EVM submissions no longer fail due to stale budget authority state.
- EVM/Tempo signing code cannot proceed from `SigningBudgetStatus.kind ===
'unavailable'`.
- Budget failures report budget errors. Email OTP authority failures report auth
  errors.

Tracking:

- [x] Split budget authority from Email OTP auth authority; budget-status reads
      use the narrow `SigningSessionBudgetStatusAuth` Wallet Session JWT
      authority.
- [x] Confirm `budget_unknown` no longer drives Email OTP auth selection in
      SDK signing code.
- [x] Use the committed Email OTP ECDSA lane's wallet-session authority for
      trusted budget-status reads and fail when it does not match ready signer
      material.
- [x] Ensure first EVM/Tempo transaction after step-up waits for committed
      budget readiness.
- [x] Allow concurrent EVM signing operations to reserve distinct budget
      operations.
- [x] Add route/runtime smoke coverage for the first transaction after step-up
      (`signingFlow.readySigner.unit.test.ts`).
- [x] Add focused budget-coordinator coverage for concurrent EVM submissions.

## Phase 5: Route Surface Cleanup

Status: complete for the 82B implementation scope. The obsolete generic
Router A/B ECDSA key-identities route, the AuthService-shaped Router API facade,
and the AuthService recovery-grant app-session binding checks are deleted.
Router API route required-service metadata now uses explicit facade service keys
instead of broad AuthService-era keys. Shared Router A/B Ed25519 wallet-session
JWT signing, parsing, verified auth, budget matching, and route attach paths now
carry `WalletAuthAuthority`; lower threshold/admission adapters derive
`authorityScope` only at their boundary. The mechanical AuthService module
split remains separately owned. Notes:
[journal](./refactor-82B-journal.md#phase-5-route-surface-cleanup-july-3-2026).

Do:

- Audit routes that currently reject non-`passkey_rp` wallet sessions.
- For each route, choose one:
  - make it authority-generic
  - rename and restrict it as passkey-only
  - delete it if obsolete
- Start with:
  - `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`
  - `packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts`
  - sync-account routes
  - wallet unlock routes
  - key export routes
- Remove duplicate AuthService-era route semantics that still imply Passkey
  authority.

Exit criteria:

- Shared wallet-session routes accept `WalletAuthAuthority`.
- Passkey-only routes are named passkey-only.
- OTP unlock/sign/export never calls a passkey-only route.

Tracking:

- [x] Audit routes that still require `passkey_rp`; the only remaining hit is
      the passkey-specific SDK login session-policy assertion.
- [x] Make shared wallet-session routes accept `WalletAuthAuthority` for the
      Router A/B Ed25519 wallet-session JWT path; parse/build boundaries verify
      the bound authority and derive legacy Ed25519 `authorityScope` only for
      threshold-store/admission adapters.
- [x] Rename true Passkey-only routes as Passkey-only.
  - July 3 source audit complete: no active route/helper names still use
    `passkey-only` as generic wallet-session authority terminology. Remaining
    `passkey-only` literals are test fixture names and guard messages only.
- [x] Delete obsolete AuthService/passkey-only route semantics.
  - July 3 guard audit complete: generic Ed25519 registration no longer has
    passkey-only RP-ID helper paths, and
    `refactor82CloudflareD1Runtime.guard.unit.test.ts` rejects the old D1 and
    AuthService-era `rpId` registration authority hooks.
- [x] Delete the obsolete generic Router A/B ECDSA key-identities route; the
      inventory boundary is wallet-scoped
      `/wallets/:walletId/signers/ecdsa/key-facts/inventory`.
- [x] Delete obsolete AuthService Email OTP recovery-grant app-session binding
      checks; grants bind to stable Email OTP authority fields.
- [x] Remove the Router API public port's type dependency on `AuthService`;
      `RouterApiServiceBag` is a nested route-family object with direct method
      signatures.
- [x] Delete the D1 Router API AuthService-shaped facade
      (`CloudflareD1RouterApiAuthMetadataService`).
- [x] Replace Router API route required-service metadata with explicit facade
      service keys; `authService` and stale `threshold` route metadata keys are
      guarded against reintroduction.

## Phase 6: Sealed Session And IndexedDB Cleanup

Status: complete for the 82B implementation scope. Sealed-session reads
classify into the `CurrentSealedSessionRecord` union at the boundary; sealed
restore metadata uses strict auth branches; Ed25519 available-lane and restore
paths consume the material-state union; stale compatibility fields are rejected
or confined to record-reader classification. Notes:
[journal](./refactor-82B-journal.md#phase-6-sealed-session-cleanup-july-3-2026).

Do:

- Normalize sealed session records into discriminated unions at read time
  (done for the SDK reader: `classifyRawSealedSessionRecord` is the boundary
  parser).
- Remove optional identity/auth/session fields from core sealed-session types.
- Make Email OTP sealed records require stable provider subject identity.
- Replace flat Ed25519 material fields with `Ed25519WorkerMaterialState` in core
  lane/session selection.
- Make sealed material restore builders accept `sealed_material` only, and make
  runtime signing paths accept `loaded_material` only.
- Remove direct reads of `materialKeyId`, `bindingDigest`, `sealedWorkerMaterialRef`,
  and worker handles from flat session records in core signing code.
- Remove stale compatibility fields after parsers are updated.
- Update Refactor 85 if any IndexedDB schema cut is required.

Exit criteria:

- Core signing code never reads optional auth identity fields.
- Ed25519 signing and export lane selection read material through
  `Ed25519WorkerMaterialState`.
- Compatibility parsing stays inside IndexedDB/D1 boundary parsers.
- Sealed-session restore for Passkey and Email OTP uses one authority union.
- Sealed material builders accept only `Ed25519WorkerMaterialState` branches that
  actually contain material.

Tracking:

- [x] Normalize sealed session records into discriminated unions at read time.
- [x] Remove optional identity/auth/session fields from core sealed-session
      types (top-level `subjectId`/`userId`/ECDSA signing-root fields are done;
      broader shared sealed-record optional-field cleanup remains — see
      journal).
  - Partial July 3 sealed-recovery slice complete: accepted sealed recovery
    records reject duplicated authority identity fields (`rpId`,
    `credentialIdB64u`, `providerSubjectId`, `emailHashHex`) and expose the
    bound authority as the only normalized source for those facts.
  - Partial July 3 sealed-recovery slice complete: normalized Email OTP
    Ed25519 and companion Ed25519 sealed records no longer carry passkey
    `rpId` siblings; the configured RP is supplied only at the boundary that
    still writes the current Ed25519 session-row shape.
  - Partial July 3 sealed-store write slice complete: current sealed-session
    write inputs now require canonical `thresholdSessionIds` instead of
    inferring session identity from the branch `thresholdSessionId`.
  - Partial July 3 sealed-store lifecycle slice complete: current sealed-session
    write inputs now require explicit `issuedAtMs` and `updatedAtMs`, and
    `buildCurrentSealedSessionRecord` no longer invents lifecycle timestamps
    inside core sealed-session construction.
  - Partial July 3 resolved-identity slice complete: `PublishResolvedIdentityInput`
    is now the exact resolved identity shape and requires explicit `updatedAtMs`
    from the caller; identity publication no longer defaults lifecycle time
    inside the sealed-session store.
  - Partial July 3 sealed-policy slice complete: `updateExactSealedSessionPolicy`
    now requires explicit `updatedAtMs`, so policy updates cannot synthesize
    lifecycle time inside the sealed-session store.
  - Partial July 3 sealed parser strictness coverage complete:
    `signingSessionRestoreCoordinator.unit.test.ts` now proves stale Ed25519
    `authSubjectId` aliases and ECDSA top-level signing-root siblings are
    rejected at the sealed-record boundary before restore is attempted.
  - Partial July 3 shared sealed-record type strictness complete:
    `SealedSigningSessionRecord` is now a curve-discriminated current record
    shape with required `walletId`, `relayerUrl`, curve-local
    `thresholdSessionIds`, and curve-local restore metadata. Stale
    `subjectId` / `userId` fields and ECDSA top-level signing-root siblings
    are rejected by shared type fixtures; raw legacy rows remain accepted only
    by sealed-store boundary parsing.
  - Partial July 3 sealed-store current-type cleanup complete:
    `CurrentSealedSessionRecord` and current sealed-record write inputs no
    longer carry stale top-level `subjectId` / `userId` rejection fields.
    The builder still rejects those raw extras at the boundary before
    classifying or writing a current record.
  - Partial July 3 sealed restore auth cleanup complete: shared sealed
    restore metadata now represents Wallet Session authority as a
    discriminated union, so `sessionKind: 'jwt'` requires `walletSessionJwt`
    and `sessionKind: 'cookie'` rejects it. The SDK sealed-store boundary
    parser classifies raw partial states before they can become current
    records.
  - Partial July 3 sealed-recovery helper cleanup complete: normalized sealed
    recovery wallet-session auth now exposes `sessionKind` as literal `jwt`
    and `walletSessionJwt` as a required string, so core restore code cannot
    observe the boundary-only missing-JWT state.
  - Partial July 3 sealed-recovery strictness slice complete: direct sealed
    recovery normalization now rejects stale top-level `userId` the same way
    the IndexedDB sealed-store reader rejects `subjectId`/`userId`, with
    focused coverage in `sealedRecoveryRecord.strict.unit.test.ts`.
  - Partial July 3 ECDSA sealed normal-signing slice complete: ECDSA sealed
    restore metadata now requires `routerAbEcdsaHssNormalSigning`, and Email
    OTP publication/UI-confirm restore paths propagate that Router A/B state
    into sealed records with type fixtures updated.
  - Complete July 3 final sealed-session audit: current sealed records expose
    canonical `thresholdSessionIds`, required wallet/session/lifecycle fields,
    and branch-local restore metadata. Stale top-level identity and signing-root
    fields are rejected at boundary classifiers before core restore code sees
    them.
- [x] Replace flat Ed25519 material fields with branch-specific material
      state in available-lane, transaction-selection, and export-selection
      surfaces.
- [x] Require the SDK available-lanes runtime Ed25519 port to carry the
      branch-specific material state instead of optional flat material fields.
- [x] Convert passkey Ed25519 reconnect recovery to read material through the
      normalized session-record material discriminator.
- [x] Convert Router A/B Ed25519 restore to consume the classified
      `RouterAbEd25519RestorableWorkerMaterial` branch atomically.
- [x] Narrow Router A/B Ed25519 wallet-session material readers to the
      `material_ready` and restorable session-record branches.
- [x] Delete stale runtime-handle-only Ed25519 warm-session persistence
      coverage that preserved an incomplete restore state.
- [x] Make ECDSA and Ed25519 sealed restore metadata require exactly one
      stable auth identity branch in the shared wire type.
- [x] Convert persisted available-lane Ed25519 runtime projection and warm
      signing-session authorization to branch-specific material state.
- [x] Convert Email OTP persisted-session snapshot Ed25519 runtime projection
      to the shared Router A/B classified material-state helper.
- [x] Convert sealed-recovery exact lookup and durable available-lane assembly
      to use normalized Ed25519 sealed material identity instead of direct
      sealed-record material field reads.
- [x] Require accepted Ed25519 sealed recovery records to carry complete sealed
      worker-material metadata.
- [x] Replace remaining flat Ed25519 material reads in sealed/session-record
      core consumers with branch-specific material state.
- [x] Keep IndexedDB compatibility parsing inside record readers only.
  - Partial July 3 sealed-recovery slice complete: durable available-lane and
    restore core code no longer cast normalized sealed records back to raw
    auth-identity fields; those fields are read only while normalizing raw
    sealed store metadata.
  - Complete July 3 final IndexedDB boundary audit: raw sealed aliases are read
    only by sealed-store and sealed-recovery boundary classifiers; accepted
    records handed to restore/selection code carry normalized authority and
    canonical threshold-session identity.
- [x] Delete the stale sealed-session `authSubjectId` compatibility alias from
      Email OTP provider identity readers.
- [x] Delete remaining stale compatibility fields after readers are strict.
  - Partial July 3 wallet-auth-method slice complete: IndexedDB Email OTP
    auth-method records no longer strip or accept a stale passkey `rpId`, and
    row parsing no longer accepts the old `wallet_auth_method_id` that included
    that `rpId`.
  - Partial July 3 sealed-record id slice complete: sealed recovery parsing no
    longer accepts legacy `thresholdSessionId` or `walletSigningSessionId`
    aliases; accepted sealed records must carry canonical `thresholdSessionIds`
    and `signingGrantId`.
  - Complete July 3 final stale-field audit: stale sealed identity fields now
    classify records as `delete_required`/`invalid_identity`; no compatibility
    alias is accepted into current sealed-session records outside the reader
    boundary.

## Phase 8: Tests And Guards

Status: complete for type guards, focused unit/runtime guards, and obsolete
behavior test deletion. End-to-end browser/runtime coverage is deferred to
Phase 10. Notes: [journal](./refactor-82B-journal.md#phase-8-tests-and-guards-july-3-2026).

Do:

- Add type fixtures for invalid authority combinations:
  - `rpId` on Email OTP authority
  - OTP proof IDs in session policy
  - missing Email OTP provider subject
  - Passkey session without credential ID
  - sealed worker material missing `materialKeyId`
  - registration candidate passed to active wallet-session code
  - core lifecycle object with `authSubjectId` beside `authority`
  - a `kind` field that restates the authority factor branch on a lane or
    resolution type
- Update unit coverage for:
  - Passkey registration -> unlock -> NEAR/EVM/Tempo sign -> export
  - Google SSO Email OTP registration -> unlock -> NEAR/EVM/Tempo sign -> export
  - Email OTP challenge registration -> unlock -> NEAR/EVM/Tempo sign -> export
  - step-up auth first transaction after exhaustion
  - concurrent EVM signing requests
- Delete tests that preserve obsolete AuthService/passkey-only behavior.

Exit criteria:

- Tests protect both authority branches.
- No tests depend on legacy `authorityScope` proof IDs in core session state.

Tracking:

- [x] Add type fixtures for invalid Email OTP ECDSA authority combinations.
- [x] Add type fixtures for missing required ECDSA lane/session authority.
- [x] Add type fixtures rejecting Email OTP ready ECDSA signing selections
      without a committed lane.
- [x] Add type fixtures and source guards rejecting Passkey ready ECDSA signing
      selections and Passkey ready ECDSA export material without a committed
      lane.
- [x] Add a source guard proving SDK signing/session code reads Email OTP
      wallet authority provider identity through shared accessors, not direct
      flat `authority.provider` / `authority.providerUserId` fields.
- [x] Add shared authority type fixtures rejecting mixed Passkey/Email OTP
      wallet authority branches, proof objects that carry stable authority
      identity, and authority refs that carry raw authority data
      (`walletAuthAuthority.typecheck.ts`).
- [x] Add shared runtime coverage proving bound Email OTP wallet authority
      parsing rejects flat legacy provider shapes, requires matching
      `bindingId`, and hashes the bound authority object with wallet-id equality
      validation (`walletAuthAuthority.shared.unit.test.ts`).
- [x] Add type fixtures rejecting missing auth-lane input to Email OTP
      app-session JWT/subject and route-auth projection helpers.
- [x] Add type fixtures rejecting raw `appSessionJwt`, loose `routeAuth`, and
      `sessionKind` on core Email OTP ECDSA and Ed25519 login; coordinator
      runtime coverage now passes explicit login route plans.
- [x] Add type fixtures rejecting raw `appSessionJwt`, loose `routeAuth`, and
      `sessionKind` on core Email OTP ECDSA registration/enroll; coordinator
      runtime coverage now passes explicit registration route plans.
- [x] Add type fixtures for invalid Email OTP companion-lane mixed-auth and
      chain-distinct branch combinations.
- [x] Add focused runtime coverage for Email OTP ECDSA selection, companion
      lane selection, sealed restore, export reauth, and same-grant Tempo/Arc
      authority handling.
- [x] Add focused runtime coverage for Email OTP Ed25519 export selection and
      deferred runtime-scope reconstruction with canonical auth-context `use`
      state.
- [x] Add focused runtime coverage proving Email OTP device restore/remove
      worker results are normalized to `providerUserId` before reaching
      public SDK result types.
- [x] Add focused strict-record coverage for Router A/B Ed25519 restore
      material-state classification and canonical ECDSA key-slot identity.
- [x] Add focused Ed25519 warm-session coverage proving sealed material is
      retained and incomplete runtime-handle-only restore records are rejected.
- [x] Update ECDSA export fixtures to use canonical
      `evmFamilySigningKeySlotId` and branch-specific Email OTP provider
      authority.
- [x] Add type and runtime coverage proving Email OTP ECDSA export material
      requires record-backed committed lanes and rejects loose route-auth
      `record` fields.
- [x] Add type and runtime coverage proving Email OTP key-export challenge
      requests use explicit fresh-login vs signing-session authority branches
      and reject loose app-session `routeAuth` on committed export paths.
- [x] Add type and runtime coverage proving Email OTP ECDSA reauth selections
      carry committed lanes and reject loose `reauthAuthority` route-auth
      fields.
- [x] Update stale ECDSA and warm-session fixtures to use canonical
      `evmFamilySigningKeySlotId`, branch-specific Email OTP `use` state, exact
      ECDSA key-slot mutation, and complete Ed25519 material-state fields.
- [x] Add type and runtime coverage proving Email OTP ECDSA companion
      selection for Ed25519 step-up carries record-backed committed lanes and
      rejects direct companion `record` and sibling `walletSessionAuthority`
      fields.
- [x] Delete obsolete Router A/B ECDSA key-identities route tests and add a
      source guard proving key-facts inventory has one wallet boundary.
- [x] Rewrite the stale raw threshold-ECDSA email-recovery removal test to
      exercise the route request parser directly.
- [x] Add focused Ed25519 HSS route/registration coverage proving finalize
      requests reject client-sent server finalize output and current
      orchestration fixtures carry canonical ECDSA key-slot and Ed25519
      material-state data.
- [x] Add focused sealed parser coverage proving stale Ed25519 `authSubjectId`
      and ECDSA top-level signing-root aliases are rejected before restore.
- [x] Add shared sealed-record type fixtures rejecting stale `subjectId`,
      `userId`, ECDSA top-level signing-root siblings, missing wallet identity,
      and missing curve-local restore metadata.
- [x] Move end-to-end browser/runtime coverage and CI gating to the deferred
      manual-validation phase. Phase 8 remains focused on type guards, focused
      unit/runtime guards, and obsolete-behavior test deletion.
- [x] Delete tests that preserve obsolete AuthService/passkey-only behavior
      (obsolete Router API relayer harnesses are deleted; see journal).
      Focused guard evidence on July 3:
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts
./unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --grep
"AuthService-backed Router API route harnesses stay deleted"
--reporter=line` passes. Current `passkey-only` source hits are
      canonical account-auth fixtures or guard messages, not obsolete behavior
      fixtures.

## Phase 9: Cleanup And Line Count Closure

Status: complete. July 3 review removed the stale "relayer wording" cleanup
item as redundant: current hits are valid domain identifiers for NEAR relayer
accounts, threshold relayer key material, or historical package/test paths
outside this authority cleanup. Validation evidence:
[journal](./refactor-82B-journal.md#phase-9-validation-evidence-record).

Do:

- Remove deleted authority names and stale comments:
  - passkey authority in shared code
  - compatibility helpers outside request/persistence boundaries
- Manually remove duplicate proof-to-authority conversion helpers after the
  canonical boundary parsers are in place.
- Document line count change for non-doc code (record in the journal).
- Mark completed tasks in this file and parent Refactor 82.

Exit criteria:

- No duplicate proof-to-authority conversion paths.
- No legacy authority fields in core session/key/lane types.
- Net code growth is explained and minimized.

Tracking:

- [x] Remove stale "passkey authority" wording from shared code.
- [x] Remove duplicate proof-to-authority conversion helpers
      (`walletAuthModeResolver.ts` and the server Ed25519 session-mint
      projection are deleted).
- [x] Run source searches for loose authority/session shapes after cleanup.
- [x] Record current validation evidence for the SDK-side committed-lane slice
      (moved to the journal).
- [x] Record current validation evidence for the wallet-bound Email OTP
      authority slice: `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json
--noEmit --pretty false`, `pnpm -C tests exec playwright test -c
playwright.unit.config.ts ./unit/walletAuthAuthority.shared.unit.test.ts
--reporter=line`, and `pnpm build:sdk` pass on July 3, 2026.
- [x] Document non-doc line count changes (moved to the journal).
- [x] Mark completed tasks in this file and parent Refactor 82.

## Phase 10: Manual Runtime Validation

Status: in progress. Passkey registration and unlock browser-runtime contracts
pass locally; Email OTP manual/browser runtime validation remains open. This
phase is intentionally outside the implementation closure for Phases 1-9.
The Email OTP contracts require a local Google ID token through
`SEAMS_INTENDED_GOOGLE_ID_TOKEN`; without that credential the intended harness
cannot start either Email OTP runtime flow.

Local Google OIDC setup is now scripted:

```sh
pnpm setup:intended-google-oidc
pnpm refresh:intended-google-token
```

The setup command creates or validates the test service account, enables IAM
Credentials, grants the active `gcloud` account service-account token-creator
permission, writes ignored `.env.intended.local`, and refreshes the one-hour
Google ID token. When creating a new local env file, pass
`--client-secret=<secret>` to persist `SEAMS_INTENDED_GOOGLE_CLIENT_SECRET` and
`GOOGLE_OIDC_CLIENT_SECRET` locally; the impersonated ID-token refresh uses the
OAuth client ID as its audience. `pnpm test:intended`,
`pnpm test:intended:ci`, and mutation preflight load that env file
automatically. Restart already-running local router/site services after
changing Google OIDC env values so runtime code sees `GOOGLE_OIDC_CLIENT_ID`.

Do:

- Run the user-facing browser flows against a fresh dev state before marking
  runtime coverage complete.
- Keep deployment and CI promotion out of this phase; record those tasks in
  Phase 11 after manual runtime validation is complete.

Tracking:

- [x] Browser-runtime verify Passkey registration, unlock, sign, and export.
      Local intended contracts passed on July 3, 2026:
      `pnpm -C tests exec playwright test -c playwright.intended.config.ts
e2e/intended-behaviours/passkey.registration.contract.test.ts
--reporter=line` and
      `pnpm -C tests exec playwright test -c playwright.intended.config.ts
e2e/intended-behaviours/passkey.unlock.contract.test.ts --reporter=line`.
      Re-run together on July 4, 2026: 2/2 passed in 1.3m.
- [x] Handle Wrangler dev-server worker restarts during registration prepare.
      The SDK retries `/wallets/register/prepare` once only when Wrangler
      returns the exact "worker restarted mid-request" 503 response. Focused
      coverage:
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts
unit/walletRegistrationPrepareTransport.unit.test.ts --reporter=line`.
- [x] Align Email OTP registration authority hash format with D1.
      Browser-side Email OTP wallet-auth authority now uses unprefixed SHA-256
      email hash hex, matching the server authority and wallet-auth-method
      binding id. Focused coverage:
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts
unit/emailOtpEmailHash.unit.test.ts --reporter=line`.
- [ ] Manually verify Google SSO Email OTP registration, unlock, sign, and
      export. Requires `SEAMS_INTENDED_GOOGLE_ID_TOKEN`, refreshed through
      `pnpm refresh:intended-google-token`.
- [ ] Manually verify direct Email OTP challenge registration, unlock, sign,
      and export. Requires `SEAMS_INTENDED_GOOGLE_ID_TOKEN`, refreshed through
      `pnpm refresh:intended-google-token`, in the current intended harness.

## Phase 10A: Canonical Lane Inventory And Selection

Status: implemented for SDK runtime selection. Manual Email OTP runtime validation exposed that
`duplicate_records` is still modeled too close to raw record multiplicity.
Repeated step-up can create several valid records for one wallet authority and
one EVM-family key. The selector must canonicalize those facts into one
committed lane, while still failing closed for real key-material conflicts or
multiple distinct matching key groups.

Canonicalization rules:

- **Group key:** wallet-bound authority plus stable ECDSA key-slot identity
  (`evmFamilySigningKeySlotId`, `ecdsaThresholdKeyId`, signing root id, and
  signing root version). Verified public facts are consistency checks inside the
  group, not part of the grouping key.
- **Public-fact integrity:** same group plus different owner address, key handle,
  public key, or participant set is `conflicting_key_material`.
- **Supersession order:** operation-usable facts beat unusable facts; higher
  server-issued session generation beats lower generation; exact target facts
  beat shared projections for the exact same target; the final deterministic
  tie-break is lexicographic over stable session identity fields. Local write
  time is not a primary ordering signal.
- **Session generation source:** prefer server-issued activation/issuance data
  from the parsed signing-session authority or Router A/B normal-signing state.
  If two operation-usable facts in one group lack a comparable generation after
  parsing, return `ambiguous_material` instead of choosing by local timestamp.
- **Superseded-valid authority:** successful step-up must retire predecessors for
  the same authority/key group. Canonicalization is a read-model guard, not the
  only revocation mechanism. Until the retirement write is complete, older
  still-valid records remain bounded by their server-issued TTL and are exposed
  as diagnostics.
- **Policy boundary:** the inventory selector does not emit `requires_step_up`.
  Step-up is derived by the caller after canonical selection from the lane's
  spend/freshness state or from `no_current_lane` plus a reauth anchor.

Do:

- Introduce a canonical ECDSA lane-inventory read model:
  `EcdsaLaneRecordFact`, `EcdsaLaneGroupKey`, `EcdsaLaneGroup`, and
  `EcdsaCanonicalLaneSelection`, generic over `WalletAuthAuthority`.
- Parse runtime session records, sealed restore records, warm material facts,
  and EVM-family shared projections into record facts at the read-model
  boundary.
- Group ECDSA facts by wallet-bound authority and stable ECDSA key-slot identity.
  Treat repeated step-up records and stale/exhausted records as superseded facts
  inside the group according to the canonical supersession order.
- Select one canonical `EcdsaCommittedLane` per operation target before signing,
  step-up, or export code runs.
- Replace broad `duplicate_records` / `duplicate_authority_records` failures in
  core signing/export paths with precise domain failures:
  `conflicting_key_material`, `ambiguous_material`, or `no_current_lane`.
- Retire superseded-valid same-authority/same-key ECDSA session records when
  step-up creates a replacement session.
- Keep duplicate raw persistence rows observable through diagnostics, read-model
  telemetry, or cleanup jobs only.
- Add type fixtures that reject passing `EcdsaLaneRecordFact` or
  `EcdsaLaneGroup` into signing/export functions that require
  `EcdsaCommittedLane`.
- Convert Phase 4B companion selection to consume canonical lane groups: multiple
  records inside one group canonicalize, while multiple canonical groups for the
  same chain target still fail closed.
- Re-scope the Refactor 88 `duplicate exact lane` matcher to duplicate canonical
  lanes / ambiguous groups, not benign duplicate raw records.
- Keep the Phase 10A/10B/10C canonical material boundary aligned with Refactor 85
  `LocalCapabilityMaterial`; Refactor 85 consumes canonical outputs, and only
  consumes typed facts at persistence boundaries instead of adding a new
  inventory shape.

Exit criteria:

- Repeated Email OTP ECDSA step-up leaves old records in inventory without
  poisoning Tempo or Arc transaction selection.
- Successful step-up retires superseded same-authority/same-key records, or the
  lack of retirement support is a blocking implementation failure.
- ECDSA key export selects the canonical current lane when stale same-key facts
  remain.
- Same authority plus conflicting owner address, key handle, public key, or
  participant set fails before a committed lane is built.
- Multiple distinct ECDSA key groups matching one operation fail with
  `ambiguous_material`.
- No new auth-method × curve × operation × source named type family is added.

Tracking:

- [x] Add the immediate transaction-selector guard that uses the availability
      read model's canonical lane when all allowed ECDSA candidates share the
      same wallet authority and key material.
- [x] Add focused runtime coverage for repeated Email OTP Tempo step-up records
      selecting the active canonical exact lane.
- [x] Add the canonical ECDSA lane-inventory read-model types.
- [x] Define and implement server-issued session generation ordering for ECDSA
      facts from session expiry; final ties use deterministic session ids.
- [x] Move same-authority/same-key candidate collapse from transaction/export
      selectors into the read-model grouping boundary.
- [x] Delete the temporary transaction-selector same-authority/same-key collapse
      guard once the read-model grouping boundary owns canonicalization.
- [x] Convert ECDSA transaction signing to consume canonical availability
      output before operation selection.
- [x] Convert ECDSA key export to consume canonical availability output before
      exact export selection.
- [x] Replace broad duplicate-record failures in core ECDSA signing/export
      paths with precise domain failures.
- [x] Retire superseded-valid same-authority/same-key ECDSA session records on
      successful step-up.
- [x] Convert Phase 4B companion selection and duplicate-chain tests from
      record-count semantics to canonical-group semantics.
  - July 4 fix: Ed25519 Email OTP step-up now selects the current concrete
    ECDSA companion by wallet-bound Email OTP authority. It no longer requires
    the ECDSA companion to share the stale Ed25519 signing grant after repeated
    Tempo/Arc step-ups.
- [x] Update Refactor 88 intended-behavior duplicate-lane matcher to assert on
      duplicate canonical lanes / ambiguous groups.
- [x] Add type fixtures rejecting record facts and lane groups as direct
      signing/export inputs.
- [x] Add focused tests for stale same-key facts, conflicting key material,
      ambiguous multiple-key material, and shared Tempo/Arc canonical
      selection.
- [x] Document Ed25519 scope explicitly: manual NEAR step-up validation showed
      Ed25519 needs the same canonical record-fact/group pattern as ECDSA. The
      immediate availability-boundary fix is implemented; Phase 10B extracts
      the shared typed canonicalization kernel so the two curves cannot drift
      again.

## Phase 10B: Generic Canonical Lane Inventory Kernel

Status: complete for the availability/selection kernel. Phase 10A implemented
canonical inventory behavior for ECDSA, and manual NEAR step-up validation
exposed the same duplicate-record failure class in Ed25519. The immediate
Ed25519 availability fix closes the runtime bug. This phase removes the
remaining duplicated canonicalization algorithms by extracting a small generic
kernel with strict ECDSA and Ed25519 adapters. Write-side retirement is split
into Phase 10C because restore and current-session commit are different
lifecycle transitions.

Intent:

- Share the canonical lane inventory flow:
  raw boundary records -> typed record facts -> stable authority/key groups ->
  material consistency checks -> current-lane selection -> committed lane.
- Keep curve-specific identity, material, and restore semantics in adapters.
  The generic kernel must not know about EVM-family shared keys, NEAR account
  ids, key handles, worker material handles, or sealed restore shapes.
- Prevent Phase 10A's failure mode from recurring: fixing duplicate-lane
  canonicalization for one curve must naturally exercise the same shared
  selection state machine for the other curve.
- The kernel owns the Phase 10A supersession policy; adapters supply
  extractors only. If adapters owned comparators, the curves could drift on
  exactly the logic this phase exists to unify — the kernel would share the
  trivial grouping loop while each adapter reimplemented the load-bearing
  ordering.

Input contract: the kernel canonicalizes a pre-scoped fact set — one
wallet-bound authority, one operation target, one curve. The adapter query
layer performs that scoping before invoking the kernel; exactness preference
is target-relative and only meaningful because the set is pre-scoped.
Mixed-curve fact sets are unrepresentable because `TFact` differs per
invocation — that is the type-level reason the kernel needs no runtime curve
check.

Target kernel sketch:

```ts
type ServerIssuedGeneration = string & { readonly __brand: 'ServerIssuedGeneration' };

type CanonicalFactExactness = 'exact_target' | 'shared_projection';

type CanonicalFactSupersession<TFact> = {
  isOperationUsable(fact: TFact): boolean;
  // null = no comparable server-issued generation after parsing.
  generation(fact: TFact): ServerIssuedGeneration | null;
  exactness(fact: TFact): CanonicalFactExactness;
  // Deterministic total tie-break over stable ids (threshold session id,
  // signing grant id, source, chain-target key). Never wall-clock time.
  tieBreak(left: TFact, right: TFact): -1 | 0 | 1;
};

type CanonicalLaneInventoryAdapter<TFact, TGroupKey, TConflict> = {
  // Total: group identity is parsed into the fact type at the boundary. An
  // ungroupable record is a boundary parse failure and never reaches the
  // kernel — no silent drops.
  groupKey(fact: TFact): TGroupKey;
  groupKeyString(groupKey: TGroupKey): string;
  // Runs over the FULL group before supersession filtering: a stale
  // superseded record with mismatched public facts still poisons the group.
  groupConflicts(facts: readonly TFact[]): readonly TConflict[];
  supersession: CanonicalFactSupersession<TFact>;
};

type CanonicalLaneSelection<TFact, TConflict> =
  | {
      kind: 'selected';
      selectedFact: TFact;
      supersededFacts: readonly TFact[];
    }
  | { kind: 'no_current_lane'; unusableFacts: readonly TFact[] }
  | { kind: 'conflicting_key_material'; conflicts: readonly TConflict[] }
  | { kind: 'ambiguous_material'; candidates: readonly TFact[] };

function canonicalizeLaneFacts<TFact, TGroupKey, TConflict>(
  facts: readonly TFact[],
  adapter: CanonicalLaneInventoryAdapter<TFact, TGroupKey, TConflict>,
): CanonicalLaneSelection<TFact, TConflict>;
```

The kernel implements the complete layered order from Phase 10A: usable
beats unusable, higher server-issued generation beats lower, exact target
beats shared projection, deterministic tie-break last — and maps two top
usable candidates with incomparable generations to `ambiguous_material`
itself. A numeric comparator could not express "refuse to order"; the
ingredients interface can.

The kernel is selection-only. There is no `TLane` and no `laneFromFact`:
committed-lane and availability-lane construction stays in the existing
validated builders, which consume `selectedFact` and keep their
prepare-boundary mismatch rejection. `no_current_lane` carries the unusable
facts so callers can derive step-up (per the Phase 10A policy boundary)
without re-probing raw stores.

Adapter ownership:

- **ECDSA adapter:** owns `EcdsaLaneRecordFact`, `EcdsaLaneGroupKey`,
  public-fact conflict checks, exactness classification (exact target vs
  EVM-family shared projection), threshold key id consistency, and the
  supersession ingredients. Canonical ECDSA availability/committed lane
  construction stays in the existing validated ECDSA builders, consuming
  `selectedFact`.
- **Ed25519 adapter:** owns `Ed25519LaneRecordFact`, `Ed25519LaneGroupKey`,
  NEAR account/signing-key/signer-slot group identity, usability
  classification derived from the Phase 6 `materialState` union (never
  re-derived from flat material fields), sealed-vs-loaded material checks,
  and the supersession ingredients. Lane construction stays in the existing
  validated Ed25519 builders.
- **Shared kernel:** owns grouping, the complete supersession order (usable >
  server-issued generation > exact-over-shared > deterministic tie-break),
  the incomparable-usable-pair -> `ambiguous_material` rule, exhaustive
  result states, superseded/unusable-fact reporting, and deterministic
  selection. Adapters cannot override the order — there is no comparator
  surface to override it with.

Rules:

- Raw DB records, runtime records, warm capability records, and sealed restore
  records are parsed before entering the kernel. The kernel accepts only typed
  facts, and `groupKey` is total over them — an ungroupable record is a
  boundary parse failure upstream, never a fact the kernel silently skips.
- The supersession order lives in the kernel; adapters provide
  `CanonicalFactSupersession` extractors only. Two operation-usable facts
  without comparable server-issued generations are `ambiguous_material` for
  both curves — never resolved by local timestamp or adapter-specific
  ordering.
- The kernel receives pre-scoped fact sets (one authority, one operation
  target, one curve); the adapter query layer owns the scoping.
- Core signing/export/step-up functions must consume committed lanes or
  canonical availability output, never raw facts, groups, or diagnostics.
- Adapter inputs must require identity, auth, session, material, restore, and
  policy fields that are mandatory for that curve. Optional fields are allowed
  only for genuinely optional display/config data.
- The generic kernel must be parameterized by types. It must not add
  auth-method x curve x operation aliases or broad "lane bag" objects.
- `duplicate_records` remains a persistence/read-model diagnostic. The kernel
  returns `conflicting_key_material`, `ambiguous_material`, or
  `no_current_lane` for semantic failures.
- ECDSA and Ed25519 fixtures must prove that stale same-authority records
  canonicalize, while different auth factors, different stable keys, or
  conflicting key/material facts fail at the boundary.

Do:

- Add `canonicalLaneInventory.ts` under the SDK signing-session availability
  boundary with the generic discriminated-union result, the adapter
  interface, and the `CanonicalFactSupersession` extractor contract.
- Freeze the current Phase 10A/Ed25519 availability behavior with focused tests
  before extraction, then convert one adapter at a time and delete the old
  helper path after equivalence is proven.
- Implement the layered supersession order once, in the kernel, including
  the incomparable-usable-pair -> `ambiguous_material` rule.
- Move the shared grouping and selected/superseded-fact algorithm out of the
  current ECDSA and Ed25519 availability helpers.
- Rebuild ECDSA canonicalization as an adapter over the generic kernel; the
  existing validated ECDSA lane builders consume `selectedFact`.
- Rebuild Ed25519 canonicalization as an adapter over the generic kernel,
  with usability classification read from the Phase 6 `materialState`
  discriminators.
- Keep write-side retirement out of availability reads. Phase 10C replaces the
  temporary Ed25519 upsert-boundary retirement with explicit fact-write and
  current-session commit commands.
- Add type fixtures rejecting direct signing/export calls with
  `CanonicalLaneRecordFact`, group objects, diagnostics, or uncommitted generic
  selections.
- Add a fixture proving adapters cannot override the supersession order:
  the adapter surface exposes ingredients only, and a hand-rolled comparator
  has no entry point.
- Update duplicate-lane tests so both curves exercise the same kernel behavior:
  stale same-authority facts collapse, conflicting key/material facts fail closed,
  incomparable usable pairs are ambiguous, and multiple stable key groups
  cannot produce a committed lane.
- Keep Refactor 85's `LocalCapabilityMaterial` boundary pointed at canonical
  material / committed-lane outputs. If Refactor 85 needs inventory facts at a
  persistence boundary, it must consume typed canonical facts from this boundary
  and must not create a separate inventory representation.

Exit criteria:

- ECDSA and Ed25519 availability use the same generic canonicalization kernel.
- The supersession order is implemented once, in the kernel; adapters supply
  ingredients only, and a fixture proves an adapter cannot override the
  ordering.
- Two operation-usable facts without comparable server-issued generations
  produce `ambiguous_material` for both curves.
- Ed25519 availability remains correct when older and newer same-authority
  facts coexist. Write-side retirement semantics are owned by Phase 10C.
- `no_current_lane` output carries the unusable facts, and step-up derivation
  consumes it without re-querying raw stores.
- Curve-specific adapters remain strict and small; raw parsing, material
  validation, and lane construction stay outside the kernel.
- No operation path selects from raw record count, diagnostics, or broad
  duplicate-record state.
- No new duplicate type family is introduced for auth method x curve x
  operation x source.
- `pnpm build:sdk` and focused ECDSA/Ed25519 duplicate-lane tests pass.

Tracking:

- [x] Add the generic `CanonicalLaneSelection`,
      `CanonicalLaneInventoryAdapter`, and `CanonicalFactSupersession` types.
- [x] Extract shared grouping and selected/superseded-fact selection into
      `canonicalLaneInventory.ts`, with the layered supersession order and
      the incomparable-usable -> `ambiguous_material` rule kernel-owned.
- [x] Freeze current ECDSA and Ed25519 canonical availability behavior with
      focused tests before extraction.
- [x] Convert ECDSA availability canonicalization to the generic kernel;
      lane builders consume `selectedFact`.
- [x] Convert Ed25519 availability canonicalization to the generic kernel,
      reading usability from the Phase 6 `materialState` union.
- [x] Replace the temporary Ed25519 upsert-boundary retirement with the
      Phase 10C fact-write/current-session-commit command split.
- [x] Add type fixtures rejecting raw facts/groups/selections as signing or
      export inputs, and the adapter-cannot-override-ordering fixture.
- [x] Update focused duplicate-lane tests for both adapters, including the
      incomparable-generation ambiguity case.
- [x] Run `pnpm build:sdk` and focused availability duplicate suites.

## Phase 10C: Current Session Commit Commands

Status: complete. Review of Phase 10B found that retirement at the generic
session-record upsert boundary treats restore writes and freshly minted current
sessions as the same lifecycle transition. That can invert authority freshness:
a sealed restore can write generation N after step-up already committed
generation N+1, and an unconditional upsert-boundary cleanup can delete the
newer record.

This phase splits persistence into fact writes and current-session commits for
both Ed25519 and ECDSA. Keep the two curves as small parallel command types
because their record shapes and material metadata differ at persistence
boundaries.

Target command shapes:

```ts
type Ed25519SessionFactWrite = {
  kind: 'restore_fact_write';
  record: ThresholdEd25519SessionRecord;
};

type Ed25519CurrentSessionCommit = {
  kind: 'current_session_commit';
  record: OperationUsableThresholdEd25519SessionRecord;
  transition: 'registration' | 'wallet_unlock' | 'step_up';
  generation: ServerIssuedGeneration;
};

type ThresholdEd25519SessionCommitResult =
  | {
      kind: 'committed_current';
      current: OperationUsableThresholdEd25519SessionRecord;
      retired: readonly ThresholdEd25519SessionRecord[];
      diagnostics: readonly ThresholdEd25519RetirementDiagnostic[];
    }
  | {
      kind: 'same_generation_distinct_session';
      incoming: OperationUsableThresholdEd25519SessionRecord;
      existing: OperationUsableThresholdEd25519SessionRecord;
    }
  | {
      kind: 'stale_commit_ignored';
      incoming: OperationUsableThresholdEd25519SessionRecord;
      current: OperationUsableThresholdEd25519SessionRecord;
    };
```

Do:

- Rename the generic Ed25519 upsert path to fact-write semantics:
  `upsertThresholdEd25519SessionFact`. It only parses and stores a fact.
  Restore, sealed rehydration, status reads, and reusable-material hydration
  use this path.
- Add `commitCurrentThresholdEd25519Session` for registration, wallet unlock,
  and successful step-up paths that mint a new operation-usable current
  session. A generic `ThresholdEd25519SessionRecord` must not typecheck as a
  commit input.
- Add the matching ECDSA fact-write/current-session-commit split. Remove the
  previous upsert-boundary cleanup helpers so ECDSA retirement only happens
  inside current-session commits.
- Make `OperationUsableThresholdEd25519SessionRecord` and the ECDSA equivalent
  boundary-built types. Required fields include wallet-bound authority, stable
  key identity, threshold session id, signing grant id, wallet-session JWT,
  ready/restorable material state, remaining uses, expiry/generation, and
  curve-specific restore metadata.
- Store the incoming current record before retiring predecessors. A crash
  between store and retire leaves both facts, and the canonical kernel selects
  safely.
- Retirement rule for same authority/key group:
  - Same `thresholdSessionId`: replace as an idempotent re-commit.
  - `generation(existing) < generation(incoming)`: retire existing.
  - `generation(existing) === generation(incoming)` with a different
    `thresholdSessionId`: keep both and return
    `same_generation_distinct_session`.
  - `generation(existing) > generation(incoming)`: keep existing and return
    `stale_commit_ignored`.
  - `generation(existing) === null` and incoming has current-session commit
    evidence: retire existing with a diagnostic.
- State the asymmetry with the read model explicitly: the canonical kernel
  refuses to order null-generation facts during reads because reading is
  guessing. A current-session commit has fresh server-issued transition
  evidence, so it can retire same-group null-generation legacy facts.
- Treat `stale_commit_ignored` as an operation anomaly for registration, unlock,
  and step-up callers. The caller must surface diagnostics and re-read canonical
  state; it must not proceed as if its just-minted session committed.

Exit criteria:

- Restore/rehydration writes no longer retire same-authority/same-key records.
- Step-up commits generation N+1, then sealed restore writes generation N via
  fact write; N+1 survives and canonical selection picks N+1.
- Commit of generation N while generation N+1 exists returns
  `stale_commit_ignored`, retires nothing, and callers treat it as a failed
  current-session commit.
- Equal-generation same-session retry replaces idempotently.
- Equal-generation different-session commit keeps both records and returns
  `same_generation_distinct_session`.
- Same-group null-generation legacy facts are retired only from
  current-session commit, with diagnostics.
- Type fixtures reject passing a generic persisted session record into current
  commit functions.
- ECDSA and Ed25519 have parallel command splits; no curve-generic persistence
  abstraction is introduced.
- `pnpm build:sdk` and focused restore/step-up supersession tests pass.

Tracking:

- [x] Add Ed25519 fact-write and current-session-commit command types.
- [x] Replace generic Ed25519 upsert-boundary retirement with
      `commitCurrentThresholdEd25519Session`.
- [x] Route Ed25519 restore/rehydration/status writes through fact write only.
- [x] Add Ed25519 regression tests for restore generation N after step-up N+1,
      stale commit N while N+1 exists, equal-generation idempotent retry,
      equal-generation distinct-session anomaly, and null-generation legacy
      retirement during current commit.
- [x] Add Ed25519 type fixtures rejecting generic records as current-commit
      inputs.
- [x] Add ECDSA fact-write and current-session-commit command types.
- [x] Restrict ECDSA superseded-record cleanup to current commit paths.
- [x] Add ECDSA parity tests for restore-after-step-up and stale-commit
      anomalies.
- [x] Run `pnpm build:sdk` and focused supersession tests.

## Phase 11: Deferred Deployment And CI Gate

Status: deferred. Start only after Phase 10 manual runtime validation and
Phase 10A/10B/10C canonical lane-inventory cleanup has passed for Passkey and
Email OTP flows.

Do:

- Promote the verified runtime flows into the later CI/intended-behavior gate
  after manual testing.
- Add deployment/CI checks only after the browser runtime contracts are stable
  enough to be mandatory.

Tracking:

- [ ] Promote verified runtime flows into the later CI/intended-behavior gate.
- [ ] Run the Refactor 88 pre-merge lifecycle gate with `pnpm test:intended`.
      Email OTP flows require `SEAMS_INTENDED_GOOGLE_ID_TOKEN`; the CI startup
      path provides fresh local services/state, not a Google OIDC credential.
- [ ] Add deployment/CI enforcement after manual runtime validation is complete.

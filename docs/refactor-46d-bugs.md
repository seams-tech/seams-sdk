# Refactor 46d: OTP/Passkey Regression Postmortem and Hardening

Date created: 2026-05-30

Status: fixed-behaviour postmortem plus proposed hardening plan.

## Manual Validation Baseline

Manual testing after the 46c fixes confirms the target behavior for both Email
OTP and passkey accounts:

- registration succeeds
- NEAR, Tempo, and EVM transaction signing succeeds
- step-up auth plus transaction signing succeeds for NEAR, Tempo, and EVM
- Ed25519 and ECDSA key export succeeds

This document records the bug classes that made the work difficult and the
hardening tasks that should prevent the same regressions from returning.

This is both:

- a postmortem for the bugs already fixed and manually validated
- a hardening plan for preventing the same bug classes from recurring

The plan is split into two tracks:

- **Must prevent recurrence now**: small, high-signal guards and parity checks
  that should land before more registration/signing refactors.
- **Structural cleanup**: deeper type and architecture consolidation that should
  remove the underlying ambiguity without creating another oversized change set.

## Main Bug Classes

### 1. Email OTP Challenge Binding Mixed Purpose And Wallet Identity

Email OTP registration supports requesting one OTP code, rerolling the generated
wallet name, then finalizing with the original code. The challenge was created
for the initial wallet id and later verified against the final wallet id and a
different purpose shape. That produced:

```txt
Email OTP challenge is not valid for the current app session
```

The real invariant is that the same provider subject, challenged email,
organization, app-session version, OTP code, and allowed registration purpose own
the challenge. The final wallet id can differ during registration reroll.

### 2. Provider Subject, User Id, And Wallet Id Were Ambiguous

Several values used similar names:

- durable wallet id
- OIDC provider subject
- Email OTP challenge subject
- route/session user id
- NEAR account id projection

This made comparisons like `record.userId === proof.providerSubject` hard to
reason about. The registration verifier now uses the clearer invariant:

```ts
record.challengeSubjectId === input.providerSubject
```

The lesson is that identity terms must encode the domain they identify.

### 3. Registration State And Unlock State Diverged

Some failures appeared only immediately after registration. The same wallet
worked after a later unlock because unlock rebuilt cleaner runtime lanes and
worker-backed material.

Affected paths included:

- Email OTP Ed25519 warm-session readiness
- Email OTP ECDSA lane publication
- ECDSA worker material for Tempo and Arc/EVM
- key export lane selection

Registration finalize must produce the same usable local state that unlock
produces for the same auth method.

### 4. Email OTP Ed25519 Readiness Was Gated By Retention

The lane reader treated inline Email OTP Ed25519 material as ready only for one
retention branch. Registration could persist usable inline material with another
retention value, causing the lane to appear restorable or missing even though the
record had signing material.

Any Email OTP Ed25519 record with valid inline signing material, positive
remaining uses, and a future expiry should produce a ready lane.

### 5. Email OTP ECDSA Reached Passkey Warm-Session Infrastructure

Email OTP ECDSA accidentally flowed through passkey/touch-confirm sealed restore
paths. This caused misleading failures such as:

- missing PRF material
- missing concrete ECDSA chain target for seal persistence
- passkey signer lookup for an Email OTP wallet
- invalid Email OTP auth context after passkey-shaped restore

Passkey and Email OTP can share HSS activation logic. Their warm-session
persistence ownership must remain branch-specific after activation.

### 6. ECDSA Shared-Key Target Handling Was Incomplete

Tempo and Arc/EVM share ECDSA key facts, while signing requests are target
specific. Some code paths published or restored only the primary target. Others
selected an Arc/EVM lane backed by Tempo public identity without resolving the
source-chain signer material.

Failures included:

```txt
Threshold ECDSA signing session is not ready
[SigningEngine][ecdsa] exact available lane is unavailable after restore
```

ECDSA shared-key state must carry both the source chain target and every
published target. Material resolution must know when it is using source-chain
material for another target.

In this document, Tempo means canonical ECDSA target `tempo:42431`. Arc/EVM
means canonical ECDSA target `evm:eip155:5042002`.

### 7. Budget Lookup Was Too Session-Id Oriented

Tempo and Arc/EVM can share `walletSigningSessionId` and `thresholdSessionId`.
Budget/status lookup that keys only by those ids can select the wrong record or
auth token. ECDSA budget checks need the exact lane identity:

- wallet id
- auth method
- curve
- chain target
- key handle
- wallet signing session id
- threshold session id

### 8. Registration-Created ECDSA Sessions Had Insufficient Initial Uses

Some registration-created ECDSA sessions had a single remaining use. Tempo could
consume that use, leaving Arc/EVM unavailable immediately after registration.

The registration warm budget must cover the configured immediate post-registration
transaction targets, while the UI can still present this as one registration
approval.

### 9. Diagnostics Collapsed Distinct Failures

Several distinct bugs surfaced as generic readiness or challenge errors. The
useful diagnostics were the ones that named the exact layer:

- challenge purpose mismatch
- provider-subject mismatch
- wallet reroll binding mismatch
- missing exact ECDSA target record
- ECDSA material missing after restore
- non-active budget status
- wrong auth-method restore path

Targeted client diagnostics should stay on anomalous paths and avoid logging
auth tokens or secret material.

## Symptom-To-Root-Cause Checklist

| Symptom | Root cause | Fix landed | Regression guard |
| --- | --- | --- | --- |
| `Email OTP challenge is not valid for the current app session` after wallet-name reroll | Registration proof was effectively bound to the wrong wallet/purpose shape | Reroll proof binds provider subject, challenged email, challenge id, org, app-session version, and allowed registration purpose; final wallet id may differ | Route tests for one-code registration with reroll and wrong-subject/wrong-email rejection |
| Immediate OTP NEAR signing failed with missing/exact lane errors | Registration-created Ed25519 state did not match unlock-created state | Email OTP Ed25519 inline material can produce a ready lane when session budget/expiry are valid | Immediate post-registration NEAR signing test plus registration/unlock parity check |
| Immediate OTP Tempo/EVM failed with `threshold_ecdsa_session_not_ready` | ECDSA target publication and source-chain material resolution were incomplete | ECDSA shared-key target selection resolves source-chain material for target lanes | Tempo-primary material signs Arc/EVM transaction test |
| ECDSA signing failed with `exact available lane is unavailable after restore` | Public identity was treated as enough to select a lane even when signing material was absent | Material selection distinguishes public identity from ready signing material | Type fixture rejecting ready ECDSA lanes without signer material/source reference |
| Export failed with `readWarmSessionStatusOnly` undefined | Export path accepted incomplete warm-capability dependencies | Export readiness uses exact branch-specific dependencies | Type fixture for export dependency shape |
| OTP unlock wrote an invalid sealed session record | Sealed-record persistence accepted incomplete branch metadata | Persistence requires auth method, curve, chain target, wallet signing session id, and threshold session id | Sealed-record boundary tests |
| OTP ECDSA produced passkey/PRF/touch-confirm errors | Email OTP ECDSA reached passkey warm-session persistence | Email OTP ECDSA persistence follows Email OTP worker/publication path | Source guard forbidding Email OTP ECDSA imports/calls into passkey PRF seal persistence |
| Arc/EVM could consume or read Tempo budget status | ECDSA budget lookup used session ids without exact chain-target identity | ECDSA budget status resolves records by threshold session id and concrete chain target | Budget-status test with shared session ids and distinct target records |
| Immediate Arc/EVM failed after Tempo consumed the only ECDSA use | Registration ECDSA warm sessions minted too few signature uses for configured targets | Registration mints enough signature uses for immediate configured ECDSA targets | Registration allocation tests covering required ECDSA target count |

## Must Prevent Recurrence Now

These are narrow guardrails. They should land before more registration, storage,
or signing-session refactors.

### 1. Make The Behaviour Contract Testable

- [x] Treat `docs/intended-behaviours.md` as the source-of-truth behaviour
  contract for registration, unlock, signing, step-up, export, and page refresh.
- [x] Add a test matrix that maps each row in that document to at least one
  automated test or explicit manual-verification item.
- [x] Keep the matrix small and high-value:
  Email OTP registration with reroll, immediate NEAR/Tempo/Arc signing,
  immediate Ed25519/ECDSA export, post-exhaustion step-up for all three signing
  surfaces, and the same passkey sanity path.

### 2. Share Registration And Unlock Runtime Postconditions

Registration and wallet unlock must call the same postcondition checker. The
checker should prove that the wallet is locally usable before either flow reports
success.

Target shape:

```ts
type WalletRuntimePostconditionSource = 'registration_finalize' | 'wallet_unlock';

type WalletRuntimePostconditionInput = {
  source: WalletRuntimePostconditionSource;
  walletId: WalletId;
  authMethod: 'email_otp' | 'passkey';
  requiredEd25519: boolean;
  requiredEcdsaTargets: readonly ThresholdEcdsaChainTarget[];
};

type ReadyRuntimeLane = {
  state: 'ready';
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdSessionId;
  remainingSignatureUses: number;
  expiresAtMs: number;
};

type WalletRuntimePostcondition =
  | {
      ok: true;
      walletId: WalletId;
      authMethod: 'email_otp' | 'passkey';
      ed25519?: ReadyRuntimeLane;
      ecdsaByTarget: ReadonlyMap<string, ReadyRuntimeLane>;
    }
  | {
      ok: false;
      code:
        | 'wallet_missing'
        | 'auth_method_missing'
        | 'ed25519_lane_missing'
        | 'ecdsa_lane_missing'
        | 'lane_inventory_mismatch';
      details: Record<string, unknown>;
    };
```

Tasks:

- [x] Create one `assertWalletRuntimePostconditions(...)` entrypoint.
- [x] Call it from registration finalize before returning local success.
- [x] Call it from wallet unlock before reporting unlock success.
- [x] Compare auth method, curve, chain target, readiness, material source, and
  budget identity.
- [x] Add one parity test proving registration and unlock produce equivalent
  postconditions for the same wallet/auth method.

### 3. Lock Down Auth-Method Boundaries With Source Guards

- [x] Add a source guard proving Email OTP signing/export never calls passkey
  credential lookup.
- [x] Add a source guard proving Email OTP ECDSA never imports or calls passkey
  PRF/touch-confirm sealed restore.
- [x] Add a source guard proving EVM-family signing prep does not hardcode
  `authMethod: 'passkey'` outside passkey-only builders.
- [x] Add a source guard proving ECDSA budget status checks require a concrete
  `chainTarget`.
- [x] Add a source guard proving no wallet-subject vocabulary re-enters active
  runtime code.

### 4. Preserve High-Signal Failure Codes

- [x] Keep branch-specific challenge mismatch codes:
  `challenge_purpose_mismatch`, `challenge_subject_mismatch`,
  `challenge_email_mismatch`, `registration_attempt_missing`, and
  `registration_attempt_expired`.
- [x] Keep branch-specific runtime postcondition codes:
  `ed25519_lane_missing`, `ecdsa_lane_missing`, `lane_inventory_mismatch`, and
  `auth_method_route_mismatch`.
- [x] Keep diagnostics at boundaries only. Normal success paths should not emit
  temporary debug logs.

## Structural Cleanup

These tasks address the underlying ambiguity. They should land as small,
separately reviewable refactors after the recurrence guards are in place.

### Phase 1: Centralize Branded Domain IDs

Do not define duplicate branded ids. The codebase already has branded or
semi-branded identity types in multiple places:

- `WalletId` in `shared/src/utils/registrationIntent.ts`
- `WalletSigningSessionId`, `ThresholdEd25519SessionId`, and
  `ThresholdEcdsaSessionId` in
  `client/src/core/signingEngine/session/operationState/types.ts`
- `AccountId` / `StrictAccountId` in `client/src/core/types/accountIds.ts`
- ECDSA public-key brands in `shared/src/threshold/ecdsaHssRoleLocalBootstrap.ts`

The cleanup should consolidate shared identity brands into one central module
and re-export from old local modules during the refactor.

Preferred target:

```ts
// shared/src/utils/domainIds.ts
export type DomainId<TBrand extends string> = string & {
  readonly __domainIdBrand: TBrand;
};

// Durable wallet identity. This is the canonical local/server wallet id and
// must not be used as an OIDC subject, challenge owner, or session id.
export type WalletId = DomainId<'WalletId'>;

// Subject from the upstream identity provider, such as a Google OIDC `sub`.
// This identifies the human/provider account that requested or verified OTP.
export type ProviderSubject = DomainId<'ProviderSubject'>;

// Subject that owns an Email OTP challenge. For Google registration this should
// match ProviderSubject after parsing, but it remains a separate type so
// challenge records cannot be accidentally compared to wallet ids.
export type ChallengeSubjectId = DomainId<'ChallengeSubjectId'>;

// Email OTP challenge handle. This identifies one issued OTP challenge and
// must not be used as the provider subject that owns the challenge.
export type EmailOtpChallengeId = DomainId<'EmailOtpChallengeId'>;

// Hosted Email OTP registration-attempt handle. This is a server-side attempt
// pointer, distinct from both the OTP challenge id and the wallet id.
export type EmailOtpRegistrationAttemptId = DomainId<'EmailOtpRegistrationAttemptId'>;

// Tenant or organization scope for hosted auth and wallet records.
export type OrgId = DomainId<'OrgId'>;

// App-session version string from the auth/session authority.
export type AppSessionVersion = DomainId<'AppSessionVersion'>;

// Client wallet signing-session id. This groups one local approval/session
// budget and can cover multiple threshold-session ids.
export type WalletSigningSessionId = DomainId<'WalletSigningSessionId'>;

// Server threshold Ed25519 session id used for NEAR signing and Ed25519 export.
export type ThresholdEd25519SessionId = DomainId<'ThresholdEd25519SessionId'>;

// Server threshold ECDSA session id used for Tempo/EVM signing and ECDSA export.
export type ThresholdEcdsaSessionId = DomainId<'ThresholdEcdsaSessionId'>;

// Curve-specific server threshold session id. Use this only at APIs that are
// genuinely curve-generic; prefer the curve-specific id in curve-specific code.
export type ThresholdSessionId = ThresholdEd25519SessionId | ThresholdEcdsaSessionId;
```

Tasks:

- [x] Inventory existing branded ids and choose the central module path.
- [x] Move shared identity brands into the central module.
- [x] Re-export `WalletId` from `shared/src/utils/registrationIntent.ts` instead
  of defining it there.
- [x] Re-export signing-session ids from operation-state modules instead of
  defining separate local brands.
- [x] Add `ProviderSubject` and `ChallengeSubjectId` to the central module.
- [x] Add `EmailOtpChallengeId` and `EmailOtpRegistrationAttemptId` to the
  central module so OTP challenge handles cannot be confused with challenge
  owners or registration-attempt handles.
- [x] Add type fixtures proving provider subjects cannot be passed where wallet
  ids are required, and wallet ids cannot be passed where provider subjects are
  required.
- [x] Add type fixtures proving OTP challenge ids and registration-attempt ids
  are not interchangeable.
- [x] Add a source guard rejecting duplicate declarations of central domain-id
  brands outside `shared/src/utils/domainIds.ts`.
- [x] Keep string validation and branding at route, JWT, DB, worker, and UI
  boundaries.

### Phase 2: Normalize Email OTP Challenge Proof Once

- [x] Introduce a boundary parser that returns a narrow
  `EmailOtpRegistrationChallengeProof` union.
- [x] Parse the server registration challenge proof into branded
  `ProviderSubject`, `ChallengeSubjectId`, `WalletId`, `EmailOtpChallengeId`,
  and `EmailOtpRegistrationAttemptId` before challenge verification.
- [x] Model registration reroll explicitly:
  `originalWalletId`, `finalWalletId`, `providerSubject`, `challengeSubjectId`,
  `challengeEmail`, `orgId`, `appSessionVersion`, and `challengeId`.
- [x] Require registration finalize to accept only the normalized proof type.
- [x] Split failure codes for purpose mismatch, provider-subject mismatch,
  email mismatch, expired challenge, missing attempt, and disallowed reroll.
- [x] Split hosted registration-attempt missing and expired cases into
  `registration_attempt_missing` and `registration_attempt_expired`.
- [x] Add route/service tests for one-code registration with zero rerolls, one reroll,
  multiple rerolls, wrong provider subject, wrong challenged email, and expired
  challenge.

### Phase 3: Split Warm-Session Persistence By Auth Method

- [x] Define branch-specific warm-session persistence ports:
  `PasskeyWarmSessionPersistencePort` and `EmailOtpWarmSessionPersistencePort`.
- [x] Require Email OTP ECDSA persistence to carry `authMethod: 'email_otp'`,
  `curve: 'ecdsa'`, concrete `chainTarget`, wallet id, wallet signing session id,
  threshold session id, and Email OTP auth context.
- [x] Require passkey ECDSA persistence to carry passkey PRF/seal-specific
  material and credential identity.
- [x] Delete generic Email OTP calls into touch-confirm/passkey warm persistence
  after the branch-specific ports are wired.
- [x] Add source guards proving Email OTP ECDSA cannot import or call passkey PRF
  seal persistence.

### Phase 4: Make ECDSA Shared-Key State Explicit

- [x] Introduce an `EvmFamilySharedEcdsaReadyState` type with:
  source chain target, published target list, shared public facts, wallet signing
  session id, threshold session id, auth method, and material handle/source.
- [x] Require every target-specific lane to reference a concrete shared-key
  source state.
- [x] Make `public_identity_only` and `ready_to_sign` separate states.
  Signing prep may not treat public identity as signing material.
- [x] Add type fixtures that reject a ready ECDSA lane without signer material,
  worker handle, or source-chain material reference.
- [x] Add tests for Tempo-primary material signing Arc/EVM transactions and
  Arc/EVM-primary material signing Tempo transactions if that direction is
  supported.

### Phase 5: Make Budget Status Lane-Exact

- [x] Replace session-id-only ECDSA budget status lookups with the existing
  `EcdsaLaneBudgetStatusCheck` exact lane shape, or rename it only as part of a
  complete call-site/type-fixture update.
- [x] Include chain target and key handle in every ECDSA budget auth lookup.
- [x] Add guards rejecting calls to ECDSA budget status with only
  `walletSigningSessionId` and `thresholdSessionId`.
- [x] Keep internal server enforcement in signature-use units.
- [x] Keep public UX/API wording in approval units, with registration/step-up
  minting enough signature uses for the approved operation.

### Phase 6: Regression Coverage And Release Gates

- [x] Add immediate post-registration signing coverage for Email OTP NEAR,
  Tempo, and Arc/EVM lanes. Browser smoke coverage can follow after those
  invariants are locked.
- [x] Add immediate post-registration export coverage for Email OTP Ed25519 and
  ECDSA export after export approval.
- [x] Add the same immediate post-registration signing coverage for passkey
  accounts.
- [x] Add the same immediate post-registration export coverage for passkey
  accounts after export approval.
- [x] Add unlock parity tests proving registration-created lanes and
  unlock-created lanes have the same auth method, target, readiness, and material
  shape.
- [x] Add page-refresh tests proving valid exact lanes restore from durable
  sealed records and invalid exact lanes are rejected before success.
- [x] Keep temporary diagnostic logs out of normal success paths.

## Implementation Spec Appendix

This appendix is the implementation-ready contract for the hardening work above.
It names the files, types, parsers, old paths to delete, acceptance tests, and
non-goals for each phase.

### Implementation Order

1. Add recurrence guards and the behaviour matrix.
2. Centralize domain id brands through re-exports, without creating duplicate
   brands.
3. Normalize Email OTP registration challenge proof once at the server boundary.
4. Add the shared registration/unlock runtime postcondition.
5. Split passkey and Email OTP warm-session persistence ports.
6. Model ECDSA shared-key readiness and budget exactness.
7. Wire release gates to commands or source guards.

### Phase A: Behaviour Contract And Test Matrix

**Files to change**

- `docs/intended-behaviours.md`
- `docs/refactor-46d-bugs.md`
- `tests/unit/emailOtpRegistrationRoute.unit.test.ts`
- `tests/relayer/email-otp.authservice.test.ts`
- `tests/relayer/email-otp.routes.test.ts`
- `tests/unit/registrationIntentAllocation.unit.test.ts`
- `tests/unit/nearSigning.sessionSelection.unit.test.ts`
- `tests/unit/evmFamily.requestBoundary.unit.test.ts`
- `tests/unit/ecdsaSelection.restorable.unit.test.ts`
- `tests/unit/exportLaneSelection.unit.test.ts`
- `tests/unit/webauthnPromptCredentialSelection.unit.test.ts`

**Acceptance matrix**

| Behaviour | Required test layer | Required fixture |
| --- | --- | --- |
| Email OTP registration with zero rerolls uses one OTP code | relayer route test | challenge wallet id equals final wallet id |
| Email OTP registration with one reroll uses the original OTP code | relayer route test | original wallet id differs from final wallet id |
| Email OTP registration with multiple rerolls uses the original OTP code | relayer route test | two final wallet id changes before finalize |
| Wrong provider subject is rejected | auth service unit test | same code/email, different provider subject |
| Wrong challenged email is rejected | auth service unit test | same provider subject/code, different email |
| Registration and unlock produce equivalent runtime lanes | client unit test | same wallet/auth method, compare required lane keys |
| Immediate OTP registration signs NEAR | client signing test | Email OTP Ed25519 ready lane |
| Immediate OTP registration signs Tempo | client signing test | Tempo primary ECDSA target |
| Immediate OTP registration signs Arc/EVM | client signing test | `evm:eip155:5042002` target backed by shared ECDSA material |
| Tempo-primary material can sign Arc/EVM | client signing test | source target `tempo:42431`, request target `evm:eip155:5042002` |
| Arc/EVM-primary material can sign Tempo when supported | client signing test | source target `evm:eip155:5042002`, request target `tempo:42431` |
| Key export uses exact branch dependencies | client export test | Ed25519 and ECDSA export lanes |
| Step-up keeps auth method stable | client signing test | Email OTP step-up never reaches passkey lookup |
| Passkey smoke path still works | client signing test | passkey NEAR, Tempo, Arc/EVM, export |

**Commands**

```sh
pnpm -C tests exec playwright test ./unit/emailOtpRegistrationRoute.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.relayer.config.ts ./relayer/email-otp.authservice.test.ts ./relayer/email-otp.routes.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/nearSigning.sessionSelection.unit.test.ts ./unit/evmFamily.requestBoundary.unit.test.ts ./unit/ecdsaSelection.restorable.unit.test.ts ./unit/exportLaneSelection.unit.test.ts --reporter=line
pnpm build:sdk
```

**Non-goals**

- Do not add a broad browser flow before the unit/route invariants exist.
- Do not preserve legacy account fixtures that rely on missing signer material.

### Phase B: Central Domain IDs

**Files to change**

- `shared/src/utils/domainIds.ts` - new central home for shared identity brands.
- `shared/src/utils/registrationIntent.ts` - re-export `WalletId`.
- `client/src/core/signingEngine/interfaces/ecdsaChainTarget.ts` - import
  `WalletId` and `toWalletId` from the central module or keep a thin re-export.
- `client/src/core/signingEngine/session/operationState/types.ts` - re-export
  signing-session id brands from the central module.
- `client/src/core/types/accountIds.ts` - keep NEAR account-specific ids here
  and import shared ids from the central module when needed.
- `server/src/router/emailOtpRouteHandlers.ts`
- `server/src/router/relayWalletRegistration.ts`
- `server/src/core/AuthService.ts`
- `server/src/core/types.ts`

**New types**

Use one shared brand helper. Do not define a second `WalletId`,
`ProviderSubject`, `ChallengeSubjectId`, `WalletSigningSessionId`,
`ThresholdEd25519SessionId`, or `ThresholdEcdsaSessionId` in another module.

```ts
// shared/src/utils/domainIds.ts
export type DomainId<TBrand extends string> = string & {
  readonly __domainIdBrand: TBrand;
};

// Durable wallet identity. This is the canonical local/server wallet id and
// must not be used as an OIDC subject, challenge owner, or session id.
export type WalletId = DomainId<'WalletId'>;

// Subject from the upstream identity provider, such as a Google OIDC `sub`.
// This identifies the human/provider account that requested or verified OTP.
export type ProviderSubject = DomainId<'ProviderSubject'>;

// Subject that owns an Email OTP challenge. For Google registration this should
// match ProviderSubject after parsing, but it remains a separate type so
// challenge records cannot be accidentally compared to wallet ids.
export type ChallengeSubjectId = DomainId<'ChallengeSubjectId'>;

// Client wallet signing-session id. This groups one local approval/session
// budget and can cover multiple threshold-session ids.
export type WalletSigningSessionId = DomainId<'WalletSigningSessionId'>;

// Server threshold Ed25519 session id used for NEAR signing and Ed25519 export.
export type ThresholdEd25519SessionId = DomainId<'ThresholdEd25519SessionId'>;

// Server threshold ECDSA session id used for Tempo/EVM signing and ECDSA export.
export type ThresholdEcdsaSessionId = DomainId<'ThresholdEcdsaSessionId'>;

// Curve-specific server threshold session id. Use this only at APIs that are
// genuinely curve-generic; prefer the curve-specific id in curve-specific code.
export type ThresholdSessionId = ThresholdEd25519SessionId | ThresholdEcdsaSessionId;

export type DomainIdParseError = {
  code: 'missing' | 'invalid';
  message: string;
};

export type DomainIdParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: DomainIdParseError };
```

**Boundary parsers**

```ts
export function parseWalletId(raw: unknown): DomainIdParseResult<WalletId>;
export function parseProviderSubject(raw: unknown): DomainIdParseResult<ProviderSubject>;
export function parseChallengeSubjectId(raw: unknown): DomainIdParseResult<ChallengeSubjectId>;
export function parseWalletSigningSessionId(
  raw: unknown,
): DomainIdParseResult<WalletSigningSessionId>;
export function parseThresholdEd25519SessionId(
  raw: unknown,
): DomainIdParseResult<ThresholdEd25519SessionId>;
export function parseThresholdEcdsaSessionId(
  raw: unknown,
): DomainIdParseResult<ThresholdEcdsaSessionId>;
export function parseThresholdSessionId(raw: unknown): DomainIdParseResult<ThresholdSessionId>;
```

Normalize strings at these boundaries:

- route bodies in `server/src/router/*`
- JWT/app-session claims in `server/src/router/emailOtpRouteHandlers.ts` and
  `server/src/router/emailOtpSessionRouteHelpers.ts`
- DB records in server stores and IndexedDB record parsers
- worker messages in `client/src/core/signingEngine/workerManager/workers`
- UI prompt outputs before they enter signing-engine core functions

**Deleted paths**

- Local duplicate brand helpers for wallet ids or threshold-session ids.
- Core functions that accept raw `string` for provider subject, wallet id,
  challenge subject id, wallet signing session id, or threshold session id.

**Acceptance tests**

- Add type fixtures with `@ts-expect-error` proving a `ProviderSubject` cannot be
  passed where `WalletId` is required.
- Add type fixtures proving a `WalletId` cannot be passed where
  `ProviderSubject` or `ChallengeSubjectId` is required.
- Add a source guard that fails when new domain-id brands are declared outside
  `shared/src/utils/domainIds.ts` and approved crypto public-key brand modules.

**Non-goals**

- Do not move chain/network display ids into this phase.
- Do not change persisted column names in this phase.

### Phase C: Email OTP Registration Challenge Proof

**Files to change**

- `server/src/core/types.ts`
- `server/src/core/AuthService.ts`
- `server/src/router/relayWalletRegistration.ts`
- `server/src/router/emailOtpRouteHandlers.ts`
- `client/src/core/rpcClients/relayer/walletRegistration.ts`
- `client/src/core/SeamsPasskey/emailOtpRegistrationAuthority.ts`
- `client/src/core/SeamsPasskey/registration.ts`
- `tests/unit/emailOtpRegistrationRoute.unit.test.ts`
- `tests/relayer/email-otp.authservice.test.ts`
- `tests/relayer/email-otp.routes.test.ts`

**Parser input shape**

```ts
export type RawEmailOtpRegistrationChallengeProofInput = {
  challengeId?: unknown;
  otpCode?: unknown;
  providerSubject?: unknown;
  proofEmail?: unknown;
  googleEmailOtpRegistrationAttemptId?: unknown;
  originalWalletId?: unknown;
  finalWalletId?: unknown;
  orgId?: unknown;
  appSessionVersion?: unknown;
};
```

**Normalized output shape**

```ts
export type EmailOtpChallengePurpose =
  | { kind: 'registration'; action: 'wallet_email_otp_registration'; operation: 'registration' }
  | { kind: 'registration_reroll'; action: 'wallet_email_otp_login'; operation: 'wallet_unlock' };

export type EmailOtpRegistrationChallengeProof =
  | {
      kind: 'registration_attempt';
      challengeId: EmailOtpChallengeId;
      registrationAttemptId: EmailOtpRegistrationAttemptId;
      providerSubject: ProviderSubject;
      challengeSubjectId: ChallengeSubjectId;
      proofEmail: LowercaseEmail;
      originalWalletId: WalletId;
      finalWalletId: WalletId;
      orgId: OrgId;
      appSessionVersion: AppSessionVersion;
      purpose: EmailOtpChallengePurpose;
    }
  | {
      kind: 'direct_proof_email';
      challengeId: EmailOtpChallengeId;
      providerSubject: ProviderSubject;
      challengeSubjectId: ChallengeSubjectId;
      proofEmail: LowercaseEmail;
      finalWalletId: WalletId;
      orgId: OrgId;
      appSessionVersion: AppSessionVersion;
      purpose: EmailOtpChallengePurpose;
      registrationAttemptId?: never;
      originalWalletId?: never;
    };
```

**Validation order**

1. Parse app-session claims and body fields into branded ids and lowercase email.
2. Resolve `googleEmailOtpRegistrationAttemptId` when present.
3. Load the challenge record by `challengeId`.
4. Verify challenge existence, OTP code, and expiry.
5. Verify the allowed purpose:
   `wallet_email_otp_registration/registration` or the explicit reroll bridge
   from `wallet_email_otp_login/wallet_unlock`.
6. Verify provider subject, challenge subject, proof email, organization, and
   app-session version.
7. Verify reroll wallet rules.
8. Return the normalized proof. Registration finalize and storage writes must
   receive only this normalized proof type.

**Allowed reroll differences**

Only `finalWalletId` may differ from the wallet id originally attached to the
OTP challenge. These fields must match exactly:

- `challengeId`
- `otpCode`
- `providerSubject`
- `challengeSubjectId`
- `proofEmail`
- `orgId`
- `appSessionVersion`
- allowed challenge purpose

**Failure codes and HTTP statuses**

| Code | HTTP status | Meaning |
| --- | --- | --- |
| `invalid_body` | 400 | Missing or malformed proof fields |
| `registration_attempt_missing` | 409 | Attempt id was provided but no attempt exists |
| `registration_attempt_expired` | 409 | Attempt exists and is expired |
| `challenge_not_found` | 401 | Challenge id is unknown |
| `challenge_expired` | 401 | Challenge is expired |
| `challenge_code_mismatch` | 401 | OTP code does not match |
| `challenge_purpose_mismatch` | 401 | Challenge action/operation is not allowed for registration |
| `challenge_subject_mismatch` | 401 | Provider subject or challenge subject differs |
| `challenge_email_mismatch` | 401 | Challenged email differs |
| `registration_reroll_disallowed` | 401 | A login/unlock OTP was submitted for registration without an explicit reroll bridge |
| `challenge_session_mismatch` | 401 | Org or app-session version differs |
| `registration_reroll_wallet_mismatch` | 409 | A non-reroll branch changed wallet id |

**Deleted paths**

- Verification helpers that accept broad objects with optional identity fields.
- Finalize call sites that inspect `proofEmail`, `providerSubject`, or wallet ids
  from raw request bodies after proof normalization.

**Acceptance tests**

- Zero reroll succeeds with one OTP code.
- One reroll succeeds with one OTP code.
- Multiple rerolls succeed with one OTP code.
- Wrong provider subject fails with `challenge_subject_mismatch`.
- Wrong email fails with `challenge_email_mismatch`.
- Wrong purpose fails with `challenge_purpose_mismatch`.
- Expired registration attempt fails with `registration_attempt_expired`.

**Non-goals**

- Do not send a second OTP code during wallet-name reroll.
- Do not add compatibility for legacy proof names beyond the route parser.

### Phase D: Registration And Unlock Runtime Postconditions

**Files to change**

- `client/src/core/signingEngine/session/postconditions/runtimePostconditions.ts`
  - new shared checker.
- `client/src/core/SeamsPasskey/registration.ts`
- `client/src/core/SeamsPasskey/login.ts`
- `client/src/core/signingEngine/flows/registration/accountLifecycle.ts`
- `client/src/core/signingEngine/session/availability/availableSigningLanes.ts`
- `client/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts`
- `client/src/core/signingEngine/session/availability/readiness.ts`
- `tests/unit/runtimePostconditions.unit.test.ts`
- `tests/unit/availableSigningLanes.emailOtpParity.unit.test.ts`

**New types**

```ts
export type RuntimePostconditionSource = 'registration_finalize' | 'wallet_unlock';

export type RuntimePostconditionTarget =
  | { curve: 'ed25519'; chainTarget?: never }
  | { curve: 'ecdsa'; chainTarget: ThresholdEcdsaChainTarget };

export type RuntimeLaneMaterial =
  | { kind: 'durable_sealed_record' }
  | { kind: 'runtime_session_record' }
  | { kind: 'runtime_and_durable' }
  | {
      kind: 'evm_family_shared_key';
      sourceChainTarget: ThresholdEcdsaChainTarget;
    };

export type ReadyRuntimeLane = {
  state: 'ready';
  authMethod: 'email_otp' | 'passkey';
  target: RuntimePostconditionTarget;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdSessionId;
  remainingSignatureUses: PositiveSignatureUses;
  expiresAtMs: FutureEpochMs;
  material: RuntimeLaneMaterial;
};

export type WalletRuntimeInventory = {
  walletId: WalletId;
  authMethod: 'email_otp' | 'passkey';
  ed25519?: ReadyRuntimeLane;
  ecdsaByTarget: ReadonlyMap<string, ReadyRuntimeLane>;
};

export type WalletRuntimePostconditionResult =
  | { ok: true; inventory: WalletRuntimeInventory }
  | {
      ok: false;
      code:
        | 'wallet_missing'
        | 'auth_method_missing'
        | 'ed25519_lane_missing'
        | 'ecdsa_lane_missing'
        | 'lane_inventory_mismatch'
        | 'auth_method_route_mismatch'
        | 'lane_material_missing';
      details: Record<string, unknown>;
    };
```

**Builder and comparison contract**

```ts
export function readWalletRuntimePostconditions(args: {
  source: RuntimePostconditionSource;
  walletId: WalletId;
  authMethod: 'email_otp' | 'passkey';
  requiredTargets: readonly RuntimePostconditionTarget[];
}): Promise<WalletRuntimePostconditionResult>;

export function assertWalletRuntimePostconditions(args: {
  source: RuntimePostconditionSource;
  walletId: WalletId;
  authMethod: 'email_otp' | 'passkey';
  requiredTargets: readonly RuntimePostconditionTarget[];
}): Promise<WalletRuntimeInventory>;

export function compareWalletRuntimeInventories(args: {
  registration: WalletRuntimeInventory;
  unlock: WalletRuntimeInventory;
}): WalletRuntimePostconditionResult;
```

The comparison must use exact lane keys:

- wallet id
- auth method
- curve
- canonical ECDSA chain target key
- wallet signing session id presence
- threshold session id presence
- positive signature-use budget
- future expiry
- material branch that can satisfy the operation

`public_identity_only` is not a ready lane. `restorable` is not a ready lane.

**Call sites**

- Registration finalize calls `assertWalletRuntimePostconditions(...)` after
  persistence and warm hydration, before reporting success to UI.
- Wallet unlock calls the same function after warm hydration, before reporting
  success to UI.
- Email OTP unlock derives ECDSA required targets from the same configured
  publication/snapshot target set used for post-registration ECDSA lanes.

**Deleted paths**

- Registration-only postcondition checks that inspect different fields than
  unlock.
- Success paths that report local success with a missing required runtime lane.

**Acceptance tests**

- Email OTP registration and unlock produce equivalent required lane keys.
- Passkey registration and unlock produce equivalent required lane keys.
- Missing Ed25519 lane fails with `ed25519_lane_missing`.
- Missing sibling ECDSA target during Email OTP unlock fails with
  `ecdsa_lane_missing`.
- Missing Tempo lane fails with `ecdsa_lane_missing`.
- Arc/EVM lane backed only by public identity fails with `lane_material_missing`.

**Non-goals**

- Do not require key export readiness without export approval.
- Do not require every configured chain in products that only enable one target.

### Phase E: Auth-Method-Specific Warm-Session Persistence Ports

**Files to change**

- `client/src/core/signingEngine/session/passkey/warmSessionPersistence.ts`
  - new passkey-owned port or existing passkey module extension.
- `client/src/core/signingEngine/session/emailOtp/warmSessionPersistence.ts`
  - new Email OTP-owned port.
- `client/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts`
- `client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts`
- `client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts`
- `client/src/core/signingEngine/uiConfirm/UiConfirmManager.ts`
- `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- `client/src/core/signingEngine/workerManager/workerTypes.ts`
- `tests/unit/refactor46d.guard.unit.test.ts`
- `tests/unit/warmSessionStore.errorNormalization.unit.test.ts`

**New port signatures**

```ts
export type WarmSessionPersistenceError =
  | { code: 'invalid_args'; message: string }
  | { code: 'store_unavailable'; message: string }
  | { code: 'seal_failed'; message: string };

export type WarmSessionPersistenceResult =
  | { ok: true }
  | { ok: false; error: WarmSessionPersistenceError };

export type EmailOtpEcdsaReadyPersistInput = {
  authMethod: 'email_otp';
  curve: 'ecdsa';
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  material:
    | { kind: 'inline'; clientAdditiveShare32B64u: string }
    | { kind: 'worker_handle'; workerSessionId: string };
};

export type EmailOtpEd25519ReadyPersistInput = {
  authMethod: 'email_otp';
  curve: 'ed25519';
  walletId: WalletId;
  accountId: AccountId;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEd25519SessionId;
  material:
    | { kind: 'inline'; clientSecretB64u: string }
    | { kind: 'worker_handle'; workerSessionId: string };
  emailOtpAuthContext?: never;
};

export type PasskeyReadyPersistenceSource =
  | { kind: 'fresh_webauthn'; credentialIdB64u: string }
  | {
      kind: 'session_reconnect';
      restoredThresholdSessionId: ThresholdEcdsaSessionId | ThresholdEd25519SessionId;
    };

export type PasskeyEcdsaReadyPersistInput = {
  authMethod: 'passkey';
  curve: 'ecdsa';
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  persistenceSource: PasskeyReadyPersistenceSource;
  prfSealMaterial: PasskeyPrfSealMaterial;
};

export interface EmailOtpWarmSessionPersistencePort {
  persistEcdsaReady(input: EmailOtpEcdsaReadyPersistInput): Promise<WarmSessionPersistenceResult>;
  persistEd25519Ready(input: EmailOtpEd25519ReadyPersistInput): Promise<WarmSessionPersistenceResult>;
}

export interface PasskeyWarmSessionPersistencePort {
  persistEcdsaReady(input: PasskeyEcdsaReadyPersistInput): Promise<WarmSessionPersistenceResult>;
  persistEd25519Ready(input: PasskeyEd25519ReadyPersistInput): Promise<WarmSessionPersistenceResult>;
}
```

**Replacement targets**

Email OTP ECDSA must use `EmailOtpWarmSessionPersistencePort`. These calls must
not appear on an Email OTP ECDSA path:

- `touchConfirm.putWarmSessionMaterial(...)`
- `ensureEcdsaPrfSealPersisted(...)`
- `sealAndPersistWarmSessionMaterial(...)`
- passkey credential lookup before Email OTP signing/export
- passkey PRF material lookup before Email OTP signing/export

Passkey ECDSA continues to use passkey/touch-confirm persistence.

**Deleted paths**

- Generic ECDSA persistence helpers that infer auth method from optional fields.
- Email OTP ECDSA persistence inputs with optional `chainTarget` or optional
  `emailOtpAuthContext`.

**Acceptance tests**

- Source guard: Email OTP ECDSA modules do not import passkey PRF seal helpers.
- Unit test: Email OTP ECDSA persistence requires chain target.
- Unit test: Email OTP ECDSA persistence requires `emailOtpAuthContext`.
- Unit test: Passkey ECDSA persistence requires credential identity and PRF seal
  material.

**Non-goals**

- Do not rewrite the HSS cryptographic activation protocol in this phase.
- Do not remove passkey/touch-confirm persistence for passkey accounts.

### Phase F: ECDSA Shared-Key Readiness State

**Files to change**

- `client/src/core/signingEngine/session/availability/availableSigningLanes.ts`
- `client/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts`
- `client/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts`
- `client/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts`
- `client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts`
- `client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts`
- `client/src/core/signingEngine/flows/recovery/ecdsaExportMaterial.ts`
- `client/src/core/signingEngine/flows/recovery/exportLaneSelection.ts`
- `client/src/core/signingEngine/session/persistence/records.ts`
- `tests/unit/ecdsaSelection.restorable.unit.test.ts`
- `tests/unit/exportLaneSelection.unit.test.ts`

**Canonical chain targets**

- Tempo testnet: `tempo:42431`
- Arc EVM testnet: `evm:eip155:5042002`

Use the existing canonical target-key helper for equality. Display fields such
as `networkSlug` must not influence equality.

**New union**

```ts
export type EvmFamilySharedEcdsaState =
  | {
      kind: 'unavailable';
      reason: 'missing_record' | 'invalid_record' | 'unsupported_target';
      walletId: WalletId;
      requestChainTarget: ThresholdEcdsaChainTarget;
    }
  | {
      kind: 'public_identity_only';
      walletId: WalletId;
      authMethod: 'email_otp' | 'passkey';
      sourceChainTarget: ThresholdEcdsaChainTarget;
      publishedTargets: readonly ThresholdEcdsaChainTarget[];
      sharedPublicFacts: EvmFamilyEcdsaPublicFacts;
      walletSigningSessionId?: never;
      thresholdSessionId?: never;
      signerMaterial?: never;
    }
  | {
      kind: 'restorable';
      walletId: WalletId;
      authMethod: 'email_otp' | 'passkey';
      sourceChainTarget: ThresholdEcdsaChainTarget;
      publishedTargets: readonly ThresholdEcdsaChainTarget[];
      sharedPublicFacts: EvmFamilyEcdsaPublicFacts;
      restore:
        | { kind: 'email_otp_worker'; workerSessionId: string }
        | { kind: 'passkey_seal'; credentialIdB64u: string };
      walletSigningSessionId: WalletSigningSessionId;
      thresholdSessionId: ThresholdEcdsaSessionId;
      signerMaterial?: never;
    }
  | {
      kind: 'ready_to_sign';
      walletId: WalletId;
      authMethod: 'email_otp' | 'passkey';
      sourceChainTarget: ThresholdEcdsaChainTarget;
      publishedTargets: readonly ThresholdEcdsaChainTarget[];
      sharedPublicFacts: EvmFamilyEcdsaPublicFacts;
      walletSigningSessionId: WalletSigningSessionId;
      thresholdSessionId: ThresholdEcdsaSessionId;
      remainingSignatureUses: PositiveSignatureUses;
      expiresAtMs: FutureEpochMs;
      signerMaterial:
        | { kind: 'inline'; clientAdditiveShare32B64u: string }
        | { kind: 'worker_handle'; workerSessionId: string }
        | { kind: 'source_chain_material'; sourceChainTarget: ThresholdEcdsaChainTarget };
    }
  | {
      kind: 'ready_for_export';
      walletId: WalletId;
      authMethod: 'email_otp' | 'passkey';
      sourceChainTarget: ThresholdEcdsaChainTarget;
      publishedTargets: readonly ThresholdEcdsaChainTarget[];
      sharedPublicFacts: EvmFamilyEcdsaPublicFacts;
      exportMaterial: EcdsaExportMaterialHandle;
      walletSigningSessionId: WalletSigningSessionId;
      thresholdSessionId: ThresholdEcdsaSessionId;
    }
```

Expired and exhausted candidates remain in `ReauthRequiredEcdsaMaterial.reason`
for the signing-selection layer. They are not branches of
`EvmFamilySharedEcdsaState`, because the shared-key state model represents
public identity, restorable state, ready signing material, and export readiness.

**Selection rules**

- Signing may consume only `ready_to_sign`.
- Export may consume only `ready_for_export` or a branch that explicitly builds
  `ready_for_export` after export approval.
- `public_identity_only` can display addresses and public facts.
- `restorable` requires same-auth-method restoration before signing.
- `ReauthRequiredEcdsaMaterial.reason` carries `expired` and `exhausted` before
  the state can become `ready_to_sign`.
- A target lane can use `source_chain_material` only when the source target and
  requested target share the same ECDSA key facts.

**Deleted paths**

- Any branch that treats public identity as ready signing material.
- Any branch that chooses a target lane without carrying `sourceChainTarget`.
- Hard-coded `authMethod: 'passkey'` in EVM-family signing prep outside
  passkey-only builders.

**Acceptance tests**

- Type fixture rejects `ready_to_sign` without signer material.
- Type fixture rejects `public_identity_only` with signer material.
- Tempo-primary ready material signs Arc/EVM.
- Arc/EVM-primary ready material signs Tempo when that direction is supported.
- Arc/EVM target with only public identity fails with a material-specific error.

**Non-goals**

- Do not duplicate ECDSA records per target when one shared-key source can be
  represented explicitly.
- Do not use diagnostics objects to decide readiness.

### Phase G: Exact ECDSA Budget Status

**Files to change**

- `client/src/core/signingEngine/session/budget/budget.ts`
- `client/src/core/signingEngine/session/budget/budgetStatusReader.ts`
- `client/src/core/signingEngine/session/budget/BudgetCoordinator.ts`
- `client/src/core/signingEngine/flows/signEvmFamily/budgetSpending.ts`
- `client/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts`
- `server/src/router/signingBudgetStatus.ts`
- `server/src/router/signingBudgetStatus.typecheck.ts`
- `server/src/router/cloudflare/routes/sessions.ts`
- `tests/unit/evmFamily.requestBoundary.unit.test.ts`

**Type shape**

Use the existing `EcdsaLaneBudgetStatusCheck` shape as the exact ECDSA budget
type. Rename it only if the codebase also updates every call site and type
fixture in the same change.

```ts
export type EcdsaLaneBudgetStatusCheck = {
  kind: 'ecdsa_lane_budget_status_check';
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  chainTarget: ThresholdEcdsaChainTarget;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  walletId?: never;
  targetThresholdSessionIds?: never;
  targetBackingMaterialSessionIds?: never;
  trustedStatusAuth?: never;
};

export type AuthenticatedEcdsaLaneBudgetStatusCheck = Omit<
  EcdsaLaneBudgetStatusCheck,
  'kind' | 'trustedStatusAuth'
> & {
  kind: 'authenticated_ecdsa_lane_budget_status_check';
  trustedStatusAuth: SigningSessionBudgetStatusAuth;
};
```

**Server lookup behaviour**

- Reject partial ECDSA status requests with `400 invalid_body`.
- Require chain target, key handle, wallet signing session id, threshold session
  id, and shared key identity.
- Resolve ECDSA budget by exact lane identity:
  wallet id from authenticated scope, auth method, chain target key, key handle,
  wallet signing session id, and threshold session id.
- Reject session-id-only ECDSA lookups even if the ids are globally unique in a
  test fixture.
- Return inactive status for exhausted or expired records. Do not silently pick a
  sibling target record.

**Deleted paths**

- ECDSA status calls that pass only `walletSigningSessionId` and
  `thresholdSessionId`.
- ECDSA status calls that omit `chainTarget` or `keyHandle`.
- ECDSA status readers that use wallet-wide budget checks for target-specific
  signing.

**Acceptance tests**

- Shared session ids with Tempo and Arc/EVM records return the requested target
  status.
- Missing chain target fails before server lookup.
- Missing key handle fails before server lookup.
- Wrong target auth token fails.
- Exhausted target does not borrow budget from a sibling target.

**Non-goals**

- Do not change server enforcement from signature-use units.
- Do not expose signature-use terminology as the primary UI copy.

### Phase H: Source Guards And Mechanical Success Criteria

**Files to change**

- `tests/unit/refactor46d.guard.unit.test.ts` - new guard suite.
- `tests/unit/indexedDBConsolidation.guard.unit.test.ts`
- `tests/unit/signingEngine.refactor33.guard.unit.test.ts`

**Required guards**

- Email OTP ECDSA modules do not import passkey PRF seal persistence.
- Email OTP signing/export modules do not call passkey credential lookup.
- EVM-family signing prep does not hardcode passkey auth outside passkey-only
  builders.
- ECDSA budget status builders require concrete chain target and key handle.
- Domain id brands are declared in the central module only, except approved
  crypto public-key brands.
- Active runtime code does not use wallet-subject naming.
- Sealed-session record writes require auth method, curve, wallet signing
  session id, threshold session id, and ECDSA chain target for ECDSA.

**Mechanical success criteria**

| Success criterion | Evidence |
| --- | --- |
| Registration and unlock produce equivalent lane inventories | `runtimePostconditions.unit.test.ts` |
| Email OTP reroll uses one OTP code | `emailOtpRegistrationRoute.unit.test.ts` |
| Email OTP ECDSA avoids passkey/touch-confirm persistence | `refactor46d.guard.unit.test.ts` |
| ECDSA budget status is target exact | `evmFamily.requestBoundary.unit.test.ts` |
| Domain ids cannot be mixed at compile time | type fixtures plus `pnpm build:sdk` |
| No temporary debug logs remain in success paths | `refactor46d.guard.unit.test.ts` |

**Non-goals**

- Do not make this guard suite inspect generated bundles.
- Do not add brittle line-number assertions.

## Success Criteria

- [x] Email OTP and passkey registration produce immediately usable NEAR, Tempo,
  and Arc/EVM transaction lanes.
- [x] Email OTP and passkey registration produce immediately usable Ed25519 and
  ECDSA export lanes after the required export approval.
- [x] Unlock and registration produce equivalent lane inventories for the same
  wallet/auth method.
- [x] Email OTP ECDSA has no runtime dependency on passkey PRF/touch-confirm
  sealed restore.
- [x] ECDSA budget status is always resolved with exact chain-target identity.
- [x] Challenge verification errors identify the failing invariant directly.
- [x] Type fixtures reject the identity and lifecycle mixups that caused the
  regressions.

# Refactor 46d: OTP/Passkey Regression Postmortem and Hardening

Date created: 2026-05-30

Status: proposed.

## Manual Validation Baseline

Manual testing after the 46c fixes confirms the target behavior for both Email
OTP and passkey accounts:

- registration succeeds
- NEAR, Tempo, and EVM transaction signing succeeds
- step-up auth plus transaction signing succeeds for NEAR, Tempo, and EVM
- Ed25519 and ECDSA key export succeeds

This document records the bug classes that made the work difficult and the
hardening tasks that should prevent the same regressions from returning.

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

## Hardening Plan

### Phase 1: Make Identity Terms Structural

- [ ] Add branded types for `WalletId`, `ProviderSubject`, `ChallengeSubjectId`,
  `NearAccountId`, `WalletSigningSessionId`, and `ThresholdSessionId` where
  these values cross auth, registration, session, and persistence boundaries.
- [ ] Rename any remaining core `userId` fields in Email OTP challenge and
  registration proof code to `providerSubject` or `challengeSubjectId`.
- [ ] Add type fixtures proving provider subjects cannot be passed to APIs that
  require wallet ids, and wallet ids cannot be passed to APIs that require
  provider subjects.
- [ ] Keep string normalization at route, JWT, DB, worker, and UI boundaries.
  Core registration and signing code should consume branded identity types.

### Phase 2: Normalize Email OTP Challenge Proof Once

- [ ] Introduce a boundary parser that returns a narrow
  `EmailOtpRegistrationChallengeProof` union.
- [ ] Model registration reroll explicitly:
  `originalWalletId`, `finalWalletId`, `providerSubject`, `challengeSubjectId`,
  `challengeEmail`, `orgId`, `appSessionVersion`, and `challengeId`.
- [ ] Require registration finalize to accept only the normalized proof type.
- [ ] Split failure codes for purpose mismatch, provider-subject mismatch,
  email mismatch, expired challenge, missing attempt, and disallowed reroll.
- [ ] Add route tests for one-code registration with zero rerolls, one reroll,
  multiple rerolls, wrong provider subject, wrong challenged email, and expired
  challenge.

### Phase 3: Make Registration Finalize Prove Runtime Parity

- [ ] Add a single post-finalize runtime-state object that registration must
  construct before declaring local registration complete.
- [ ] Require this state to include the configured Ed25519 and ECDSA lanes for
  the wallet and auth method.
- [ ] For Email OTP registration, require the same lane readiness shape that
  unlock would produce.
- [ ] For passkey registration, require the same lane readiness shape that
  passkey unlock would produce.
- [ ] Add a postcondition check that proves immediate NEAR, Tempo, Arc/EVM,
  Ed25519 export, and ECDSA export lane selection have exact candidates.
- [ ] Treat a failed postcondition as a registration-local persistence failure
  with actionable diagnostics. Blockchain rollback remains impossible after
  account creation, so the error must preserve enough state to repair or retry
  local persistence.

### Phase 4: Split Warm-Session Persistence By Auth Method

- [ ] Define branch-specific warm-session persistence ports:
  `PasskeyWarmSessionPersistencePort` and `EmailOtpWarmSessionPersistencePort`.
- [ ] Require Email OTP ECDSA persistence to carry `authMethod: 'email_otp'`,
  `curve: 'ecdsa'`, concrete `chainTarget`, wallet id, wallet signing session id,
  threshold session id, and Email OTP auth context.
- [ ] Require passkey ECDSA persistence to carry passkey PRF/seal-specific
  material and credential identity.
- [ ] Delete generic Email OTP calls into touch-confirm/passkey warm persistence
  after the branch-specific ports are wired.
- [ ] Add source guards proving Email OTP ECDSA cannot import or call passkey PRF
  seal persistence.

### Phase 5: Make ECDSA Shared-Key State Explicit

- [ ] Introduce an `EvmFamilySharedEcdsaReadyState` type with:
  source chain target, published target list, shared public facts, wallet signing
  session id, threshold session id, auth method, and material handle/source.
- [ ] Require every target-specific lane to reference a concrete shared-key
  source state.
- [ ] Make `public_identity_available` and `ready_to_sign` separate states.
  Signing prep may not treat public identity as signing material.
- [ ] Add type fixtures that reject a ready ECDSA lane without signer material,
  worker handle, or source-chain material reference.
- [ ] Add tests for Tempo-primary material signing Arc/EVM transactions and
  Arc/EVM-primary material signing Tempo transactions if that direction is
  supported.

### Phase 6: Make Budget Status Lane-Exact

- [ ] Replace session-id-only ECDSA budget status lookups with an
  `ExactEcdsaBudgetStatusCheck` that requires exact lane identity.
- [ ] Include chain target and key handle in every ECDSA budget auth lookup.
- [ ] Add guards rejecting calls to ECDSA budget status with only
  `walletSigningSessionId` and `thresholdSessionId`.
- [ ] Keep internal server enforcement in signature-use units.
- [ ] Keep public UX/API wording in approval units, with registration/step-up
  minting enough signature uses for the approved operation.

### Phase 7: Regression Tests And Source Guards

- [ ] Add browser or orchestration tests for immediate post-registration signing
  and export:
  Email OTP NEAR, Tempo, Arc/EVM, Ed25519 export, and ECDSA export.
- [ ] Add the same immediate post-registration coverage for passkey accounts.
- [ ] Add unlock parity tests proving registration-created lanes and
  unlock-created lanes have the same auth method, target, readiness, and material
  shape.
- [ ] Add source guards for:
  no Email OTP signing path calls passkey credential lookup;
  no Email OTP ECDSA path calls passkey PRF sealed restore;
  no EVM-family signing prep hardcodes `authMethod: 'passkey'`;
  no ECDSA budget status check omits chain target;
  no wallet-subject vocabulary re-enters active code.
- [ ] Keep targeted diagnostics for anomalous readiness and budget states:
  `[ECDSA_MATERIAL_SELECTION_DIAGNOSTIC][not-ready]` and
  `[SigningBudgetStatus][ecdsa][...]`.

## Success Criteria

- [ ] Email OTP and passkey registration produce immediately usable NEAR, Tempo,
  and Arc/EVM transaction lanes.
- [ ] Email OTP and passkey registration produce immediately usable Ed25519 and
  ECDSA export lanes after the required export approval.
- [ ] Unlock and registration produce equivalent lane inventories for the same
  wallet/auth method.
- [ ] Email OTP ECDSA has no runtime dependency on passkey PRF/touch-confirm
  sealed restore.
- [ ] ECDSA budget status is always resolved with exact chain-target identity.
- [ ] Challenge verification errors identify the failing invariant directly.
- [ ] Type fixtures reject the identity and lifecycle mixups that caused the
  regressions.

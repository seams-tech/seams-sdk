# Refactor 46c: Email OTP Regression Guards

Date created: 2026-05-30

Status: runtime fixes complete; manual validation passed for OTP and passkey accounts.
Follow-up type/inventory evidence remains tracked below.

## Goal

Prevent regressions in Email OTP registration, wallet-name reroll, immediate
post-registration signing/export, and auth-method-specific session hydration.

The recent bugs were hard to isolate because the broken state was often only
visible in the narrow window after registration. The same wallet usually worked
after a later unlock because the unlock path rebuilt a cleaner runtime state.
This plan makes that difference impossible to miss.

## Root Causes

### Challenge Purpose Drift

Email OTP challenge records can represent distinct purposes:

- registration
- wallet unlock
- add-auth-method
- recovery/export step-up

The registration flow allowed a challenge created for one purpose to reach a
verification path expecting another purpose. The clearest failure was a record
stored with:

```ts
action: 'wallet_email_otp_login'
operation: 'wallet_unlock'
```

being verified as:

```ts
action: 'wallet_email_otp_registration'
operation: 'registration'
```

The verifier detected the mismatch and returned:

```txt
Email OTP challenge is not valid for the current app session
```

The message was technically correct, but it hid the important detail that the
wrong challenge lifecycle had entered the registration finalize path.

### Wallet Reroll Was Bound To The Wrong Identity

Email OTP registration intentionally supports this flow:

1. send one OTP code
2. generate a wallet name
3. reroll the wallet name
4. finalize with the original OTP code

The OTP should be owned by the provider subject and challenged email. The final
wallet id can change during reroll. Earlier validation mixed wallet id,
session digest, challenge purpose, provider subject, and email into one binding
shape. That made reroll look like a suspicious session mismatch even when the
same provider subject and email were completing the registration.

### Ambiguous Subject Names

The same `userId` vocabulary was used for several different identities:

- durable wallet id
- route/session user
- OIDC provider subject
- Email OTP challenge owner

This made the key reroll invariant hard to read and easy to break:

```ts
record.userId === proof.providerSubject
```

The corrected invariant is explicit:

```ts
record.challengeSubjectId === input.providerSubject
```

### Registration Attempt Context Was Scattered

The registration finalize path reconstructed proof binding from multiple places:

- app-session JWT
- route body
- registration attempt store
- challenge record
- UI state after wallet-name reroll

When `googleEmailOtpRegistrationAttemptId`, proof email, or provider subject was
missing or stale, the verifier produced the same generic challenge error. The
boundary should normalize these values once into a required registration-proof
binding, then core verification should consume that narrow type.

### Immediate Registration State Diverged From Unlock State

Email OTP ECDSA registration persisted fresh ECDSA runtime material with:

```ts
source: 'registration'
```

That source means passkey-owned registration state. Immediately after Email OTP
registration, Tempo/EVM signing and ECDSA export selected passkey-oriented
runtime paths and failed with errors like:

```txt
[multichain] no passkey signer found for account ...
```

After unlock, the Email OTP login path rebuilt the ECDSA material with the
Email OTP source and auth context, which masked the registration bug. The
registration path and unlock path must create equivalent auth-method-specific
runtime state.

### Registration Finalize Had Weak Postconditions

Registration finalize succeeded before proving the local wallet could perform
the expected operations immediately:

- NEAR signing
- Tempo/EVM signing
- Ed25519 export
- ECDSA export
- step-up session selection

That allowed half-valid local state to persist. The first real operation later
became the integrity check, which made the bug feel unrelated to registration.

### Diagnostics Were Too Generic

Several distinct failures collapsed into similar messages:

- challenge purpose mismatch
- wallet reroll binding mismatch
- missing registration attempt
- stale app-session digest
- missing Email OTP auth context
- passkey path selected for an Email OTP wallet
- missing immediate Ed25519/ECDSA lanes

The logs eventually exposed the exact mismatch fields. Those diagnostics should
be retained at boundaries and summarized into stable failure codes.

## Regression Issues To Address

These regressions were found after the first 46c fixes. They belong in this
plan because they are the same class of bug: Email OTP registration created state
that only worked after a later unlock or after a passkey-shaped fallback repaired
runtime material.

### Warm-Session Transport Lost During Normalization

The specific Tempo failure:

```txt
Warm-session cache could not persist sealed refresh material (invalid_args):
Missing concrete ECDSA chain target for signing-session seal persistence
```

was caused by `prfCache.ts` dropping `transport` during warm-session material
normalization. The Email OTP ECDSA bootstrap had an exact chain target, but the
normalized cache write lost the ECDSA transport before sealed refresh persistence
read it back.

Required fix and guard:

- Preserve `transport` through warm-session material normalization.
- Add a focused regression test proving ECDSA `transport.chainTarget` survives the
  PRF cache path.
- Treat missing ECDSA transport at the persistence boundary as a typed boundary
  failure with the original session id and chain target key in diagnostics.

### Email OTP ECDSA Still Uses Passkey-Shaped Warm Persistence

The transport fix removes one trigger, but the larger flaw remains:
Email OTP ECDSA still depends on the generic
`touchConfirm.putWarmSessionMaterial(...)` path in
`session/passkey/ecdsaBootstrap.ts`.

That path is shaped around passkey PRF material and UiConfirm-owned sealed session
metadata reconstruction. Email OTP ECDSA correctness should not depend on
`UiConfirmManager` reconstructing ECDSA metadata from generic warm material.

Required fix and guard:

- Keep shared HSS activation logic where it genuinely belongs.
- Make persistence branch-specific after activation.
- Passkey ECDSA may continue to use `touchConfirm.putWarmSessionMaterial(...)`.
- Email OTP ECDSA must persist sealed refresh material through the Email OTP
  worker/publication path in `session/emailOtp/ecdsaPublication.ts`.
- The Email OTP persistence path must require `authMethod: 'email_otp'`,
  `curve: 'ecdsa'`, exact `chainTarget`, and Email OTP auth context.
- Add a source guard proving `email_otp_ecdsa_bootstrap` never writes warm
  material through touch-confirm.
- Add a source guard proving Email OTP ECDSA bootstrap does not call the passkey
  PRF seal persistence path.

### Post-Registration ECDSA Chain Targets Are Incomplete

The observed split:

- Tempo attempted role-local bootstrap for `tempo:42431`.
- EVM later failed with `threshold_ecdsa_session_not_ready` for `evm:5042002`.

shows that immediate post-registration ECDSA lane inventory is still incomplete
for all required chain targets. The primary chain can be bootstrapped while a
second configured ECDSA target remains missing, unrestored, or without worker
backing.

Required fix and guard:

- Registration finalize must prove every configured required ECDSA target has an
  exact Email OTP lane before returning success.
- The immediate post-registration lane inventory must match post-unlock inventory
  for the same wallet and auth method.
- `emailOtpEcdsaPublicationChainTargets(...)` must publish the same target set
  registration needs for immediate Tempo, EVM, and ECDSA export flows.
- Add a regression test that signs both Tempo and EVM immediately after Email OTP
  registration from a fresh local state.

### EVM-Family Signing Still Has A Passkey Default

EVM-family signing prep still contains a passkey-oriented default auth selection.
That makes Email OTP correctness depend on later lane selection overriding the
initial default. The signing plan should derive auth method from the selected
exact lane from the beginning.

Required fix and guard:

- Remove hard-coded passkey auth selection from EVM-family signing prep.
- Build signing intent from the exact selected lane's auth method.
- Add a guard that fails if an Email OTP lane reaches WebAuthn credential
  collection or passkey signer lookup.

### Immediate NEAR Signing And Export Must Stay On Email OTP Lanes

The earlier immediate-registration failures for NEAR signing and ECDSA export
had the same shape as the Tempo/EVM failures: fresh Email OTP registration state
was routed through passkey or generic warm-session paths.

Required fix and guard:

- NEAR signing after Email OTP registration must use the Email OTP Ed25519 warm
  lane and never require `PRF.first` from a passkey credential.
- ECDSA export after Email OTP registration must select an Email OTP ECDSA lane
  and never fail with `no passkey signer found`.
- Add immediate post-registration tests for NEAR signing, ECDSA export, and
  absence of passkey credential lookup.

## Target Invariants

- One Email OTP registration code can be reused across wallet-name rerolls for
  the same provider subject, challenged email, org, and app-session version.
- Reroll does not send another OTP code.
- Registration OTP verification uses a registration challenge or an explicit
  registration reroll proof.
- Unlock, add-auth-method, recovery, and export OTP challenges stay bound to
  their own purpose-specific verification branches.
- Registration proof always carries `providerSubject`.
- Stored Email OTP challenge ownership uses `challengeSubjectId`.
- The core reroll check is:

  ```ts
  record.challengeSubjectId === input.providerSubject
  ```

- Email OTP registration writes ECDSA session material with
  `source: 'email_otp'` and an Email OTP auth context.
- Passkey registration writes passkey-owned registration material.
- Immediate post-registration lanes match post-unlock lanes for the same wallet
  and auth method.
- Email OTP signing/export never invokes passkey credential lookup unless a
  passkey auth method is explicitly selected.
- Registration finalize proves all required local persistence rows exist before
  returning success.

## Non-Goals

- Do not send a second OTP solely because the wallet name changed.
- Do not add passkey fallback paths for Email OTP signing/export.
- Do not add compatibility flags or parallel legacy registration flows.
- Do not broaden core function inputs with optional identity/auth/session fields.

## Implementation Strategy

The fix should remove ambiguity at the boundary, commit only branch-specific
domain state, and prove registration success through readback before the UI sees
a completed wallet.

- Parse raw route/JWT/body data once, then pass required internal types through
  registration core.
- Represent Email OTP challenge purpose as a discriminated union.
- Represent signing/export auth as a discriminated union.
- Persist Email OTP and passkey runtime state through branch-specific builders.
- Add finalize postconditions that compare immediate registration lanes against
  unlock-produced lanes.
- Add static guards for known escape hatches: broad `source` writes, optional
  auth fields, passkey credential collection from Email OTP branches, and
  unchecked challenge-purpose casts.
- Keep diagnostic logs at request/persistence boundaries, with stable codes and
  exact mismatch fields.

## Implementation Order

1. Land boundary type cleanup for registration proof and challenge purpose.
2. Land reroll code-delivery and single-challenge guarantees.
3. Land auth-method-specific registration persistence and post-finalize
   readbacks.
4. Manually validate fresh Email OTP registration, reroll, immediate signing,
   immediate export, unlock, and post-unlock parity.
5. Add focused regression coverage after the manual behavior is proven.
6. Add the Postgres cleanup command and prune known corrupt local/staging rows.

## Implementation Evidence

- `pnpm -C tests exec playwright test ./unit/authService.hostedAccountPrivacy.unit.test.ts ./unit/stepUpAuthorization.builders.unit.test.ts --reporter=line`
- `pnpm -C tests exec playwright test -c playwright.relayer.config.ts ./relayer/email-otp.authservice.test.ts --reporter=line`
- `pnpm -C tests exec playwright test ./unit/emailOtpRegistrationRoute.unit.test.ts --reporter=line`
- `pnpm type-check:relay-server`
- `pnpm build:sdk`
- `node --check examples/relay-server/scripts/postgres-prune-legacy-email-otp-wallets.mjs`

## Phase 1: Boundary Types

- [x] Add a required `EmailOtpRegistrationProofBinding` internal type:

  ```ts
  type EmailOtpRegistrationProofBinding = {
    kind: 'registration_attempt' | 'direct_proof_email';
    providerSubject: string;
    proofEmail: string;
    registrationAttemptId?: string;
    challengeId: string;
  };
  ```

- [x] Normalize raw route/JWT/body values into
      `EmailOtpRegistrationProofBinding` at the route boundary.
- [x] Keep `providerSubject`, `proofEmail`, and `challengeId` required after
      parsing. `registrationAttemptId` is required for the hosted Google
      registration-attempt branch.
- [x] Make route parsing return a result union:

  ```ts
  type EmailOtpRegistrationProofBindingParseResult =
    | { ok: true; binding: EmailOtpRegistrationProofBinding }
      | { ok: false; code: EmailOtpRegistrationProofBindingParseError };
  ```

- [x] Reject missing `providerSubject`, missing `proofEmail` or hosted
      registration attempt, and missing `challengeId` before any challenge
      verification or registration side effect.
- [x] Remove optional identity/auth/session fields from Email OTP registration
      core functions.
- [x] Replace helper signatures that accept raw route objects with signatures
      that require `EmailOtpRegistrationProofBinding`.
- [ ] Add a type fixture proving registration core cannot be called with a
      partial proof binding.
- [x] Preserve persistence compatibility only inside challenge and registration
      attempt record parsers.

## Phase 2: Challenge Purpose Unions

- [x] Model Email OTP challenge verification input as a discriminated union:

  ```ts
  type EmailOtpChallengeVerificationIntent =
    | {
        kind: 'registration';
        binding: EmailOtpRegistrationProofBinding;
      }
    | {
        kind: 'wallet_unlock';
        walletId: string;
      }
    | {
        kind: 'add_auth_method';
        walletId: string;
      }
    | {
        kind: 'step_up';
        walletId: string;
        operation: EmailOtpChallengeOperation;
      };
  ```

- [x] Make each verification branch require its exact action and operation.
- [x] Keep the registration reroll exemption only in the `registration` branch.
- [x] Encode the expected stored challenge shape for each intent:

  ```ts
  type EmailOtpStoredChallengePurpose =
    | { kind: 'registration'; action: 'wallet_email_otp_registration'; operation: 'registration' }
    | { kind: 'wallet_unlock'; action: 'wallet_email_otp_login'; operation: 'wallet_unlock' }
    | { kind: 'add_auth_method'; action: 'wallet_email_otp_add_auth_method'; operation: 'add_auth_method' }
    | { kind: 'step_up'; action: 'wallet_email_otp_step_up'; operation: EmailOtpChallengeOperation };
  ```

- [x] Add an exhaustive mapper from verification intent to stored challenge
      purpose.
- [x] Delete direct action/operation comparisons outside that mapper and the
      boundary parser.
- [x] Return branch-specific mismatch codes:
      `challenge_purpose_mismatch`, `challenge_subject_mismatch`,
      `challenge_email_mismatch`, `registration_attempt_missing`, and
      `registration_attempt_expired`.
- [x] Keep structured boundary logs that include expected/actual action,
      operation, subject, wallet id, app-session version, and org match flags.

## Phase 3: Reroll Flow Contract

- [x] Keep one durable registration attempt across wallet-name rerolls.
- [x] Ensure reroll updates only the pending wallet id in registration UI state
      and registration intent state.
- [x] Keep the original OTP challenge and registration attempt id.
- [x] Store the registration attempt id as the stable handle for the user-visible
      OTP flow.
- [x] Make code delivery explicit:

  ```ts
  type EmailOtpRegistrationCodeDelivery =
    | { kind: 'sent'; challengeId: string; registrationAttemptId: string }
    | { kind: 'reused'; challengeId: string; registrationAttemptId: string };
  ```

- [x] Assert that reroll never calls the OTP send endpoint when a valid
      registration attempt already exists for the same provider subject and
      email.
- [x] Add a controller-level guard that treats wallet-name reroll as a local
      registration-intent update when `codeDelivery.kind === 'reused'`.
- [x] Add a server-side dry-run log for reroll validation with:
      registration attempt id, original wallet id, final wallet id, challenge
      id, provider-subject match, and proof-email match.
- [x] Add a boundary check that recovery-wrapped enrollment escrow metadata
      matches the final rerolled wallet id before finalize commits.
- [x] Add an explicit error code for escrow/final wallet mismatch:
      `registration_escrow_wallet_mismatch`.

## Phase 4: Auth-Method-Specific Registration State

- [x] Keep ECDSA bootstrap persistence branch-specific:

  ```ts
  type WalletRegistrationEcdsaBootstrapAuth =
    | { kind: 'passkey' }
    | {
        kind: 'email_otp';
        emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      };
  ```

- [x] Require the Email OTP branch to write:

  ```ts
  source: 'email_otp'
  emailOtpAuthContext.authSubjectId === providerSubject
  ```

- [x] Require the passkey branch to write passkey-owned registration state.
- [x] Add a static guard rejecting broad calls that pass `source` directly into
      wallet-registration ECDSA bootstrap persistence.
- [x] Add a type fixture proving Email OTP bootstrap cannot be built without
      an Email OTP auth context.
- [x] Add a type fixture proving passkey bootstrap cannot carry
      `emailOtpAuthContext`.
- [x] Add a targeted source guard for `source: 'registration'` inside Email OTP
      registration branches.
- [x] Add a targeted source guard for `source: 'email_otp'` inside passkey
      registration branches.
- [x] Make `ThresholdEcdsaEmailOtpAuthContext.authSubjectId` required and assert
      it equals `providerSubject` at the registration boundary.
- [x] Write a small debug inventory helper that prints exact ECDSA records by
      wallet id, auth method, source, chain target, threshold key id, and owner
      address.

## Phase 5: Registration Finalize Postconditions

- [x] Add a post-finalize readback check before returning registration success.
- [x] For Email OTP Ed25519-only registration, assert:
      wallet row, auth-method row, signer row, Ed25519 key material, and exact
      Ed25519 warm lane are present.
- [x] For Email OTP ECDSA-only registration, assert:
      wallet row, auth-method row, signer row, ECDSA key material/reference,
      and exact ECDSA ready lane are present.
- [x] For combined Email OTP registration, assert both Ed25519 and ECDSA
      postconditions.
- [ ] Assert that immediate post-registration lane inventory is equivalent to
      post-unlock lane inventory for the same wallet and auth method.
- [x] Fail registration before returning success when any postcondition is
      missing.
- [x] Return a branch-specific finalize failure code for every missing
      postcondition:
      `wallet_missing`, `auth_method_missing`, `signer_missing`,
      `key_material_missing`, `ed25519_lane_missing`, `ecdsa_lane_missing`, and
      `lane_inventory_mismatch`.
- [x] Log the post-finalize readback inventory only on failure or explicit debug
      mode.
- [ ] Ensure failed postconditions trigger registration rollback for local DB
      rows before the UI sees success.
- [x] Keep immutable chain-state rollback messaging separate from local
      persistence rollback messaging.

## Phase 6: Signing And Export Guards

- [x] Make signing/export auth plans branch-specific:

  ```ts
  type SigningAuthPlan =
    | { kind: 'passkey'; credentialIdB64u: string }
    | { kind: 'email_otp'; authSubjectId: string; grantId: string };
  ```

- [x] Route WebAuthn credential collection only from the passkey branch.
- [x] Route Email OTP signing/export only from the Email OTP branch.
- [x] Add an assertion at the WebAuthn collection boundary that logs and rejects
      `authMethod === 'email_otp'`.
- [x] Add an assertion at the Email OTP prompt boundary that logs and rejects
      `authMethod === 'passkey'`.
- [x] Add guard logs when exact lane selection fails:
      wallet id, auth method, algorithm, chain target, required signature uses,
      candidate count, and per-candidate rejection reason.
- [x] Keep failure codes stable:
      `ed25519_lane_missing`, `ecdsa_lane_missing`,
      `auth_method_route_mismatch`, and `passkey_lookup_for_email_otp`.
- [x] Add a lane-selection debug helper that can be called from NEAR, Tempo,
      EVM, Ed25519 export, and ECDSA export without influencing control flow.
- [x] Ensure diagnostics objects never decide which auth branch to execute.

## Phase 7: Regression Coverage

Add tests only after the manual reproduction passes with the intended runtime
behavior.

- [x] Email OTP registration without wallet-name reroll succeeds.
- [x] Email OTP registration with wallet-name reroll sends one OTP and succeeds.
- [x] Reroll preserves registration attempt id and challenge id.
- [x] Login/unlock OTP challenge cannot satisfy registration verification
      unless the request includes an explicit registration reroll proof whose
      provider subject, challenged email, challenge id, org, and app-session
      version match.
- [x] Registration OTP challenge cannot satisfy wallet unlock verification.
- [x] Email OTP immediate post-registration NEAR signing succeeds without a
      separate unlock.
- [x] Email OTP immediate post-registration Tempo/EVM signing succeeds without a
      separate unlock.
- [x] Email OTP immediate post-registration Ed25519 and ECDSA export succeed
      without a separate unlock.
- [x] Email OTP immediate post-registration signing/export does not call
      passkey credential lookup.
- [ ] Unlock after registration produces the same lane inventory as immediate
      registration.
- [x] Passkey registration, signing, step-up, and export remain unchanged.
- [x] Boundary parser rejects missing `providerSubject` before any side effect.
- [x] Boundary parser rejects hosted Google registration finalize without
      `registrationAttemptId`.
- [x] Challenge verifier returns `challenge_purpose_mismatch` for a wallet-unlock
      OTP used in registration finalize.
- [x] Challenge verifier returns `challenge_subject_mismatch` when
      `challengeSubjectId` and `providerSubject` differ.
- [x] Challenge verifier returns `challenge_email_mismatch` when proof email and
      challenged email differ.
- [x] Source guard rejects Email OTP registration writing passkey-owned ECDSA
      source.
- [ ] Type fixture rejects direct object-literal construction of invalid Email
      OTP signing/export auth plans.

## Phase 8: Manual Validation Checklist

- [x] Fresh browser profile or cleared IndexedDB.
- [x] Fresh Postgres wallet id.
- [x] Email OTP registration without reroll.
- [x] Email OTP registration with reroll using the original OTP.
- [x] Immediately after registration:
      NEAR signing, Tempo signing, EVM signing, Ed25519 export, and ECDSA export.
- [x] Lock, unlock, then repeat all signing/export operations.
- [x] Exhaust a session and confirm step-up succeeds for Email OTP.
- [x] Repeat passkey registration/signing/export once to catch shared-regression
      fallout.
- [ ] Capture the registration attempt id, challenge id, final wallet id,
      provider subject, and code-delivery mode from debug logs for the reroll
      run.
- [ ] Capture immediate post-registration lane inventory and post-unlock lane
      inventory for the same wallet.

## Phase 9: Legacy Postgres OTP Cleanup

Prune development/staging Postgres rows for Email OTP wallets that were created
while the broken registration paths were active. This cleanup should target
known-corrupt or half-registered accounts. Healthy passkey wallets and current
Email OTP wallets should remain untouched.

- [x] Define a `legacy_email_otp_wallet` predicate with required evidence:
      wallet has an Email OTP auth method and at least one broken invariant
      from this plan.
- [x] Include these broken-invariant checks in the dry-run report:
      missing initial auth-method row, missing signer row, missing signer/key
      material pair, missing Ed25519 identity for an Ed25519-capable wallet,
      stale registration attempt, stale challenge, mismatched provider subject,
      and incomplete registration ceremony.
- [x] Support two cleanup modes:
      explicit wallet-id allowlist and created-at time window for local/dev
      test wallets.
- [x] Make the default command dry-run only. The report should print wallet ids,
      provider subjects, auth methods, signer counts, key-material counts,
      registration attempt ids, challenge ids, and dependent-row counts.
- [x] Require an explicit destructive argument before deleting rows.
- [x] Run deletion in one Postgres transaction per wallet id.
- [x] Delete volatile Email OTP rows first:
      `email_otp_registration_attempts`, `email_otp_challenges`,
      `email_otp_unlock_challenges`, `email_otp_grants`, auth states, and
      recovery/enrollment escrow rows scoped to the wallet or provider subject.
- [x] Delete threshold runtime rows next:
      Ed25519 sessions, ECDSA signing sessions, presign sessions,
      presignatures, and signing-session seal/server-side session rows scoped
      to the wallet.
- [x] Delete key and signer rows after runtime rows:
      wallet signers, threshold Ed25519 keys, threshold ECDSA keys, signing root
      secret shares, and NEAR public-key projections scoped to the wallet.
- [x] Delete wallet registration rows:
      registration ceremonies, registration intents, wallet enrollments, and
      recovery preparation/execution rows scoped to the wallet.
- [x] Delete the wallet-auth-method rows before deleting the wallet row.
- [x] Refuse to delete any wallet that has a passkey auth method unless that
      wallet id is explicitly listed and the dry-run report marks it as corrupt.
- [x] After deletion, rerun the dry-run query and assert the targeted wallet ids
      have no remaining dependent rows.
- [x] Add the cleanup command to operations docs with a warning that production
      pruning requires a database backup and an explicit wallet-id allowlist.

## Completed Baseline

- [x] Documented `challengeSubjectId` and `providerSubject` vocabulary in
      Refactor 46b.
- [x] Required `providerSubject` in Email OTP registration proof paths.
- [x] Included `googleEmailOtpRegistrationAttemptId` in registration finalize
      body from the app-session JWT.
- [x] Resolved reroll proof email from the durable registration attempt.
- [x] Kept add-auth-method Email OTP verification wallet-bound.
- [x] Changed Email OTP ECDSA registration bootstrap persistence to write
      Email OTP auth context instead of passkey-owned registration source.
- [x] Required `providerSubject` when building Email OTP ECDSA registration auth
      context.
- [x] Verified the latest SDK build after the immediate-registration ECDSA source
      fix.

## Review Gates

- [x] No core Email OTP registration function accepts optional identity/auth
      fields.
- [x] No Email OTP registration path writes passkey-owned ECDSA registration
      source.
- [x] No Email OTP signing/export path invokes passkey credential lookup unless
      a passkey branch was selected.
- [x] No reroll path sends a second OTP for the same active provider subject and
      challenged email.
- [x] All challenge-purpose mismatches produce structured diagnostics at the
      boundary.
- [x] Legacy corrupt Email OTP Postgres rows have a dry-run cleanup path with
      explicit destructive confirmation.
- [x] Immediate post-registration validation covers the window before any
      separate unlock can repair runtime state.
- [ ] Registration and unlock produce equivalent lane inventories for matching
      auth method and wallet id.
- [x] Source/type guards reject the specific invalid states that caused this
      regression.
- [x] Manual immediate post-registration validation is complete before marking
      this refactor complete.

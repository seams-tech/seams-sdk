# Refactor 107: Reusable Signing Sessions and Operation Step-Up

Date created: August 12, 2026

Last reconciled: August 12, 2026 against the completed target architecture of
Refactors 100–103

Status: Planned

Implementation gate: begin after Refactors 100–103 are implemented, merged,
and their deletion and validation gates pass.

## Decision

Wallet unlock creates a short-lived reusable signing session. That session is
an optimization for repeated signing. It is not login identity, wallet-key
identity, lane lifecycle, custody readiness, material activation, or export
authority.

Every ordinary signing operation chooses one authorization source:

```text
exact reusable signing session is active and has budget
  -> use reusable signing authorization

reusable signing session is missing, expired, exhausted, or out of scope
  -> use same-method operation step-up
  -> authorize exactly one operation
```

Key export always uses fresh export-scoped operation step-up. Reusable signing
authority is ignored for export. Its absence or expiry never blocks export.

A successful step-up authorizes one operation. It does not unlock the wallet,
create or renew a reusable signing session, replenish signing budget, activate
a lane, recover custody, or change material.

## Post-Refactor 103 Baseline

Refactor 107 starts from the completed results of Refactors 100–103. It does
not plan around today's transitional custody, lane, rotation, or linked-device
code.

The required baseline is:

- Refactor 100 supplies server-held encrypted owner custody, wallet-scoped
  recovery envelopes, factor-specific unwrap, and opaque worker capabilities;
- Refactor 101 supplies stable `WalletKey` identity, active share-bearing
  `SigningLane` records, exact lane/material selection, and
  `PreparedWalletExecution`;
- Refactor 102 supplies curve-specific lane creation, refresh, aggregate
  activation, revocation, and exact activation receipts;
- Refactor 103 supplies active linked-device enrollments, linked-device lanes,
  reusable linked-device signing authorization, local-presence policy, and
  immediate revocation;
- the existing authorization domain supplies active Seams/app sessions,
  reusable authorization grants and quota, verified factor evidence,
  `AuthorizedOperation`, and atomic operation admission;
- `near.export_key` and `evm.export_key` are quota-neutral operation kinds;
- owner and linked-device material remain active when reusable authorization
  expires or exhausts its quota.

Refactor 107 consumes these results as fixed inputs. It does not recreate
wallet-key, lane, custody, rotation, or device state.

## Compatibility With Refactors 100–103

Refactor 107 is compatible with their target architecture. It intentionally
supersedes their remaining `Wallet Session` terminology and the behavior that
describes expiry as a terminal admission denial.

### Refactor 100: passkey custody

Refactor 100 keeps ownership of:

- random client roots and holder shares;
- passkey and recovery envelopes;
- KEK derivation and factor-specific unwrap;
- opaque live worker capabilities;
- synced-passkey cold custody access;
- credential replacement and wallet-scoped recovery.

Refactor 107 adds no custody format and never places authorization identity in
an envelope or material handle. A step-up ceremony may obtain the factor output
needed to open an exact owner or linked-device envelope, but authorization must
commit before plaintext root/share work begins. The factor output stays in the
secure worker.

Refactor 100 statements that use `WalletSessionId`, Wallet Session quota, or
Wallet Session admission now mean the reusable-signing-session branch defined
here. Its separation between authorization and material remains authoritative.

### Refactor 101: wallet keys and signing lanes

Refactor 101 remains the authority for:

- stable `WalletKey` identity;
- `SigningLaneRecord` and `ActiveSigningLaneReference`;
- lane kind, share epoch, revocation epoch, participants, and material
  activation;
- `PreparedOwnerWalletExecution` and `PreparedLinkedDeviceWalletExecution`;
- the rule that inactive or revoked lanes cannot execute;
- the rule that linked-device and delegated lanes cannot export.

Refactor 107 plans authorization before constructing
`PreparedWalletExecution`. Successful reusable or step-up admission produces
the `AuthorizedOperation` that Refactor 101 already requires. The exact active
lane and `MpcMaterialActivationRef` remain independent inputs.

Reusable-session unavailability is recoverable through step-up. An inactive,
revoked, stale, or superseded lane is a hard lane/material failure and never a
reason to step up.

### Refactor 102: rotation and revocation

Refactor 102 remains the authority for:

- curve-specific lane provisioning and refresh;
- share and revocation epochs;
- aggregate activation;
- forward-only protocol completion;
- lane and enrollment revocation;
- invalidation of stale material handles.

Step-up cannot reactivate a revoked lane or authorize a stale epoch. A valid
step-up may use only an exact active lane resolved after any pending activation
journal is reconciled.

Refactor 102 statements that Wallet Session expiry or quota exhaustion reject
new admission are narrowed as follows: they make the reusable branch
unavailable, preserve lane material, and cause the planner to select step-up
when the operation and lane permission allow it.

### Refactor 103: linked devices

Refactor 103 remains the authority for:

- linked-device enrollment and identity;
- linked-device signing lanes and aggregate key manifests;
- signing-only permission;
- required local user presence;
- reusable linked-device signing authorization and quota;
- immediate enrollment and child-lane revocation;
- the prohibition on linked-device export, recovery, and administration.

On an active linked device, missing, expired, exhausted, or scope-mismatched
reusable signing authority falls back to linked-device same-method step-up for
permitted signing operations. Required local user presence remains in force on
both authorization branches. User confirmation/local presence is a separate
requirement from whether authorization is reusable or one-operation.

Linked-device revocation remains a hard denial. Step-up cannot bypass it.
Linked-device lanes and holder packages remain unable to export.

## Goal

Establish one authorization model across owner and linked-device signing:

- the Seams/app session owns logged-in identity;
- `WalletKey` owns stable public signing identity;
- active `SigningLane` owns share-bearing execution topology;
- Refactor 100 custody owns encrypted holder/root material;
- `MpcMaterialActivationRef` owns exact active material identity;
- unlock owns reusable signing-session creation;
- reusable signing sessions own multi-use signing authority and quota;
- verified step-up owns one quota-neutral operation;
- export always requires fresh owner export step-up;
- reusable-session unavailability falls through to step-up;
- lane, enrollment, custody, or material failure remains an exact hard failure.

The first demonstrated operating path is owner Ed25519 export after reusable
signing-session expiry for passkey and Email OTP accounts.

## Canonical Domain Model

### Seams/app identity session

The identity session establishes:

- tenant and principal;
- wallet identity;
- registered auth-authority reference;
- device, audience, and request origin;
- app-session version and identity-session expiry.

Its lifecycle is independent from reusable signing-session expiry and quota.
An unavailable identity session requires login and prevents operation step-up.

### Wallet key

The active Refactor 101 `WalletKey` is the stable public identity for signing
and owner export. Credential replacement, lane refresh, reusable-session
expiry, step-up, and linked-device enrollment do not change it.

### Signing lane

An active Refactor 101 `SigningLane` supplies the exact execution topology for
ordinary signing:

- wallet key and lane ID;
- lane kind;
- holder and server participants;
- lane share and revocation epochs;
- exact `MpcMaterialActivationRef`;
- verified activation receipt.

Authorization availability is not part of lane lifecycle.

### Custody and live material

Refactor 100 envelope records and opaque worker handles supply factor-owned
material. The planner may resolve public envelope metadata before
authorization. Plaintext root/share opening and MPC work begin only after
authorization admission succeeds.

A live handle is a material cache. It is not a signing session and grants no
authority. Its TTL and zeroization lifecycle remain independent from reusable
authorization.

### Reusable signing session

Unlock creates an exact reusable signing session. The session contains:

- reusable authorization grant identity;
- reusable signing-session identity;
- exact wallet, key, permitted lane set, and audience binding;
- expiry;
- remaining-use quota.

It may authorize ordinary signing operations covered by its exact scope. It
cannot authorize export, lane creation, refresh, revocation, device linking,
recovery, or administration.

The availability presented to core planning is:

```ts
type ReusableSigningAuthorizationAvailability =
  | {
      readonly kind: 'available';
      readonly session: ExactActiveReusableSigningSession;
    }
  | {
      readonly kind: 'unavailable';
      readonly reason:
        | 'missing'
        | 'expired'
        | 'budget_exhausted'
        | 'scope_mismatch';
    };
```

Raw JWT presence, UI diagnostics, and inferred timestamps cannot construct
this union.

### Verified operation step-up

Step-up verifies the selected lane's or owner wallet's registered auth method
and authorizes one exact operation. It carries:

- tenant and principal;
- wallet key and, for signing, exact active lane;
- material activation or owner export material binding;
- operation ID and kind;
- lane, intent, and display digests;
- verified factor-evidence digest;
- short expiry;
- authorized-operation lifecycle.

Every verified step-up operation is quota-neutral and contains no reusable
signing-session identity.

## State and Policy Matrix

| Identity | Key/lane/custody | Reusable signing session | Operation | Result |
| --- | --- | --- | --- | --- |
| active | exact active | available | permitted signing | reusable authorization |
| active | exact active | missing/expired/exhausted/out of scope | permitted signing | same-method step-up |
| active | exact active owner export target | any state | owner key export | export step-up |
| missing/expired | any | any | signing or export | login required |
| active | lane inactive/revoked/stale | any | signing | exact lane failure |
| active | owner custody unavailable/corrupt | any | owner export | exact custody failure |
| active | linked-device/delegated/recovery-only target | any | export | export forbidden |
| active | active linked-device lane | unavailable | permitted signing | linked-device step-up with local presence |

Step-up is the fallback for reusable authorization failure. It is not fallback
for identity, permission, lane, enrollment, custody, or material failure.

## Authorization Planning

Authorization selection belongs in one post-103 planner. Inputs are already
normalized domain values:

- exact operation kind and normalized intent;
- active `WalletKey`;
- exact active owner or linked-device `SigningLane` for signing;
- owner export target for export;
- selected auth method and authority reference;
- reusable signing-session availability;
- required local-presence policy.

The ordinary-signing result is:

```ts
type WalletExecutionAuthorizationPlan =
  | {
      readonly kind: 'reusable_signing_session';
      readonly session: ExactActiveReusableSigningSession;
      readonly stepUp?: never;
    }
  | {
      readonly kind: 'verified_step_up';
      readonly preparation: ExactWalletExecutionStepUpPreparation;
      readonly session?: never;
    };
```

The export planner has one valid branch:

```ts
type OwnerExportAuthorizationPlan = {
  readonly kind: 'verified_step_up';
  readonly preparation: ExactOwnerExportStepUpPreparation;
};
```

Planning is linear:

1. require an active identity session;
2. require an active wallet key;
3. require operation permission and an exact active lane or owner export
   target;
4. for ordinary signing, select a usable exact reusable session when present;
5. otherwise select same-method step-up;
6. for export, select owner export step-up unconditionally.

After authorization admission, combine the claimed `AuthorizedOperation` with
the exact Refactor 101 lane and material activation to construct
`PreparedWalletExecution`. Diagnostics cannot construct prepared execution.

No caller may independently gate an operation with `isUnlocked`, JWT presence,
an expiry timestamp, an error string, or a wallet-iframe lifecycle projection.

## Operation Policy

| Operation | Reusable signing session | Step-up | Required execution target |
| --- | --- | --- | --- |
| NEAR transaction | preferred | fallback | active permitted signing lane |
| NEAR delegate action | preferred | fallback | active permitted signing lane |
| NEP-413 message | preferred | fallback | active permitted signing lane |
| EVM-family transaction | preferred | fallback | active permitted signing lane |
| Ed25519 key export | forbidden | required | active owner wallet key and owner custody |
| ECDSA key export | forbidden | required | active owner wallet key and owner custody |

Linked-device and delegated lanes cannot satisfy either export row. This rule
is inherited from Refactors 101–103 and remains true even when the user can
complete fresh step-up on that device.

## Owner Export Target

Export is not modeled as ordinary lane execution. Define an exact owner export
target from post-103 domain records:

```ts
type ExactOwnerExportTarget =
  | ExactOwnerEd25519ExportTarget
  | ExactOwnerEcdsaExportTarget;
```

Each branch requires:

- active `WalletKey` and wallet-key version;
- owner principal and registered owner auth method;
- immutable key identity and public key/address;
- owner custody envelope/capability identity from Refactor 100;
- exact active server material and `MpcMaterialActivationRef`;
- curve-specific threshold-session and participant bindings;
- runtime policy scope;
- no linked-device, delegated, recovery-only, or break-glass permission.

Branch-specific builders create this target. Broad lane records and UI
projections cannot be cast into it.

## Ed25519 Export Step-Up

### Prepare without reusable authority

Resolve the exact active owner Ed25519 wallet key, owner custody descriptor,
registered owner factor, active server material, and material activation. This
resolution uses no reusable signing-session projection or JWT.

Build the existing Yao export admission request and canonical export digests
from public facts before opening owner custody material.

The operation envelope binds:

- capability `near_ed25519_mpc_signing`;
- operation `near.export_key`;
- wallet, NEAR account, wallet key, Ed25519 signing-key ID, and signer slot;
- wallet-key version;
- owner custody/envelope revision;
- material activation and capability ID;
- MPC lifecycle and threshold-session identity;
- participant set and signing worker;
- registered public key and state epoch;
- runtime policy binding;
- export confirmation, authorization, lane, intent, and display digests;
- nonce and expiry.

Reuse canonical export encoders. Do not add a parallel JSON-only fingerprint.

### Verify factor and admit one operation

Extend the post-103 Ed25519 operation-step-up boundary with an exact export
branch:

```ts
type Ed25519OperationStepUpRequest =
  | ExactEd25519SigningStepUpRequest
  | ExactOwnerEd25519ExportStepUpRequest;
```

The export request carries `ExactOwnerEd25519ExportTarget`, the prepared Yao
export request, display digest, and one factor branch:

- passkey: exact owner passkey authority plus WebAuthn assertion;
- Email OTP: exact owner authority reference, provider subject, challenge ID,
  and OTP code.

Passkey and Email OTP fields are mutually exclusive. A linked-device authority
cannot construct the export branch.

The server:

1. authenticates the Seams/app session, audience, and origin;
2. re-resolves the active owner wallet key and owner auth authority;
3. re-resolves the exact active export material;
4. checks the submitted target and export request against those records;
5. verifies fresh factor proof over the export operation fingerprint;
6. records the verified evidence set;
7. claims one `near.export_key` authorized operation with
   `authorization.kind = 'verified_step_up'` and
   `quota.kind = 'quota_neutral'`;
8. returns the authorized-operation reference, evidence digest, expiry, and
   branch-specific custody-unseal authorization when needed.

The grant expiry is bounded by app-session, factor-proof, export-request, and
server export TTLs. Reusable signing-session expiry is absent.

Authorization admission completes before the worker opens plaintext owner
custody or starts Yao work. A passkey ceremony may produce both the redacted
assertion and PRF output, but the worker retains the PRF result unopened until
the grant succeeds.

### Export admission

After step-up issuance, the Yao export admission envelope carries only the
verified operation reference:

```ts
type Ed25519ExportAdmissionAuthorization = {
  readonly kind: 'verified_step_up';
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly evidenceSetDigest: AuthorizationEvidenceSetDigest;
};
```

Admission re-reads the claimed authorized operation and matches its operation
fingerprint to the exact export request. It rejects:

- another tenant, principal, origin, wallet, or owner factor;
- another wallet key, version, account, key ID, or signer slot;
- another custody revision, material activation, lifecycle, participant set,
  or signing worker;
- a transaction, message, delegate action, ECDSA, vault, device-link, or lane
  operation authorization;
- changed confirmation, authorization, lane, intent, or display digests;
- expired, completed, failed, replayed-with-conflict, or uncertain authority.

Admission persists the authorized-operation identity in the existing
request-scoped export state. The cryptographic Yao request and export artifact
format remain unchanged.

### Execution

Execution authorizes from the persisted admitted export state and exact
ceremony receipt. It does not parse a reusable signing-session JWT or request
another factor proof.

Terminal execution completes or fails the `AuthorizedOperation`. Exact replay
returns only the bounded stored result. Conflicting replay fails. Uncertain
backend outcomes retain the existing fenced uncertain-state behavior.

## Passkey Export Flow After Refactor 100

1. Resolve the active owner wallet key, owner envelope descriptor, and exact
   export material using public records.
2. Build the export request and operation fingerprint.
3. Request the exact owner credential and receive the redacted assertion plus
   PRF output inside the secure worker.
4. Send the assertion through app-session-authenticated export step-up.
5. After grant success, derive the KEK and open only the exact owner custody
   entry.
6. Convert opened material into an opaque export capability.
7. Send the authorized-operation reference to Yao export admission.
8. Execute export, zeroize on every exit, and open the viewer only after the
   artifact is ready.

No payload contains a reusable signing-session JWT. The PRF output, KEK, root,
and seed never leave the secure worker.

## Email OTP Export Flow After Refactor 100

1. Resolve the active owner wallet key, owner Email OTP custody descriptor,
   provider-subject binding, and exact export material without reusable
   authorization.
2. Request one export-scoped OTP challenge through the app session.
3. Show one OTP prompt.
4. Submit the challenge ID and code to export step-up issuance.
5. Receive the claimed authorized operation and exact owner custody-unseal
   authorization.
6. Open or rehydrate only the named owner custody material.
7. Send the authorized-operation reference to Yao export admission and execute
   export.

Unlock and transaction OTP challenges cannot authorize export. Export OTP
verification creates no reusable signing session.

## Identity-Session Lifetime

The post-103 app-session record must have its own lifecycle:

- app-session expiry comes from identity-session policy and the signed token;
- hosted-wallet exchange is bounded by the source identity session;
- reusable signing-session minting creates separate authorization and quota
  expiry;
- threshold-session expiry remains a curve-local protocol/material fact;
- lane refresh and revocation remain Refactor 102 lifecycle facts;
- reusable signing expiry never deletes or expires the active identity-session
  row.

Audit every identity-session issuance path inherited from 100–103. Remove any
clamp sourced from reusable signing quota, threshold session, material
activation, registration ceremony, or device enrollment when that source is
shorter than the intended identity-session policy.

An expired identity session requires login. An expired reusable signing
session selects step-up.

## Reusable Signing-Session Terminology

Refactors 100–103 use `Wallet Session` for reusable signing authority. After
their implementation, Refactor 107 performs one breaking terminology cutover:

| Refactors 100–103 name | Refactor 107 name |
| --- | --- |
| `WalletSessionId` | `ReusableSigningSessionId` |
| `WalletSessionAuthorization` | `ReusableSigningSessionAuthorization` |
| `LinkedDeviceWalletSessionAuthorizationV1` | `LinkedDeviceReusableSigningSessionAuthorization` |
| `ActiveWalletSessionQuota` | `ActiveSigningSessionQuota` |
| `walletSessionJwt` | `signingSessionJwt` |
| `reusable_wallet_session` | `reusable_signing_session` |
| `consume_reusable_wallet_session` | `consume_reusable_signing_session` |

Preserve these distinct post-103 identities:

- `SeamsSessionId`: logged-in identity session;
- `WalletKeyId`: stable public wallet-key identity;
- `SigningLaneId`: share-bearing execution lane;
- `ThresholdEd25519SessionId` / `ThresholdEcdsaSessionId`: curve-local MPC
  lifecycle;
- `MpcMaterialActivationRef`: exact active material;
- `LinkedDeviceEnrollmentId`: device product lifecycle;
- `AuthorizedOperationId`: one-operation authority.

This is an atomic replacement. Add no aliases, deprecated exports, dual token
parsers, legacy wire branches, or compatibility unions. Persistence/request
migration code is allowed only at its boundary and is deleted after deployed
records are replaced.

## Implementation Phases

### Phase 0: Confirm the post-103 gate

- Confirm Refactor 100 portable custody, cold unlock, recovery, and opaque
  handle tests pass.
- Confirm Refactor 101 wallet-key, active lane, and prepared-execution types are
  the only execution model.
- Confirm Refactor 102 lane protocols, activation, refresh, and revocation
  tests pass.
- Confirm Refactor 103 linked-device enrollment, signing, local-presence, and
  revocation tests pass.
- Confirm temporary types and compatibility paths from 100–103 are deleted.
- Record the exact post-103 source files that own identity sessions, reusable
  signing sessions, authorization planning, owner export targets, and
  authorized-operation persistence.

Exit criterion: 107 has no dependency on a superseded pre-103 record or route.

### Phase 1: Freeze the lifecycle contract

- Update `docs/intended-behaviours.md` to use the post-103 wallet-key and lane
  model.
- Define unlock solely as reusable signing-session creation.
- Define missing, expired, exhausted, and out-of-scope reusable authority as
  step-up selection.
- Define inactive lane, revoked enrollment, unavailable custody, and missing
  identity session as distinct hard outcomes.
- Define owner export as unconditional export step-up.
- State that linked-device and delegated lanes cannot export.
- Remove statements that step-up mints signature uses or refreshes a reusable
  session.

Exit criterion: intended contracts fail against the pre-107 behavior for the
expected authorization reason.

### Phase 2: Separate identity and reusable signing lifetimes

- Remove signing-session and protocol clamps from app-session issuance and
  active authorization-session persistence.
- Preserve exact principal, wallet, authority, device, audience, origin, and
  app-session-version validation.
- Prove active owner and linked-device identity sessions can issue permitted
  step-up after reusable expiry and quota exhaustion.
- Preserve login-required behavior when identity itself is unavailable.

Exit criterion: operation-step-up authentication contains no reusable
signing-session status read.

### Phase 3: Land canonical authorization planning

- Add the exhaustive post-103 authorization planner.
- Feed it active `WalletKey`, active `SigningLane`, exact material, permission,
  auth method, local-presence policy, and reusable availability.
- Select step-up for every recoverable reusable-session outcome.
- Keep lane/enrollment/custody/material failures outside fallback.
- Construct Refactor 101 `PreparedWalletExecution` only after operation
  admission succeeds.
- Remove `isUnlocked`, token-presence, and diagnostic control-flow gates.

Exit criterion: owner and linked-device signing demonstrate reusable and
step-up branches without changing lane or material identity.

### Phase 4: Add the post-103 owner export target

- Add branch-specific Ed25519 and ECDSA owner export target builders.
- Resolve owner custody through Refactor 100 and active key/material through
  Refactors 101–102.
- Make linked-device, delegated, recovery-only, and break-glass records
  unrepresentable as export targets.
- Add type fixtures for cross-key, cross-lane, and cross-custody substitution.

Exit criterion: export core functions accept only exact active owner targets.

### Phase 5: Issue Ed25519 export step-up

- Extend the post-103 Ed25519 step-up boundary with the owner export branch.
- Reuse app-session authentication, active record resolution, factor evidence,
  authorized-operation admission, audit, and replay services.
- Build `near.export_key` from the canonical Yao export request.
- Verify passkey and Email OTP branches exhaustively.
- Return only one-operation authority and exact custody-unseal output.

Exit criterion: both owner auth methods obtain an export authorization while
reusable signing authority is absent.

### Phase 6: Cut owner clients and workers over

- Remove reusable signing-session reads from owner export preparation.
- Route passkey export through the Refactor 100 owner envelope and one
  app-session-authenticated export step-up.
- Route Email OTP challenge and owner-custody unseal through export step-up.
- Carry only the authorized-operation reference into export admission.
- Preserve secret ownership, zeroization, cancellation, and viewer timing.

Exit criterion: no Ed25519 export client or worker payload contains a reusable
signing-session JWT.

### Phase 7: Cut admission and execution over

- Replace the Wallet Session export adapter with an authorized-operation
  adapter.
- Bind request-scoped export state to the exact owner export authorized
  operation.
- Authorize execution from persisted admission and ceremony state.
- Complete/fail the operation with the export lifecycle.
- Preserve exact replay, conflict, and uncertain-outcome fencing.

Exit criterion: export admission and execution contain no reusable session
claim parser, quota read, or signing-session expiry check.

### Phase 8: Rename and delete

- Perform the atomic reusable-signing-session terminology cutover across the
  post-103 owner and linked-device authorization domain.
- Delete old export adapters, worker payloads, auth lanes, lifecycle gates,
  fixtures, and source guards.
- Delete tests that require a reusable JWT for export.
- Add type fixtures rejecting mixed identity, key, lane, threshold-session,
  material, enrollment, reusable-session, and authorized-operation IDs.
- Remove any migration boundary immediately after replacement data commits.

Exit criterion: the retired Wallet Session authorization vocabulary and export
path are absent with no compatibility alias.

## Behavioral Coverage

### Owner passkey

- Active reusable session signs without authorization step-up.
- Missing, expired, exhausted, and scope-mismatched reusable sessions each
  prompt once for same-method step-up and sign.
- Step-up preserves wallet key, owner lane, share epoch, and material
  activation.
- Step-up completion leaves reusable signing authority unavailable.
- Ed25519 and ECDSA export prompt once and succeed for every reusable-session
  state.
- Export opens only the exact Refactor 100 owner custody entry.
- Cancellation performs no operation and consumes no quota.

### Owner Email OTP

- The same ordinary-signing fallback cases show one operation-specific OTP
  prompt and sign.
- Step-up completion leaves reusable signing authority unavailable.
- Ed25519 and ECDSA export use one export OTP challenge for every reusable
  session state.
- Export never calls passkey credential lookup or passkey PRF restore.
- Cancellation or failed OTP performs no operation and consumes no quota.

### Linked device

- Active reusable linked-device authority signs through its exact active lane
  with required local presence.
- Missing, expired, exhausted, and scope-mismatched reusable authority use
  linked-device step-up and preserve the enrollment and lane.
- Step-up cannot bypass enrollment or lane revocation.
- Step-up cannot expand the signing-only permission.
- Export remains forbidden from linked-device lanes and custody.
- Owner and unrelated linked-device lanes remain unaffected.

### Separation and security

- Missing identity session requires login.
- Inactive wallet key, inactive/revoked lane, revoked enrollment, stale epoch,
  missing custody, or superseded material does not enter step-up fallback.
- Reusable-session expiry does not log the user out, retire a lane, revoke a
  device, run Yao recovery, or replace material.
- Transaction step-up cannot authorize export and export step-up cannot sign.
- One wallet, key, lane, factor, origin, material activation, or enrollment
  cannot substitute for another.
- Export authority is consumed once; exact replay is bounded and conflicting
  replay fails.

## Type-Level Coverage

Add static fixtures proving:

- export cannot carry reusable signing authorization;
- linked-device and delegated lane records cannot construct owner export
  targets;
- a reusable signing branch requires an exact active session;
- a verified-step-up branch cannot carry reusable quota or session identity;
- passkey and Email OTP proof fields cannot mix;
- inactive/revoked lanes cannot construct prepared execution;
- wallet-key, lane, share epoch, threshold-session, material activation,
  enrollment, reusable-session, and authorized-operation identities cannot be
  substituted;
- every switch over operation, auth method, lane kind, and authorization source
  is exhaustive;
- broad object spreads cannot construct mixed branches.

Use branch-specific builders and `@ts-expect-error` fixtures. Complex records
come from shared test factories.

## Test Classification

Classify failures before changing tests:

- fresh export proof, exact owner custody, active wallet key, exact material,
  and operation binding: `valid_test_needs_update` when wire shapes change;
- reusable JWT requirements or export rejection caused solely by reusable
  expiry: `obsolete_test_or_fixture`;
- a step-up that changes key/lane/material identity or crosses permission:
  `production_regression`;
- unavailable Redis, RPC, browser, faucet, or production Yao dependency:
  `environment_or_infrastructure_failure`.

Do not widen the post-103 domain types or restore transitional records to make
old inline fixtures pass.

## Verification Order

1. Owner passkey Ed25519 export after reusable-session expiry.
2. Owner Email OTP Ed25519 export after expiry.
3. Identity-session lifetime versus reusable-session expiry.
4. Owner ordinary-signing fallback for each unavailable reason.
5. Linked-device fallback, local presence, permission, and revocation.
6. Owner export-target type fixtures.
7. Ed25519 export grant, admission, execution, replay, and substitution tests.
8. Passkey and Email OTP worker/export tests.
9. `pnpm test:intended`.
10. Relevant unit, wallet-iframe, relayer, device-link, lane-rotation, custody,
    and Yao suites.
11. `pnpm check`.

Regenerate crypto vectors only if canonical MPC/export encoding changes. The
preferred implementation preserves Yao requests, factor derivation, encrypted
inputs, recipient packages, and export artifacts.

## Deletion Checklist

Confirm the absence of:

- reusable signing-session JWTs in Ed25519 export client or worker payloads;
- reusable session claim parsing in export admission or execution;
- signing-session expiry checks in export;
- Email OTP export routes authenticated by reusable signing authority;
- operation gates based on `isUnlocked` or JWT presence;
- expiry paths that revoke/retire lanes, revoke devices, or start material
  recovery;
- step-up paths that mint or refresh reusable signing authority;
- linked-device or delegated export branches;
- compatibility aliases for old Wallet Session authorization names;
- tests, fixtures, and guards whose sole invariant is the retired export gate.

## Non-Goals

- Change Refactor 100 custody formats, recovery semantics, or KEK derivation.
- Change Refactor 101 wallet-key or signing-lane identity.
- Change Refactor 102 provisioning, refresh, activation, or revocation
  protocols.
- Expand Refactor 103 linked-device permission or allow linked-device export.
- Change Ed25519 Yao or ECDSA cryptographic protocols or exported key formats.
- Make unavailable local custody appear on a device through authorization.
- Let step-up reactivate a revoked lane or enrollment.
- Let step-up silently unlock the wallet.
- Add auth-method fallback between passkey and Email OTP.
- Add legacy parsers, flags, dual wire branches, or compatibility unions.

## Completion Criteria

Refactor 107 is complete when:

1. Refactors 100–103 remain authoritative and their custody, lane, rotation,
   linking, and revocation suites still pass;
2. wallet unlock has one authorization meaning: create a reusable signing
   session;
3. permitted owner and linked-device signing automatically use same-method
   step-up when reusable authority is unavailable;
4. lane, enrollment, custody, material, and identity failures remain exact hard
   outcomes;
5. Ed25519 and ECDSA export accept only active owner export targets and always
   use export-scoped step-up;
6. Ed25519 export succeeds after reusable-session expiry for owner passkey and
   Email OTP accounts;
7. identity-session lifetime is independent from reusable signing expiry and
   quota;
8. step-up creates one quota-neutral `AuthorizedOperation` and no reusable
   authority;
9. Ed25519 export admission and execution have no reusable JWT dependency;
10. linked-device and delegated export remain unrepresentable;
11. operation confusion, substitution, replay, origin, factor, permission,
    custody, lane, and material tests pass;
12. old Wallet Session authorization names and obsolete export paths are
    deleted without compatibility aliases.

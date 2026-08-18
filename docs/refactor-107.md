# Refactor 107: Delete the Wallet App Session Plane

Date created: August 12, 2026

Last reconciled: August 17, 2026 against the landed implementation
(`7dabc3769`, `a68098fd6`, `5666434c7`, `76f28275d`, `cb28cd463`,
`15c0298ef`, `b68eed371` and follow-ups)

Status: Complete. Phases 0–5 landed. The stale wallet app-session tests were
reconciled in `76f28275d`, and the final repository gate passes.

## Reconciliation Verdict

R107 is the right next plan with a simpler boundary than the original draft.
The remaining problems are duplicated signing-authorization planning across
the server, SDK, iframe, and curve-specific flows, plus a wallet app session
whose responsibilities are already owned by narrower authorities. The current
client retries some expired or exhausted Wallet Sessions with same-method
step-up, but the choice happens after failed signing requests and is
implemented separately for NEAR and EVM-family operations.

R107 moves that choice to one server-owned admission decision.

R107 removes application authentication from the wallet SDK. Applications may
use any authentication system and then pass an untrusted wallet locator to the
SDK. That locator selects a wallet; it never proves ownership. The wallet
server prepares the exact owner ceremony required to open the wallet and create
signing authorization. Passkey and Email OTP remain the two owner methods in
R107. Their verifiers produce one server-internal `VerifiedOwnerProof` rather
than app-session state.

Successful owner authentication creates an opaque, D1-backed Wallet Session.
The browser receives a random bearer token with no authorization claims. The
gateway hashes and resolves that token, validates its live wallet, authority,
budget, expiry, and revocation state, and passes a trusted internal admission
record to signing workers. Client-visible Wallet Session JWTs and duplicated
claim validation are deleted.

Wallet-owner authentication has two protocol branches:

- built-in passkey;
- built-in Email OTP.

Refresh restores an untrusted wallet/auth-method locator and asks the server
for the next exact ceremony. Hosted-wallet iframe handoff uses a single-use,
origin-bound exchange capability. Wallet administration and vault operations
require fresh operation-bound owner proof. None of those paths needs a
long-lived `ActiveAuthorizationSession` or an application JWT.

Console authentication remains an independent console session. R107 does not
change it.

R107 has four deliverables:

1. centralize owner authorization around `VerifiedOwnerProof`;
2. make passkey and Email OTP its only proof producers;
3. finish opaque, server-resolved Wallet Sessions;
4. remove wallet AppSession JWTs and every obsolete app-session dependency.

The replacement seams land before their old consumers are deleted so each
vertical slice remains testable throughout the cutover.

R107 also has two implementation constraints:

- reduce conceptual and operational complexity by deleting duplicate session,
  claim-validation, fallback-planning, and persistence paths;
- finish with a net reduction in production source lines. Report forward
  migrations, generated artifacts, tests, and documentation separately so they
  cannot hide implementation growth.

New seams must replace old seams in the same refactor. Wrappers, dual paths,
compatibility branches, and another generic wallet login-session abstraction
fail this constraint.

The result is:

```text
owner signing request
  -> valid reusable Wallet Session
       -> atomically claim AuthorizedOperation and consume quota
  -> recoverable Wallet Session unavailability
       -> return exact same-method step-up preparation
       -> verify one operation-bound proof
       -> atomically claim one quota-neutral AuthorizedOperation
  -> invalid identity, authority, lane, material, or operation binding
       -> hard denial
```

Step-up authorizes one operation. It does not create, renew, or replenish a
reusable Wallet Session.

Key export continues to require fresh owner proof. The existing export flows
already implement that product behavior; R107 keeps it as an admission
invariant and removes any remaining dependency on a reusable signing session.

## Current Architecture To Simplify

The implemented Refactor 100–103 model has independent authority planes. R107
keeps those boundaries while deleting the redundant wallet app-session plane.

| Plane                         | Current authority                                                                                | R107 responsibility                                         |
| ----------------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| Application authentication    | Wallet SDK app-session and provider-specific bootstrap paths                                     | Delete; applications bring their own authentication         |
| Wallet owner authentication   | Built-in passkey and Email OTP paths coupled to wallet app sessions                              | Both produce one server-internal `VerifiedOwnerProof`       |
| Wallet discovery and handoff  | `ActiveAuthorizationSession`, browser projection, hosted-wallet exchange                         | Use untrusted locators and one-time exchange                |
| Signing authorization         | Wallet Session JWT, linked-device authorization, quotas, `AuthorizedOperation`, verified step-up | Use opaque D1-backed sessions and central owner admission   |
| Signing identity and material | `WalletKey`, active `SigningLane`, exact `MpcMaterialActivationRef`, share and revocation epochs | Re-resolve before admission and execution; never mutate     |
| Custody and execution         | Factor-wrapped owner custody, opaque workers, curve-specific Router A/B execution                | Require an operation claim before custody or execution open |
| Console authentication        | `console_session_v1`                                                                             | Preserve as the console-only session boundary               |

Concrete implementation evidence:

- `packages/wallet-server/src/authorization/domain.ts` already defines the
  disjoint `AuthorizationGrant`, `OperationAuthorizationSource`, and
  `AuthorizedOperation` unions.
- `packages/wallet-server/src/authorization/factorEvidence.ts` still contains
  wallet paths that bind evidence to `ActiveAuthorizationSession`, copy its
  session and device IDs, and clamp evidence expiry to the app session. R107
  replaces those wallet paths with operation-bound evidence and deletes the
  obsolete session-bound records after vault and administration move.
- `packages/wallet/src/core/types/seams.ts` projects authentication,
  `ReusableWalletSessionState`, capability readiness, and linked-device state
  as separate lifecycle unions. R107 preserves that separation.
- `packages/wallet/src/core/signingEngine/session/operationState/authorizationAdmission.ts`
  and the NEAR/EVM signing flows already implement client-side retry decisions.
  R107 replaces those policy decisions with rendering of a server decision.
- `packages/wallet/src/core/signingEngine/flows/signEvmFamily/signingFlow.ts`
  already models owner and linked-device authorization as a discriminated
  union. R107 keeps those branches explicit.
- `packages/wallet/src/core/signingEngine/session/lanes/linkedDeviceExecutionBundle.ts`
  binds a linked session to its enrollment, device, wallet keys, child lanes,
  activations, permission, and revocation epoch. Owner fallback must never
  manufacture or replace that bundle.

## Refactor 100–103 Invariants

### Refactor 100: owner custody

- Passkey and Email OTP are factor-specific ways to open the same portable
  owner custody.
- Factor proof, KEKs, custody seeds, roots, and holder shares stay inside their
  owning workers.
- A fresh authorization proof does not create new signing material or change a
  public key.
- Lock, expiry, success, and failure preserve the existing zeroization rules.

### Refactor 101: wallet keys and lanes

- `WalletKey` is the stable signing identity.
- `SigningLane` is one independently revocable holder/server execution path.
- Every operation resolves one active wallet key, lane, participant binding,
  share epoch, revocation epoch, and material activation.
- Authorization completes before root, share, presignature, Client,
  SigningWorker, or relayer work begins.
- Export accepts owner authorization only.

### Refactor 102: rotation and activation

- Lane creation and refresh preserve the wallet public identity.
- A fresh `MpcMaterialActivationRef` identifies each activated lane epoch.
- Authorization identity never aliases lane identity, activation identity, or
  an aggregate enrollment receipt.
- Stale, retired, superseded, or revoked material is a hard denial. Fresh proof
  cannot reactivate it.

### Refactor 103: linked devices

- A linked device owns a distinct `LinkedDeviceWalletSessionAuthorizationV1`,
  quota, enrollment, device identity, child-lane set, and revocation epoch.
- Every linked signature requires local user presence and a signing-only
  permission.
- Linked-device signing stays on its existing linked routes and active
  execution bundle.
- An unavailable linked Wallet Session returns a linked-device renewal or
  denial result. It never falls through to owner passkey or owner Email OTP
  step-up.
- Linked-device and delegated lanes remain unable to export or recover keys.

## Terminology

Use the current domain names precisely during the cutover:

- **wallet locator** — untrusted local wallet ID plus auth-method ID used only
  to request the next server-prepared ceremony;
- **application authentication** — authentication owned entirely by the
  integrating application; it is outside the wallet SDK and grants no wallet
  authority;
- **verified owner proof** — server-internal, short-lived, single-use evidence
  produced by a built-in owner-method verifier and bound to one wallet-session
  mint or one exact operation;
- **hosted-wallet exchange** — short-lived, single-use, origin-bound delivery
  capability created by successful login or registration and consumed once by
  the wallet host;
- **opaque Wallet Session** — random bearer token whose hash identifies one
  server-side `WalletSessionAuthorization`, budget, expiry, and revocation
  state; the token contains no claims;
- **step-up evidence** — fresh factor evidence bound to one exact operation;
- **threshold session** — curve-local cryptographic session identified by
  `thresholdSessionId`;
- **signing lane** — durable share-bearing execution material;
- **material activation** — exact active cryptographic capability identity.

R107 does not perform a repository-wide `WalletSession` rename. The current
symbols remain valid when they describe reusable signing authorization.

## Required Outcome

R107 delivers the following behavior for owner operations:

1. Registration and unlock create an opaque Wallet Session with the configured
   budget and expiry.
2. Transaction signing consumes that session while it is active and has enough
   uses.
3. Missing, expired, exhausted, or explicitly ended owner sessions produce one
   same-method step-up preparation when the authority and material remain
   active.
4. Fresh passkey or Email OTP proof claims exactly one quota-neutral
   `AuthorizedOperation`.
5. NEAR, Tempo, and EVM use the same decision contract.
6. Key export always uses fresh owner proof and never consumes reusable signing
   quota.
7. Invalid credentials and stale identity or material fail without a prompt
   loop.
8. Page refresh restores wallet UI from untrusted locators or wallet-host local
   state without an app authorization session.
9. Vault and wallet administration require fresh owner proof bound to the exact
   operation.
10. Linked-device authorization and console sessions keep their independent
    boundaries.
11. Application authentication is absent from wallet SDK types, routes,
    storage, and iframe messages.

## Server Authorization Decision

Reuse the existing operation, grant, quota, and material types. Add one shared
decision union at the server boundary:

```ts
type OwnerOperationAuthorizationDecision =
  | {
      readonly kind: 'authorized';
      readonly operation: Extract<AuthorizedOperation, { lifecycle: 'claimed' }>;
      readonly source: Extract<
        OperationAuthorizationSource,
        { readonly kind: 'authorization_grant' | 'verified_step_up' }
      >;
      readonly stepUp?: never;
      readonly denial?: never;
    }
  | {
      readonly kind: 'step_up_required';
      readonly reason:
        | 'wallet_session_missing'
        | 'wallet_session_expired'
        | 'wallet_session_exhausted'
        | 'wallet_session_ended'
        | 'wallet_session_superseded';
      readonly stepUp: OwnerOperationStepUpPreparation;
      readonly operation?: never;
      readonly source?: never;
      readonly denial?: never;
    }
  | {
      readonly kind: 'denied';
      readonly denial: OwnerOperationAuthorizationDenial;
      readonly operation?: never;
      readonly source?: never;
      readonly stepUp?: never;
    };
```

The exact shared type should reuse the established NEAR and ECDSA step-up
preparation records rather than introducing another curve-specific payload.
Boundary parsers normalize route input once. Core admission receives only the
precise branch it can execute.

The planner runs in this order:

1. Parse and fingerprint the exact operation.
2. Resolve tenant, principal, wallet, active owner authority, wallet key,
   signing lane, share epoch, revocation epoch, and material activation.
3. Reject invalid identity, operation, or material bindings.
4. Hash and resolve a presented opaque Wallet Session token, then validate its
   live server-side authorization.
5. Atomically claim and consume quota when it is usable.
6. Return an exact same-method step-up preparation for recoverable session
   unavailability.
7. Verify fresh operation-bound proof and atomically claim one quota-neutral
   operation.
8. Open custody or start MPC only after the claim succeeds.

### Recoverable unavailability

These states may request same-method owner step-up:

- no reusable owner Wallet Session is available;
- the session expired;
- its quota is exhausted;
- the user explicitly ended it;
- its projection was superseded and re-resolution found the same active owner
  authority.

### Hard denial

These states fail directly:

- unknown, expired, revoked, or malformed opaque token;
- wrong issuer, audience, origin, tenant, principal, or wallet;
- auth-method substitution;
- revoked or replaced owner authority;
- linked-device token presented to an owner route;
- revoked linked enrollment;
- inactive, stale, retired, superseded, or revoked key, lane, epoch, or
  material activation;
- operation, lane, intent, display, fingerprint, or material mismatch;
- expired, consumed, or replayed step-up challenge or evidence;
- unavailable authorization persistence or other server infrastructure
  failure.

An infrastructure failure is never converted into a user prompt.

## Verified Owner Proof

Passkey and Email OTP verification converge on one server-internal proof. This
is the central authorization seam for R107.

```ts
type VerifiedOwnerProofCommon = {
  readonly kind: 'verified_owner_proof_v1';
  readonly proofId: VerifiedOwnerProofId;
  readonly method: 'passkey' | 'email_otp';
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authority: WalletAuthAuthorityRef;
  readonly origin: string;
  readonly audience: string;
  readonly replayIdentity: string;
  readonly verifiedAtMs: number;
  readonly expiresAtMs: number;
};

type VerifiedOwnerProof = VerifiedOwnerProofCommon &
  (
    | {
        readonly purpose: 'wallet_session';
        readonly operation?: never;
      }
    | {
        readonly purpose: 'operation';
        readonly operation: OwnerOperationBinding;
      }
  );
```

`VerifiedOwnerProof` is never serialized to the browser. The verifier creates
it after resolving the active owner authority and consuming the exact factor
challenge. The authorization service consumes it once to mint an opaque Wallet
Session or claim one `AuthorizedOperation`.

The proof carries no app authorization session ID, app-session version, copied
app device ID, reusable Wallet Session authorization, quota, threshold session,
or material activation. A factor-specific credential or challenge identity
remains part of the verifier's replay state when its protocol requires it.

Passkey preparation binds RP ID, allowed credential, origin, wallet, owner
authority, purpose, and exact operation fingerprint.

Email OTP preparation resolves the destination from the stored active authority
and binds tenant, principal, wallet, provider subject, purpose, origin/audience,
operation fingerprint, expiry, and attempt limits. The request never supplies
the destination email.

Challenges remain short-lived, rate-limited, opaque, single-use, and atomically
consumed with Wallet Session minting or the operation claim.

## Wallet Connection Bootstrap

The application authenticates its own users outside this SDK. It may then call
the wallet SDK with a wallet ID and auth-method ID retained by the browser or
application. Those values are untrusted locators and grant no authority.

The bootstrap route:

1. resolves the exact active wallet and owner authority;
2. applies origin, audience, tenant, and rate-limit checks;
3. returns only the next passkey or Email OTP ceremony preparation;
4. keeps email, provider subject, credential inventory, key material, and broad
   wallet state private.

Known-wallet Email OTP unlock keeps the existing client unlock-key proof. OTP
alone cannot open custody or create an opaque Wallet Session.

Application OAuth, OIDC, and API sessions remain outside wallet domain state
and grant no wallet authority.

This bootstrap replaces wallet app-session refresh. A successful owner ceremony
may mint only the opaque Wallet Session, operation evidence, or one-time
hosted-wallet exchange required by the caller.

## Deferred External Owner Methods

External verification webhooks are outside R107. R107 creates the future
extension seam by making passkey and Email OTP produce the same
`VerifiedOwnerProof`. A later refactor may add another server-side verifier that
produces this proof after explicit console configuration, wallet enrollment,
challenge binding, and custody binding.

R107 adds no external-verifier routes, persistence, SDK branches, webhook
configuration, signing keys, or environment variables. Application sessions
and arbitrary application JWTs remain unable to produce `VerifiedOwnerProof`.

## Hosted-Wallet Iframe Handoff

The iframe needs delivery, not a parallel login authority.

1. Successful registration or login mints one opaque exchange capability for
   the exact app origin and wallet-host origin.
2. The outer app transfers that capability to the wallet host.
3. The host consumes it once and receives only the wallet projection and opaque
   Wallet Session explicitly included in the delivery.
4. The wallet host stores the opaque token in its own origin. The outer
   application never receives it.
5. Refresh uses host-local persisted projection and Wallet Session state. When
   those are unavailable, the host uses wallet connection bootstrap.
6. Replay, wrong origin, expiry, or identity mismatch fails closed.

Delete the source `ActiveAuthorizationSession` requirement from exchange mint
and redemption. The exchange record itself owns origin, audience, wallet,
expiry, nonce, and consumption state.

## Vault And Wallet Administration

Vault access, recovery mutation, device management, and other sensitive wallet
administration use fresh owner proof bound to one exact operation. They do not
accept a reusable signing Wallet Session and do not require an app
authorization session.

Non-sensitive wallet UI reads use local projections or narrowly scoped public
status routes. If a read cannot be safe with an untrusted wallet locator and
origin/rate-limit checks, require fresh owner proof. Do not introduce a
replacement generic wallet login session.

## Export Admission

The current post-103 export model is already correct and remains authoritative:

1. select the exact active owner export lane and material activation;
2. prepare the operation-bound ceremony for the enrolled owner method;
3. verify fresh owner proof;
4. atomically claim a quota-neutral `AuthorizedOperation` with
   `authorization.kind === 'verified_step_up'`;
5. re-resolve the lane and activation;
6. open custody and execute export.

The request type rejects reusable Wallet Session and linked-device
authorization branches with `never` fields. R107 removes remaining app-session
coupling from export evidence and does not redesign the export workers or
viewer.

## Owner And Linked-Device Dispatch

Keep the outer signing dispatch exhaustive:

```ts
type SigningAuthority =
  | { readonly kind: 'owner' }
  | {
      readonly kind: 'linked_device';
      readonly execution: ActiveLinkedDeviceExecutionBundleV1;
      readonly localPresence: LinkedDeviceLocalPresenceAssertionV1;
    };
```

Use exhaustive `switch` statements at the public NEAR and EVM-family dispatch
boundaries. The owner branch calls the R107 planner. The linked-device branch
continues through its linked normal-signing routes, exact child lane, local
presence proof, authorization grant, and quota. Tempo continues to share the
EVM-family branch.

## Persistence And Migration

The current signer baseline already contains:

- `authorization_sessions`, which R107 removes after its remaining wallet
  exchange, vault, and administration consumers migrate;
- `authorization_wallet_session_quotas` for reusable signing budget;
- `authorized_operations` and audit events for atomic operation lifecycle;
- `verified_grant_evidence_sets`, whose current `session_id` foreign key also
  serves non-wallet authorization;
- linked-device authorization and quota tables.

Keep reusable and linked-device tables intact. Add one wallet-operation step-up
evidence table or an equally narrow replacement branch without an
`authorization_sessions` foreign key. Use the existing
`authorized_operations.authorization_source_kind = 'verified_step_up'`
admission path.

Store only a hash of each opaque Wallet Session token. The session row owns its
wallet, owner authority, quota, expiry, revocation, and replacement state. A
gateway lookup converts the public token into a narrow trusted internal
admission record. Router, Deriver, SigningWorker, and application code never
parse Wallet Session claims. Remove Wallet Session JWT signing keys, issuers,
claim types, parsers, and claim-copying persistence after the cutover.

Migration rules:

1. Treat the currently deployed canonical `0001_signer_d1_initial.sql` as an
   immutable baseline for fresh databases.
2. Add a new numbered forward migration for the R107 persistence change.
3. Never rewrite an applied migration under the same filename or migration ID.
4. Add the new table and required columns to signer readiness checks before
   deployment.
5. Cut over once. Remove old wallet reads and writes in the same change; do not
   add dual-write or runtime compatibility paths.
6. Drop `authorization_sessions` and its wallet-only evidence foreign keys once
   no wallet route reads them. Preserve unrelated persistence only when a
   current non-wallet domain still owns it.
7. Revoke opaque sessions by updating their authoritative D1 row; no token
   blocklist or secondary revocation cache is needed.

These rules incorporate the post-103 canonical-schema model and prevent a
fresh local database from diverging from an already-migrated staging database.

## Route Boundary

Classify wallet routes by their actual authority requirement:

1. **Wallet discovery** — wallet connection challenge preparation and minimal
   public status from untrusted locators.
2. **Proof completion** — passkey, OTP, and client unlock-key verification.
3. **Owner operation admission** — R107 authorization decision followed by
   signing or export.
4. **Opaque Wallet Session management** — mint, resolve, inspect, consume, and
   revoke server-side signing authorization.
5. **Linked-device operation admission** — existing linked session, local
   presence, permission, enrollment, and lane checks.
6. **Hosted-wallet handoff** — mint and consume one origin-bound, single-use
   exchange delivery.
7. **Wallet administration and vault** — fresh operation-bound owner proof for
   recovery, custody access, device management, and other sensitive actions.

Use the existing route composition and shared parsers. A new route registry is
unnecessary unless the current code cannot express one of these boundaries.
Console `console_session_v1` stays isolated and wallet routes reject its token
kind and audience.

Application authentication has no wallet route category. The SDK public API
accepts a locator, owner-ceremony responses, and operation requests. It does
not accept an application JWT or an application-authenticated principal as
wallet authority.

## Implementation Plan

### Phase 0 — Readiness

- [x] Make staging `SIGNER_DB` readiness green with the current post-103
      canonical schema.
- [x] Run the existing intended-behavior contract once to record the baseline.
- [x] Identify the current owner NEAR and EVM-family retry call sites and the
      shared server admission functions they already use.
- [x] Inventory every wallet `ActiveAuthorizationSession`, AppSession JWT, and
      client-visible Wallet Session JWT producer and consumer.
- [x] Record the production-source line baseline for those owned paths and list
      the abstractions that R107 will delete.

### Phase 1 — Centralize verified owner proof

- [x] Add the exact server-internal `VerifiedOwnerProof` union and boundary
      builders.
- [x] Make passkey and Email OTP the only proof producers.
- [x] Add session-independent owner factor evidence and remove app-session
      fields from new challenges and evidence.
- [x] Consume the proof once for either opaque Wallet Session minting or one
      quota-neutral `AuthorizedOperation` claim.
- [x] Prove one EVM-family operation-bound step-up vertical slice first.

### Phase 2 — Finish opaque Wallet Sessions and owner admission

- [x] Add the exhaustive owner authorization decision and boundary parser.
- [x] Replace client-visible Wallet Session JWTs with hashed opaque tokens and
      authoritative D1 lookup at the gateway.
- [x] Pass a narrow trusted admission record from the gateway to internal
      signing services; remove claim parsing from workers.
- [x] Add the forward signer migration and readiness requirement.
- [x] Reuse `OperationAuthorizationSource`, `AuthorizedOperation`, quota, and
      current operation fingerprints.
- [x] Route NEAR transaction, delegate, and NEP-413 signing through the same
      server decision.
- [x] Render server `step_up_required` preparations with the current passkey and
      Email OTP UI/worker flows.
- [x] Remove NEAR and EVM-family client policy that infers fallback from failed
      signing responses.
- [x] Preserve in-flight admission waiting as a retry, with no user prompt.

### Phase 3 — Remove wallet AppSessions

- [x] Verify export remains fresh-owner-proof-only for both curves.
- [x] Move vault, recovery mutation, device management, and sensitive wallet
      administration to fresh operation-bound owner proof.
- [x] Replace hosted-wallet source-session exchange with a self-contained,
      origin-bound, single-use delivery capability.
- [x] Restore wallet UI after refresh from host-local projection or untrusted
      wallet/auth-method locators plus wallet connection bootstrap.
- [x] Remove provider-specific application login and discovery from the wallet
      SDK public API. Applications bring their own authentication.
- [x] Remove app-session minting from wallet registration and unlock.
- [x] Remove AppSession JWT parsing, signing keys, claims, routes, iframe
      messages, and persistence from wallet code after their replacement
      boundaries are live.
- [x] Remove Wallet Session JWT issuance, parsing, keys, claims, and duplicated
      identity checks after opaque session lookup is live.
- [x] Remove app session ID, app-session version, and copied app device identity
      from wallet operation step-up evidence and challenges.
- [x] Remove duplicate client fallback policy and obsolete retry helpers.
- [x] Remove wallet-only persistence reads, fixtures, and tests that encode the
      retired coupling. Deleted `tests/unit/sessionTokens.unit.test.ts`
      (tested the removed `requireAppSessionJwt` / `requireWalletSessionJwt` /
      `appOrWalletSessionJwtAuth` / `parseAppSessionJwt` helpers),
      `tests/unit/walletIframeHostedSessionSource.unit.test.ts` (keyed
      hosted-wallet exchange on `appSessionJwt`; `HostedWalletSeamsSessionSource`
      now carries `walletSessionToken`), and
      `tests/unit/walletIframeUnlockOptions.unit.test.ts` (asserted the retired
      `session: {kind:'jwt'}` PM_UNLOCK option and `ecdsaKeyFactsInventory`
      `mode:'app_session'`); dropped the same retired `session` option from
      `tests/wallet-iframe/router.behavior.test.ts`. Repaired
      `tests/unit/walletIframeAuthHandlers.unit.test.ts` and
      `tests/unit/walletIframeHost.emailOtpRecoveryCodes.unit.test.ts` onto the
      current boundary: the host rejects a parent-supplied `walletSessionToken`,
      injects its own origin token for `mode:'opaque_wallet_session'` key-facts
      lookups, passes `mode:'webauthn'` through, clears hosted sessions on lock,
      and keeps the redeemed token out of every parent-facing message.
      `tests/unit/walletIframe.signerModeConfigPropagation.unit.test.ts` needed
      no change — its `kind:'jwt'` values are `EcdsaSignerProvisioningSession`
      config, not the retired PM_UNLOCK session option.
- [x] Delete wallet `ActiveAuthorizationSession` types, services, D1 rows, and
      foreign keys after the last wallet consumer is gone.
- [x] Delete application-auth provider types and iframe messages from the wallet
      SDK.
- [x] Do not replace it with another generic wallet login-session abstraction.

### Phase 4 — Preserve adjacent authority branches

- [x] Keep owner and linked-device dispatch exhaustive and separate.
- [x] Verify linked-device expiry, quota exhaustion, local presence, and
      revocation remain on the R103 path.
- [x] Keep console authorization isolated and unchanged.
- [x] Keep one-time hosted-wallet handoff, wallet administration, and vault
      authorization outside the reusable signing planner.

### Phase 5 — Final gate

- [x] Update `docs/intended-behaviours.md` and its authoritative contract with
      the changed server-owned decision.
- [x] Run focused tests while each vertical slice lands.
- [x] Run one integrated intended-behavior E2E covering an active Wallet
      Session, expired/exhausted fallback, passkey, Email OTP, NEAR, and
      EVM-family signing
      (`tests/e2e/intended-behaviours/passkey.unlock.contract.test.ts`,
      `email-otp.unlock.contract.test.ts`, `harness.ts`
      `exhaustSigningBudget`). Manual verification passed alongside it.
- [x] Run the signer migration/readiness check.
- [x] Report production lines added and deleted. Production source must be net
      negative; list migration, generated, test, and documentation totals
      separately. Measured `978c565f1..dc2eeb21f` — production source
      (`packages|crates|wasm|apps` under `src/`, excluding `*.typecheck.ts`):
      +19,104 / −31,771 (net **−12,667**); type fixtures: +296 / −1,372;
      signer migrations: +313 / −0; tests: +1,875 / −9,492; docs: +1,409 /
      −2,166.
- [x] Confirm the final architecture has fewer authorization/session concepts,
      route branches, token parsers, and persistence paths than the baseline.
- [x] Run `pnpm check` once. The August 17 closure run passed lint, TypeScript,
      documentation, Rust formatting and clippy, signing architecture, six Rust
      signer-parity vectors, and three browser/WASM replay contracts. Closure
      also restored the workspace lint gate (`cb28cd463`), made router type
      checks self-contained (`15c0298ef`), and corrected the embedded signer
      parity lock (`b68eed371`).
- [x] Commit, then reconcile this document with the landed implementation.

## Required Type Guarantees

Keep focused type fixtures for these invalid states:

1. export input cannot carry reusable Wallet Session or linked-device
   authorization;
2. an authorization decision cannot contain both an admitted operation and a
   step-up preparation;
3. owner step-up evidence cannot carry app-session or reusable-session fields;
4. linked-device execution cannot enter the owner fallback planner;
5. a verified-step-up operation is quota-neutral;
6. a reusable owner operation consumes exactly one Wallet Session quota;
7. a wallet locator cannot satisfy owner proof or operation authorization;
8. wallet SDK inputs cannot carry application JWTs or application auth state;
9. public opaque tokens cannot be constructed as trusted internal admission
   records;
10. a `VerifiedOwnerProof` cannot be both a Wallet Session mint proof and an
    operation-bound proof;
11. a `VerifiedOwnerProof` cannot be constructed from browser input or
    serialized as a public bearer credential;
12. passkey and Email OTP are the exhaustive R107 owner-method union.

## Required Behavioral Evidence

The integrated contract must prove:

- active owner Wallet Sessions sign without a prompt and consume budget;
- missing, expired, exhausted, ended, and safely superseded sessions request
  one same-method step-up and then sign;
- passkey and known-wallet Email OTP fallback work for NEAR, Tempo, and EVM;
- changing or removing the application's authentication provider does not
  change wallet owner authentication or an existing Wallet Session;
- each built-in verifier produces the same server-internal
  `VerifiedOwnerProof` shape after its method-specific checks;
- a Wallet Session proof cannot authorize an operation directly, and an
  operation proof cannot mint a reusable Wallet Session;
- a forged wallet locator can prepare only a rate-limited ceremony and cannot
  authorize, open custody, or inspect private wallet state;
- opaque Wallet Session lookup, quota consumption, expiry, replacement, and
  revocation are enforced from D1;
- signing workers receive trusted internal admission and never parse a public
  Wallet Session token;
- in-flight admission waits and retries without prompting;
- both exports always require fresh owner proof;
- successful step-up creates one operation and no reusable Wallet Session;
- malformed token, cross-wallet identity, wrong origin/audience, revoked
  authority, stale material, replay, and operation mismatch fail without a
  prompt loop;
- linked-device signing still uses linked routes and local presence, and cannot
  export;
- refresh restores wallet UI without a wallet app session;
- hosted-wallet exchange remains origin-bound and single-use without a source
  app session;
- the outer application never receives the wallet host's opaque Wallet Session
  token;
- vault and wallet administration require fresh owner proof;
- console sessions remain functional and isolated.

## Completion Criteria

R107 is complete when:

- the server alone chooses reusable owner authorization, same-method step-up,
  or hard denial for every owner signing operation;
- NEAR, Tempo, and EVM share that decision contract;
- wallet operation step-up evidence has no app authorization session
  dependency;
- wallet registration, unlock, refresh, iframe handoff, vault, and wallet
  administration have no `ActiveAuthorizationSession` dependency;
- the wallet SDK has no application-authentication API, provider integration,
  app JWT, or app-session persistence;
- passkey and Email OTP verifiers produce one exact server-internal
  `VerifiedOwnerProof` union;
- reusable Wallet Sessions are opaque, D1-backed, revocable bearer tokens with
  no client-visible claims;
- internal signing services consume trusted admission records rather than
  public Wallet Session tokens;
- reusable Wallet Session authorization remains budgeted and exact;
- export remains fresh-owner-proof-only and quota-neutral;
- linked-device authorization, local presence, lanes, and revocation retain the
  R103 boundary;
- key, lane, activation, custody, and execution identities retain the
  Refactor 100–103 boundaries;
- duplicate client fallback policy and obsolete wallet-only persistence are
  deleted;
- wallet app-session types, routes, and persistence are deleted rather than
  renamed or wrapped;
- production source has a net reduction in lines, with migrations, generated
  artifacts, tests, and documentation reported separately;
- the final domain model contains fewer session and authorization concepts than
  the Refactor 100–103 baseline;
- the migration/readiness check, integrated intended-behavior E2E, and final
  gate all pass.

## Explicit Non-Goals

- repository-wide `WalletSession` renaming;
- console-session redesign;
- external owner methods, verification webhooks, provider plugins, and their
  enrollment or custody model; these belong to a later refactor built on
  `VerifiedOwnerProof`;
- accepting application authentication as wallet authority;
- linked-device renewal redesign;
- new custody, key, lane, activation, export, or worker abstractions;
- delegated-agent authorization from Refactor 104;
- historical migration rewrites;
- generated planning artifacts or source-text guards.

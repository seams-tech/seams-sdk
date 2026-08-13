# Refactor 107: Signing-Session Step-Up Fallback

Date created: August 12, 2026

Last reconciled: August 13, 2026

Status: Planned

Implementation starts after Refactors 100–103 are implemented and green.

## Outcome

Wallet unlock creates a signing session. A signing session is a short-lived,
budgeted authorization for multiple signing operations.

The server selects the authorization path for each operation:

```text
valid signing session with remaining budget
  -> atomically authorize the operation and consume session budget

missing, expired, exhausted, or user-ended signing session
  -> request same-method step-up
  -> atomically authorize exactly one operation
```

Step-up is the fallback for signing-session unavailability. It does not create,
renew, or replenish a signing session.

Key export always requires fresh, operation-bound step-up. Signing-session state
never admits or blocks export.

Wallet authentication no longer depends on an AppSession JWT. Passkey and Email
OTP proof directly create either:

- a signing session during unlock; or
- one `AuthorizedOperation` during step-up.

The Google SSO + Email OTP user experience stays the same. Google remains part
of registration and cold account discovery for a Google-backed Email OTP
authority. Once the wallet and active authority are known, unlock and step-up
use Email OTP without reopening Google SSO.

Registration remains a separate ceremony that establishes the authority.
Unlock and step-up resolve an already-established active authority. Preserve
the current Google token, provider-subject, email, issuer/audience, expiry, and
redirect-integrity checks while removing the AppSession intermediary.

## Required Scope

R107 implements only the work needed for that outcome:

1. Remove wallet AppSession issuance, admission, and persistence dependencies.
2. Let passkey and Email OTP proof create a signing session directly.
3. Let fresh passkey and Email OTP proof create one operation authorization
   without an active signing session.
4. Make the server authoritative for choosing signing-session authorization,
   step-up, or hard denial.
5. Apply the same authorization behavior to NEAR Ed25519 and EVM ECDSA signing.
6. Make both owner key-export paths step-up-only.
7. Preserve Refactors 100–103 custody, key, lane, material, and linked-device
   rules.
8. Reclassify every wallet route so an expired signing session cannot block the
   narrow bootstrap needed to authenticate again.
9. Remove wallet-only AppSession code after the new path works.

The following work is deliberately excluded:

- a repository-wide `WalletSession` to `SigningSession` symbol rename;
- a new console-session architecture;
- new Google OIDC nonce or redirect-state plumbing;
- new export-target, custody, lane, or key abstractions;
- linked-device redesign beyond connecting R103's existing proof and local-
  presence path to the common authorization decision;
- historical migration rewrites;
- source-text guards, generated planning artifacts, or exhaustive test matrices.

The implementation may retain current `WalletSession*` symbols. This document
uses “signing session” as the domain term. A mechanical rename can happen later
as one atomic change if it is still worthwhile.

## Post-103 Baseline

R107 assumes these refactors are complete:

| Refactor | Remains authoritative for | R107 changes |
| --- | --- | --- |
| R100 | encrypted owner custody, factor unwrap, recovery envelopes, worker capabilities | authorization entry only |
| R101 | `WalletKey`, active `SigningLane`, exact execution preparation, export permissions | authorization selection only |
| R102 | provisioning, refresh, activation, epochs, material and lane revocation | no lifecycle changes |
| R103 | linked-device enrollment, permissions, local presence, child lanes, revocation | session-unavailable fallback through its existing proof path |

Authorization and signing material stay separate. Signing sessions remain bound
to tenant, principal, wallet, and active authentication authority. The operation
claim resolves and binds the current key, lane, material, and revocation epochs.
R107 does not add lane or material sets to the session.

An inactive, stale, or revoked lane remains a hard failure. Fresh authentication
cannot reactivate signing material or bypass a linked-device restriction.

## Authentication Methods and UX

Keep the existing `WalletAuthAuthorityRef` and
`EmailOtpWalletAuthAuthority` model. Email OTP continues to support its current
provider variants, including the Google-backed authority. R107 does not add a
parallel `GoogleEmailOtp` domain type.

The required ceremonies are:

| Situation | Ceremony | Result |
| --- | --- | --- |
| Passkey unlock | passkey assertion | signing session |
| Passkey operation step-up | operation-bound passkey assertion | one `AuthorizedOperation` |
| Google-backed cold entry | existing Google SSO, Email OTP, and client unlock-key proof | signing session |
| Known-wallet Email OTP unlock | Email OTP and existing client unlock-key proof | signing session |
| Known-wallet Email OTP step-up | operation-bound Email OTP | one `AuthorizedOperation` |

Cold Email OTP unlock must preserve the current custody boundary. OTP
verification yields the one-use challenge consumed by the enrolled client
unlock-key signature; OTP alone does not unseal custody or mint the signing
session.

Google participates again only when discovery or re-establishing the Google-
bound authority genuinely requires it. Signing-session expiry by itself never
causes a Google prompt.

## Server-Authoritative Authorization

The client supplies the operation and either a presented signing-session token
or an explicit no-session attempt with an untrusted known-wallet locator. Raw
request input is normalized once into a discriminated union.

The server returns one exhaustive result:

```ts
type OperationAuthorizationDecision =
  | {
      readonly kind: 'authorized';
      readonly source: 'signing_session' | 'operation_step_up';
      readonly operation: AuthorizedOperation;
    }
  | {
      readonly kind: 'step_up_required';
      readonly reason:
        | 'signing_session_missing'
        | 'signing_session_expired'
        | 'signing_session_exhausted'
        | 'signing_session_ended'
        | 'signing_session_scope_unavailable';
      readonly preparation: OperationStepUpPreparation;
    }
  | {
      readonly kind: 'denied';
      readonly reason: OperationAuthorizationDenial;
    };
```

There is one server planner. Client, iframe, and worker code render the requested
ceremony and return its proof. They do not reproduce session-validity or
fallback policy.

Authorization follows this order:

1. Parse and fingerprint the exact operation using the post-103 canonical
   operation types.
2. Resolve the current wallet, principal, authentication authority, key, lane,
   material, enrollment, and revocation state.
3. Validate a presented signing session.
4. Atomically claim an `AuthorizedOperation` and consume quota when the session
   is usable.
5. Return `step_up_required` for recoverable session unavailability.
6. Verify fresh operation-bound proof, then atomically claim one
   `AuthorizedOperation`.
7. Open custody or begin MPC work only after the claim succeeds.

The following conditions permit fallback:

- no signing session was presented;
- the signing session expired or exhausted its budget;
- the user ended or superseded the signing session while its authentication
  authority remains active;
- a valid same-wallet session lacks permission for the requested operation.

The following conditions are hard denials:

- malformed token, bad signature, wrong issuer, audience, tenant, or origin;
- cross-wallet or cross-principal presentation;
- revoked or replaced authentication authority;
- revoked linked-device enrollment;
- inactive, stale, superseded, or revoked key, lane, epoch, or material;
- operation fingerprint, intent, display, or lane mismatch;
- consumed, expired, or replayed challenge or evidence.

This distinction prevents a bad credential from being downgraded into a fresh
authentication prompt. “Signing session ended” and “authentication authority
revoked” must remain different lifecycle states in code and persistence.

## Session-Independent Step-Up Evidence

The current factor-evidence path requires an `ActiveAuthorizationSession`,
copies its session and device IDs, and clamps proof expiry to the AppSession.
Remove that dependency for wallet operation step-up.

The operation-bound evidence must contain validated, required fields for:

- tenant, principal, wallet, and active authority;
- proof kind and replay identity;
- exact capability and operation kind;
- canonical lane, intent, and display digests already defined by R101–103;
- origin and audience where the factor protocol requires them;
- verification and expiry timestamps.

It must not contain an AppSession ID, AppSession version, or signing-session
authorization. The operation claim re-reads the active authority and current
key/lane/material state before accepting the evidence.

Passkey challenges bind the RP ID, allowed credential, origin, wallet,
authority, purpose, and exact operation fingerprint.

Email OTP challenges bind the server-resolved active authority, stored email
and provider subject, tenant, wallet, purpose, origin/audience, exact operation
fingerprint, expiry, and attempt limits. The destination email comes from the
stored authority, never from the request.

Challenges remain short-lived, rate-limited, single-use, and atomically
consumed with the authorization claim. Responses remain opaque enough to avoid
wallet, account, and authentication-method enumeration.

## Known-Wallet Bootstrap After Expiry

The client needs a way to begin OTP or passkey authentication after losing its
signing session. Persist the existing wallet ID and authentication-authority ID
as untrusted locators. They grant no authority.

The server uses those locators only to find and re-resolve the exact active
wallet and method. It applies origin/audience checks, enumeration-safe
responses, and existing challenge rate limits before returning a narrow
ceremony preparation. Provider subjects, email addresses, credential inventory,
key material, and broad wallet state are never returned by this bootstrap.

An expired JWT may be decoded for diagnostics only. Its claims cannot serve as
the locator or authorization source.

Known-wallet OTP unlock uses OTP without Google SSO and still performs the
existing client unlock-key proof. Known-wallet OTP operation step-up ends at one
`AuthorizedOperation`; it does not unlock the wallet.

## Export Admission

Reuse the exact NEAR and EVM export requests, custody rules, operation
fingerprints, and owner-lane restrictions produced by R100–103. R107 adds no
export target type.

For both curves:

1. Prepare the exact export operation without requiring a signing session.
2. Request fresh passkey or Email OTP proof from the active owner authority.
3. Create session-independent step-up evidence.
4. Atomically claim the quota-neutral `AuthorizedOperation`.
5. Re-resolve the active owner lane and material.
6. Open custody and execute export.

Linked-device and delegated lanes remain unable to export. A signing-session
token in an export request is rejected at the request boundary rather than
consulted by admission.

## Route and Persistence Cutover

### Wallet routes

Classify every wallet route in the post-103 route registry and enforce the
classification centrally:

1. **Opaque bootstrap** — cold discovery, known-wallet challenge preparation,
   and minimal expired-session status.
2. **Proof completion** — passkey, OTP, and client unlock-key verification.
3. **Operation admission** — server decision followed by signing-session claim
   or operation step-up.
4. **Signing-session management** — creation, active-session inspection, and
   revocation.
5. **Wallet administration** — the existing fresh-auth policy for the exact
   administrative operation.

No route receives a blanket signing-session requirement. Bootstrap routes
return only the information needed for the next proof. Local wallet lock always
works; a server revocation attempt may be best-effort when the session is
already unavailable.

Implement this as one registry derived from the actual post-103 routes, mapping
each route to its admission class and bootstrap requirement. Do not create a
separate planning artifact. Reuse existing route tests and add coverage only
for missing fallback, bootstrap, and credential-isolation behavior.

### Persistence

Use a forward migration. Preserve historical migrations.

`authorization_sessions` and `verified_grant_evidence_sets` currently also
serve non-wallet capabilities such as vault access. Do not delete those shared
tables as part of the wallet fix. Split wallet operation evidence into the
narrow session-independent persistence branch required by
`AuthorizedOperation` admission, then remove wallet reads and writes from the
old branch. There is no dual-write or runtime compatibility path after cutover.

The wallet evidence branch must enforce exact operation binding, expiry,
single-use consumption, active-authority revalidation, and atomic operation
claim. Existing reusable signing-session quota and `AuthorizedOperation`
lifecycle machinery remain in place.

Remove wallet `sessionHash`, `appSessionVersion`, AppSession foreign keys,
claims, route middleware, client payloads, iframe messages, and worker inputs
after their replacements are live. Delete obsolete wallet-only fixtures and
tests with them.

### Console isolation

Keep the existing console-specific `console_session_v1` implementation. Console
redesign is outside R107. Wallet routes must reject console token kinds and
audiences, and console code must not import wallet authorization middleware.

This means R107 removes AppSession from the wallet security plane. Any generic
authorization-session persistence still required by vault capabilities and the
isolated console session remain separate systems with separate audiences.

## Four-Agent Implementation Plan

Land one small, compilable foundation change first. It defines the final
authorization-decision union, session-independent wallet evidence shape,
request-boundary attempt union, and typed `step_up_required` response. While it
lands, the other agents can derive the post-103 route manifest, locate current
call sites, and prepare focused tests. All later branches build on this seam.

After that seam merges, four agents work concurrently:

### Agent 1 — Direct authentication and persistence

Owns:

- shared auth types and boundary parsers;
- wallet factor-evidence builders;
- passkey and Email OTP challenge bindings;
- known-wallet bootstrap and unlock verification;
- the forward signer migration and persistence adapter;
- removal of wallet AppSession producers.

Delivers direct proof-to-signing-session and proof-to-operation evidence for
both wallet auth methods. Owns focused auth and migration tests.

### Agent 2 — Server planning, admission, and execution

Owns:

- the single server authorization planner;
- signing-session availability classification;
- atomic `AuthorizedOperation` admission;
- NEAR Ed25519 and EVM ECDSA signing/export route handlers;
- revalidation before custody opening and MPC execution;
- removal of wallet AppSession consumers in server operation paths.

Delivers one end-to-end server path first, then applies the same established
path to the other curve. Owns focused planner, replay, and admission tests.

### Agent 3 — SDK, iframe, worker, and UX

Owns:

- client handling of `authorized`, `step_up_required`, and `denied`;
- passkey and OTP prompts requested by the server;
- known-wallet locator persistence;
- wallet unlock, transaction signing, and export orchestration;
- iframe/worker protocol cleanup;
- removal of wallet AppSession payloads and client-side duplicate planning.

Delivers unchanged Google + OTP cold UX, OTP-only known-wallet flows, and
successful fallback after session expiry. Owns focused client and iframe tests.

### Agent 4 — Route boundary and continuous integration

Owns:

- the central wallet route-admission registry and concrete route manifest;
- isolation of the existing console session from wallet middleware;
- intended-behavior contracts and the three type-level invalid-state checks;
- shared barrels or central files that would otherwise cause merge conflicts;
- continuous integration of Agents 1–3 from the foundation change onward.

Agent 4 does not redesign console authentication. It keeps the working branch
compilable and runs the narrow checks as each operating path lands.

Each agent owns tests and obsolete-fixture deletion for its source area. Agents
avoid editing another agent's modules. Agent 4 owns genuine central-file
conflicts.

## Phased TODO List

The phases express code dependencies. Agents work concurrently inside a phase
where ownership permits. Integration starts with the foundation change and
continues throughout implementation.

### Phase 0 — Shared seam

- [ ] Define the exhaustive server `OperationAuthorizationDecision` union.
- [ ] Define session-independent wallet factor evidence and boundary parsers.
- [ ] Define the request union for presented-session and no-session attempts.
- [ ] Add the typed `step_up_required` response to the shared protocol.
- [ ] Land the forward schema shape without changing historical migrations.
- [ ] Confirm the shared seam compiles before parallel source changes begin.

### Phase 1 — Direct authentication foundation

- [ ] Agent 1: remove `ActiveAuthorizationSession` from wallet step-up factor
  evidence and expiry calculation.
- [ ] Agent 1: bind passkey and Email OTP challenges to the active authority and
  exact operation fingerprint.
- [ ] Agent 1: implement the opaque known-wallet authentication bootstrap.
- [ ] Agent 1: preserve Google-backed cold entry and client unlock-key proof.
- [ ] Agent 1: make passkey and known-wallet Email OTP unlock create signing
  sessions directly.
- [ ] Agent 4: add the central route-admission registry and classify the routes
  needed by the first operating path.

### Phase 2 — First complete operating path

- [ ] Agent 2: implement the server authorization planner and the exact split
  between recoverable signing-session unavailability and hard denial.
- [ ] Agent 2: atomically claim `AuthorizedOperation` from session-independent
  step-up evidence.
- [ ] Agent 2: make NEAR Ed25519 transaction signing fall back to step-up after
  signing-session expiry.
- [ ] Agent 2: make NEAR Ed25519 export step-up-only and independent of signing-
  session state.
- [ ] Agent 3: handle `step_up_required` and perform the server-selected passkey
  or Email OTP ceremony.
- [ ] Agent 3: prove the full expired-session flow through client, iframe, and
  worker without reopening Google SSO for known-wallet Email OTP.
- [ ] Agent 4: integrate the vertical slice and run its focused auth, admission,
  route, and client tests.

### Phase 3 — Complete supported operations

- [ ] Agent 2: apply the established planner and admission path to EVM ECDSA
  transaction signing and export.
- [ ] Agent 2: re-resolve active authority, key, lane, material, and revocation
  state before custody opening or MPC execution on both curves.
- [ ] Agent 3: finish unlock, signing, and export orchestration for both wallet
  authentication methods and curves.
- [ ] Agent 4: classify every remaining wallet route and enforce its admission
  class centrally.
- [ ] Connect R103 linked-device signing to the common decision while preserving
  its permissions, local-presence requirement, and hard revocation behavior.
- [ ] Isolate `console_session_v1` so wallet routes reject console credentials.

### Phase 4 — Delete the retired wallet path

- [ ] Remove wallet AppSession producers, middleware, claims, and persistence
  dependencies.
- [ ] Remove `sessionHash` and `appSessionVersion` from wallet challenges and
  operation evidence.
- [ ] Remove wallet AppSession payloads from SDK, iframe, and worker protocols.
- [ ] Remove duplicate client-side authorization planning.
- [ ] Delete wallet-only fixtures, tests, and helpers that enforce the retired
  AppSession path.
- [ ] Confirm vault authorization and the existing console session remain
  isolated and functional.

### Phase 5 — Verify and finish

- [ ] Update `docs/intended-behaviours.md` and its contracts with the behavior
  change.
- [ ] Add the three required type-level invalid-state checks.
- [ ] Run the focused tests for each changed operating path.
- [ ] Run the intended-behavior contracts and signer migration check.
- [ ] Run `pnpm check` once on the integrated change.
- [ ] Confirm every completion criterion below and remove any obsolete wallet
  AppSession code uncovered by verification.

## Required Verification

Update `docs/intended-behaviours.md` and its authoritative contracts in the same
change as the behavior.

The minimum behavioral coverage is:

- an active signing session signs without a prompt and consumes budget;
- missing, expired, exhausted, and user-ended sessions produce one same-method
  step-up and then sign successfully;
- passkey and known-wallet Email OTP fallback work for NEAR and EVM;
- Google-backed cold unlock keeps Google SSO + OTP + client unlock-key proof;
- known-wallet Email OTP unlock and step-up never reopen Google SSO;
- NEAR and EVM export work after session expiry and always require fresh proof;
- successful step-up creates one operation and no signing session;
- invalid token, cross-wallet binding, wrong origin/audience, revoked authority,
  revoked enrollment, stale lane/material, replay, and operation mismatch fail
  without a prompt loop;
- challenge bootstrap works after expiry without exposing method inventory;
- linked-device fallback preserves R103 permission, local-presence, and
  revocation rules;
- wallet routes reject console credentials;
- no wallet client, iframe, worker, route, or operation-admission path requires
  an AppSession.

Keep three type-level checks for the changed domain seam:

1. export input cannot carry signing-session authorization;
2. known-wallet OTP ceremony cannot carry Google provider evidence;
3. an authorization decision cannot contain both signing-session and step-up
   state.

Prefer updating existing fixtures and contracts. Add a new test only when no
current authoritative test owns the behavior. Classify failures before changing
production code; delete tests that exist solely for the retired AppSession path.

Run, in order:

1. focused auth, planner, persistence, client, and route tests owned by each
   changed path;
2. the intended-behavior contracts;
3. the signer migration check;
4. `pnpm check` once after integration.

## Completion Criteria

R107 is complete when:

- wallet unlock directly creates a signing session from verified passkey or
  Email OTP authentication;
- signing-session unavailability falls back to same-method step-up for every
  permitted signing operation;
- export admission is step-up-only and independent of signing-session state;
- wallet operation evidence and admission have no AppSession dependency;
- the server alone selects authorization behavior;
- revoked identity, authority, enrollment, lane, and material states remain
  hard denials;
- Google-backed cold and known-wallet UX match the required ceremonies;
- wallet routes are isolated from console and non-wallet session systems;
- wallet AppSession runtime code and obsolete tests are deleted;
- the required verification passes.

## Issues Flagged by Review

These are implementation constraints, not extra projects:

1. **Known-wallet bootstrap is required.** Removing AppSession without retaining
   an untrusted wallet/authority locator would make OTP-only fallback impossible.
2. **Bootstrap cannot require a signing session.** Authenticator inventory,
   public-key lookup, or session-state routes must not recreate the expiry
   lockout. Return a narrow ceremony preparation instead of broad inventory.
3. **Shared authorization persistence cannot be deleted wholesale.** Vault
   evidence currently references `authorization_sessions`; migrate the wallet
   branch and leave unrelated capability storage intact.
4. **Revocation meanings must stay separate.** Ending a signing session permits
   fallback. Revoking its authentication authority, linked enrollment, lane, or
   material is a hard denial.
5. **Cold OTP unlock includes client-key proof.** Preserve that custody-unseal
   step when removing the AppSession intermediary.
6. **Exact route names depend on the merged R100–103 tree.** Derive the route
   manifest from that tree once. Do not plan or implement against transitional
   routes.
7. **Global naming cleanup is high-conflict, behavior-neutral work.** R107 uses
   clear domain language while leaving the mechanical symbol rename outside the
   correctness fix.

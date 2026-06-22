# Refactor 74B: Router A/B OTP Unlock Postmortem

Date created: June 22, 2026

Status: postmortem

## Summary

Router A/B signing became the only active signing path, but several wallet
unlock, restore, bootstrap, and capability-read paths still treated persisted
session records as if they were durable proof of signing readiness.

That was the main cause of the bugs.

The final signing boundary was strict: it required Wallet Session JWT auth,
Router A/B normal-signing state, signing grant identity, runtime policy scope,
active budget, and worker-owned signing material. Earlier lifecycle boundaries
were not equally strict. They could persist or select records that had auth and
metadata, while the current worker had not validated material for that exact
session binding.

The result was a repeated class of failures:

- wallet unlock succeeded
- registration or OTP verification appeared successful
- capability readers advertised or selected a lane too early
- final signing failed later with `missing_material_handle`, `material_pending`,
  challenge drift, or budget/status errors

## Primary Cause

We mixed three different concepts into one loose idea of "warm session":

- auth-ready: the wallet has a valid Wallet Session JWT and signing grant
- restore-ready: the wallet has sealed or worker-owned material that can be
  restored for a current runtime
- sign-ready: the current worker has validated material for the exact Wallet
  Session, signing grant, threshold session, signing root, runtime policy scope,
  SigningWorker scope, and public verifier binding

Only sign-ready records should be selectable for signing without step-up or
restore. Persisted records can store hints and sealed restore references, but
they cannot be durable proof that the current runtime worker has loaded and
validated material.

## Issue Timeline

### Ed25519 Passkey Reconnect Challenge Drift

The planned passkey challenge and the actual Wallet Session mint used different
session policies. The actual mint included Router A/B normal-signing state while
the prepare step did not. That made the server compute a different expected
challenge.

Fix:

- use one policy builder for the prepare and mint paths
- include Router A/B normal-signing state consistently
- fail early when reconnect does not produce strict Router A/B state

### Extra Touch ID Prompt After Registration

Registration could finish with an auth-ready record while Ed25519 worker
material was still not runtime-validated. The first signing attempt then fell
into passkey reconnect instead of using an already sign-ready session.

Fix:

- split auth readiness from signing material readiness
- require runtime-validated Ed25519 material before no-prompt signing
- keep final signing strict: no HSS, PRF claim, restore, or fallback inside
  final signing

### Ed25519 Verifying-Share Mismatch

Stale or mismatched Ed25519 material could be treated as reusable because the
record contained material metadata. Worker validation needed to prove the
material binding against the current session facts before a lane could become
sign-ready.

Fix:

- classify persisted material handles as hints
- validate worker material against the current binding before sign-ready
  classification
- fail closed on mismatched verifier/material binding

### ECDSA Registration `ecdsa_lane_missing`

Fresh registration persisted ECDSA state without carrying
`routerAbEcdsaHssNormalSigning` through the client bootstrap boundary. The strict
Router A/B lane reader correctly hid the record, and the registration
postcondition failed.

Fix:

- parse Router A/B ECDSA Wallet Session JWT claims at the registration boundary
- copy `routerAbEcdsaHssNormalSigning` onto the ECDSA key ref
- persist the Router A/B state before lane classification
- keep the lane reader strict

### ECDSA `material_pending` During Email OTP Unlock

Email OTP ECDSA bootstrap returned worker-owned material with
`backendBinding.materialKind: 'email_otp_worker_handle'`. The commit path only
treated `role_local_worker_handle` as runtime-validated. The record therefore
persisted with worker material present, while the strict Router A/B classifier
still reported `material_pending`.

A second bug made this harder to see: the bootstrap readiness postcondition read
the wallet-level selected Tempo/EVM lane. If an older material-pending record was
selected for the same wallet and chain, it could mask the exact freshly
bootstrapped session.

Fix:

- treat `email_otp_worker_handle` as worker-provisioned runtime material
- mark the exact persisted ECDSA record runtime-validated after commit
- make Email OTP restore re-mark an existing worker-backed record before
  returning `ready`
- make the bootstrap postcondition read the exact threshold session id instead
  of the wallet-level selected lane
- let `getWarmSession()` read Email OTP ECDSA warm status through the Email OTP
  worker path

### Budget And Step-Up Drift

The SDK could sign more than the intended shared budget because budget tracking
was not consistently server-authoritative across Router A/B signing routes and
client planning.

Fix:

- server owns budget reserve, commit, release, and status
- SDK treats remaining uses as read-only status
- evidence harness asserts the shared `3 -> 2 -> 1 -> 0` transition
- step-up creates a new signing grant when the server budget is exhausted

### Google SSO Failure

The Google SSO issue was separate from Router A/B signing. Chrome silently
blocked third-party sign-in prompts for `https://localhost:443`. That made FedCM
fail with token retrieval errors.

Fix:

- keep the existing UX
- avoid adding a second Google modal flow
- make One Tap handling less brittle
- treat browser or OAuth-origin failures as environmental diagnostics, not as
  signing-session readiness bugs

## What Made The Bugs Hard To Find

- Runtime validation was volatile, but persisted records looked authoritative.
- Wallet-level capability selection could pick an older record for the same
  wallet and chain.
- Email OTP, Passkey, registration, unlock, restore, and step-up shared similar
  words for different lifecycle states.
- Tests often constructed ready fixtures directly, bypassing the real
  unlock-to-sign path.
- Some routes and helpers accepted legacy-shaped or under-bound session records
  while final signers had become Router A/B-only.
- Error messages surfaced final symptoms such as `material_pending`, while the
  actual cause was often earlier record classification or exact-session
  selection.

## Correct Model

Persisted state must be classified as one of these lifecycle states:

- invalid
- non-signing
- auth-ready material-pending
- restore-available
- material-hint-unvalidated
- runtime-validated

Only `runtime-validated` is sign-ready.

`thresholdSessionId` and `signingGrantId` must not be conflated:

- `thresholdSessionId` names the MPC/HSS protocol session and signing material
  lineage. Multi-round protocol state, restored holder material, and server
  material must all bind to this id.
- `signingGrantId` names the Wallet Session signing authorization grant. It owns
  budget, expiry, remaining uses, and step-up.

Restore-ready state means the system has enough durable material metadata to
attempt restore. It is not proof that the current browser worker can sign.

Sign-ready state means auth, budget, protocol identity, Router A/B scope, and
current worker-owned material have all been validated together:

```ts
switch (state.kind) {
  case 'runtime_validated':
    // The only sign-ready state.
    return state.value;

  case 'restore_available':
  case 'material_hint_unvalidated':
  case 'auth_ready_material_pending':
  case 'invalid':
  case 'non_signing':
    throw new Error(`not sign-ready: ${state.reason}`);
}
```

Final signing should only accept the `runtime_validated` branch. All restore,
step-up, remint, and repair work belongs in explicit pre-signing phases.

Unlock, registration, restore, and reconnect may produce auth-ready or
restore-available state. They must not report sign-ready until the current worker
validates the material for the exact current binding.

Final signing receives only sign-ready state. It does not repair, restore,
prompt, run HSS, claim PRF, or choose fallback material.

## Engineering Rules From This Incident

- A postcondition after bootstrap must check the exact threshold session id it
  just created or restored.
- Wallet-level lane selection is for display and planning, not for proving a
  freshly bootstrapped session is ready.
- Worker material handles are runtime-local hints until worker validation
  succeeds.
- Server budget is the source of truth for remaining signing uses.
- Challenge construction must use the exact same policy input as the server
  verification path.
- Source guards are useful, but unlock-to-sign regression tests are required for
  lifecycle correctness.
- Compatibility belongs at persistence and request boundaries only.

## Regression Tests Added Or Required

Added during the fix sequence:

- Email OTP ECDSA bootstrap with `email_otp_worker_handle` reaches ready state.
- Email OTP coordinator sealed restore and session-retained login preserve the
  current transport shape.
- ECDSA warm capability/reconnect tests cover strict ready, pending, and restore
  states.
- Router A/B budget evidence asserts shared remaining-use transitions.

Still useful as longer-running evidence:

- browser OTP unlock -> NEAR sign -> Tempo sign -> EVM sign
- budget exhaustion -> one step-up auth -> continued signing
- reload during OTP session -> sealed restore -> exact-session ready check

## Final Status

As of this postmortem:

- Passkey registration works.
- Passkey wallet unlock works.
- Email OTP registration works.
- Email OTP wallet unlock works.
- NEAR, Tempo, and EVM signing work.
- Step-up auth signing works.
- Ed25519 and ECDSA key export work.

No active legacy signing path remains in normal signing flows.

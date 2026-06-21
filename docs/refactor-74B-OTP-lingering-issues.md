# Refactor 74B: OTP Lingering Issues Postmortem

Date created: June 22, 2026

Status: postmortem

## Main Cause

The main cause was an incomplete lifecycle model around Email OTP signing
sessions.

Router A/B final signing required strict sign-ready state, but Email OTP unlock,
restore, bootstrap, and capability-read paths could still produce or select
records that were only auth-ready or restore-ready. The SDK then tried to use
those records as if the current worker had already validated signing material
for the exact session.

In practice, "warm session" was overloaded. It sometimes meant:

- a Wallet Session JWT exists
- a signing grant exists
- worker material may be restorable
- worker material is loaded and validated
- a wallet-level lane is selected

Those are separate states. Only the last validated-material state can sign.

## Correct Lifecycle Model

Email OTP unlock should produce one of these explicit states:

- `auth_ready`: Wallet Session JWT and signing grant exist.
- `restore_available`: sealed or worker-owned material can be restored.
- `material_pending`: material exists as a hint, but the current worker has not
  validated it.
- `runtime_validated`: the current worker has validated material for the exact
  current session binding.

Only `runtime_validated` is sign-ready.

Persisted records are durable hints. They are not durable proof that a browser
worker has loaded material. Worker validation is runtime-local and must be
re-established after reload, restore, reconnect, bootstrap, or worker restart.

## Issues Found

### 1. Email OTP ECDSA Worker Material Was Not Promoted

The Email OTP ECDSA worker returned:

```ts
backendBinding.materialKind === 'email_otp_worker_handle'
```

The commit path only treated:

```ts
backendBinding.materialKind === 'role_local_worker_handle'
```

as runtime-validated worker material.

That left a persisted ECDSA record with worker material present, while the
Router A/B classifier still reported `material_pending`.

Symptom:

```text
[SigningEngine] Email OTP bootstrap did not reach warm-session ready state
(tempo:42431, state=material_pending)
```

Fix:

- treat `email_otp_worker_handle` as worker-provisioned runtime material
- mark the persisted ECDSA record runtime-validated immediately after commit
- throw if the marker cannot be set for a worker-provisioned bootstrap

### 2. Restore Could Return Ready Without Re-Marking Runtime Validation

The sealed restore orchestrator checked the Email OTP worker status and returned
`ready` when the worker still had material for the session.

That was not enough. The Router A/B signable classifier uses a separate
runtime-validation marker keyed by the persisted record's binding facts. After a
reload or worker lifecycle edge, worker status could be `ok` while the Router
A/B runtime marker was absent.

Fix:

- existing-worker restore only returns `ready` after
  `markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)` succeeds
- otherwise the flow proceeds through sealed restore instead of claiming a ready
  state

### 3. Bootstrap Readiness Checked The Wallet-Level Lane

After ECDSA bootstrap, the postcondition called a wallet-level capability reader
and selected the Tempo/EVM lane by chain kind.

That is too broad. If an older Tempo record existed for the same wallet, the
wallet-level selected lane could still be `material_pending`, even though the
freshly bootstrapped session was ready.

Fix:

- bootstrap postconditions read the exact threshold session id produced by the
  bootstrap response
- `assertWarmThresholdEcdsaCapabilityReady()` no longer accepts broad
  `getWarmSession(walletId)` as proof
- the readiness check compares exact session id, signing grant id, chain target,
  key id, and participants

### 4. `getWarmSession()` Missed The Email OTP ECDSA Worker Status Path

`getEcdsaSigningSessionStatus()` already knew how to ask the Email OTP worker
for a warm-session claim. The wallet-level `getWarmSession()` path did not use
that same path for ECDSA records.

That allowed UI/planning capability reads to report an Email OTP ECDSA record as
pending or missing while exact status reads could see it as warm.

Fix:

- wallet-scoped ECDSA claim reads now use the same Email OTP worker-backed
  status path when strict record and volatile wallet-scoped claims are absent

### 5. Google SSO Looked Like An OTP Bug

Chrome silently blocked third-party sign-in prompts for `https://localhost:443`.
That caused Google FedCM / One Tap to fail before OTP verification could proceed.

This was an environment/browser setting issue, not a Router A/B signing-session
issue.

Fix:

- keep the existing UX
- avoid adding a second Google SSO modal flow
- make One Tap handling less brittle
- report Google token failures as browser/OAuth diagnostics

## Why Tests Missed It

The tests often verified one layer at a time:

- worker bootstrap returned material
- record persistence stored the expected metadata
- exact status reads could report warm state
- final signing required strict state

The missing regression was the full lifecycle:

```text
OTP verification
  -> ECDSA bootstrap
  -> persist Email OTP worker-backed record
  -> mark exact record runtime-validated
  -> wallet/capability reader sees exact session as ready
  -> signing proceeds without material_pending
```

The old tests also used ready fixtures or role-local worker-handle fixtures that
did not match the actual `email_otp_worker_handle` emitted by the Email OTP
worker.

## Guardrails Going Forward

- Do not use wallet-level lane selection to prove a just-created session is
  ready.
- Do not treat persisted handles as sign-ready state.
- Do not return `ready` from restore unless the Router A/B runtime-validation
  marker is set.
- Do not add fallback material restore inside final signing.
- Keep Email OTP, Passkey, and registration fixtures aligned with real worker
  output shapes.
- Add unlock-to-sign tests for each auth method whenever a readiness classifier
  changes.

## Validation Added

The fix path added or updated targeted coverage for:

- Email OTP ECDSA bootstrap with `email_otp_worker_handle`
- exact threshold-session readiness after bootstrap
- Email OTP coordinator sealed restore and session-retained login
- ECDSA warm capability pending/ready/reconnect behavior
- ECDSA registration/bootstrap parity

Manual validation after the fixes:

- Email OTP wallet unlock works.
- NEAR signing works.
- Tempo signing works.
- EVM signing works.
- Step-up auth signing works.

## Lesson

Router A/B readiness must be enforced upstream, not discovered at final signing
time. Auth, restore, and sign-ready state need separate types and separate
postconditions. The system should only advertise a signing lane when the exact
current runtime has validated the worker-owned material for that lane.

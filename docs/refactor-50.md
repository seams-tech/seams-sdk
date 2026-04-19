# Refactor 50: Signing Auth, Email OTP, and Route Boundary Cleanup

## Purpose

This plan captures the next cleanup pass after the signer-slot, signing-root,
and Email OTP refactors. The current architecture is directionally correct, but
some implementation surfaces still carry transition-era concepts that can cause
auth-method drift, duplicate route behavior, stale session assumptions, and
hard-to-debug regressions.

The goal is to make the signing stack boring:

- one canonical signing auth plan format;
- one wallet auth-mode resolver used by every wallet flow;
- one signer lifecycle boundary for local account signer records;
- one shared Email OTP route implementation used by Express and Cloudflare;
- no legacy slot names, no deprecated auth-mode aliases, and no duplicate
  compatibility paths.

Breaking changes are acceptable. This codebase is still in development, so the
preferred outcome is a clean model rather than compatibility shims.

## Current Problems

### 1. Signing Auth Still Has Two Shapes

Touch-confirm payloads still carry both:

```ts
type SigningAuthMode = 'webauthn' | 'warmSession' | 'emailOtp';
type SigningAuthPlan = ...;
```

Several payloads accept both `signingAuthMode` and `signingAuthPlan`, and the
flow orchestrator falls back from the new plan to the old mode. This keeps a
transition surface alive and makes it possible for callers to accidentally route
Email OTP accounts through WebAuthn prompts, or passkey accounts through the
wrong warm-session path.

Target state:

- `SigningAuthPlan` is the only request/payload input.
- UI components may derive a local display mode from `SigningAuthPlan`, but
  that derived mode is not accepted as a public input.
- No production code branches on a caller-provided `SigningAuthMode`.

### 2. SigningEngine Owns Too Much Email OTP Orchestration

`SigningEngine` currently contains a large amount of Email OTP orchestration:

- relay URL and route-auth normalization;
- Email OTP challenge and session calls;
- managed bootstrap grant requests;
- threshold Ed25519 registration HSS prepare/respond/finalize;
- threshold Ed25519 session minting;
- threshold ECDSA bootstrap persistence;
- app-session JWT memory;
- local signer metadata persistence.

This makes `SigningEngine` a catch-all coordinator and increases the chance that
Ed25519 and ECDSA lanes drift.

Target state:

- Extract a focused Email OTP threshold session coordinator.
- `SigningEngine` calls high-level operations and owns wallet-level orchestration
  only.
- Ed25519 and ECDSA provisioning share normalized auth/session inputs.

### 3. Express and Cloudflare Email OTP Routes Still Duplicate Logic

The Email OTP route helpers have started to reduce duplication, but the Express
and Cloudflare session routes still duplicate route bodies, response shaping,
event emission, validation, and failure handling.

Target state:

- Shared route handlers implement the Email OTP domain behavior once.
- Express and Cloudflare files become thin transport adapters.
- Response shape and status mapping are identical by construction.

### 4. Wallet Auth Resolution Needs a Tighter Boundary

The wallet auth-mode resolver is the right abstraction, but the boundary should
be stricter:

- account auth metadata should be validated before flow-specific auth decisions;
- warm-session usage should be explicit as an operation proof method;
- curve-specific code should not guess passkey versus Email OTP behavior;
- export policy should be represented in the auth plan, not hidden in UI or
  route-specific branches.

Target state:

- Every wallet flow asks the resolver for a complete executable auth plan.
- The resolver returns one of:
  - warm-session authorization;
  - passkey reauth;
  - Email OTP reauth;
  - explicit policy denial.
- Transaction signing, login/unlock, session mint, and export flows all use the
  same resolver.

### 5. Signer Lifecycle Errors Are Too Generic

The account signer lifecycle API centralizes slot allocation, but failure modes
still need to be first-class:

- duplicate account registration;
- occupied signer slot;
- invalid signer metadata;
- signer material mismatch;
- missing account auth metadata.

Target state:

- Lifecycle failures use typed errors with stable codes.
- UI and tests assert codes, not string fragments.
- Duplicate account creation fails clearly and does not replace existing signer
  material.

### 6. IndexedDB Manager Is Too Broad

`PasskeyClientDBManager` still acts as a large facade over profiles,
authenticators, chain accounts, account signers, preferences, recovery email
state, and last-profile state.

Target state:

- Store-specific repository modules own low-level IndexedDB operations.
- `PasskeyClientDBManager` remains the public facade.
- Signer lifecycle code depends on the smallest practical store surface.

### 7. Confirmation Readiness Registry Can Leak State

The confirmation readiness registry uses module-level state. If a caller fails
to consume or clear a readiness promise, stale entries can survive inside the
long-running wallet iframe.

Target state:

- Readiness state is scoped to the touch-confirm manager instance, or carries a
  TTL/abort cleanup path.
- Confirmation completion, cancellation, and route errors always clean up.

### 8. Session Token Validation May Preserve Compatibility Behavior

Session token helpers should not accept missing or null token kinds unless this
is a deliberate, temporary migration. Since there are no production customers,
the cleaner model is to require explicit token kinds.

Target state:

- App-session JWTs and threshold-session JWTs require explicit `kind`.
- Tests cover rejection of missing or wrong `kind`.
- No compatibility aliases remain.

### 9. Persisted ECDSA HSS Replay Needs Signing-Root Binding

Persisted ECDSA HSS replay/reconstruction paths must be bound to:

- `signingRootId`;
- `signingRootVersion`;
- account and chain context;
- signer kind and auth method.

Target state:

- Persisted ECDSA HSS state cannot be reused across signing roots.
- Reconstruction tests fail on wrong root id, wrong root version, and wrong
  account context.

## Target Model

### Canonical Signing Auth Plan

All signing and export flows should use one auth-plan input:

```ts
type WalletAuthProofMethod = 'passkey' | 'email_otp' | 'session';

type SigningAuthPlan =
  | {
      method: 'session';
      sessionKind: 'threshold-ed25519' | 'threshold-ecdsa';
      sessionId: string;
      expiresAt?: number;
    }
  | {
      method: 'passkey';
      reason:
        | 'wallet_unlock'
        | 'transaction_sign'
        | 'ed25519_export'
        | 'ecdsa_export'
        | 'session_mint';
      credentialIds?: readonly string[];
    }
  | {
      method: 'email_otp';
      reason:
        | 'wallet_unlock'
        | 'transaction_sign'
        | 'ed25519_export'
        | 'ecdsa_export'
        | 'session_mint';
      email: string;
      challenge?: unknown;
    };
```

The exact type can differ from this sketch, but the rule is strict:

- callers provide `SigningAuthPlan`;
- renderers derive display mode from the plan;
- no caller provides `SigningAuthMode`;
- no production code accepts both.

### Wallet Auth Resolver

The resolver should own auth-mode decisions:

```ts
type WalletAuthIntent =
  | 'wallet_unlock'
  | 'transaction_sign'
  | 'ed25519_export'
  | 'ecdsa_export'
  | 'session_mint'
  | 'link_device';

type WalletAuthResolution =
  | { ok: true; plan: SigningAuthPlan }
  | {
      ok: false;
      code:
        | 'missing_auth_metadata'
        | 'unsupported_auth_method'
        | 'export_policy_denied'
        | 'session_not_available';
    };
```

Rules:

- Passkey accounts use passkey proof unless a valid warm session is sufficient.
- Email OTP accounts use Email OTP proof unless a valid warm session is
  sufficient.
- `session` is not a signer auth method. It is an operation proof method.
- Export policy is explicit. If Email OTP export is supported, it receives an
  Email OTP auth plan. If not supported, the resolver returns policy denial.

### Email OTP Route Boundary

Shared Email OTP route handlers should be transport-neutral:

```ts
type RouteResult<TBody> = {
  status: number;
  body: TBody;
  auditEvents?: readonly EmailOtpAuditEvent[];
  webhookEvents?: readonly EmailOtpWebhookEvent[];
};
```

Express and Cloudflare adapters should only:

- read request body;
- pass dependencies into the shared handler;
- serialize `RouteResult`;
- map thrown typed errors to response bodies.

### Signer Lifecycle Boundary

The signer lifecycle API remains the only production writer for account signer
activation:

```ts
type SignerKind = 'threshold-ed25519' | 'threshold-ecdsa';

type SignerAuthMethod = 'passkey' | 'email_otp';

type SignerSource = 'passkey_registration' | 'email_otp_registration' | 'self_hosted_import';
```

Rules:

- New signer material gets a new signer slot.
- Duplicate account creation fails.
- Registration never silently replaces existing signer material.
- Rotation or migration creates a new slot, not an overwrite.
- Historical signer records remain for audit/debugging.

## Phased Todo List

### Phase 1: Remove `SigningAuthMode` From Payload Inputs

- [x] Inventory every production payload that accepts `signingAuthMode`.
- [x] Convert callers to pass `SigningAuthPlan`.
- [x] Replace flow-orchestrator fallback logic with strict plan validation.
- [x] Keep a derived UI-only display mode if the renderer still needs it.
- [x] Remove public/exported `SigningAuthMode` where possible.
- [x] Update tests to assert auth-plan shape rather than auth-mode strings.
- [x] Add negative tests that reject payloads missing `SigningAuthPlan`.

Acceptance criteria:

- No production request shape accepts both `signingAuthMode` and
  `signingAuthPlan`.
- Searching for `signingAuthMode` shows only internal derived UI usage or no
  results.

### Phase 2: Extract Email OTP Threshold Session Coordinator

- [x] Create a focused client-side coordinator module for Email OTP threshold
      sessions.
- [x] Move relay URL, rpId, app-session JWT, and worker-call normalization for
      Email OTP signing/session reauth into the coordinator.
- [x] Move route-auth normalization for registration/enrollment bootstrap into
      the coordinator.
- [x] Move Ed25519 Email OTP registration HSS provisioning into the coordinator.
- [x] Move ECDSA Email OTP bootstrap/session persistence into the coordinator.
- [x] Make `SigningEngine` call coordinator methods for Email OTP signing,
      session warm-up, and warm-session material operations instead of
      route-specific primitives.
- [x] Add unit tests for coordinator input normalization and error mapping.
- [x] Add smoke coverage for Email OTP login/unlock warming both Ed25519 and
      ECDSA sessions.
      Covered by `tests/e2e/emailOtp.thresholdEcdsa.tempoSigning.test.ts`,
      which exercises Email OTP registration, login, Ed25519 signing, ECDSA
      signing, and Ed25519/ECDSA export with WebAuthn counters asserted at
      zero.

Acceptance criteria:

- `SigningEngine` no longer contains route-level Email OTP request assembly.
- Ed25519 and ECDSA Email OTP lanes share common normalized auth inputs.

### Phase 3: Tighten Wallet Auth Resolver

- [x] Validate account auth metadata before returning a warm-session plan, or
      document and test why warm-session proof is allowed first.
- [x] Return typed policy-denial results for unsupported exports.
- [x] Ensure transaction signing, unlock/login, session mint, Ed25519 export,
      and ECDSA export all use the resolver.
- [x] Remove curve-specific passkey-vs-Email-OTP guesses.
- [x] Add tests for passkey account flows.
- [x] Add tests for Email OTP account flows.
- [x] Add tests for missing auth metadata and unsupported auth methods.

Acceptance criteria:

- No wallet flow directly decides passkey versus Email OTP without calling the
  resolver.
- Remaining `source === 'email_otp'` checks are limited to persisted
  session/source invariants, single-use Email OTP policy, worker share handling,
  and export lane execution after resolver selection.
- Export behavior is explicit and tested.

### Phase 4: Add Typed Signer Lifecycle Errors

- [x] Define signer lifecycle error codes.
- [x] Replace generic lifecycle `Error` throws with typed errors.
- [x] Update UI and callers to branch on codes rather than message text.
- [x] Add tests for duplicate account registration.
- [x] Add tests for occupied signer slot.
- [x] Add tests for signer material mismatch.
- [x] Add tests for invalid signer metadata.

Acceptance criteria:

- Duplicate account creation fails with a stable code.
- The wallet iframe error boundary forwards `Error.code` generically; no
  signer-lifecycle caller or test relies on lifecycle message fragments.
- Rotation and migration paths allocate new signer slots rather than replacing
  existing signer material.

### Phase 5: Dedupe Express and Cloudflare Email OTP Routes

- [x] Extract transport-neutral Email OTP route handlers.
- [x] Extract `/wallet/email-otp/login/challenge` into a shared
      transport-neutral handler.
- [x] Extract `/wallet/email-otp/login/verify` into a shared
      transport-neutral handler.
- [x] Extract `/wallet/email-otp/unseal` into a shared transport-neutral
      handler.
- [x] Extract `/wallet/email-otp/registration/challenge` into a shared
      transport-neutral handler.
- [x] Extract `/wallet/email-otp/registration/seal` into a shared
      transport-neutral handler.
- [x] Extract `/wallet/email-otp/registration/finalize` into a shared
      transport-neutral handler.
- [x] Extract `/wallet/email-otp/dev/cleanup-google-registration` into a shared
      transport-neutral handler.
- [x] Extract `/wallet/email-otp/dev/otp-outbox` into a shared transport-neutral
      handler.
- [x] Extract `/wallet/unlock/challenge` and `/wallet/unlock/verify` into a
      shared backend-neutral wallet unlock handler.
- [x] Review wallet-unlock Email OTP endpoints for
      remaining transport duplication before closing the whole phase.
- [x] Move common request validation into shared route helpers.
- [x] Move common response shaping into shared route helpers.
- [x] Move common audit/webhook event creation into shared route helpers.
- [x] Convert Express routes to thin adapters.
- [x] Convert Express `/wallet/email-otp/login/challenge` to a thin adapter.
- [x] Convert Express `/wallet/email-otp/login/verify` to a thin adapter.
- [x] Convert Express `/wallet/email-otp/unseal` to a thin adapter.
- [x] Convert Express `/wallet/email-otp/registration/challenge` to a thin
      adapter.
- [x] Convert Express `/wallet/email-otp/registration/seal` to a thin adapter.
- [x] Convert Express `/wallet/email-otp/registration/finalize` to a thin
      adapter.
- [x] Convert Express `/wallet/email-otp/dev/cleanup-google-registration` to a
      thin adapter.
- [x] Convert Express `/wallet/email-otp/dev/otp-outbox` to a thin adapter.
- [x] Convert Express `/wallet/unlock/challenge` and `/wallet/unlock/verify`
      to thin adapters.
- [x] Convert Cloudflare routes to thin adapters.
- [x] Convert Cloudflare `/wallet/email-otp/login/challenge` to a thin adapter.
- [x] Convert Cloudflare `/wallet/email-otp/login/verify` to a thin adapter.
- [x] Convert Cloudflare `/wallet/email-otp/unseal` to a thin adapter.
- [x] Convert Cloudflare `/wallet/email-otp/registration/challenge` to a thin
      adapter.
- [x] Convert Cloudflare `/wallet/email-otp/registration/seal` to a thin
      adapter.
- [x] Convert Cloudflare `/wallet/email-otp/registration/finalize` to a thin
      adapter.
- [x] Convert Cloudflare `/wallet/email-otp/dev/cleanup-google-registration` to
      a thin adapter.
- [x] Convert Cloudflare `/wallet/email-otp/dev/otp-outbox` to a thin adapter.
- [x] Convert Cloudflare `/wallet/unlock/challenge` and
      `/wallet/unlock/verify` to thin adapters.
- [x] Add parity tests that exercise both adapters against the same scenarios.

Acceptance criteria:

- Express and Cloudflare Email OTP and wallet-unlock route files contain no
  duplicated route-domain logic for the covered endpoints.
- Response bodies and status codes are identical by construction for the covered
  endpoints.
- Failure and lockout audit payload construction is shared. Core
  `/wallet/email-otp/*` registration, login, unseal, and dev helper endpoints now
  use transport-neutral handlers; wallet-unlock routes use a shared
  backend-neutral handler.

### Phase 6: Split IndexedDB Store Repositories

- [x] Extract profile store operations.
- [x] Extract authenticator store operations.
- [x] Extract chain account store operations.
- [x] Extract read-only chain account query operations.
- [x] Extract chain account write operations without breaking signer lifecycle
      reconciliation.
- [x] Extract account signer store operations.
- [x] Extract read-only account signer query operations.
- [x] Extract account signer write operations without breaking lifecycle invariants.
- [x] Extract last-profile-state store operations.
- [x] Keep `PasskeyClientDBManager` as the public facade.
- [x] Point signer lifecycle code at the smallest repository surface it needs.
- [x] Update tests to target both repository behavior and facade behavior.

Acceptance criteria:

- New signer lifecycle work does not require editing the large DB manager
  directly.
- Store-specific code is easier to audit for IndexedDB schema changes.

### Phase 7: Scope Confirmation Readiness State

- [x] Replace module-level readiness registry state with instance-scoped state,
      or add TTL/abort cleanup.
- [x] Ensure confirmation success consumes readiness state.
- [x] Ensure cancellation clears readiness state.
- [x] Ensure route errors clear readiness state.
- [x] Add tests for abandoned confirmation flows.
- [x] Add tests for concurrent confirmations.

Acceptance criteria:

- Stale readiness promises cannot survive indefinitely in the wallet iframe.
- Concurrent confirmations cannot consume each other's readiness state.

### Phase 8: Tighten Session Token Validation

- [x] Require explicit `kind` for app-session JWTs.
- [x] Require explicit `kind` for threshold-session JWTs.
- [x] Remove null/missing-kind compatibility behavior.
- [x] Add tests rejecting missing token kind.
- [x] Add tests rejecting wrong token kind.
- [x] Update any fixtures that relied on missing `kind`.

Acceptance criteria:

- Session token validation has no legacy compatibility branch.
- Token-kind mismatches fail closed.

### Phase 9: Bind Persisted ECDSA HSS State To Signing Root

- [x] Inventory persisted ECDSA HSS replay/reconstruction fields.
- [x] Add `signingRootId` and `signingRootVersion` to persisted binding data.
- [x] Validate signing-root binding before replay or reconstruction.
- [x] Add failure tests for wrong signing root id.
- [x] Add failure tests for wrong signing root version.
- [x] Add failure tests for wrong account or chain context.
- [x] Update docs that describe persisted ECDSA HSS session state.

Acceptance criteria:

- Persisted ECDSA HSS state cannot be reused across signing roots.
- Wrong-root replay fails before signing material is used.

### Phase 10: Remove Duplicated Validation Helpers

- [x] Inventory local `normalizeNonEmptyString`, positive integer, and enum
      validation helpers.
- [x] Reuse shared validation utilities where they fit.
- [x] Convert repeated string unions to shared constants or enums where useful.
- [x] Avoid runtime enums when literal unions plus `as const` validators produce
      cleaner bundle output.
- [x] Add tests for shared validators used by wallet auth and signer lifecycle.

Acceptance criteria:

- Validation behavior is consistent across client, server, and shared modules.
- Repeated local validation helpers are removed unless they enforce truly local
  semantics.

### Phase 11: Minor Performance Cleanup

- [x] Avoid unnecessary `structuredClone` before `postMessage` when the browser
      already performs structured cloning.
- [x] Avoid repeated signing-root scope derivation inside one flow.
- [x] Cache managed registration bootstrap grant data within a single
      provisioning operation.
- [x] Measure before and after for large transaction display payloads.
      Synthetic 1.06 MB transaction-display payload measurement:
      explicit `structuredClone` median `0.3877 ms`; envelope construction
      median `0.0001 ms`; avoided explicit clone median `0.3876 ms`.
- [x] Confirm no crypto-path optimization is needed unless benchmarks show it.

Acceptance criteria:

- Large touch-confirm payloads avoid avoidable double cloning.
- Signing-root/auth-scope normalization is performed once per flow.

## Verification Plan

Run targeted checks after each phase, then broader checks after grouped phases:

- [x] SDK build/typecheck.
- [x] Relay-server typecheck.
- [x] Cloudflare worker typecheck if package wiring supports it. No dedicated
      worker typecheck script is currently exposed; SDK build and relay-server
      typecheck passed.
- [x] Unit tests for signer lifecycle.
- [x] Unit tests for wallet auth resolver.
- [x] Unit tests for session token validation.
- [x] Unit tests for Email OTP route helpers.
- [x] Touch-confirm auth-plan tests.
- [x] Email OTP registration/login/sign/export smoke tests.
      Verified with `pnpm -C tests exec playwright test
      ./e2e/emailOtp.thresholdEcdsa.tempoSigning.test.ts --reporter=line`.
- [x] Passkey registration/login/sign/export smoke tests.
      Verified with the passkey threshold smoke subset: `thresholdEd25519`
      managed registration plus Ed25519 signing, `thresholdEcdsa` Tempo
      signing, passkey unlock warm-up, passkey export worker happy paths, and
      wallet-iframe export/signing isolation.
- [x] ECDSA persisted HSS signing-root binding failure tests.

## Release Gates

Do not treat this cleanup as complete until:

- [x] `signingAuthMode` is gone from public/request payloads. Remaining uses are
      internal UI display mode derivation or negative validation tests.
- [x] Email OTP route behavior is shared between Express and Cloudflare.
- [x] `SigningEngine` no longer owns low-level Email OTP route orchestration.
      Email OTP challenge, export authorization, and app-session refresh route
      calls live in `EmailOtpThresholdSessionCoordinator`.
- [x] Wallet auth resolver is used by all wallet flows.
- [x] Duplicate registration fails with a typed error.
- [x] Session token `kind` validation is strict.
- [x] Persisted ECDSA HSS state is bound to signing root id and version.
- [x] No legacy slot names or compatibility aliases remain. Remaining
      `deviceNumber` references are historical notes inside the signer-slot
      refactor plan.
- [x] Specs and tests describe the final model without deprecated terminology.
      Public docs and relayer test payloads use `signer_slot`/`signerSlot`.

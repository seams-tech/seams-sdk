# Threshold Session Auth Naming Cleanup

## Goal

Rename threshold signing-session JWT terminology to `thresholdSessionAuthToken` without changing behavior.

This separates two auth concepts:

- `appSessionJwt`: app or SSO boundary auth. It proves the caller has an app session.
- `thresholdSessionAuthToken`: threshold signing-session capability. It authorizes work for one concrete signing-session identity.

The token can remain JWT-backed internally. This phase is a naming cleanup only: update field names, local variable names, diagnostics, and docs so future work does not confuse app/SSO JWTs with threshold-session auth tokens.

## Design Rules

- App-session auth stays at app/session boundaries.
- Threshold-session auth names should say `authToken`, not `jwt`, in threshold-session code.
- This phase must not add claim validation, signing-root token requirements, server route semantics, or bootstrap behavior changes.
- Rename callsites directly. Do not add compatibility aliases for old names.
- Delete stale helper or fixture names while touching each callsite.

## Registration Continuation Token

Passkey registration can register Ed25519 only, ECDSA only, or both. Post-registration ECDSA provisioning should use a short-lived continuation token instead of forcing inline ECDSA provisioning inside account creation.

```ts
type RegistrationContinuationClaims = {
  kind: 'registration_continuation_v1';
  walletId: string;
  rpId: string;
  thresholdEcdsaChainTargets: ThresholdEcdsaChainTarget[];
  registrationExpiresAtMs: number;
  runtimePolicyScope: RuntimePolicyScope;
};
```

Rules:

- Mint only after successful account registration.
- Scope to wallet, RP ID, runtime policy scope, and explicit ECDSA targets.
- Allow only registration/post-registration ECDSA provisioning.
- Reject for transaction signing, key export, restore, budget admission, presign, and maintenance restore.
- Server HSS prepare compares continuation claims to `sessionPolicy.walletId` and `sessionPolicy.chainTarget`.

This is separate future work. Do not implement registration continuation token semantics in this rename pass.

## Rename Todo

### 1. Move And Link The Plan

- [x] Move this plan to `docs/signing-session-architecture/threshold-session-auth-token.md`.
- [x] Update docs links that still point at `docs/disambiguate-threshold-session-jwt.md`.
- [x] Delete the root-level `docs/disambiguate-threshold-session-jwt.md`.

### 2. Inventory Names

- [x] Run:
  `rg "thresholdSessionJwt|hasThresholdSessionJwt|thresholdRouteAuth" client server shared tests`.
- [x] Classify hits as app auth, threshold-session auth, registration continuation auth, fixture, or dead code.
- [x] Delete dead compatibility code while renaming the affected callsite.

### 3. Rename Production Fields

- [x] Rename `thresholdSessionJwt` to `thresholdSessionAuthToken`.
- [x] Rename `hasThresholdSessionJwt` to `hasThresholdSessionAuthToken`.
- [x] Rename `thresholdRouteAuth` to `thresholdSessionAuth`.
- [x] Rename threshold-session local variables named `jwt` when the surrounding type or object is threshold-session-specific.
- [x] Rename threshold-session diagnostics and error messages that say JWT.
- [x] Apply the rename to runtime records, key refs, sealed-session records, worker payloads, iframe/RPC payloads, server route schemas, and focused tests.
- [x] Delete old fixture shapes in the same patch.

### 4. Cleanup Verification

- [x] Run a final grep for deleted production names:
  `thresholdSessionJwt`, `hasThresholdSessionJwt`, and `thresholdRouteAuth`.
- [x] Keep old names only in this plan or deliberately named negative fixtures.
- [x] Run the smallest relevant focused tests for renamed surfaces.
- [x] Run the SDK/type-check target required for changed public types. Existing Phase 12 fixture churn remains outside this rename pass.

## Acceptance Criteria

- Production threshold-session code uses `thresholdSessionAuthToken`.
- App/SSO JWT names remain limited to app-session boundary modules.
- Old production field names are deleted after the rename.
- The implementation is rename-only: no new token claim validation, HSS payload fields, bootstrap semantics, or lifecycle behavior changes.

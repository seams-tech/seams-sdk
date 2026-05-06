# Threshold Session Auth Token Cleanup

## Goal

Rename threshold signing-session JWT fields to `thresholdSessionAuthToken` and route threshold-session claim checks through one validator.

This separates two auth concepts:

- `appSessionJwt`: app or SSO boundary auth. It proves the caller has an app session.
- `thresholdSessionAuthToken`: threshold signing-session capability. It authorizes work for one concrete signing-session identity.

The token can remain JWT-backed internally. Signing, export, bootstrap, restore, and budget code should treat it as an opaque threshold-session auth token after boundary validation.

## Design Rules

- App-session auth stays at app/session boundaries.
- Threshold-session auth is lane-bound and must validate against the selected concrete lane before use.
- Registration continuation auth is registration-bound and authorizes only post-registration provisioning for explicit targets.
- Token claim validation lives in one function per runtime package boundary.
- Delete compatibility aliases while renaming. Do not keep `thresholdSessionJwt`, `hasThresholdSessionJwt`, `sessionKind: 'jwt'`, or mixed `jwt` naming in production threshold-session code.
- Required identity fields must be required by type: session id, wallet signing-session id, subject id, chain target, threshold key id, and signing root.

## Target Types

Add a small auth-token module near the signing-session lifecycle types:

`client/src/core/signingEngine/session/signingSession/thresholdSessionAuthToken.ts`

```ts
export type ThresholdSessionAuthToken = string & {
  readonly __thresholdSessionAuthTokenBrand: unique symbol;
};

export type ThresholdSessionAuthMode = 'bearer_token';

export type ThresholdSessionAuthClaims =
  | {
      curve: 'ed25519';
      accountId: string;
      thresholdSessionId: string;
      walletSigningSessionId: string;
      expiresAtMs: number;
    }
  | {
      curve: 'ecdsa';
      subjectId: WalletSubjectId;
      chainTarget: ThresholdEcdsaChainTarget;
      ecdsaThresholdKeyId: string;
      signingRootId: string;
      signingRootVersion: string;
      thresholdSessionId: string;
      walletSigningSessionId: string;
      expiresAtMs: number;
    };

export type ExpectedThresholdSessionAuthIdentity =
  | {
      curve: 'ed25519';
      accountId: string;
      thresholdSessionId: string;
      walletSigningSessionId: string;
    }
  | {
      curve: 'ecdsa';
      lane: EcdsaLaneIdentity;
    };

export type ThresholdSessionBearerAuth = {
  kind: 'threshold_session';
  token: ThresholdSessionAuthToken;
  mode: ThresholdSessionAuthMode;
};
```

Keep app auth in app/session boundary code:

```ts
export type AppSessionAuth = {
  kind: 'app_session';
  jwt: string;
};
```

## Single Validator

Add one validator and make threshold-session token consumers call it before sending a request or using token-backed material:

```ts
export function validateThresholdSessionAuthTokenClaims(args: {
  token: ThresholdSessionAuthToken;
  expected: ExpectedThresholdSessionAuthIdentity;
  nowMs: number;
  context: string;
}): ThresholdSessionAuthClaims;
```

Validation requirements:

- Decode the JWT payload inside this function.
- Require `thresholdSessionId` and `walletSigningSessionId`.
- For ECDSA, require `subjectId`, `chainTarget`, `ecdsaThresholdKeyId`, `signingRootId`, and `signingRootVersion`.
- Compare ECDSA lane identity with `thresholdEcdsaLaneKey(...)`.
- Reject expired tokens.
- Throw a context-specific error naming the mismatched field.

Delete direct threshold-session JWT payload decoding from callsites once this validator exists.

## Registration Continuation Token

Passkey registration can register Ed25519 only, ECDSA only, or both. Post-registration ECDSA provisioning should use a short-lived continuation token instead of forcing inline ECDSA provisioning inside account creation.

```ts
type RegistrationContinuationClaims = {
  kind: 'registration_continuation_v1';
  walletId: string;
  rpId: string;
  subjectId: WalletSubjectId;
  thresholdEcdsaChainTargets: ThresholdEcdsaChainTarget[];
  registrationExpiresAtMs: number;
  runtimePolicyScope: RuntimePolicyScope;
};
```

Rules:

- Mint only after successful account registration.
- Scope to wallet subject, RP ID, runtime policy scope, and explicit ECDSA targets.
- Allow only registration/post-registration ECDSA provisioning.
- Reject for transaction signing, key export, restore, budget admission, presign, and maintenance restore.
- Server HSS prepare compares continuation claims to `sessionPolicy.subjectId` and `sessionPolicy.chainTarget`.

## Implementation Todo

### 1. Move And Link The Plan

- [x] Move this plan to `docs/signing-session-architecture/threshold-session-auth-token.md`.
- [x] Update docs links that still point at `docs/disambiguate-threshold-session-jwt.md`.
- [x] Delete the root-level `docs/disambiguate-threshold-session-jwt.md`.

### 2. Inventory Names

- [x] Run:
  `rg "thresholdSessionJwt|hasThresholdSessionJwt|sessionKind.*jwt|thresholdRouteAuth|sessionJwt|threshold.*jwt|jwt.*threshold" client server shared tests`.
- [x] Classify hits as app auth, threshold-session auth, registration continuation auth, fixture, or dead code.
- [ ] Delete dead compatibility code before adding new helpers.

### 3. Add Types And Validator

- [ ] Add `ThresholdSessionAuthToken`, `ThresholdSessionAuthMode`, `ThresholdSessionAuthClaims`, `ExpectedThresholdSessionAuthIdentity`, and `ThresholdSessionBearerAuth`.
- [ ] Add `validateThresholdSessionAuthTokenClaims(...)`.
- [ ] Use canonical ECDSA lane comparison inside the validator.
- [ ] Return typed claims from the validator.

### 4. Rename Production Fields

- [ ] Rename `thresholdSessionJwt` to `thresholdSessionAuthToken`.
- [ ] Rename `hasThresholdSessionJwt` to `hasThresholdSessionAuthToken`.
- [ ] Replace `sessionKind: 'jwt'` with `thresholdSessionAuthMode: 'bearer_token'`.
- [x] Rename `thresholdRouteAuth` to `thresholdSessionAuth`.
- [ ] Apply the rename to runtime records, key refs, sealed-session records, worker payloads, iframe/RPC payloads, and server route schemas.
- [ ] Delete aliases and old fixture shapes in the same patch.

### 5. Normalize At Boundaries

- [ ] Parse raw threshold token strings into `ThresholdSessionAuthToken` at server, worker, and iframe boundaries.
- [ ] Parse app auth into `AppSessionAuth` at app/session boundaries.
- [ ] Reject payloads that mix app auth fields with threshold-session token fields.
- [ ] Ensure internal signing/export/bootstrap functions accept typed auth objects.

### 6. Replace Token Use Sites

- [ ] Validate ECDSA HSS prepare/bootstrap token claims before `/threshold-ecdsa/hss/prepare`.
- [ ] Validate ECDSA signing readiness token claims against the selected transaction lane.
- [ ] Validate ECDSA key export token claims against the selected export lane.
- [ ] Validate Ed25519 signing/export token-backed material against the selected Ed25519 lane.
- [ ] Validate restored sealed-refresh token claims before publishing hot material.
- [ ] Validate server threshold ECDSA route tokens against request policy and selected ECDSA lane identity.

### 7. Minimal Tests

- [ ] Unit test matching Ed25519 claims.
- [ ] Unit test matching ECDSA claims.
- [ ] Unit test mismatched ECDSA lane identity.
- [ ] Unit test expired or malformed token.
- [ ] Focused regression test for ECDSA step-up before HSS prepare.
- [ ] Focused regression test for ECDSA key export.

### 8. Cleanup Verification

- [ ] Run a final grep for deleted production names:
  `thresholdSessionJwt`, `hasThresholdSessionJwt`, `sessionKind: 'jwt'`, and `thresholdRouteAuth`.
- [ ] Keep old names only in this plan or deliberately named negative fixtures.
- [ ] Run focused validator tests.
- [ ] Run the SDK/type-check target required for changed public types.

## Acceptance Criteria

- Production threshold-session code uses `thresholdSessionAuthToken`.
- App/SSO JWT names remain limited to app-session boundary modules.
- Every threshold token use validates through `validateThresholdSessionAuthTokenClaims(...)`.
- ECDSA validation compares against full `EcdsaLaneIdentity`.
- Old production field names are deleted after the rename.
- The implementation removes stale compatibility paths while touching each callsite.

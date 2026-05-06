# Disambiguate Threshold Session Auth Tokens

## Goal

Rename threshold signing-session JWT fields to `thresholdSessionAuthToken` and route all threshold-session claim checks through one validator.

This separates two different auth concepts:

- `appSessionJwt`: app or SSO boundary auth. It proves the caller has an app session.
- `thresholdSessionAuthToken`: threshold signing-session capability. It authorizes work for one concrete signing-session identity.

The threshold token can remain JWT-backed internally for now. Core signing/export/bootstrap code should treat it as an opaque threshold-session auth token after boundary validation.

## Design Rules

- App-session auth is boundary-only. Core lane restore, signing, budget, bootstrap, and export code should never accept an app/SSO JWT as signing-session authority.
- Threshold-session auth is lane-bound. Every threshold token must validate against the selected concrete lane before use.
- Registration continuation auth is registration-bound. It authorizes post-registration provisioning for explicit concrete targets and must never be accepted as transaction signing, export, restore, or budget authority.
- Token claim validation lives in one function per runtime package boundary. Callers receive parsed, typed claims.
- No compatibility aliases. Delete `thresholdSessionJwt`, `sessionKind: 'jwt'`, and mixed `jwt` naming from production threshold-session code.
- No optional identity fields. If validation requires a session id, wallet signing-session id, subject id, chain target, threshold key id, or signing root, the type must require it.

## Registration Continuation Token

Passkey registration should be able to register Ed25519 only, ECDSA only, or both without forcing an inline ECDSA ceremony inside account creation. The relay registration response can include a short-lived continuation token when the client asks for post-registration ECDSA targets:

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

- The token is minted only by `/registration/bootstrap` after successful account registration.
- The token is scoped to the new wallet subject, RP ID, runtime policy scope, and explicit ECDSA chain targets.
- ECDSA post-registration provisioning can consume this token with the PRF root share from the original registration credential, so it does not need a second WebAuthn assertion.
- `/threshold-ecdsa/hss/prepare` may accept this token only for `registration_bootstrap` and post-registration `session_bootstrap`.
- Server validation must compare the token claims to the requested `sessionPolicy.subjectId` and `sessionPolicy.chainTarget`.
- For `session_bootstrap` against an existing ECDSA key, the server must also verify that `ecdsaThresholdKeyId` belongs to the same wallet/RP scope.
- The token must not authorize signing, key export, restore, budget admission, presign, or any transaction operation.
- Customers that want only one curve should omit the other curve’s registration/provisioning request. The account creation response should not force ECDSA material to exist.

## Target Types

Add a small auth-token module near the signing-session lifecycle types, for example:

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
```

Keep `AppSessionAuth` separate in the app/session boundary:

```ts
export type AppSessionAuth = {
  kind: 'app_session';
  jwt: string;
};

export type ThresholdSessionBearerAuth = {
  kind: 'threshold_session';
  token: ThresholdSessionAuthToken;
  mode: ThresholdSessionAuthMode;
};
```

## Single Claim Validator

Add one validator and make all threshold-session token consumers call it before sending a request or using token-backed material:

```ts
export function validateThresholdSessionAuthTokenClaims(args: {
  token: ThresholdSessionAuthToken;
  expected: ExpectedThresholdSessionAuthIdentity;
  nowMs: number;
  context: string;
}): ThresholdSessionAuthClaims;
```

Validation requirements:

- Decode the JWT payload in this function only.
- Require `thresholdSessionId` and `walletSigningSessionId`.
- For ECDSA, require `subjectId`, `chainTarget`, `ecdsaThresholdKeyId`, `signingRootId`, and `signingRootVersion`.
- Compare ECDSA lane identity with the canonical lane comparator, such as `thresholdEcdsaLaneKey(...)`.
- Reject expired tokens.
- Throw context-specific errors with the selected lane identity and claim mismatch field.

Direct JWT payload decoding for threshold-session tokens should be deleted from callsites once this validator exists.

## Rename Plan

### 1. Inventory Current Names

Use targeted searches before editing:

```sh
rg "thresholdSessionJwt|sessionKind.*jwt|thresholdRouteAuth|sessionJwt|threshold.*jwt|jwt.*threshold" client server tests
```

Classify each hit as one of:

- App-session auth.
- Threshold-session auth token.
- Test fixture.
- Dead compatibility code to delete.

### 2. Rename Threshold-Session Fields

Replace threshold-session names across runtime records, key refs, worker payloads, and RPC payloads:

- `thresholdSessionJwt` -> `thresholdSessionAuthToken`
- `hasThresholdSessionJwt` -> `hasThresholdSessionAuthToken`
- `sessionKind: 'jwt'` -> `thresholdSessionAuthMode: 'bearer_token'`
- `thresholdRouteAuth` -> `thresholdSessionAuth`

Likely files to edit:

- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.ts`
- `client/src/core/signingEngine/session/sealedSessionStore.ts`
- `client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts`
- `client/src/core/signingEngine/api/evmFamily/ecdsaProvisioner.ts`
- `client/src/core/signingEngine/api/evmFamily/ecdsaReadiness.ts`
- `client/src/core/signingEngine/SigningEngine.ts`
- Server threshold ECDSA route handlers and request schemas.

Delete transitional aliases in the same patch. Tests should be updated to the new names.

### 3. Normalize At Boundaries

Raw JSON may still arrive from server routes, workers, and iframe messages. Normalize it once:

- Parse raw token strings into `ThresholdSessionAuthToken`.
- Parse raw app auth into `AppSessionAuth`.
- Reject payloads that mix app JWT fields with threshold-session token fields.
- Reject threshold-session payloads missing required lane identity fields.

After boundary normalization, internal functions should accept typed auth unions instead of raw strings.

### 4. Replace Callsite Validation

Update every threshold-session token use to validate through `validateThresholdSessionAuthTokenClaims(...)`.

Required callsites:

- ECDSA HSS prepare/bootstrap before `/threshold-ecdsa/hss/prepare`.
- ECDSA signing readiness before using key refs or records.
- ECDSA key export before export authorization.
- Ed25519 signing and export when token-backed runtime material is used.
- Server-side `/threshold-ecdsa/hss/prepare`, `/respond`, `/finalize`, and export routes where threshold token claims are checked.

Callsites should pass the already selected concrete lane as `expected`.

### 5. Split Request Auth From Lane Identity

Keep request auth and lane identity separate in function signatures:

```ts
export type ThresholdBootstrapRequestAuth =
  | AppSessionAuth
  | ThresholdSessionBearerAuth
  | { kind: 'webauthn'; credential: WebAuthnAuthenticationCredential }
  | { kind: 'email_otp'; challengeId: string; proof: string };
```

ECDSA lane identity should come from `EcdsaLaneIdentity`. It should not be reconstructed from request auth.

### 6. Update Server Semantics

Server request schemas should use the same names:

- `thresholdSessionAuthToken`
- `thresholdSessionAuthMode`
- `subjectId`
- `chainTarget`
- `ecdsaThresholdKeyId`
- `signingRootId`
- `signingRootVersion`

If a route still needs account/user context for audit or routing, name it separately:

```ts
type RequestAuditContext = {
  appUserId: string;
  rpId: string;
};
```

ECDSA authorization should compare `thresholdSessionAuthToken` claims to the selected ECDSA lane identity.

## Tests

Add focused validator tests:

- Accepts matching Ed25519 token claims.
- Accepts matching ECDSA token claims.
- Rejects mismatched `thresholdSessionId`.
- Rejects mismatched `walletSigningSessionId`.
- Rejects mismatched ECDSA `subjectId`.
- Rejects mismatched ECDSA `chainTarget`.
- Rejects mismatched ECDSA `ecdsaThresholdKeyId`.
- Rejects mismatched ECDSA signing root.
- Rejects expired token.
- Rejects malformed token.

Add flow regressions:

- ECDSA step-up validates token claims against the selected lane before HSS prepare.
- ECDSA key export validates token claims against the selected export lane.
- App-session JWT cannot satisfy threshold-session token validation.
- Threshold-session auth token cannot be passed to app-session-only APIs.

## Static Guards

Add architecture guards that fail on:

- `thresholdSessionJwt` in production code.
- `sessionKind: 'jwt'` in production threshold-session code.
- Direct threshold-session JWT decoding outside `validateThresholdSessionAuthTokenClaims(...)`.
- ECDSA bootstrap/export/signing callsites that accept raw `jwt` strings.
- ECDSA callsites that derive lane identity from request auth.
- Any `hasThresholdSessionJwt` debug field.

Allowed exceptions should be limited to this plan document and validator unit-test fixture names.

## Acceptance Criteria

- Production code uses `thresholdSessionAuthToken` for threshold signing-session capability tokens.
- App/SSO JWT names remain limited to app-session boundary modules.
- Every threshold token use validates through `validateThresholdSessionAuthTokenClaims(...)`.
- ECDSA validation compares against full `EcdsaLaneIdentity`.
- No production code contains `thresholdSessionJwt`, `hasThresholdSessionJwt`, or `sessionKind: 'jwt'`.
- HSS prepare and key export errors report the mismatched claim field and selected lane identity.

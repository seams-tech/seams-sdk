# SSO + Email OTP + `shamir3pass` Wallet Signing Spec

Date updated: April 14, 2026

## Objective

Define the canonical Email OTP signing system.

This spec describes a wallet-signing model where:

1. Google SSO authenticates the app user
2. Email OTP authorizes unseal of the enrolled client secret `S`
3. `shamir3pass` performs server-assisted unseal without the server returning plaintext `S`
4. the client derives threshold signing material from recovered `S`
5. `WarmSessionManager` decides how long recovered signing material stays in memory

First-release scope:

1. `passkey` remains the default and strongest signing method
2. `email_otp` is a lower-security convenience signing method
3. `email_otp` uses exactly 6 decimal digits
4. threshold signing scope is threshold ECDSA only
5. `S = randombytes(32)`
6. Email OTP supports both `session` and `per_operation` retention policies

## Product Decision

We support three canonical account families:

1. `passkey`
   - non-custodial account option
   - deterministic secret source from WebAuthn PRF
   - default and recommended signing method
2. `password`
   - non-custodial account option
   - deterministic secret source derived from password material
   - developer-enabled alternative
3. `email_otp`
   - Google-SSO-backed signing option
   - client-side `shamir3pass` unseal of enrolled secret `S`
   - cross-device signing supported
   - weaker than `passkey` because mailbox security and server escrow are in the auth path

Recommended product policy:

1. `passkey` is the default option
2. `email_otp` is available as a convenience option
3. `password` is available only when explicitly enabled by the developer
4. product copy must never present `email_otp` as equally secure with `passkey`

## Canonical Model

Email OTP does not derive the wallet secret.

Email OTP authorizes client-side unseal of the enrolled secret `S`.

Canonical shape:

```text
Google SSO app session + 6-digit Email OTP -> single-use auth grant
auth grant + server-stored escrow blob -> server-assisted shamir3pass unseal
client recovers S
S -> threshold derivation branches
S -> wallet unlock proof
S -> WarmSessionManager retention policy
S -> resumed ECDSA bootstrap
```

This system is intentionally parallel to the passkey signing path:

1. `passkey`
   - WebAuthn PRF yields the secret source material
   - PRF-derived material is used to derive threshold signing inputs
2. `email_otp`
   - `shamir3pass` unwrap yields secret `S`
   - recovered `S` is used to derive threshold signing inputs

In both modes, the output of the secret-source stage feeds the same threshold ECDSA derivation path.

## Security Posture

`email_otp` is a convenience signing method, not the strongest security mode.

Compared with `passkey`, it is weaker because:

1. mailbox compromise is in the auth path
2. the server stores a sealed escrow blob
3. the server controls the seal key used during unseal
4. OTP delivery and phishing risks are materially higher than passkey risks

Therefore:

1. `passkey` is the recommended default
2. `email_otp` must be labeled as lower-security convenience signing in product copy
3. sensitive actions must still require stronger auth than Email-OTP-only auth
4. passkey and `email_otp` must not be described as equivalent trust models

## Secret Source Model

All account modes fit one internal abstraction:

```text
client_secret_source -> threshold derivation branches
```

The source differs by mode:

1. `passkey`
   - `client_secret_source = PRF.first`
2. `password`
   - `client_secret_source = password-derived secret`
3. `email_otp`
   - `client_secret_source = recovered Email-OTP secret S`

Secret shape:

```text
S = random 32-byte secret generated on the client at enrollment
```

Rules:

1. `S` is high-entropy client-generated secret material
2. `S` is used directly as the Email-OTP secret source after unseal
3. do not add any second `PIN + OPRF` step or any secondary low-entropy wrapper around `S`

## Storage Model

### Server-side escrow only

The canonical persisted artifact is:

```text
E_ks(S)
```

where:

1. `ks` is the server `shamir3pass` seal key
2. `S` is the enrolled Email OTP client secret

Rules:

1. the server stores the authoritative escrow blob `E_ks(S)`
2. the client must not persist plaintext `S`
3. the client must not cache `E_ks(S)` locally
4. every Email OTP flow is online and server-mediated
5. every Email OTP unseal must pass through app-session validation, OTP verification, and server-assisted unseal

### Server-escrow implication

If the server stores `E_ks(S)` and holds `ks`, then server compromise plus key compromise can recover `S`.

Therefore:

1. protect `ks` with stronger controls than ordinary application secrets
2. treat Email OTP as a convenience signing feature with explicit lower-security posture
3. do not market this mode as non-custodial or equivalent to passkey

### Seal-key storage posture

Production rule:

1. production must source the Email OTP server seal key material from a KMS, HSM, or equivalent external key-management boundary
2. plaintext `SHAMIR_E_S_B64U` and `SHAMIR_D_S_B64U` environment variables are acceptable only for local development, tests, and temporary bootstrap environments
3. `PRF_SESSION_SEAL_KEY_VERSION` remains the routing identifier exposed to the application layer
4. application processes may hold the active key material only in-memory for the duration needed to apply or remove the server seal
5. long-lived plaintext seal-key storage in ordinary application config, `.env` files, or source-controlled deployment manifests is out of scope for production

## `shamir3pass` Protocol

### Enrollment seal

1. client generates client secret `S`
2. client computes `a = E_kc1(S)`
3. server returns `b = E_ks(a)`
4. client computes `sealed = D_kc1(b) = E_ks(S)`
5. client uploads `sealed` as the server-side Email OTP escrow blob

Persisted artifact:

```text
E_ks(S)
```

### Login or signing unseal

1. client requests Email OTP challenge under a valid Google-SSO-backed `app_session_v1`
2. user completes 6-digit Email OTP verification
3. server mints a single-use short-lived auth grant
4. client fetches the server-stored escrow blob `E_ks(S)`
5. client computes `d = E_kc2(E_ks(S))`
6. client sends `d` plus the auth grant
7. server returns `e = D_ks(d) = E_kc2(S)`
8. client computes `S = D_kc2(e)`

Rules:

1. the server must never return plaintext `S`
2. the server must not sign on behalf of the user using `S`
3. the client must recover `S` locally and derive signing material locally
4. Email OTP must not have an offline path

## Warm-session Retention Policies

Email OTP supports two retention policies. Both use the same Google SSO + Email OTP + `shamir3pass` unseal flow. The only difference is how long recovered signing material is retained in memory.

Canonical policy field:

```text
email_otp_auth_policy = "session" | "per_operation"
```

### `email_otp_auth_policy = session`

1. Google SSO succeeds
2. Email OTP is verified once for the login/session
3. client recovers `S`
4. client derives signing material
5. `WarmSessionManager` keeps the warm capability in memory
6. the client signs multiple transactions until expiry, logout, revocation, or invalidation

This is the default Email OTP UX mode.

### `email_otp_auth_policy = per_operation`

1. Google SSO succeeds
2. each sign operation requires a fresh Email OTP verification
3. client recovers `S` on demand
4. client derives signing material
5. client signs once
6. `WarmSessionManager` discards recovered secret-derived material immediately after the operation

This is the higher-friction, higher-security Email OTP mode.

### Policy ownership

The following layers may participate in policy selection:

1. SDK config
2. application policy
3. wallet policy

The effective policy must be explicit and inspectable.

### Authority split

The implementation must use this authority model:

1. the server is authoritative for security policy and abuse controls
2. the client is authoritative for the in-memory warm-session lifecycle
3. the client must treat server policy as upper bounds, not as optional hints

In practice this means:

1. the server owns OTP challenge TTL, login-grant TTL, failure counters, lockout timestamps, last Email OTP login time, strong-auth timestamps, and revocation state
2. the client owns live warm-capability state, in-memory expiry timers, remaining-use depletion, and local discard of recovered secret-derived material
3. client-side warm-session TTL or use counters must never extend beyond the limits imposed by the server
4. switching device, storage, or runtime must not bypass server-side lockouts or strong-auth policy

### Required retention semantics

If the policy says to discard, that means:

1. clear the warm capability
2. clear recovered `S`
3. clear derived signers or signer handles
4. zero worker memory as far as practical

### Session-mode requirements

When `email_otp_auth_policy = session`, the system must define:

1. warm-capability TTL
2. expiry semantics
3. logout invalidation
4. revocation invalidation

### Sensitive-operation overrides

The system must support forcing stronger requirements for sensitive operations even when default policy is `session`.

At minimum, the specs must allow:

1. step-up auth
2. forced `per_operation`
3. passkey requirement for especially sensitive actions

### Warm-session modeling requirements

`WarmSessionManager` must not model this only as “cached vs not cached.”

It should model explicit policy and context, for example:

```text
retention: 'session' | 'single_use'
reason: 'login' | 'sign'
authMethod: 'passkey' | 'email_otp'
stepUpRequired: boolean
```

This keeps policy readable and prevents accidental drift.

## Derivation Model

All derivations in this spec are normative and use:

1. RFC 5869 HKDF-SHA-256
2. explicit extract plus expand for every derivation step
3. UTF-8 encoding for string inputs
4. canonical ordered field encoding for every multi-field `info` value

Canonical field encoding:

```text
encode_field(x) = u16be(len(x)) || x
encode_tuple([a, b, c]) = encode_field(a) || encode_field(b) || encode_field(c)
```

Rules:

1. all identifiers such as `wallet_id`, `org_id`, `user_id`, `key_purpose`, `key_version`, and `derivation_version` are encoded as exact persisted UTF-8 string values
2. `participant_ids` must be deduplicated and sorted ascending by raw UTF-8 byte order before encoding
3. `derivation_path` must be encoded as canonical ASCII string form
4. output length is 32 bytes unless a later section explicitly says otherwise

### Threshold root

```text
threshold_root =
  HKDF-SHA-256(
    ikm=S,
    salt="tatchi/email-otp/root/v1",
    info=encode_tuple([wallet_id])
  )
```

### Threshold ECDSA branch

First release:

1. `derivation_path = "evm-signing"`
2. `clientRootShare32B64u = base64url(ecdsa_client_share_seed)`
3. do not add a second client-side scalar-reduction step before calling the existing ECDSA runtime

```text
ecdsa_client_share_seed =
  HKDF-SHA-256(
    ikm=threshold_root,
    salt="tatchi/email-otp/threshold-client-share/v1",
    info=encode_tuple([user_id, derivation_path])
  )
```

### Unlock proof branch

```text
unlock_auth_seed =
  HKDF-SHA-256(
    ikm=threshold_root,
    salt="tatchi/email-otp/unlock-auth/v1",
    info=encode_tuple([wallet_id])
  )
unlock_signing_key = DeterministicKey(unlock_auth_seed)
unlock_public_key = PublicKey(unlock_signing_key)
```

This key is not used for threshold signing. It exists only to prove possession of the recovered client secret in the current runtime.

## Registration Flow

Canonical Email OTP registration:

1. user signs in with Google SSO
2. server issues `app_session_v1`
3. account is created for the Email OTP path
4. Email OTP enrollment is completed
5. client generates strong random secret `S`
6. client seals `S` into server escrow `E_ks(S)` via `shamir3pass`
7. client derives:
   - threshold ECDSA client verifying share when ECDSA threshold is enabled
   - unlock public key
8. client uploads:
   - server escrow blob `E_ks(S)`
   - enrolled derived threshold material
   - enrolled unlock public key
   - Email OTP metadata

Registration therefore becomes:

```text
Google SSO -> account creation -> Email OTP enrollment -> client-secret generation -> server escrow
```

## Login Flow

### High-level flow

1. user logs in with Google SSO
2. app holds valid Google-SSO-backed `app_session_v1`
3. client requests Email OTP challenge
4. server sends 6-digit Email OTP
5. user enters the 6-digit Email OTP
6. server verifies the OTP and mints a short-lived single-use auth grant
7. client fetches the server-stored escrow blob
8. client performs the `shamir3pass` unseal round-trip
9. client recovers `S`
10. client derives `clientRootShare32B64u` for threshold ECDSA and the unlock proof key
11. client signs a fresh wallet unlock challenge
12. server verifies the unlock proof and establishes wallet-unlocked state
13. client provisions an ECDSA warm capability through `WarmSessionManager` using:
    - recovered `clientRootShare32B64u`
    - validated `app_session_v1`
    - explicit `ecdsaThresholdKeyId`
    - exact `sessionPolicy.participantIds` match against the active integrated ECDSA signer set
14. the warm ECDSA capability must reach `ready`
15. `WarmSessionManager` applies either `session` retention or `per_operation` retention according to policy

### Why there is still a wallet unlock proof

OTP verification authorizes unseal.

The unlock proof confirms fresh possession of the recovered client secret in the current browser/runtime and keeps wallet unlock semantics aligned with the passkey path.

## Transaction Signing Flow

Transaction signing is policy-driven by `WarmSessionManager`.

### Session-retained signing

1. Google SSO login completes
2. Email OTP verification completes
3. `shamir3pass` unseal recovers `S`
4. `WarmSessionManager` retains the warm ECDSA capability in memory
5. subsequent transactions reuse the ready warm capability until expiry or invalidation

### Per-operation signing

1. a sign request is initiated
2. if no reusable Email OTP warm capability is allowed, the app requires a fresh Email OTP
3. `shamir3pass` unseal recovers `S`
4. the client derives the same ECDSA client share and signs once
5. recovered secret-derived material is discarded immediately

This dual-policy model is intentional. The system supports both OTP-once-per-session and OTP-per-transaction via one secret-source and derivation model.

## Challenge And Grant Model

### Email OTP challenge

Recommended payload:

```json
{
  "challengeId": "oc_123",
  "issuedAt": "2026-04-14T12:00:00Z",
  "expiresAt": "2026-04-14T12:05:00Z",
  "orgId": "org_123",
  "userId": "user_123",
  "walletId": "wallet_123",
  "sessionHash": "base64url-hash",
  "appSessionVersion": "v7",
  "channel": "email_otp",
  "action": "wallet_email_otp_authorize"
}
```

Policy:

1. challenge TTL defaults to 5 minutes
2. maximum OTP attempts default to 5
3. lockout TTL defaults to 15 minutes after the configured maximum failed attempts for an enrolled wallet
4. there is no resend route in v1; the client requests a fresh challenge instead
5. `walletId` currently equals `userId` because the runtime binds login to `app_session_v1.sub`

### Email OTP auth grant

This is a server-minted, single-use, short-lived authorization artifact for exactly one unseal.

Required claims:

1. `orgId` when present in the current app session claims
2. `userId`
3. `walletId`
4. `challengeId`
5. `channel = email_otp`
6. `sessionHash`
7. `appSessionVersion`
8. `issuedAt`
9. `expiresAt`
10. `action = wallet_email_otp_unseal`

Policy:

1. grant TTL defaults to 30 seconds
2. grants are single-use and consumed on first successful validation
3. grants become invalid if the underlying app session changes or expires

## Enrollment Model

Email OTP enrollment happens only after Google SSO app session issuance.

Persisted server-side data:

1. escrow blob `E_ks(S)`
2. `emailOtpKeyVersion`
3. `unlockPublicKey`
4. `unlockKeyVersion`
5. `thresholdEcdsaClientVerifyingShareB64u` when applicable
6. `createdAtMs`
7. `updatedAtMs`
8. `lastEmailOtpLoginAtMs`
9. `lastStrongAuthAtMs`
10. OTP failure and lockout counters

The client does not store `E_ks(S)`.

## API Shape

Keep the canonical route planes:

1. session plane: existing `session/*`
2. wallet plane: existing `wallet/*`

Minimum route set:

1. `POST /wallet/email-otp/enroll/challenge`
2. `POST /wallet/email-otp/enroll/seal`
3. `POST /wallet/email-otp/enroll/verify`
4. `POST /wallet/email-otp/challenge`
5. `POST /wallet/email-otp/verify`
6. `POST /wallet/email-otp/unseal`
7. `POST /wallet/unlock/challenge`
8. `POST /wallet/unlock/verify`

## Product Rules

### Positioning

1. `passkey` is the strongest and recommended signing method
2. `email_otp` is a lower-security convenience signing method
3. `password` is a developer-enabled alternative
4. product copy must say Email OTP is less secure than passkey

### Sensitive actions

Require stronger auth than Email OTP alone for:

1. key export
2. login-method changes
3. passkey removal
4. disabling login fallbacks
5. high-risk admin actions

### Policy defaults

Recommended defaults:

1. default Email OTP policy: `session`
2. optional high-security apps: `per_operation`
3. sensitive actions: stronger auth or forced `per_operation`

## Observability

Add structured events for:

1. Email OTP enrollment success
2. Email OTP login failure
3. Email OTP lockout
4. Email OTP login success
5. Email OTP login from a new device
6. Email OTP sign request in `per_operation` mode
7. Email OTP warm-capability establishment in `session` mode
8. Email OTP warm-capability discard after single-use signing

Do not log:

1. OTP code
2. plaintext Email OTP client secret
3. raw wrapped ciphertext inputs
4. unlock private key

## Implementation Requirements

The implementation must preserve these invariants:

1. the server never returns plaintext `S`
2. the server never signs on behalf of the user using `S`
3. the client derives signing material locally after unseal
4. `session` and `per_operation` share the same derivation path from recovered `S`
5. `per_operation` clears recovered secret-derived material after single-use signing
6. `session` defines explicit TTL, logout, and invalidation behavior
7. passkey remains the strongest and recommended mode
8. server-side security policy and abuse controls are authoritative over any client-side warm-session policy

## Recommended First Release Scope

1. offer `passkey` as the default and strongest signing method
2. offer `email_otp` as a convenience signing method
3. offer `password` only when developer-enabled
4. use 6-digit `email_otp` as the only OTP channel in first release
5. support threshold ECDSA as the only product signing capability in first release
6. fix `S` to 32 random bytes in first release
7. support both `session` and `per_operation` Email OTP retention policies through `WarmSessionManager`
8. do not add any `PIN + OPRF` layer to this flow
9. do not store `E_ks(S)` on the client
10. do not enable any offline Email OTP path

## Definition of Done

1. login surfaces clearly offer `passkey` and `email_otp`, with `passkey` presented as the stronger default
2. Email OTP is explicitly documented and labeled as lower-security convenience signing
3. users can sign on a new device with Google SSO plus a 6-digit Email OTP
4. the Email OTP client secret is never persisted in plaintext at rest
5. the server stores only server-sealed escrow blobs
6. the client does not cache server escrow blobs
7. threshold ECDSA derivation is deterministic from the recovered client secret
8. `wallet/unlock/verify` accepts only public unlock proof material
9. Email OTP signing reaches a `ready` ECDSA warm capability through the canonical warm-session runtime
10. `WarmSessionManager` supports both `session` and `per_operation` retention for Email OTP
11. OTP challenges and grants are rate-limited, expiring, and single-use
12. passkey, `password`, and Email OTP coexist without duplicate legacy route or symbol pollution

## Current Implementation Status

### Completed

1. canonical Email OTP route plane exists under `wallet/email-otp/*`
2. server-authoritative escrow exists and the client does not cache `E_ks(S)`
3. client-side `shamir3pass` unseal of `S` exists
4. threshold ECDSA derivation from recovered `S` exists
5. wallet unlock proof from recovered `S` exists
6. resumed ECDSA bootstrap from recovered `S` exists
7. `email_otp` is already a first-class internal source in the threshold session store
8. rate limits, lockouts, single-use grants, and stronger-auth gates already exist
9. Express and Cloudflare parity already exist
10. the SDK now has a canonical Email OTP policy surface via `emailOtpAuthPolicy = session | per_operation`
11. Email OTP bootstrap now persists explicit warm-session auth context:
   - `policy`
   - `retention`
   - `reason`
   - `authMethod`
   - `stepUpRequired`
12. Email OTP bootstrap now threads explicit policy metadata through the client runtime and ECDSA session store
13. the current Email OTP login bridge defaults `per_operation` to a one-use ECDSA session budget when the caller does not override `remainingUses`
14. the shared EVM and Tempo signing path now delegates single-use Email OTP post-sign discard to `WarmSessionManager`
15. `WarmSessionManager` now actively enforces Email OTP retention semantics instead of only surfacing metadata:
   - `single_use` Email OTP capabilities are discarded after successful ECDSA signing
   - Email OTP capabilities are invalidated when warm-session status becomes `missing`, `expired`, or `exhausted`
16. Email OTP session TTL and invalidation semantics now clear stale local lane state and worker warm material when the client-side warm session is no longer valid
17. sensitive-operation overrides are now generalized through `WarmSessionManager` policy checks:
   - stronger operations can require fresh passkey authentication
   - stronger operations can require fresh Email OTP with `per_operation` policy
18. `PasskeyAuthMenu` now exposes `emailOtpAuthPolicy` and forwards the chosen policy through the Email OTP login CTA
19. the Email OTP bootstrap wrapper no longer returns `clientRootShare32B64u` after bootstrap consumes it
20. best-effort local cleanup now zeroizes secret-derived byte buffers in the Email OTP unlock, enrollment, and threshold bootstrap paths when those buffers are materialized client-side
21. transient Email OTP secret-source references are now shortened in the client runtime:
   - the unsealed client secret is blanked locally after the unlock handoff completes
   - the bootstrap wrapper blanks its transient `clientRootShare32B64u` reference after session bootstrap
   - decoded unlock challenge bytes are zeroized after unlock proof signing completes
22. Email OTP discard/invalidation now clears lane-scoped threshold-ECDSA presignature pools so single-use or expired sessions do not retain reusable presign material after warm-session teardown
23. background threshold-ECDSA presign refill now respects lane invalidation generation guards, preventing stale refill work from repopulating a cleared Email OTP lane after discard
24. `ethSigner` worker handlers now zeroize owned secret-derived byte buffers after use where the worker owns them:
   - unlock/signing private keys and PRF-derived inputs
   - threshold additive shares and signature-share inputs
   - presignature buffers after cloning them for transfer back to the runtime
25. `wasm/eth_signer` now zeroizes owned secret-bearing `Vec<u8>` inputs after cryptographic operations return:
   - secp256k1 sign inputs
   - PRF-derived key derivation input
   - threshold share and signature computation inputs
   - threshold presign constructor private share input
26. threshold-ECDSA coordinator cleanup now zeroizes decoded presign and signature-share buffers after they are serialized or handed off to the relayer finalize step
27. threshold-ECDSA client presignature pool state no longer stores `kShare` and `sigmaShare` as long-lived base64url strings:
   - private presign material now uses owned byte buffers
   - pooled entries are zeroized on pop, lane invalidation, and global teardown
28. sign and login-prefill paths now enforce explicit ownership for decoded `clientSigningShare32` buffers:
   - callers clone before handing secret bytes to async refill or sign work
   - caller-owned buffers are zeroized in `finally` after the final consumer returns
29. shared Email OTP derivation helpers now expose byte-oriented secret-source APIs:
   - recovered `S` is decoded once and reused as bytes
   - HKDF intermediates such as `prk`, `thresholdRoot`, and tuple-encoding buffers are zeroized after final use
30. focused lifecycle validation now covers stale-buffer rejection and post-discard cleanup:
   - direct refill, scheduled refill, and foreground sign all zeroize their owned signing-share buffers
   - stale zeroized signing-share buffers are rejected on attempted reuse
31. the main-thread Email OTP runtime now keeps recovered secret `S` byte-owned after the transport boundary:
   - unseal decodes the recovered secret once into `Uint8Array`
   - unlock and bootstrap handoff consume byte-owned secret input instead of re-passing base64url secret strings
   - enrollment keeps caller-owned secret bytes live only until verifier derivation and escrow upload complete
32. the `shamir3pass` worker/runtime boundary now exposes byte-oriented entrypoints for the main-thread Email OTP flow:
   - enrollment can send caller-owned secret bytes into the worker without first base64url-encoding them on the main thread
   - unseal can return recovered secret bytes from the worker without requiring an extra main-thread base64url decode step
   - existing string-based entrypoints remain available only as compatibility fallbacks
33. the `shamir3pass` WASM export surface now has matching byte-oriented lock helpers for the Email OTP worker path:
   - the worker no longer has to re-encode caller-owned secret bytes into base64url before invoking the WASM add-lock path
   - the worker can receive recovered secret bytes directly from the WASM remove-lock path before handing them back to the runtime
   - the older string-based WASM exports remain only for compatibility callers and phased migration
34. `shamir3pass` client lock exponents no longer need to cross into the main thread for the Email OTP flow:
   - the runtime can create opaque worker-held key handles
   - the app-facing runtime surface is now handle-based instead of exposing explicit client lock keypairs
   - Email OTP seal/unseal paths use those handles and destroy them in `finally`
   - focused unit coverage asserts the handle path and byte-returning unseal path are used
35. PRF session seal apply/remove in the passkey confirm worker now also uses opaque worker-held `shamir3pass` key handles only:
   - sealed refresh no longer materializes client encrypt/decrypt exponents in the worker flow
   - focused single-flight sealed-mode worker tests still pass after the handle migration

### Remaining Alignment Work

1. review whether additional app-facing UI surfaces should expose `emailOtpAuthPolicy` directly beyond the current `PasskeyAuthMenu` prop and API path
2. continue best-effort discard review below the current runtime layer wherever secret-derived material may still cross worker or WASM boundaries transiently
3. finish the remaining worker/WASM audit below the new byte-oriented runtime entrypoints:
   - verify any remaining compatibility string paths are as short-lived as practical and never leak back into broader runtime state
   - keep removing stale mock and helper assumptions that still describe the pre-handle `shamir3pass` flow

#### Current audit notes

The latest focused audit leaves these concrete residuals:

1. [emailOtp.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/emailOtp.ts) still contains the main-thread secret-bearing runtime path:
   - secret-bearing route assembly still happens in main-thread JS
   - unlock proof derivation and signing are still composed from the main thread
2. [emailOtp.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/emailOtp.ts) still exposes compatibility/public string-secret entrypoints:
   - `completeEmailOtpUnlock(...)` still accepts `clientSecretB64u`
   - `enrollEmailOtpWallet(...)` still accepts optional `clientSecretB64u` for caller-supplied enrollment secret input
3. [emailOtpDerivation.ts](/Users/pta/Dev/rust/simple-threshold-signer/shared/src/utils/emailOtpDerivation.ts) still contains JS derivation helpers:
   - the byte-oriented helpers are hardened, but derivation still runs in JS until the dedicated worker plus WASM refactor lands

### Core status

The core Email OTP signing system is functionally implemented and hardened enough that the remaining work is no longer a core lifecycle redesign.

Current status:

1. the canonical SSO + Email OTP + `shamir3pass` + warm-session model is implemented
2. the main remaining work is broader validation, local QA, and residual secret-handling audit below the current runtime layer
3. the dedicated OTP WASM-worker refactor is a separate follow-on project and is not required to consider the current core OTP system implemented

### Validation Status

The current core OTP lifecycle work is complete enough that the remaining effort is validation and broader integration confidence, not another major lifecycle redesign.

#### Completed validation

1. focused Email OTP derivation and lifecycle tests pass:
   - `tests/unit/emailOtpDerivation.unit.test.ts`
   - `tests/unit/tatchiPasskey.emailOtp.unit.test.ts`
   - `tests/unit/thresholdEcdsa.presignPoolRefill.unit.test.ts`
2. broader OTP-adjacent unit coverage passes:
   - `tests/unit/warmSessionManager.emailOtpPolicy.unit.test.ts`
   - `tests/unit/configs.emailOtpAuthPolicy.test.ts`
   - `tests/unit/signingEngine.emailOtpBootstrap.unit.test.ts`
   - `tests/unit/tatchiPasskey.loginThresholdWarm.unit.test.ts`
3. indirect OTP-adjacent UI and capability-resolution coverage passes:
   - `tests/unit/warmSessionManager.capabilityResolution.unit.test.ts`
   - `tests/unit/passkeyAuthMenu.fouc.unit.test.ts`
4. relayer Email OTP integration coverage passes for both adapters:
   - `tests/relayer/email-otp.authservice.test.ts`
   - `tests/relayer/email-otp.bootstrap-integration.test.ts`
   - `tests/relayer/email-otp.routes.test.ts`
   - `tests/relayer/email-otp.shamir3pass.test.ts`
5. first-class Email OTP end-to-end coverage now extends beyond the original Tempo-only path:
   - `tests/e2e/emailOtp.thresholdEcdsa.tempoSigning.test.ts`
   - session-mode Tempo signing passes
   - `per_operation` Tempo signing passes
   - session-mode EVM signing passes
   - wallet-iframe EVM `per_operation` parity is still open and must not be treated as complete until the second-sign replay is blocked
6. the ECDSA authorization-bootstrap shape is now aligned with the live integrated-key verifier model:
   - app-session bootstrap no longer sends an explicit `expectedClientVerifyingShareB64u` hint
   - prepare/finalize validation relies on the persisted integrated ECDSA key binding instead of a redundant client-supplied verifier hint
7. the current core release-gate validation was rerun after the latest `shamir3pass` handle-only cleanup and still passes:
   - `tests/e2e/emailOtp.thresholdEcdsa.tempoSigning.test.ts`
   - `tests/relayer/email-otp.authservice.test.ts`
   - `tests/relayer/email-otp.routes.test.ts`
   - `tests/relayer/email-otp.bootstrap-integration.test.ts`
   - `tests/relayer/email-otp.shamir3pass.test.ts`
   - `pnpm -C sdk run build:prepare`

#### Next validation steps

1. finish ECDSA parity for the remaining local-product Email OTP surface:
   - keep the current Tempo session and `per_operation` coverage as release-gate tests
   - keep the current EVM session-mode coverage as a release-gate test
   - close wallet-iframe EVM `per_operation` parity so the second sign is rejected after the first sign consumes the originating Email OTP auth
2. finish the remaining secret-handling audit below the current runtime layer:
   - replace any remaining string-backed secret retention with byte-owned buffers and explicit zeroization points
   - verify any WASM-returned secret buffers that cross into JS are zeroed immediately after their final consumer
3. run the dedicated Email OTP E2E flow and relayer policy suites as a standing release gate for the Email OTP core slice
4. treat repo-wide type-check cleanup as a separate track because current non-OTP failures are outside the Email OTP core slice

## Future Directions

### Email OTP to Passkey upgrade path

Email OTP can be used as a low-friction onboarding path, with passkey presented as the stronger long-term upgrade.

The intended safety model is:

1. Google SSO plus Email OTP may authenticate the user and establish signing capability
2. an Email OTP-authenticated session may initiate passkey enrollment
3. the new passkey must be created and proven successfully before any downgrade or removal of the Email OTP path
4. removal of the old Email OTP path must never happen blindly in the same step as unproven passkey enrollment

### Proposed upgrade surface

The upgrade flow should be modeled as four distinct steps:

1. `beginPasskeyUpgrade`
   - allowed from an Email OTP-authenticated session
   - starts passkey enrollment intent
   - does not modify or remove the Email OTP path
2. `completePasskeyUpgradeRegistration`
   - creates the new passkey credential
   - attaches the new passkey-backed auth or signing path to the account
   - records the account as `passkey_pending_verification` until a real passkey-authenticated step succeeds
3. `verifyPasskeyUpgrade`
   - requires fresh passkey auth with the newly enrolled passkey
   - marks the passkey upgrade as complete
   - clears `stepUpRequired`
4. `disableEmailOtpAfterPasskeyUpgrade`
   - requires fresh passkey auth
   - may remove or disable the Email OTP path only after the passkey is already verified

This separation is required so `addKey(new_passkey)` and `removeKey(old_email_otp_path)` cannot collapse into one blind mailbox-compromise path.

### Completed design steps

1. define the upgrade mutation surface as separate begin, complete, verify, and disable steps
2. freeze the rule that passkey proof must happen before any Email OTP removal or downgrade
3. freeze the rule that fresh passkey auth is the event that clears `stepUpRequired`

### TODO

1. add a first-class `Upgrade to Passkey` product flow for accounts that currently use Email OTP
2. allow an Email OTP-authenticated session to invoke `beginPasskeyUpgrade` while `stepUpRequired = true`
3. implement `completePasskeyUpgradeRegistration` so it adds the passkey-backed path without immediately removing Email OTP
4. implement `verifyPasskeyUpgrade` so fresh passkey proof marks the upgrade complete and clears `stepUpRequired`
5. implement `disableEmailOtpAfterPasskeyUpgrade` with a hard requirement for fresh passkey auth
6. ensure the account model can represent `passkey_pending_verification` without ambiguity
7. add UI copy that positions Email OTP as the low-friction onboarding method and passkey as the stronger recommended upgrade
8. add audit events for:
   - passkey upgrade started from Email OTP
   - passkey upgrade completed
   - Email OTP path removed after successful passkey verification
9. add tests for:
   - Email OTP account can add a passkey
   - unverified passkey cannot replace the Email OTP path
   - fresh passkey auth clears stronger-auth restrictions
   - Email OTP-only session cannot remove all stronger auth methods

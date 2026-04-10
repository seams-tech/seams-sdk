# SSO + OTP Cross-Device Wallet Unlock Plan

Date updated: April 7, 2026

## Objective

Add a cross-device wallet unlock fallback next to passkeys using:

1. SSO for identity and app session
2. OTP for recovery authorization
3. server-assisted `shamir3pass` unseal for client secret recovery

This document treats the OTP model as explicitly custodial recovery.

At account creation time, users will choose between three product modes:

1. `otp_recovery`
   - custodial recovery model
   - cross-device OTP recovery supported
2. `passkey`
   - non-custodial model
   - WebAuthn PRF-backed secret source
   - no server-escrow recovery secret
3. `password`
   - non-custodial model
   - password-backed client secret source
   - no server-escrow recovery secret

Recommended product policy:

1. `passkey` is the default option
2. `otp_recovery` is an alternative option
3. `password` is an alternative option that must be explicitly enabled by the developer

This plan intentionally does not use:

1. `enc_pin(enc_s(secret))`
2. OTP as a deterministic derivation input
3. OTP as a replacement for WebAuthn PRF

Instead, the design is:

1. enroll an OTP-guarded client secret once
2. store only a server-sealed escrow blob
3. use `SSO + OTP` to authorize unsealing on any device
4. feed the recovered secret into the same threshold-derivation layer used by the password approach

## Decision Summary

We will support three canonical account families:

1. `passkey`
   - non-custodial account option
   - deterministic secret source from WebAuthn PRF
2. `password`
   - non-custodial account option
   - deterministic client secret source derived from user password material
3. `otp_recovery`
   - custodial account option
   - cross-device recovery/unlock backend
   - functionally extends the password-style secret model with server escrow plus OTP-authorized unseal
   - requires valid SSO app session first in the current product direction
   - requires email OTP or TOTP verification
   - recovers a previously enrolled client secret through server-assisted unseal

We are explicitly choosing cross-device OTP behavior because users expect OTP recovery to work on a new device. A local-only OTP fallback would create accidental lockout.

The intended relationship between the alternative modes is:

1. `password` = non-custodial client-secret model
2. `otp_recovery` = the same client-secret role, but with `shamir3pass` escrow plus OTP-authorized cross-device recovery layered on top

## Account Creation Modes

At account creation time, the product should present three clear choices:

1. `Passkey wallet`
   - non-custodial
   - strongest default security model
   - recovery depends on passkey ecosystem and any separately enrolled recovery methods
2. `Password wallet`
   - non-custodial
   - derives the client secret from password material
   - same threshold-derivation role as passkey PRF, but different trust and UX profile
3. `OTP recovery wallet`
   - custodial recovery
   - easier cross-device recovery
   - relies on server escrow plus OTP-authorized recovery
   - uses an OTP-guarded client secret in the same derivation role that the password serves in the password wallet

This split should be explicit in product copy, internal docs, and risk reviews.

Recommended product presentation:

1. default: `Passkey wallet`
2. alternative: `SSO / OTP recovery wallet`
3. alternative: `Password wallet` when enabled by the developer

Important auth split:

1. `otp_recovery` is SSO-backed in the current product direction
2. `password` does not require SSO
3. `password + email` can be a standalone mode without SSO

## Core Model

### What OTP does

OTP is used to authorize recovery.

OTP is not used to derive the wallet secret.

That means the canonical shape is:

```text
SSO session + OTP verification -> recovery_grant
recovery_grant + escrow blob -> recover client secret S
S -> threshold derivation branches
```

### Shared abstraction: client secret source

All three account modes can be understood through one internal abstraction:

```text
client_secret_source -> threshold derivation branches
```

The source differs by mode:

1. `passkey`
   - `client_secret_source = PRF.first`
2. `password`
   - `client_secret_source = password-derived secret`
3. `otp_recovery`
   - `client_secret_source = recovered OTP-guarded secret`

The threshold derivation layer then consumes that source to produce:

1. threshold ECDSA client share material
2. threshold Ed25519 HSS client inputs
3. unlock proof material when applicable

### What gets recovered

The recovered value is a high-entropy client secret:

```text
S = random 32-byte or 64-byte secret generated at enrollment
```

After recovery, `S` is used directly. We do not wrap `S` in an extra `PIN + OPRF` layer.

In other words, the OTP account option is effectively:

1. the password-style secret model
2. plus server escrow
3. plus OTP-authorized cross-device recovery

That is the core architectural relationship between the two alternatives:

1. `password` keeps the client secret fully in the non-custodial path
2. `otp_recovery` uses the same threshold role for the client secret, but adds custodial recovery controls around it

## Why We Are Avoiding `enc_pin(enc_s(secret))`

We are explicitly not doing:

```text
enc_pin(enc_s(secret))
```

Reasons:

1. a low-entropy PIN is not the right outer wrapper for long-term server-stored recovery data
2. OTP is already the recovery authorization primitive in this design
3. if a strong client secret `S` is recovered, `S` itself should be the canonical secret
4. adding `PIN + OPRF` after recovering `S` is redundant complexity

The cleaner design is:

```text
recover S -> HKDF(S, domain-separated labels) -> threshold material
```

## SDK API Rescan Snapshot

The current SDK and relay surface matters here.

### Stable public threshold exports

The stable exports in `client/src/threshold.ts` currently expose:

1. `keygenEcdsa`
2. `connectEd25519Session`
3. `connectEcdsaSession`
4. `authorizeEcdsaWithSession`
5. ECDSA presign/sign helpers

Important constraints:

1. there is no stable public `otp_recovery` helper today
2. there is no stable public secret-source abstraction that can swap `passkey_prf` for OTP-guarded-secret-based derivation
3. `connectEd25519Session` is still WebAuthn/passkey-oriented in shape

So the first implementation seam for `otp_recovery` should be internal lifecycle/runtime code, not a forced fit into the current stable public threshold API.

### Wallet unlock routes today

Today, both Express and Cloudflare wire:

1. `POST /wallet/unlock/challenge` to WebAuthn challenge issuance
2. `POST /wallet/unlock/verify` to WebAuthn assertion verification

Those routes are passkey-specific today. They are not yet backend-neutral wallet unlock routes.

### Existing `shamir3pass` sealing model

The repo already has a commutative server-seal model for persisted secret material:

1. client adds temporary layer
2. server applies or removes server seal
3. client removes its temporary layer

That existing pattern should be reused for escrow and recovery of the OTP-guarded client secret. Conceptually, this is `shamir3pass + OTP` layered on top of the same client-secret role used by the password mode.

## Security Model

### Separation of concerns

1. SSO proves identity and mints `app_session_v1`
2. OTP proves current control over a recovery channel
3. `shamir3pass` unseal recovers the client secret
4. threshold derivation happens client-side from the recovered secret

### Explicit risk posture

This is an escrow recovery feature.

It is weaker than a purely local deterministic secret source because:

1. the server stores an escrow blob
2. the server holds the server seal key material
3. recovery is authorized by SSO + OTP

That is acceptable if deliberate, but it must be documented and hardened as custodial recovery, not as a pure client-side secret model.

### Custody statement

If the server stores `E_ks(S)` and controls `k_s`, then the server is in the custody path for recovery of the wallet secret.

Therefore:

1. `otp_recovery` must be labeled custodial
2. `passkey` and `password` may be labeled non-custodial
3. the account modes must not be described as equivalent trust models

### Required controls

1. valid fresh app session required before OTP challenge issuance
2. strict OTP rate limits and lockouts
3. single-use short-lived `recovery_grant`
4. user notification on recovery from a new device
5. audit trail for enrollment and recovery
6. HSM/KMS-backed storage for server seal key material
7. cooldown or step-up for high-risk actions after OTP-only recovery

## Canonical Terminology

Use these canonical names:

1. `passkey`
2. `otp_recovery`
3. `OTP-guarded client secret`
4. `recovery escrow blob`
5. `recovery challenge`
6. `recovery grant`
7. `threshold root`
8. `threshold ECDSA client share`
9. `threshold Ed25519 HSS client inputs`
10. `threshold Ed25519 HSS client base`

Do not introduce duplicate legacy naming for:

1. wallet password
2. OTP-derived wallet key
3. encrypted PIN wrapper
4. fallback root when the value is actually acting as the client secret source

## Secret Model

### OTP-guarded client secret

At enrollment, the client generates a strong random client secret:

```text
S = randombytes(32) or randombytes(64)
```

This is the canonical secret source for the OTP account mode.

Functionally, `S` occupies the same role that the user password occupies in the password account mode.

### Escrow blob

The canonical persisted recovery artifact is:

```text
E_ks(S)
```

where:

1. `ks` is the server `shamir3pass` seal key
2. `S` is the OTP-guarded client secret

The client may keep a local copy for convenience, but cross-device recovery requires a server-stored escrow copy.

### Important server-escrow implication

If the server stores `E_ks(S)` and also holds `ks`, then server compromise plus key compromise can recover `S`.

Therefore:

1. store escrow blobs as recovery data, not as routine runtime state
2. protect `ks` with stronger controls than ordinary application secrets
3. treat this fallback as a product recovery feature with explicit risk posture

## Derivation Model

After recovery, `S` becomes the threshold root input.

### Threshold root

```text
threshold_root = HKDF(S, salt="tatchi/otp-recovery/root/v1", info=wallet_id)
```

### Threshold ECDSA branch

```text
ecdsa_client_share_seed =
  HKDF(threshold_root, salt="tatchi/otp-recovery/threshold-client-share/v1", info=user_id || derivation_path)
```

From that branch:

1. reduce to non-zero secp256k1 scalar
2. derive the client verifying share pubkey

### Threshold Ed25519 HSS branch

NEAR threshold signing needs a distinct branch.

```text
ed25519_hss_input_material =
  HKDF(threshold_root, salt="tatchi/otp-recovery/threshold-ed25519-hss/v1", info=org_id || near_account_id || key_purpose || key_version || participant_ids || derivation_version)
```

That branch must produce deterministic analogues of:

1. `contextBindingB64u`
2. `yClientB64u`
3. `tauClientB64u`

Those are then consumed by the existing HSS prepare/finalize seam to reconstruct:

1. `xClientBaseB64u`
2. canonical public key material
3. canonical seed export material where applicable

### Unlock proof branch

Derive a separate branch for signed wallet unlock proofs:

```text
unlock_auth_seed =
  HKDF(threshold_root, salt="tatchi/otp-recovery/unlock-auth/v1", info=wallet_id)
unlock_signing_key = DeterministicKey(unlock_auth_seed)
unlock_public_key = PublicKey(unlock_signing_key)
```

This key is not used for threshold signing. It exists only to prove possession of the recovered client secret during wallet unlock.

## `shamir3pass` Escrow Protocol

This design reuses the existing commutative seal shape.

Notation:

1. `E_k(x)` = commutative encryption with key `k`
2. `D_k(x)` = corresponding decryption
3. `k_s` = server seal key
4. `k_c1`, `k_c2` = client ephemeral commutative keys

### Enrollment seal

1. client generates client secret `S`
2. client computes `a = E_kc1(S)`
3. server returns `b = E_ks(a)`
4. client computes `sealed = D_kc1(b) = E_ks(S)`
5. client uploads `sealed` as the recovery escrow blob

Persisted server-side artifact:

```text
recoveryEscrowBlob = E_ks(S)
```

### Recovery unseal

1. client loads escrow blob `E_ks(S)` from server
2. client computes `d = E_kc2(E_ks(S))`
3. client sends `d` plus valid `recovery_grant`
4. server returns `e = D_ks(d) = E_kc2(S)`
5. client computes `S = D_kc2(e)`

This preserves a desirable property:

1. the server does not need to send plaintext `S`
2. the client recovers `S` only after OTP-authorized unseal

## Recovery Channel Options

### Email OTP

Default recovery channel.

Pros:

1. no extra app required
2. familiar UX
3. fits user expectation for cross-device recovery

Cons:

1. usually same trust domain as SSO mailbox
2. weaker than a separate authenticator
3. more phishing and delivery risk

### TOTP

Optional stronger recovery channel.

Pros:

1. better factor separation
2. no email delivery dependency

Cons:

1. requires separate authenticator app
2. worse onboarding friction

### Product positioning

If email OTP is the default recovery channel for this account mode, it must be positioned as convenience-oriented custodial recovery, not as a factor equivalent to passkeys.

The current product direction is:

1. `passkey` = default
2. `otp_recovery` = SSO-backed custodial alternative
3. `password` = developer-enabled non-custodial alternative
4. `password + email` does not require SSO

## Development OTP Delivery

For local development, we do not want to require a real outbound email provider just to exercise OTP flows.

The development plan should therefore support distinct OTP delivery modes:

1. `email_provider`
   - production and staging delivery through the real email provider
2. `log`
   - local development only
   - emit the OTP to the server terminal in a structured log line
3. `memory`
   - local development and automated testing
   - write the latest OTP to an in-memory dev outbox instead of sending email

Recommended implementation order:

1. first add `log` mode so manual development can proceed immediately
2. then add `memory` mode so browser-driven and E2E flows do not depend on reading terminal output
3. keep `email_provider` as the only allowed production delivery mode

### `log` mode

For early local development, logging the OTP to the server terminal is acceptable.

Recommended log shape:

```text
[otp][dev] issued { walletId, userId, recoveryChannel, destinationHint, code, expiresAt }
```

Rules:

1. `log` mode must be disabled outside local development environments
2. the structured log should clearly mark the event as development-only
3. OTP codes must not be emitted through ordinary production logging pipelines

### `memory` mode

For proper development and test ergonomics, add a dev OTP outbox.

Recommended behavior:

1. store the latest OTP in memory keyed by `walletId` or `userId`
2. expose a dev-only read surface such as `GET /dev/otp/latest`
3. gate that surface to non-production environments only
4. optionally require a local dev secret or localhost-only access

This is preferable to terminal-only logging for automated testing because:

1. browser and E2E flows can fetch the OTP directly
2. no terminal scraping is required
3. delivery remains cleanly separated from OTP verification

### What not to do

Do not:

1. return OTP codes from normal recovery APIs
2. expose dev OTP read surfaces in production builds
3. route development OTP logs into shared production-grade log sinks

## Enrollment Model

Recovery enrollment should happen only after SSO app session issuance.

### Enrollment steps

1. user signs in with SSO
2. relay issues `app_session_v1`
3. user opts into OTP recovery
4. user verifies recovery channel ownership:
   - email OTP, or
   - TOTP bootstrap
5. client generates strong random client secret `S`
6. client seals `S` into `E_ks(S)` via `shamir3pass`
7. client derives:
   - threshold ECDSA client verifying share when ECDSA threshold is enabled
   - threshold Ed25519 HSS client inputs or registration material when NEAR threshold is enabled
   - unlock public key
8. client uploads:
   - recovery escrow blob
   - enrolled derived threshold material
   - enrolled unlock public key
   - recovery metadata

### Enrollment data to persist

Server-side:

1. `unlockBackend = otp_recovery`
2. `recoveryChannel = email_otp | totp`
3. `recoveryEscrowBlob = E_ks(S)`
4. `recoveryKeyVersion`
5. `unlockPublicKey`
6. `unlockKeyVersion`
7. `thresholdEcdsaClientVerifyingShareB64u` when applicable
8. threshold Ed25519 HSS canonical context when applicable:
   - `orgId`
   - `nearAccountId`
   - `keyPurpose`
   - `keyVersion`
   - `participantIds`
   - `derivationVersion`
9. threshold Ed25519 registration/server material when applicable
10. `createdAtMs`
11. `updatedAtMs`
12. `lastRecoveryAtMs`
13. OTP failure and lockout counters

Client-side:

1. optional cached local copy of `E_ks(S)`
2. no plaintext `S` persistence
3. no plaintext OTP persistence

## Recovery And Unlock Model

### High-level flow

1. app already has valid SSO-backed app session
2. client requests recovery challenge
3. user completes OTP verification
4. relay mints a short-lived single-use `recovery_grant`
5. client fetches recovery escrow blob
6. client performs `shamir3pass` unseal round-trip using the grant
7. client recovers `S`
8. client derives threshold material and unlock proof key
9. client signs a fresh wallet unlock challenge
10. relay verifies derived material and unlock proof
11. relay marks wallet unlocked and continues warm session bootstrap

### Why there is still a wallet unlock proof

OTP verification authorizes recovery.

The unlock proof confirms fresh possession of the recovered client secret in the current browser/runtime and preserves clean wallet unlock semantics.

This also keeps the unlock model closer to the passkey design:

1. recover or derive secret material
2. prove possession on a fresh challenge
3. continue threshold warm-session bootstrap

## Challenge Model

There are two challenge families in this design.

### Recovery challenge

Used for OTP verification.

Recommended payload:

```json
{
  "challengeId": "rc_123",
  "issuedAt": "2026-04-07T12:00:00Z",
  "expiresAt": "2026-04-07T12:05:00Z",
  "walletId": "wallet_123",
  "recoveryChannel": "email_otp",
  "action": "wallet_recovery_unlock"
}
```

### Wallet unlock challenge

Used after recovering `S`.

Recommended payload:

```json
{
  "challengeId": "wu_123",
  "nonce": "base64url-random",
  "issuedAt": "2026-04-07T12:02:00Z",
  "expiresAt": "2026-04-07T12:03:00Z",
  "action": "wallet_unlock",
  "origin": "https://app.example.com",
  "walletOrigin": "https://wallet.example.com",
  "walletId": "wallet_123",
  "sessionHash": "base64url-hash",
  "appSessionVersion": 7,
  "unlockBackend": "otp_recovery",
  "keyVersion": "otp-recovery-v1"
}
```

The server must verify:

1. app session is valid
2. challenge is unexpired
3. challenge has not been used before
4. action matches expected unlock action
5. origin and wallet origin are expected
6. session hash matches current session context
7. signature matches the enrolled `unlock_public_key`

## Proposed API Shape

Keep the canonical route planes:

1. session plane: existing `session/*`
2. wallet plane: existing `wallet/*`

Do not add auth-specific aliases.

### Current route reality

Today, `wallet/unlock/*` is a passkey API surface, not a backend-neutral wallet unlock API surface.

That means the first OTP release has two possible shapes:

1. breaking change: generalize `POST /wallet/unlock/challenge` and `POST /wallet/unlock/verify`
2. additive shape: introduce `wallet/recovery/*` routes first, then unify later

Because the current handlers are explicitly WebAuthn-bound, this plan should not assume the route surface is already generic.

### Target API shape

Recommended routes:

1. `POST /wallet/recovery/enroll/challenge`
2. `POST /wallet/recovery/enroll/verify`
3. `POST /wallet/recovery/challenge`
4. `POST /wallet/recovery/verify`
5. `POST /wallet/recovery/unseal`
6. `POST /wallet/unlock/challenge`
7. `POST /wallet/unlock/verify`

### Example `POST /wallet/recovery/challenge`

Request:

```json
{
  "walletId": "wallet_123",
  "recoveryChannel": "email_otp"
}
```

Response:

```json
{
  "ok": true,
  "challenge": {
    "challengeId": "rc_123",
    "issuedAt": "2026-04-07T12:00:00Z",
    "expiresAt": "2026-04-07T12:05:00Z",
    "walletId": "wallet_123",
    "recoveryChannel": "email_otp",
    "action": "wallet_recovery_unlock"
  }
}
```

### Example `POST /wallet/recovery/verify`

Request:

```json
{
  "walletId": "wallet_123",
  "challengeId": "rc_123",
  "recoveryChannel": "email_otp",
  "otpCode": "123456"
}
```

Response:

```json
{
  "ok": true,
  "recoveryGrant": "single-use-short-lived-token",
  "escrow": {
    "recoveryKeyVersion": "otp-recovery-v1",
    "ciphertext": "base64url"
  }
}
```

### Example `POST /wallet/recovery/unseal`

Request:

```json
{
  "walletId": "wallet_123",
  "recoveryGrant": "single-use-short-lived-token",
  "wrappedCiphertext": "base64url"
}
```

Where:

```text
wrappedCiphertext = E_kc(E_ks(S))
```

Response:

```json
{
  "ok": true,
  "ciphertext": "base64url"
}
```

Where:

```text
ciphertext = E_kc(S)
```

### Example `POST /wallet/unlock/verify`

Request:

```json
{
  "unlockBackend": "otp_recovery",
  "walletId": "wallet_123",
  "challengeId": "wu_123",
  "unlockProof": {
    "publicKey": "base64url",
    "signature": "base64url"
  },
  "threshold": {
    "ecdsa": {
      "clientRootShare32B64u": "base64url"
    },
    "ed25519": {
      "contextBindingB64u": "base64url",
      "yClientB64u": "base64url",
      "tauClientB64u": "base64url"
    }
  }
}
```

Response:

```json
{
  "ok": true,
  "unlocked": true
}
```

## Implementation Guidance

### Server modules

Add or extend:

1. OTP challenge/verification service
2. recovery escrow store
3. recovery grant mint/verify service
4. `shamir3pass` unseal endpoint using the existing seal runtime
5. wallet unlock verifier for `otp_recovery`

Recommended server responsibilities:

1. verify SSO-backed app session
2. issue and verify OTP challenges
3. mint single-use `recovery_grant`
4. fetch escrow blob by `walletId`
5. remove server seal under valid grant
6. verify wallet unlock proof and enrolled derived material

### Client modules

Add or extend:

1. recovery enrollment flow
2. recovery OTP verification flow
3. client-side `shamir3pass` wrap/unwrap helper for the OTP-guarded client secret
4. threshold derivation helpers from the recovered client secret
5. wallet unlock proof derivation/signing helper

### Secret-source abstraction

Introduce explicit internal secret-source backends:

1. `passkey_prf`
2. `password_secret`
3. `otp_recovery_secret`

Do not hide these behind passkey-only APIs or legacy optional flags.

### Threshold integration

Route the recovered client secret into:

1. threshold ECDSA client-share derivation
2. threshold Ed25519 HSS client-input derivation
3. unlock proof derivation

Do not require a second `PIN + OPRF` step after client-secret recovery.

## Product Rules

### Positioning

1. `passkey` is the non-custodial account option
2. `otp_recovery` is the custodial account option
3. `password` is the non-custodial account option with password-derived secret material
4. email OTP recovery is convenience-oriented and weaker than passkeys
5. TOTP may be offered as a stronger optional recovery channel within the custodial model

### Sensitive actions

Require stronger auth than `otp_recovery` alone for:

1. key export
2. recovery method changes
3. passkey removal
4. disabling recovery
5. high-risk admin actions

### Post-recovery restrictions

After OTP-only recovery, apply temporary restrictions or step-up requirements for:

1. key export
2. changing recovery settings
3. deleting passkeys

## Observability

Add structured events for:

1. `wallet.recovery.enroll.started`
2. `wallet.recovery.enroll.completed`
3. `wallet.recovery.challenge_issued`
4. `wallet.recovery.verified`
5. `wallet.recovery.unseal.succeeded`
6. `wallet.recovery.unseal.failed`
7. `wallet.recovery.unlock.succeeded`
8. `wallet.recovery.locked_out`

Event payloads should include:

1. `orgId`
2. `userId`
3. `walletId`
4. `unlockBackend`
5. `recoveryChannel`
6. `keyVersion`
7. `reason`

Do not log:

1. OTP code
2. plaintext OTP-guarded client secret
3. raw wrapped ciphertext inputs
4. unlock private key

## Phased TODO List

### Phase 0 — Spec lock

Goal: freeze the product and protocol shape before code changes.

- [ ] freeze canonical naming: `passkey`, `password`, `otp_recovery`
- [ ] freeze recovery channel names: `email_otp`, `totp`
- [ ] freeze account-mode labeling:
  `passkey` = non-custodial, `password` = non-custodial, `otp_recovery` = custodial
- [ ] freeze wallet identifiers and identity tuple inputs used by recovery flows
- [ ] freeze OTP challenge lifetime, resend policy, and max attempts
- [ ] freeze `recovery_grant` lifetime and single-use semantics
- [ ] freeze server seal key storage model: KMS or HSM-backed
- [ ] freeze first-release scope:
  ECDSA only or ECDSA + Ed25519 HSS

### Phase 1 — Data model and server primitives

Goal: add the server-side building blocks without exposing the feature yet.

- [ ] add persisted wallet unlock backend enum/value for `otp_recovery`
- [ ] add persisted recovery channel enum/value for `email_otp | totp`
- [ ] add persisted `recoveryEscrowBlob`
- [ ] add persisted `recoveryKeyVersion`
- [ ] add persisted `unlockPublicKey` and `unlockKeyVersion`
- [ ] add persisted OTP failure counters, lockout timestamps, and `lastRecoveryAtMs`
- [ ] add OTP challenge issuance service
- [ ] add OTP verification service
- [ ] add OTP delivery abstraction with explicit modes:
  `email_provider`, `log`, `memory`
- [ ] add environment guardrails so `log` and `memory` cannot run in production
- [ ] add `recovery_grant` mint/verify service
- [ ] add audit event emission hooks
- [ ] add user notification hook for new-device recovery

### Phase 2 — `shamir3pass` escrow and recovery runtime

Goal: reuse the existing commutative seal runtime for OTP-backed recovery of `S`.

- [ ] identify the existing `shamir3pass` seal/unseal runtime that should be reused
- [ ] implement enrollment seal flow for newly generated client secret `S`
- [ ] implement recovery unseal flow using `wrappedCiphertext = E_kc(E_ks(S))`
- [ ] enforce `recovery_grant` validation before server-side unseal
- [ ] ensure the server never returns plaintext `S`
- [ ] add key versioning for server seal rotation
- [ ] decide whether to keep an optional local cache of `E_ks(S)` for convenience

### Phase 3 — Internal secret-source abstraction

Goal: make threshold derivation consume an explicit client-secret source instead of passkey-only assumptions.

- [ ] introduce internal secret-source backends:
  `passkey_prf`, `password_secret`, `otp_recovery_secret`
- [ ] remove passkey-only assumptions from internal threshold lifecycle seams
- [ ] route the recovered OTP client secret through the same internal role as the password secret
- [ ] ensure no legacy optional flags or duplicate legacy APIs remain after the refactor
- [ ] document the internal invariant:
  `client_secret_source -> threshold derivation branches`

### Phase 4 — Threshold derivation integration

Goal: derive threshold material and unlock proof material from recovered `S`.

- [ ] implement `threshold_root = HKDF(S, ...)`
- [ ] implement threshold ECDSA client-share derivation from `threshold_root`
- [ ] integrate ECDSA verifying-share registration/verification with `otp_recovery`
- [ ] implement threshold Ed25519 HSS input derivation from `threshold_root`
- [ ] wire deterministic `contextBindingB64u`, `yClientB64u`, and `tauClientB64u` into the existing HSS prepare/finalize seam
- [ ] implement unlock proof key derivation from `threshold_root`
- [ ] ensure there is no second `PIN + OPRF` step anywhere in this flow

### Phase 5 — Relay and route integration

Goal: expose backend-neutral recovery and unlock endpoints.

- [ ] decide whether to generalize `wallet/unlock/*` immediately or land `wallet/recovery/*` first
- [ ] implement `POST /wallet/recovery/enroll/challenge`
- [ ] implement `POST /wallet/recovery/enroll/verify`
- [ ] implement `POST /wallet/recovery/challenge`
- [ ] implement `POST /wallet/recovery/verify`
- [ ] implement `POST /wallet/recovery/unseal`
- [ ] implement backend-aware wallet unlock verification for `otp_recovery`
- [ ] keep Express and Cloudflare route surfaces in parity
- [ ] remove any duplicate or transitional route shapes once the new surface lands
- [ ] if `memory` mode is implemented, add a dev-only OTP outbox read route and keep it excluded from production routing

### Phase 6 — Client SDK and app flows

Goal: make the feature usable from the client without freezing the wrong public abstraction too early.

- [ ] implement recovery enrollment flow in internal client runtime
- [ ] implement recovery challenge, OTP submission, and unseal flow in internal client runtime
- [ ] implement client-side `shamir3pass` wrap/unwrap helper usage for recovery
- [ ] implement unlock proof signing from recovered `S`
- [ ] wire recovered threshold material into ECDSA session bootstrap
- [ ] wire recovered threshold material into Ed25519 HSS bootstrap when Ed25519 is in scope
- [ ] decide what, if anything, should be added later to `client/src/threshold.ts`
- [ ] avoid publishing a stable public SDK helper until the internal abstraction is proven

### Phase 7 — Product UX

Goal: make the custody model and user choices explicit.

- [ ] add account creation choice UI for:
  `Passkey wallet`, `SSO / OTP recovery wallet`, `Password wallet`
- [ ] make `Password wallet` conditional on developer enablement
- [ ] label `otp_recovery` as custodial in product copy
- [ ] label `passkey` and `password` as non-custodial in product copy
- [ ] add recovery enrollment UI for email OTP
- [ ] add optional TOTP enrollment UI if included in first release
- [ ] add new-device recovery notification UX
- [ ] add lockout, cooldown, and retry UX
- [ ] clearly distinguish wallet recovery from ordinary sign-in

### Phase 8 — Hardening and policy controls

Goal: enforce the custodial recovery security posture.

- [ ] require valid fresh app session before OTP challenge issuance
- [ ] rate-limit OTP issuance and verification per user, IP, wallet, and org
- [ ] rate-limit `recovery_grant` redemption and unseal attempts
- [ ] enforce single-use recovery challenges and grants
- [ ] restrict sensitive actions after OTP-only recovery
- [ ] require stronger auth for key export, recovery changes, and passkey removal
- [ ] add full structured observability for recovery success, failure, and lockout paths
- [ ] verify no plaintext OTP codes or plaintext client secrets are logged
- [ ] verify dev OTP delivery modes are impossible to enable in production
- [ ] verify dev OTP outbox endpoints are impossible to expose in production

### Phase 9 — Tests and launch gate

Goal: prove the feature works and is safe to ship.

- [ ] add unit tests for OTP delivery mode selection and production guardrails
- [ ] add unit tests for dev OTP `memory` outbox behavior if implemented
- [ ] add unit tests for OTP challenge expiry, replay rejection, and lockout
- [ ] add unit tests for `recovery_grant` expiry and single-use enforcement
- [ ] add unit tests for `shamir3pass` recovery wrap/unseal semantics
- [ ] add integration test for SSO session plus recovery enrollment
- [ ] add integration test for new-device email OTP recovery
- [ ] add integration test for local development OTP flow via `log` or `memory` mode
- [ ] add integration test for wrong OTP lockout
- [ ] add integration test for unseal denial without valid `recovery_grant`
- [ ] add integration test for threshold ECDSA bootstrap from recovered client secret
- [ ] add integration test for threshold Ed25519 HSS bootstrap from recovered client secret if Ed25519 is in scope
- [ ] add parity coverage for Express and Cloudflare adapters
- [ ] confirm docs and product copy consistently label `otp_recovery` as custodial

## Open Questions

1. Should email OTP be the only default recovery channel, or should TOTP be required for higher-assurance deployments?
2. Should recovery unlock immediately grant full wallet capability, or should some high-risk actions require a second stronger step-up?
3. Should local cached escrow blobs be retained for same-device convenience, or should recovery always fetch from server?
4. Should first release cover only threshold ECDSA, or both ECDSA and Ed25519 HSS?
5. Should recovery enrollment require an already-enrolled passkey, or may SSO-only users opt into recovery directly?

## Recommended First Release Scope

1. offer `passkey` as the default non-custodial account option
2. offer `otp_recovery` as the SSO-backed custodial alternative
3. offer `password` as the developer-enabled non-custodial alternative
4. allow `password + email` without requiring SSO
5. prefer email OTP for default custodial UX, with TOTP optional
6. strongly consider scoping first release to threshold ECDSA only if that materially reduces complexity
7. do not require any `PIN + OPRF` layer in this recovery design

## Definition of Done

1. account creation clearly offers:
   - `passkey` non-custodial default
   - `otp_recovery` custodial alternative
   - `password` non-custodial alternative when developer-enabled
2. user can sign in with SSO and recover wallet unlock on a new device with OTP
3. `password + email` can operate without SSO
4. custodial nature of `otp_recovery` is explicit in product and internal documentation
5. OTP-guarded client secret is never persisted in plaintext at rest
6. server stores only server-sealed escrow blobs, not PIN-wrapped secrets
7. threshold ECDSA derivation is deterministic from the recovered client secret
8. threshold Ed25519 HSS derivation is deterministic from the recovered client secret when Ed25519 support is in scope
9. OTP challenges and recovery grants are rate-limited, expiring, and single-use
10. passkey, `password`, and `otp_recovery` coexist without duplicate legacy route or symbol pollution

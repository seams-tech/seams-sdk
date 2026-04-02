# SSO + PIN + OPRF Unlock Plan

Date updated: March 31, 2026

## Objective

Add a clean wallet unlock fallback next to passkeys:

1. `passkey` remains the primary unlock backend.
2. `pin_oprf` becomes the fallback unlock backend.
3. SSO remains app auth only. It does not directly derive threshold share material.
4. PIN unlock must bind freshness, origin, session, and action semantics in a WebAuthn-like way.

This plan intentionally does not treat `SSO + PIN` as a second login. The model is:

1. `SSO` identifies the user and mints the app session.
2. `PIN` unlocks wallet capability for that authenticated user.
3. `OPRF` turns a weak memorized secret into an online-gated deterministic root.

## Decision Summary

We will support two canonical wallet unlock backends:

1. `passkey`
   - existing WebAuthn + PRF flow
   - local deterministic secret source
2. `pin_oprf`
   - verified SSO app session required first
   - user enters a 4-digit PIN
   - client runs OPRF against relay
   - client derives deterministic root material from OPRF output
   - client derives:
     - threshold client share material
     - a dedicated unlock proof key

The unlock proof key signs a fresh relay challenge containing timestamps and session-bound context, similar in spirit to WebAuthn challenge binding.

## Why This Shape

`SSO + 4-digit PIN` alone is not strong enough for offline-derived wallet secrets.

The acceptable fallback shape is:

1. online-gated
2. session-bound
3. replay-resistant
4. deterministic across devices

`pin_oprf` provides those properties if and only if:

1. the app session is valid and fresh
2. OPRF evaluation is rate-limited and abuse-controlled
3. unlock verification checks challenge expiry, single use, and context binding

## Security Model

### Separation of concerns

1. SSO proves identity.
2. Relay issues `app_session_v1`.
3. Wallet unlock is separate from app auth.
4. Threshold signing remains dependent on client-derived secret material.

### What the 4-digit PIN is allowed to do

A 4-digit PIN is acceptable only as an online-gated unlock factor.

It is not acceptable as:

1. a standalone local seed
2. a direct replacement for WebAuthn PRF
3. a secret that must remain safe under offline attack without server participation

### Required controls

1. valid app session required before any OPRF evaluation
2. strict rate limiting per user, IP, device, org, and wallet
3. lockout after a small number of failures
4. step-up or fresh SSO requirement for PIN reset and sensitive changes
5. OPRF server key stored in hardened infrastructure
6. single-use expiring unlock challenges

## Canonical Terminology

Use these canonical names:

1. `passkey`
2. `pin_oprf`
3. `wallet unlock`
4. `unlock proof key`
5. `unlock challenge`
6. `threshold root`

Do not introduce duplicate legacy naming for:

1. secondary login
2. wallet password
3. fallback auth route aliases

## Derivation Model

### Identity binding

The deterministic root must be scoped to stable verified identity and wallet context:

```text
identity_binding =
  H("tatchi/pin-oprf/v1" || issuer || client_id || subject || wallet_id)
```

Recommended identity tuple:

1. `issuer`
2. `client_id` or equivalent audience-bound app identifier
3. `subject`
4. `wallet_id`

Do not derive from `email` as the primary stable identity input.

### OPRF input

```text
pin_input = H(identity_binding || pin)
oprf_output = OPRF(server_key_v1, pin_input)
threshold_root = HKDF(oprf_output, salt="tatchi/pin-oprf/root/v1", info=wallet_id)
```

### Threshold share branch

The threshold ECDSA share branch should mirror the current deterministic share model, but use the OPRF-derived root instead of `PRF.first`.

```text
client_share_seed =
  HKDF(threshold_root, salt="tatchi/pin-oprf/threshold-client-share/v1", info=user_id || derivation_path)
```

From that branch:

1. reduce to non-zero secp256k1 scalar
2. derive the client verifying share pubkey
3. keep the server-side threshold participant model unchanged where possible

### Unlock proof branch

Derive a separate branch for signed unlock challenges:

```text
unlock_auth_seed =
  HKDF(threshold_root, salt="tatchi/pin-oprf/unlock-auth/v1", info=wallet_id)
unlock_signing_key = DeterministicKey(unlock_auth_seed)
unlock_public_key = PublicKey(unlock_signing_key)
```

This key is not used for threshold signing. It exists only to prove fresh possession of the PIN-derived root during unlock.

## Challenge Binding Model

Do not bind timestamps into the threshold root derivation itself.

Bind timestamps and context into the unlock challenge that the client signs with `unlock_signing_key`.

Recommended challenge payload:

```json
{
  "challengeId": "ch_123",
  "nonce": "base64url-random",
  "issuedAt": "2026-03-31T12:00:00Z",
  "expiresAt": "2026-03-31T12:01:00Z",
  "action": "wallet_unlock",
  "origin": "https://app.example.com",
  "walletOrigin": "https://wallet.example.com",
  "walletId": "wallet_123",
  "sessionHash": "base64url-hash",
  "appSessionVersion": 7,
  "unlockBackend": "pin_oprf",
  "keyVersion": "pin-oprf-v1"
}
```

The server must verify:

1. app session is valid
2. challenge is unexpired
3. challenge has not been used before
4. challenge action matches the requested action
5. origin and wallet origin are expected
6. session hash matches the current session context
7. signature matches the enrolled `unlock_public_key`

This is the `pin_oprf` analogue to WebAuthn challenge freshness and context binding.

## Enrollment Model

PIN enrollment should happen only after SSO app session issuance.

### Enrollment steps

1. user signs in with SSO
2. relay issues `app_session_v1`
3. user chooses 4-digit PIN
4. client starts `pin_oprf` setup with relay
5. relay runs OPRF evaluation
6. client derives:
   - threshold client verifying share
   - unlock public key
7. client sends enrollment payload to relay
8. relay stores:
   - enrolled threshold client verifying share
   - enrolled unlock public key
   - key version metadata
   - failure counters and lockout state

### Enrollment data to persist

Server-side:

1. `unlockBackend = pin_oprf`
2. `unlockPublicKey`
3. `unlockKeyVersion`
4. `thresholdClientVerifyingShareB64u`
5. `createdAtMs`
6. `pinFailureCount`
7. `pinLockedUntilMs`

Client-side:

1. no PIN persistence
2. no threshold root persistence
3. no plaintext OPRF result persistence

## Unlock Model

### Unlock flow

1. app already has valid SSO-backed app session
2. client requests unlock challenge for `pin_oprf`
3. user enters PIN
4. client runs OPRF evaluation under the current app session
5. client derives:
   - threshold client share
   - unlock signing key
6. client signs the unlock challenge
7. client submits signed unlock proof
8. relay verifies:
   - challenge validity
   - signature against enrolled unlock public key
   - derived threshold client verifying share matches enrollment
9. relay marks wallet unlocked and continues warm session bootstrap

### Warm session bootstrap result

Once unlock succeeds, warm session behavior should align with existing threshold session behavior:

1. session JWT/cookie behavior remains unchanged
2. active warm signing session rules remain unchanged
3. threshold ECDSA and Ed25519 orchestration should consume the derived client share seed, not expect WebAuthn PRF

## Proposed API Shape

Keep the canonical route planes:

1. session plane: existing `session/*`
2. wallet plane: existing `wallet/*`

Do not add new auth-specific aliases for PIN fallback.

### Phase 1 API shape

Add backend-aware wallet unlock/setup routes:

1. `POST /wallet/unlock/challenge`
2. `POST /wallet/unlock/verify`
3. `POST /wallet/pin/setup/challenge`
4. `POST /wallet/pin/setup/verify`

### Example `POST /wallet/unlock/challenge`

Request:

```json
{
  "unlockBackend": "pin_oprf",
  "walletId": "wallet_123"
}
```

Response:

```json
{
  "ok": true,
  "challenge": {
    "challengeId": "ch_123",
    "nonce": "base64url-random",
    "issuedAt": "2026-03-31T12:00:00Z",
    "expiresAt": "2026-03-31T12:01:00Z",
    "action": "wallet_unlock",
    "origin": "https://app.example.com",
    "walletOrigin": "https://wallet.example.com",
    "walletId": "wallet_123",
    "sessionHash": "base64url-hash",
    "unlockBackend": "pin_oprf",
    "keyVersion": "pin-oprf-v1"
  }
}
```

### Example `POST /wallet/unlock/verify`

Request:

```json
{
  "unlockBackend": "pin_oprf",
  "walletId": "wallet_123",
  "challengeId": "ch_123",
  "oprf": {
    "clientData": "..."
  },
  "unlockProof": {
    "publicKey": "base64url",
    "signature": "base64url"
  },
  "threshold": {
    "clientVerifyingShareB64u": "base64url"
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

Implementation note:

The final OPRF message shape depends on the chosen OPRF suite and whether blinding/unblinding is fully client-side. The canonical requirement is not the exact wire format. The canonical requirement is:

1. no raw PIN leaves the client
2. relay evaluates under authenticated, rate-limited context
3. client derives final root locally

## Product Rules

### Positioning

1. `passkey` is the primary unlock backend
2. `pin_oprf` is the clean fallback
3. `pin_oprf` is weaker than passkeys and should be described accordingly in internal docs and risk reviews

### Sensitive actions

Require stronger auth than `pin_oprf` alone for:

1. PIN reset
2. PIN disable
3. passkey removal
4. key export
5. recovery method changes
6. high-risk admin actions

### Reset flow

PIN reset should require:

1. fresh SSO session
2. one stronger factor, preferably passkey if enrolled
3. explicit invalidation of prior PIN enrollment state

## Observability

Add structured events for:

1. `wallet.pin.setup.started`
2. `wallet.pin.setup.completed`
3. `wallet.pin.unlock.challenge_issued`
4. `wallet.pin.unlock.succeeded`
5. `wallet.pin.unlock.failed`
6. `wallet.pin.locked_out`
7. `wallet.pin.reset`

Event payloads should include:

1. `orgId`
2. `userId`
3. `walletId`
4. `unlockBackend`
5. `keyVersion`
6. `reason`
7. `lockoutUntilMs` when relevant

Do not log:

1. PIN
2. unhashed OPRF input
3. threshold root
4. unlock private key

## Rollout Plan

### Phase 0 — Spec lock

1. freeze canonical naming: `passkey` and `pin_oprf`
2. freeze route vocabulary under `wallet/*`
3. freeze identity binding tuple: `issuer + client_id + subject + wallet_id`
4. choose OPRF suite and key management model
5. define lockout, retry, and step-up policy

### Phase 1 — Server OPRF core

1. add OPRF service abstraction
2. add authenticated evaluation path bound to app session
3. add rate-limit and lockout primitives
4. add enrollment record store for `pin_oprf`
5. add audit and observability hooks

### Phase 2 — Client derivation library

1. add client OPRF helper
2. add deterministic root derivation helper
3. add threshold client share derivation branch from threshold root
4. add unlock proof key derivation branch
5. keep passkey and `pin_oprf` paths explicit rather than hidden behind legacy aliases

### Phase 3 — Wallet unlock routes

1. extend `POST /wallet/unlock/challenge` for backend-aware challenge issuance
2. extend `POST /wallet/unlock/verify` for `pin_oprf` verification
3. add dedicated PIN enrollment setup routes
4. keep session issuance and wallet unlock semantics separate

### Phase 4 — Threshold bootstrap integration

1. add a threshold root input path for ECDSA and Ed25519 warm-session bootstrap
2. preserve current passkey PRF flows as the `passkey` backend
3. refactor threshold bootstrap code so secret-source backends are explicit:
   - `passkey_prf`
   - `pin_oprf`
4. eliminate any passkey-only assumptions from shared threshold orchestration code

### Phase 5 — UX and recovery

1. add setup UI: create PIN
2. add unlock UI: enter PIN
3. add lockout and cooldown UI
4. add reset flow with stronger-factor gating
5. document that PIN unlock is convenience fallback, not the primary strongest path

### Phase 6 — Tests

1. unit tests for deterministic derivation stability
2. unit tests for challenge expiry and replay rejection
3. unit tests for lockout and cooldown logic
4. integration tests for:
   - SSO session + PIN enrollment
   - SSO session + PIN unlock
   - cross-device deterministic re-derivation
   - wrong PIN failure counting
   - challenge replay rejection
   - stale session rejection
5. parity coverage for Express and Cloudflare adapters

## Open Questions

1. Should `pin_oprf` support same-tab sealed refresh analogous to current passkey session persistence, or should refresh always require PIN re-entry?
2. Should the unlock proof key use secp256k1 for implementation reuse, or Ed25519 for stricter domain separation?
3. Should threshold Ed25519 and ECDSA both derive from the same threshold root in the first release, or should release one scope only ECDSA?
4. What lockout thresholds are acceptable for product UX versus abuse resistance?
5. Should PIN enrollment be allowed when passkey is not enrolled, or should passkey remain mandatory for initial wallet creation?

## Recommended First Release Scope

1. keep passkeys as the default primary unlock backend
2. add `pin_oprf` as opt-in fallback
3. scope first release to threshold ECDSA only if that materially reduces complexity
4. require fresh SSO session for setup and reset
5. do not support offline PIN-only unlock in any form

## Definition of Done

1. user can sign in with SSO and unlock with `pin_oprf`
2. unlock uses expiring signed challenges with timestamp and session binding
3. threshold client share derivation is deterministic across devices for the same SSO identity and PIN
4. wrong PIN attempts are rate-limited and lock out correctly
5. passkey and `pin_oprf` coexist without duplicate legacy route or symbol pollution
6. shared threshold orchestration no longer assumes WebAuthn PRF as the only secret source

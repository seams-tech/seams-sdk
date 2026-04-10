# SSO + PIN + OPRF Unlock Plan

Date updated: April 3, 2026

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
     - threshold signing material
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

## SDK API Rescan Snapshot

The current SDK and relay surface is not fully generic today.

### Stable public threshold exports

The stable exports in `client/src/threshold.ts` currently expose:

1. `keygenEcdsa`
2. `connectEd25519Session`
3. `connectEcdsaSession`
4. `authorizeEcdsaWithSession`
5. ECDSA presign/sign helpers

Important current constraints:

1. there is no stable public `keygenEd25519`
2. there is no stable public secret-source abstraction that can swap `passkey_prf` for `pin_oprf`
3. `connectEd25519Session` is still WebAuthn/passkey-oriented in shape

That means the first `pin_oprf` implementation seam should be internal lifecycle/runtime code, not a forced fit into the current stable public threshold API.

### Wallet unlock routes today

Today, both Express and Cloudflare wire:

1. `POST /wallet/unlock/challenge` to WebAuthn challenge issuance
2. `POST /wallet/unlock/verify` to WebAuthn assertion verification

Those routes are passkey-specific today. They are not yet backend-neutral wallet unlock routes.

### NEAR threshold shape today

NEAR threshold signing now uses the Ed25519 HSS Option A flow rather than a single derived client share.

The active NEAR client path derives:

1. `contextBindingB64u`
2. `yClientB64u`
3. `tauClientB64u`

and then runs the HSS ceremony to reconstruct:

1. `xClientBaseB64u`
2. canonical Ed25519 public key material
3. canonical seed export material when needed

So this plan must distinguish:

1. threshold ECDSA client-share derivation
2. threshold Ed25519 HSS client-input derivation

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
7. `threshold ECDSA client share`
8. `threshold Ed25519 HSS client inputs`
9. `threshold Ed25519 HSS client base`

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

### Threshold ECDSA branch

The threshold ECDSA branch should mirror the current deterministic share model, but use the OPRF-derived root instead of `PRF.first`.

```text
ecdsa_client_share_seed =
  HKDF(threshold_root, salt="tatchi/pin-oprf/threshold-client-share/v1", info=user_id || derivation_path)
```

From that branch:

1. reduce to non-zero secp256k1 scalar
2. derive the client verifying share pubkey
3. keep the server-side threshold participant model unchanged where possible

### Threshold Ed25519 HSS branch

NEAR threshold signing now needs a distinct branch.

Instead of deriving a single client verifying share, the client must deterministically derive HSS client inputs from `threshold_root` and then run the existing HSS prepare/finalize seam.

```text
ed25519_hss_input_material =
  HKDF(threshold_root, salt="tatchi/pin-oprf/threshold-ed25519-hss/v1", info=org_id || near_account_id || key_purpose || key_version || participant_ids || derivation_version)
```

That branch must produce deterministic analogues of:

1. `contextBindingB64u`
2. `yClientB64u`
3. `tauClientB64u`

Those are then consumed by the existing HSS ceremony to reconstruct:

1. `xClientBaseB64u`
2. canonical public key material
3. canonical seed export material where applicable

The important implication is:

1. ECDSA can continue to think in terms of “client share”
2. NEAR Ed25519 HSS must think in terms of “client inputs -> HSS ceremony -> client base”
3. the shared secret-source abstraction must support both shapes explicitly

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
   - threshold ECDSA client verifying share when ECDSA threshold is enabled
   - threshold Ed25519 HSS client inputs when NEAR threshold is enabled
   - unlock public key
7. client sends enrollment payload to relay
8. relay stores:
   - enrolled threshold ECDSA client verifying share when ECDSA threshold is enabled
   - NEAR HSS canonical context and registration material when NEAR threshold is enabled
   - enrolled unlock public key
   - key version metadata
   - failure counters and lockout state

### Enrollment data to persist

Server-side:

1. `unlockBackend = pin_oprf`
2. `unlockPublicKey`
3. `unlockKeyVersion`
4. `thresholdEcdsaClientVerifyingShareB64u` when applicable
5. threshold Ed25519 HSS canonical context when applicable:
   - `orgId`
   - `nearAccountId`
   - `keyPurpose`
   - `keyVersion`
   - `participantIds`
   - `derivationVersion`
6. threshold Ed25519 server-side registration material when applicable
7. `createdAtMs`
8. `pinFailureCount`
9. `pinLockedUntilMs`

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
   - threshold ECDSA client share when ECDSA threshold is enabled
   - threshold Ed25519 HSS client inputs when NEAR threshold is enabled
   - unlock signing key
6. client signs the unlock challenge
7. client submits signed unlock proof
8. relay verifies:
   - challenge validity
   - signature against enrolled unlock public key
   - derived threshold ECDSA client verifying share matches enrollment when applicable
   - derived threshold Ed25519 HSS client inputs match canonical context-binding requirements when applicable
9. relay marks wallet unlocked and continues warm session bootstrap

### Warm session bootstrap result

Once unlock succeeds, warm session behavior should align with existing threshold session behavior:

1. session JWT/cookie behavior remains unchanged
2. active warm signing session rules remain unchanged
3. threshold ECDSA orchestration should consume the derived ECDSA client-share branch, not expect WebAuthn PRF
4. threshold Ed25519 orchestration should consume the derived HSS client-input branch and continue through the existing HSS prepare/finalize seam
5. cached artifacts remain backend-specific:
   - ECDSA: client verifying share and warm-session state
   - Ed25519 HSS: `xClientBaseB64u` and canonical HSS session state

## Proposed API Shape

Keep the canonical route planes:

1. session plane: existing `session/*`
2. wallet plane: existing `wallet/*`

Do not add new auth-specific aliases for PIN fallback.

### Current route reality

Today, `wallet/unlock/*` is a passkey API surface, not a backend-neutral wallet unlock API surface.

That means the first PIN release has two possible shapes:

1. breaking change: generalize `POST /wallet/unlock/challenge` and `POST /wallet/unlock/verify`
2. additive shape: introduce `wallet/pin/*` setup and unlock routes, then unify later

Because the current handlers are explicitly WebAuthn-bound, this plan should not assume the route surface is already generic.

### Target API shape

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
  "walletId": "wallet_123",
  "sessionKind": "jwt"
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

Implementation note:

The final OPRF message shape depends on the chosen OPRF suite and whether blinding/unblinding is fully client-side. The canonical requirement is not the exact wire format. The canonical requirement is:

1. no raw PIN leaves the client
2. relay evaluates under authenticated, rate-limited context
3. client derives final root locally

### SDK integration guidance

Do not initially force `pin_oprf` into the current stable public `client/src/threshold.ts` surface.

Recommended implementation order:

1. add internal secret-source support in `SigningEngine` and threshold lifecycle code
2. add backend-aware wallet unlock plumbing
3. add public stable API only after the internal seam is proven

This avoids freezing a public API that still reflects passkey-specific assumptions.

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
3. add threshold ECDSA client-share derivation branch from threshold root
4. add threshold Ed25519 HSS client-input derivation branch from threshold root
5. add unlock proof key derivation branch
6. keep passkey and `pin_oprf` paths explicit rather than hidden behind legacy aliases

### Phase 3 — Wallet unlock routes

1. choose whether to generalize `wallet/unlock/*` or add `wallet/pin/*` first
2. implement `pin_oprf` challenge issuance
3. implement `pin_oprf` verification
4. add dedicated PIN enrollment setup routes
5. keep session issuance and wallet unlock semantics separate

### Phase 4 — Threshold bootstrap integration

1. add a threshold root input path for ECDSA and Ed25519 warm-session bootstrap
2. preserve current passkey PRF flows as the `passkey` backend
3. refactor threshold bootstrap code so secret-source backends are explicit:
   - `passkey_prf`
   - `pin_oprf`
4. route ECDSA through deterministic client-share derivation
5. route NEAR Ed25519 through deterministic HSS client-input derivation plus the existing HSS ceremony seams
6. eliminate any passkey-only assumptions from shared threshold orchestration code

### Phase 4.5 — Public API decision

1. review whether a new stable public helper is needed in `client/src/threshold.ts`
2. avoid mutating `connectEd25519Session` into a multi-backend kitchen-sink API unless the secret-source abstraction is clean
3. prefer explicit backend-aware APIs over hidden optional flags

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
   - threshold ECDSA bootstrap from `pin_oprf` root
   - threshold Ed25519 HSS reconstruction from `pin_oprf` root
5. parity coverage for Express and Cloudflare adapters

## Open Questions

1. Should `pin_oprf` support same-tab sealed refresh analogous to current passkey session persistence, or should refresh always require PIN re-entry?
2. Should the unlock proof key use secp256k1 for implementation reuse, or Ed25519 for stricter domain separation?
3. Should the first release cover both ECDSA and Ed25519 HSS, or should it intentionally ship ECDSA-only first and add Ed25519 HSS after the secret-source seam is stable?
4. What lockout thresholds are acceptable for product UX versus abuse resistance?
5. Should PIN enrollment be allowed when passkey is not enrolled, or should passkey remain mandatory for initial wallet creation?
6. Should we generalize `wallet/unlock/*` immediately, or ship `wallet/pin/*` first because the existing handlers are explicitly WebAuthn-bound?

## Recommended First Release Scope

1. keep passkeys as the default primary unlock backend
2. add `pin_oprf` as opt-in fallback
3. strongly consider scoping first release to threshold ECDSA only if that materially reduces complexity, because Ed25519 HSS requires a different client-derived artifact shape than ECDSA
4. require fresh SSO session for setup and reset
5. do not support offline PIN-only unlock in any form

## Definition of Done

1. user can sign in with SSO and unlock with `pin_oprf`
2. unlock uses expiring signed challenges with timestamp and session binding
3. threshold ECDSA client-share derivation is deterministic across devices for the same SSO identity and PIN
4. threshold Ed25519 HSS client-input derivation is deterministic across devices for the same SSO identity and PIN when Ed25519 support is in scope
5. wrong PIN attempts are rate-limited and lock out correctly
6. passkey and `pin_oprf` coexist without duplicate legacy route or symbol pollution
7. shared threshold orchestration no longer assumes WebAuthn PRF as the only secret source

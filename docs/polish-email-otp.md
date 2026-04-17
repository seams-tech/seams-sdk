# Polish Email OTP Wallet Flows

## Purpose

Polish the wallet flows so auth prompts match the account's active signing method:

1. Passkey-created accounts use WebAuthn/Touch ID for login, transaction confirmation, and sensitive operations.
2. Google SSO + Email OTP accounts use Google SSO for app authentication and a 6-digit Email OTP for wallet unlock/signing authorization.
3. Email OTP accounts must never fall through to a WebAuthn prompt unless the account actually has a passkey key and the operation is intentionally requiring passkey step-up.
4. Passkey accounts must not be silently downgraded to Email OTP unless the account explicitly added Email OTP as a separate key in the future add-key flow.

This plan is only for polishing the core wallet behavior. OTP-to-passkey add-key flows remain out of scope until the core Email OTP system is stable.

## Current Model

### Account Types

Passkey account:

1. user created or unlocked the wallet with a passkey
2. WebAuthn PRF output derives client-side threshold material
3. Touch ID/WebAuthn is the normal fresh-auth mechanism
4. key export can use passkey PRF-gated export paths

Email OTP account:

1. Google SSO authenticates the app/user session
2. Email OTP authorizes server-assisted `shamir3pass` unseal
3. the Email OTP worker recovers `S`, derives signing material, and owns secret-bearing runtime state
4. `WarmSessionManager` applies `session` or `per_operation` retention
5. Email OTP is lower assurance than passkey and must be presented that way in UI copy

### Email OTP Policies

`email_otp_auth_policy = session`:

1. OTP is entered once during login/unlock
2. recovered signing capability stays in memory until TTL, revocation, logout, or invalidation
3. ordinary signing should not prompt again
4. transaction UI should not show a passkey halo or WebAuthn copy

`email_otp_auth_policy = per_operation`:

1. each signing operation requires a fresh Email OTP
2. the transaction confirmer must show a 6-digit OTP input
3. the server sends/logs a transaction-scoped OTP challenge
4. worker-owned signing material is discarded immediately after the operation

## Flow Matrix

### Login And Wallet Unlock

| Account state | Login action | Required prompt | Expected result |
| --- | --- | --- | --- |
| Passkey account | Continue with Passkey | WebAuthn/Touch ID | wallet session active |
| Email OTP account | Sign in with Google SSO | Google SSO, then 6-digit Email OTP | wallet session active |
| Email OTP account, session policy | Submit OTP once | Email OTP input in `PasskeyAuthMenu` | warm session cached in memory |
| Email OTP account, per-operation policy | Submit OTP once for unlock if required by product | Email OTP input in `PasskeyAuthMenu` | no reusable signing capability beyond configured single-use scope |
| Unknown Google account | Sign in with Google SSO in login mode | no OTP until account mapping exists | show register-with-Google path |

### Transaction Signing

| Chain/signing path | Passkey account | Email OTP session policy | Email OTP per-operation policy |
| --- | --- | --- | --- |
| NEAR Ed25519 threshold | WebAuthn only when no valid warm session exists | use active Email OTP warm session, no WebAuthn prompt | show Email OTP input in tx confirmer, sign once, discard |
| EVM secp256k1 threshold | WebAuthn/Touch ID when fresh passkey auth is required | use active Email OTP warm session, no WebAuthn prompt | show Email OTP input in tx confirmer, sign once, discard |
| Tempo secp256k1 threshold | WebAuthn/Touch ID when fresh passkey auth is required | use active Email OTP warm session, no WebAuthn prompt | show Email OTP input in tx confirmer, sign once, discard |

### Key Export

Key export is a sensitive operation.

Default security posture:

1. passkey accounts may export through WebAuthn/Touch ID + PRF-gated export flows
2. Email OTP-only accounts should fail closed with clear copy: key export requires a stronger passkey-authenticated account
3. the UI must not show a WebAuthn prompt for Email OTP-only accounts, because that is confusing and cannot succeed

If product later enables Email OTP key export by explicit policy:

1. require a fresh `per_operation` Email OTP challenge for each export
2. require server-side policy approval for `export_key`
3. use export-specific challenge binding and audit events
4. show a 6-digit Email OTP input, never a passkey prompt
5. discard all recovered secret/export material immediately after the export viewer closes

Do not implement policy-gated Email OTP key export until the product/security decision is explicit. The immediate polish target is to avoid incorrect WebAuthn prompts and fail closed with accurate copy.

## Architecture Boundary

Server is authoritative for:

1. OTP challenge TTL, counters, lockouts, and revocation
2. app-session and wallet-session authorization
3. operation policy: `session`, `per_operation`, passkey step-up, and blocked sensitive actions
4. audit events for OTP challenge issuance, verification, signing, export attempts, and denial

Client is authoritative for:

1. in-memory warm-session lifecycle
2. displaying the correct auth prompt for the active method
3. clearing worker-owned warm material on logout, expiry, operation completion, and invalidation
4. treating server policy as upper bounds, not optional hints

Workers are authoritative for:

1. Email OTP secret-bearing unseal and derivation
2. worker-owned ECDSA and Ed25519 Email OTP signing material
3. single-use discard and practical zeroization
4. avoiding recovered `S` or Email OTP-derived shares crossing into JS main thread

## Implementation Plan

### Phase 1: Account Auth-Mode Source Of Truth

Goal: every flow can decide whether the current wallet session is passkey-backed or Email OTP-backed without guessing from UI state.

Tasks:

1. [ ] Add or verify a canonical `authMethod`/`accountAuthMethod` field in wallet session/readiness metadata with values such as `passkey` and `email_otp`.
2. [ ] Ensure direct SDK mode and wallet-iframe mode expose the same auth-mode metadata.
3. [ ] Persist only nonsecret auth-mode metadata in wallet-origin storage.
4. [ ] Ensure Email OTP ECDSA and Ed25519 sessions carry retention metadata: `session` or `single_use`.
5. [ ] Add tests proving login state refresh preserves auth mode after page reload and iframe reconnect.
6. [ ] Remove any code path that infers Email OTP solely from account-id format or stale UI mode.

### Phase 2: Login And Wallet Unlock Polish

Goal: Email OTP login should complete wallet unlock without blank screens, stale passkey account ids, or WebAuthn fallback.

Tasks:

1. [ ] Audit `PasskeyAuthMenu` state transitions for register/login mode, remembered account id, remembered auth method, and Google SSO enrollment-not-found handling.
2. [ ] Ensure Google SSO login mode reuses persisted Google-subject-to-wallet mapping and never creates a timestamped wallet id.
3. [ ] Keep timestamped Google SSO wallet ids only behind an explicit dev/test setting.
4. [ ] After successful Email OTP submit, refresh wallet session state and require the session to be UI-ready before transitioning out of the OTP screen.
5. [ ] Ensure wallet-iframe mode performs Google SSO session exchange and Email OTP login through wallet-origin SDK calls.
6. [ ] Ensure app-origin IndexedDB disabled mode still completes Email OTP login/unlock.
7. [ ] Add regression coverage for Email OTP login success updating React SDK login state and demo carousel routing.
8. [ ] Add copy that says: "Google signs you in. A 6-digit email code unlocks wallet signing for this session."

### Phase 3: Transaction Confirmation Auth Routing

Goal: the transaction confirmer renders the correct prompt for the active auth method.

Tasks:

1. [ ] Define a single `SigningAuthMode` surface for transaction confirmation: `webauthn`, `emailOtp`, and `warmSession`.
2. [ ] Ensure passkey transactions use `webauthn` only when fresh WebAuthn auth is needed.
3. [ ] Ensure Email OTP `session` transactions use `warmSession` or an Email OTP session presentation, never WebAuthn copy.
4. [ ] Ensure Email OTP `per_operation` transactions request an Email OTP challenge before user confirmation.
5. [ ] Ensure the Tx Confirmer modal/drawer shows a 6-digit OTP input for `emailOtp`.
6. [ ] Ensure entered OTP is bound to the preissued challenge id and operation being confirmed.
7. [ ] Ensure the server logs/sends the dev OTP for local testing through the normal Email OTP challenge route.
8. [ ] Ensure operation cancellation invalidates or abandons unused per-operation challenges cleanly.

### Phase 4: ECDSA Signing Polish

Goal: EVM and Tempo threshold signing behave correctly under both passkey and Email OTP accounts.

Tasks:

1. [ ] Verify EVM `per_operation` signing prompts for Email OTP in the Tx Confirmer, signs once, and rejects a second sign until a fresh OTP completes.
2. [ ] Verify Tempo `per_operation` signing has the same behavior.
3. [ ] Verify EVM and Tempo `session` signing does not prompt for WebAuthn after Email OTP login.
4. [ ] Ensure wallet-iframe EVM and Tempo signing use wallet-origin Email OTP challenge and bootstrap calls.
5. [ ] Ensure direct SDK EVM and Tempo signing use the same policy model as wallet-iframe mode.
6. [ ] Ensure Email OTP-derived ECDSA signing material remains behind worker-owned opaque handles.
7. [ ] Add tests for cancellation, invalid OTP, expired OTP, and retry after expired challenge.
8. [ ] Keep the existing signing-root binding issue separate: ECDSA persisted-key replay must validate `signingRootId` and `signingRootVersion` before release.

### Phase 5: Ed25519 Signing Polish

Goal: NEAR threshold Ed25519 signing follows the same auth-mode model as ECDSA.

Tasks:

1. [ ] Audit NEAR transaction signing for Email OTP account sessions.
2. [ ] Ensure Email OTP `session` mode can sign NEAR transactions using the active worker-owned warm capability.
3. [ ] Ensure Email OTP `per_operation` mode shows a 6-digit OTP input in the NEAR transaction confirmer.
4. [ ] Ensure passkey NEAR signing still uses WebAuthn/Touch ID when fresh passkey auth is required.
5. [ ] Ensure missing/expired Email OTP Ed25519 warm sessions produce a clear "verify Email OTP again" error, not "passkey required."
6. [ ] Add focused NEAR Ed25519 tests for Email OTP session signing and per-operation signing.
7. [ ] Add wallet-iframe coverage for NEAR Ed25519 Email OTP signing with app-origin IndexedDB disabled.

### Phase 6: Key Export Polish

Goal: export flows do not show impossible or misleading prompts.

Tasks:

1. [ ] Add auth-mode detection before `exportKeypairWithUI` chooses an export path.
2. [ ] For passkey accounts, keep existing WebAuthn/Touch ID export authorization.
3. [ ] For Email OTP-only accounts, fail closed by default with clear copy: "Key export requires a passkey-authenticated account."
4. [ ] Ensure Email OTP-only ECDSA export does not call `requestThresholdEcdsaExportAuthorization`, because that currently requires WebAuthn PRF material.
5. [ ] Ensure Email OTP-only Ed25519 export does not call `requestNearEd25519ExportAuthorization`, because that currently requires WebAuthn PRF material.
6. [ ] Add tests proving Email OTP-only export attempts do not open WebAuthn prompts.
7. [ ] Add tests proving passkey export flows still open WebAuthn and still export Ed25519/ECDSA when authorized.
8. [ ] If Email OTP export is later approved, add a separate policy-gated implementation that requires fresh `per_operation` Email OTP and server approval for `export_key`.

### Phase 7: UI Copy And Product Clarity

Goal: users can tell which auth method is active and why a prompt appears.

Tasks:

1. [ ] In transaction confirm UI, label passkey prompts as "Confirm with Passkey."
2. [ ] In transaction confirm UI, label Email OTP prompts as "Enter email code to sign."
3. [ ] In Email OTP session-mode transaction UI, avoid passkey halo visuals if no WebAuthn ceremony will run.
4. [ ] In AccountMenu export UI, show Email OTP export restrictions before opening the export drawer.
5. [ ] In PasskeyAuthMenu, avoid prefilled passkey account ids confusing Google SSO registration.
6. [ ] Add explicit lower-assurance copy for Email OTP: "Passkey is recommended for stronger security."
7. [ ] Ensure errors distinguish "fresh Email OTP required", "passkey step-up required", and "operation blocked by policy."

### Phase 8: Release-Gate Tests

Goal: lock the auth-routing behavior with tests before adding new account-upgrade features.

Tasks:

1. [ ] Unit test auth-mode resolution for wallet session metadata.
2. [ ] Unit test Tx Confirmer rendering for `webauthn`, `emailOtp`, and `warmSession`.
3. [ ] Unit test EVM Email OTP `per_operation` challenge, submit, sign, discard, and replay rejection.
4. [ ] Unit test Tempo Email OTP `per_operation` challenge, submit, sign, discard, and replay rejection.
5. [ ] Unit test NEAR Ed25519 Email OTP session and per-operation signing paths.
6. [ ] Unit test Email OTP-only key export fail-closed behavior.
7. [ ] E2E smoke test Google SSO + Email OTP registration, login, NEAR sign, EVM sign, Tempo sign.
8. [ ] E2E smoke test passkey registration, login, NEAR sign, EVM sign, Tempo sign, Ed25519 export, ECDSA export.
9. [ ] E2E smoke test wallet-iframe mode with app-origin IndexedDB disabled.
10. [ ] Add regression assertions that Email OTP flows do not display WebAuthn prompts unless passkey step-up is explicitly required.

## Acceptance Criteria

1. Passkey accounts continue to use WebAuthn/Touch ID for fresh auth.
2. Email OTP login and unlock never ask for WebAuthn.
3. Email OTP `session` signing does not ask for WebAuthn after login.
4. Email OTP `per_operation` signing displays a 6-digit OTP input in the Tx Confirmer.
5. Email OTP `per_operation` signing consumes the single-use capability and requires a fresh OTP for the next operation.
6. Email OTP-only key export does not open a WebAuthn prompt and fails closed unless product explicitly enables policy-gated Email OTP export.
7. Wallet-iframe mode and direct SDK mode behave the same at the public API boundary.
8. The app origin never receives recovered `S` or Email OTP-derived signing shares.
9. Error messages identify the required auth method instead of using generic "session not ready" or "passkey required" messages.
10. The release-gate test matrix covers Passkey and Email OTP across login/unlock, signing, and export decisions.


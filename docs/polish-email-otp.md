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
2. Email OTP-only accounts may export Ed25519 and ECDSA keys only after a fresh `per_operation` Email OTP step-up
3. server policy must explicitly allow the `export_key` operation for the current account, project, wallet, and session
4. export-specific challenges must bind `accountId`, `walletId`, curve, key id, operation, challenge id, and current app-session context
5. the UI must show a 6-digit Email OTP input for Email OTP-only accounts, never a WebAuthn prompt that cannot succeed
6. recovered secret/export material must be discarded immediately after the export viewer closes

Mixed passkey plus Email OTP accounts default to passkey for sensitive actions. The UI may offer a small "use one-time password" text link when project policy allows Email OTP as an alternate step-up method.

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

1. [x] Add or verify a canonical `authMethod` field in wallet session/readiness metadata with values `passkey` and `email_otp`.
2. [x] Ensure direct SDK mode and wallet-iframe mode expose the same auth-mode metadata.
3. [x] Persist only nonsecret auth-mode metadata in wallet-origin storage.
4. [x] Ensure Email OTP ECDSA and Ed25519 sessions carry retention metadata: `session` or `single_use`.
5. [x] Add tests proving login state refresh preserves auth mode after page reload and iframe reconnect.
6. [x] Remove any code path that infers Email OTP solely from account-id format or stale UI mode.

### Phase 2: Login And Wallet Unlock Polish

Goal: Email OTP login should complete wallet unlock without blank screens, stale passkey account ids, or WebAuthn fallback.

Tasks:

1. [x] Audit `PasskeyAuthMenu` state transitions for register/login mode, remembered account id, remembered auth method, and Google SSO enrollment-not-found handling.
2. [x] Ensure Google SSO login mode reuses persisted Google-subject-to-wallet mapping and never creates a timestamped wallet id.
3. [x] Ensure Google SSO registration creates a valid relayer subaccount instead of a top-level `*.testnet` account.
4. [x] Treat stale Google mappings to old top-level `*.testnet` accounts as not enrolled for login, and move them to relayer subaccounts during re-registration.
5. [x] Keep timestamped Google SSO wallet ids only behind an explicit dev/test setting.
6. [x] After successful Email OTP submit, refresh wallet session state and require the session to be UI-ready before transitioning out of the OTP screen.
7. [x] Ensure wallet-iframe mode performs Google SSO session exchange and Email OTP login through wallet-origin SDK calls.
8. [x] Ensure app-origin IndexedDB disabled mode still completes Email OTP login/unlock.
9. [x] Add regression coverage for Email OTP login success updating React SDK login state and demo carousel routing.
10. [x] Add copy that says: "Google signs you in. A 6-digit email code unlocks wallet signing for this session."

Audit result:

1. `PasskeyAuthMenu` state does not decide Email OTP vs passkey from account-id format. It delegates Google SSO to the social handler and receives an OTP prompt when required.
2. Recent account prefill still derives the displayed username from the stored NEAR account id prefix. That is display/input prefill only, not auth routing.
3. Google SSO registration now defaults to a stable relayer subaccount id. Timestamped Google wallet ids are gated behind `EMAIL_OTP_GOOGLE_REGISTRATION_WALLET_ID_POLICY=timestamped_dev` for collision testing only.

### Phase 3: Transaction Confirmation Auth Routing

Goal: the transaction confirmer renders the correct prompt for the active auth method.

Tasks:

1. [x] Define a single `SigningAuthMode` surface for transaction confirmation: `webauthn`, `emailOtp`, and `warmSession`.
2. [x] Ensure passkey transactions use `webauthn` only when fresh WebAuthn auth is needed.
3. [x] Ensure Email OTP `session` transactions use `warmSession` or an Email OTP session presentation, never WebAuthn copy.
4. [x] Ensure Email OTP `per_operation` transactions request an Email OTP challenge before user confirmation.
5. [x] Ensure the Tx Confirmer modal/drawer shows a 6-digit OTP input for `emailOtp`.
6. [x] Ensure entered OTP is bound to the preissued challenge id and operation being confirmed.
7. [x] Ensure the server logs/sends the dev OTP for local testing through the normal Email OTP challenge route.
8. [x] Ensure operation cancellation invalidates or abandons unused per-operation challenges cleanly.

### Phase 4: ECDSA Signing Polish

Goal: EVM and Tempo threshold signing behave correctly under both passkey and Email OTP accounts.

Tasks:

1. [x] Verify EVM `per_operation` signing prompts for Email OTP in the Tx Confirmer, signs once, and rejects a second sign until a fresh OTP completes.
2. [x] Verify Tempo `per_operation` signing has the same behavior.
3. [x] Verify EVM and Tempo `session` signing does not prompt for WebAuthn after Email OTP login.
4. [x] Ensure wallet-iframe EVM and Tempo signing use wallet-origin Email OTP challenge and bootstrap calls.
5. [x] Ensure direct SDK EVM and Tempo signing use the same policy model as wallet-iframe mode.
6. [x] Ensure Email OTP-derived ECDSA signing material remains behind worker-owned opaque handles.
7. [x] Add tests for cancellation, invalid OTP, expired OTP, and retry after expired challenge.
8. [x] Keep the existing signing-root binding issue separate: ECDSA persisted-key replay must validate `signingRootId` and `signingRootVersion` before release.

### Phase 5: Ed25519 Signing Polish

Goal: NEAR threshold Ed25519 signing follows the same auth-mode model as ECDSA.

Tasks:

1. [x] Audit NEAR transaction signing for Email OTP account sessions.
2. [x] Ensure Email OTP `session` mode can sign NEAR transactions using the active worker-owned warm capability.
3. [x] Ensure Email OTP `per_operation` mode shows a 6-digit OTP input in the NEAR transaction confirmer.
4. [x] Ensure passkey NEAR signing still uses WebAuthn/Touch ID when fresh passkey auth is required.
5. [x] Ensure missing/expired Email OTP Ed25519 warm sessions produce a clear "verify Email OTP again" error, not "passkey required."
6. [x] Add focused NEAR Ed25519 tests for Email OTP session signing and per-operation signing.
7. [x] Add wallet-iframe coverage for NEAR Ed25519 Email OTP signing with app-origin IndexedDB disabled.

### Phase 6: Key Export Polish

Goal: export flows do not show impossible or misleading prompts.

Coordination note:

1. `docs/refactor-signer-slot.md` Phase 14/15 is complete for the Email OTP export-lane implementation.
2. This plan now owns remaining Email OTP release polish, validation, route cleanup, and E2E coverage.
3. Avoid reopening signer-slot lifecycle design unless a new bug proves the account auth-mode resolver or signer metadata model is incorrect.

Tasks:

1. [x] Add auth-mode detection before `exportKeypairWithUI` chooses an export path.
2. [x] For passkey accounts, keep existing WebAuthn/Touch ID export authorization.
3. [x] Replace the temporary Email OTP-only export fail-closed behavior with policy-gated Email OTP export.
4. [x] Ensure Email OTP-only ECDSA export requests a fresh export-scoped Email OTP challenge instead of `requestThresholdEcdsaExportAuthorization`.
5. [x] Ensure Email OTP-only Ed25519 export requests a fresh export-scoped Email OTP challenge instead of `requestNearEd25519ExportAuthorization`.
6. [x] Add tests proving Email OTP-only export attempts do not open WebAuthn prompts.
7. [x] Add tests proving passkey export flows still open WebAuthn and still export Ed25519/ECDSA when authorized.
8. [x] Add server-side policy enforcement for Email OTP `export_key`, including TTL, replay protection, audit events, and abuse counters.
9. [x] Add tests proving Email OTP-only Ed25519 and ECDSA export use OTP UI, bind the export challenge, and discard material after viewer close.

### Phase 7: UI Copy And Product Clarity

Goal: users can tell which auth method is active and why a prompt appears.

Tasks:

1. [x] In transaction confirm UI, label passkey prompts as "Confirm with Passkey."
2. [x] In transaction confirm UI, label Email OTP prompts as "Enter email code to sign."
3. [x] In Email OTP session-mode transaction UI, avoid passkey halo visuals if no WebAuthn ceremony will run.
4. [x] In AccountMenu export UI, allow Email OTP accounts to open export and use OTP-specific export authorization.
5. [x] In PasskeyAuthMenu, avoid prefilled passkey account ids confusing Google SSO registration.
6. [x] Add explicit lower-assurance copy for Email OTP: "Passkey is recommended for stronger security."
7. [x] Ensure errors distinguish "fresh Email OTP required", "passkey step-up required", and "operation blocked by policy."

### Phase 8: Robust Google SSO Registration Architecture

Goal: Google SSO identity resolution, wallet allocation, signer activation, and Email OTP enrollment are separate lifecycle steps so stale mappings and dev wallet collisions cannot send users through the wrong flow.

Problem statement:

1. Google SSO authenticates the app/user, but does not by itself prove that a wallet should be created.
2. A stable Google subject can already be linked to a wallet whose NEAR account exists on-chain.
3. Re-running registration against that existing wallet can finalize a new threshold Ed25519 key that is not an active NEAR access key.
4. The server correctly refuses activation, but the user-facing flow should have switched to login or created a fresh dev registration attempt before key generation.

Target architecture:

1. `GoogleIdentity`: provider, subject, email, and app-session claims only.
2. `WalletAccount`: canonical wallet id plus lifecycle state: `reserved`, `provisioning`, `active`, `failed`, or `orphaned_dev`.
3. `AccountSigner`: auth method, curve, public key, and lifecycle state: `pending`, `key_finalized`, `onchain_key_active`, `active`, or `failed`.
4. `EmailOtpEnrollment`: wallet-scoped enrollment linked to a signer, with `pending`, `active`, and `revoked` states.
5. `GoogleEmailOtpRegistrationAttempt`: short-lived registration attempt containing `attemptId`, Google subject, proposed wallet id, finalized Ed25519 key if available, status, failure code, and expiry.

Tasks:

1. [x] Add an explicit Google Email OTP resolution step that returns typed outcomes: `existing_wallet`, `register_started`, `wallet_id_collision`, and `registration_incomplete`.
2. [x] Stop permanently binding the Google subject to a wallet during `/session/exchange` registration. Treat exchange as identity-session creation plus resolution only.
3. [x] Add `GoogleEmailOtpRegistrationAttempt` persistence with attempt id, proposed wallet id, Google subject, email, runtime policy scope, status, expiry, and failure code.
4. [x] Bind the Google subject to the wallet only after account provisioning, signer activation, and Email OTP enrollment have all succeeded.
5. [x] If registration finds an existing active wallet for the Google subject, return `existing_wallet` and make the frontend switch to login OTP instead of starting HSS/key generation.
6. [x] If registration finds a pending or failed attempt, either safely resume it or expire it before starting a new attempt; do not treat it as an active wallet.
7. [x] If the proposed NEAR account exists but the finalized threshold Ed25519 key is not active, fail with `wallet_id_collision`, leave identity mapping unchanged, and mark the registration attempt failed.
8. [x] Replace ambiguous challenge routing with explicit route/API names for login OTP challenge, registration OTP challenge, and registration finalize.
9. [x] Keep login strict: `account_mode=login` must require an active wallet mapping and active Email OTP enrollment, and must never allocate a wallet id or start registration.
10. [x] Rename the dev wallet-id setting to describe registration behavior, for example `EMAIL_OTP_GOOGLE_REGISTRATION_WALLET_ID_POLICY=stable|timestamped_dev`.
11. [x] In `timestamped_dev`, mint fresh wallet ids only for new registration attempts; do not let login use timestamped id generation.
12. [x] Add an explicit dev-only "force new dev wallet" path if we want to create multiple wallets for the same Google account during local testing.
13. [x] Update `PasskeyAuthMenu` and the demo social handler to follow the server's typed resolution mode instead of inferring enroll vs login from the segmented-control tab.
14. [x] Add UI copy for `existing_wallet`, `wallet_id_collision`, and `registration_incomplete` so users see whether to login, retry with a fresh dev wallet, or reset stale local state.
15. [x] Add cleanup tooling for stale local dev registration attempts and orphaned dev wallet mappings.
16. [x] Add unit tests proving Google SSO registration with an existing active wallet switches to login and does not run HSS registration.
17. [x] Add unit tests proving login mode never creates wallets and never starts Email OTP enrollment.
18. [x] Add unit tests proving timestamped dev registration creates fresh attempts even when an old stable mapping exists, without changing login semantics.
19. [x] Add relayer tests proving identity mappings are committed only after successful wallet provisioning and signer activation.
20. [ ] Add E2E coverage for stable registration, existing-wallet login handoff, timestamped dev registration, stale-attempt retry, and wallet-id collision errors.

Implementation notes:

1. Google Email OTP registration attempts now use the Email OTP store layer: Postgres when configured, in-memory otherwise.
2. Email OTP routes now use explicit login and registration names; old ambiguous route names were removed rather than aliased.
3. `EMAIL_OTP_GOOGLE_REGISTRATION_WALLET_ID_POLICY=timestamped_dev` applies only to registration attempts; login never uses timestamped id generation.
4. Local development cleanup is exposed as `POST /wallet/email-otp/dev/cleanup-google-registration`; it verifies the Google id token, deletes expired registration attempts, and removes only orphaned Google-to-relayer-wallet mappings with no active Email OTP enrollment.
5. Email OTP login operation parsing is centralized in `server/src/router/emailOtpRequestValidation.ts`. Login challenge/verify routes accept only `wallet_unlock`, `transaction_sign`, and `export_key`; registration routes do not accept login operations and remain `registration`-scoped through `AuthService`.

### Phase 9: Release-Gate Tests

Goal: lock the auth-routing behavior with tests before adding new account-upgrade features.

Tasks:

1. [x] Unit test auth-mode resolution for wallet session metadata.
2. [x] Unit test Tx Confirmer rendering for `webauthn`, `emailOtp`, and `warmSession`.
3. [x] Unit test EVM Email OTP `per_operation` challenge, submit, sign, discard, and replay rejection.
4. [x] Unit test Tempo Email OTP `per_operation` challenge, submit, sign, discard, and replay rejection.
5. [x] Unit test NEAR Ed25519 Email OTP session and per-operation signing paths.
6. [x] Unit test Email OTP-only Ed25519 and ECDSA key export with fresh OTP step-up.
7. [ ] E2E smoke test Google SSO + Email OTP registration, login, NEAR sign, EVM sign, Tempo sign.
8. [x] E2E smoke test passkey registration, login, NEAR sign, EVM sign, Tempo sign, Ed25519 export, ECDSA export.
        Completed manually: passkey registration, wallet unlock, Ed25519 threshold signing, ECDSA threshold signing, Drip fee token claim on Tempo, Ed25519 export, and ECDSA export.
9. [ ] E2E smoke test wallet-iframe mode with app-origin IndexedDB disabled.
10. [x] Add regression assertions that Email OTP flows do not display WebAuthn prompts unless passkey step-up is explicitly required.

## Acceptance Criteria

1. Passkey accounts continue to use WebAuthn/Touch ID for fresh auth.
2. Email OTP login and unlock never ask for WebAuthn.
3. Email OTP `session` signing does not ask for WebAuthn after login.
4. Email OTP `per_operation` signing displays a 6-digit OTP input in the Tx Confirmer.
5. Email OTP `per_operation` signing consumes the single-use capability and requires a fresh OTP for the next operation.
6. Email OTP-only key export does not open a WebAuthn prompt and requires fresh export-scoped Email OTP step-up.
7. Wallet-iframe mode and direct SDK mode behave the same at the public API boundary.
8. The app origin never receives recovered `S` or Email OTP-derived signing shares.
9. Error messages identify the required auth method instead of using generic "session not ready" or "passkey required" messages.
10. The release-gate test matrix covers Passkey and Email OTP across login/unlock, signing, and export decisions.

## Separate ECDSA Signing-Root Follow-Up

The item "Keep the ECDSA signing-root binding issue separate but unresolved" refers to the persisted ECDSA HSS replay/reconstruction path. Once ECDSA-HSS context binds `signingRootId` and `signingRootVersion`, any persisted integrated-key replay path must feed those values into the ECDSA HSS context and reject records whose stored signing-root metadata does not match the authenticated runtime scope.

Recommendation:

1. Keep this separate from Email OTP auth polish because it is a custody-domain binding issue, not an OTP prompt or warm-session lifecycle issue.
2. Treat it as a release blocker for persisted ECDSA HSS signing/export, especially self-hosted or multi-tenant deployments.
3. Track the implementation in the signer-slot/signing-root refactor lane so it is fixed with the ECDSA HSS context shape, persisted key schema, replay path, fixtures, and tests together.
4. Do not hide it behind a compatibility fallback; development can tolerate breaking schema/test updates.

## Cleanup: Domain Literal Constants

Recommendation:

1. Keep small local TypeScript-only discriminated unions when they are private to one function/module and are not parsed from JSON, persisted, or shared across router/client/server boundaries.
2. Replace repeated string unions with exported domain constants and derived types when the values are wire-level, persisted, audited, or shared across packages.
3. Prefer `as const` domain maps/arrays plus derived union types for most TypeScript code. Use a real `enum` only when runtime enum semantics are explicitly useful, such as generated API clients, Rust/WASM binding symmetry, or UI option iteration that benefits from a named runtime object.
4. Centralize parsers next to the domain constants so request handling cannot silently coerce unknown strings into defaults.
5. Use shared validation and normalization helpers from `shared/src/utils/validation.ts` and `shared/src/utils/normalize.ts` instead of redefining equivalent local helpers.
6. Treat Express and Cloudflare Email OTP route duplication as a drift risk; extract shared server helpers when the behavior must remain identical.

Todo:

1. [x] Add a shared Email OTP domain module with channel, login-operation, registration-operation, action constants, derived types, and parser predicates.
2. [x] Update the Email OTP request parser, export-policy audit payload, Express/Cloudflare export-policy routes, client Email OTP helper, AuthService challenge/verify path, and Email OTP store normalization to use shared Email OTP constants instead of local string unions.
3. [x] Finish auditing Email OTP domain literals and consolidate remaining server/client values such as `email_otp`, `wallet_unlock`, `transaction_sign`, `export_key`, `registration`, `wallet_email_otp_login`, and `wallet_email_otp_registration`.
        Email OTP wire surfaces now use shared `emailOtpDomain` constants and
        derived types across request parsing, AuthService challenge/verify,
        Express/Cloudflare session routes, threshold-ECDSA enrollment claim
        injection, client SDK auth APIs, wallet-iframe messages/router,
        SigningEngine Email OTP auth calls, and Email OTP worker message
        payloads.
4. [x] Audit wallet auth and signer-slot domain literals such as `passkey`, `session`, `email_otp`, `threshold-ed25519`, `threshold-ecdsa`, `passkey_registration`, and `email_otp_registration`; shared `signerDomain` now owns the wallet-auth method, wallet-auth proof method, signer kind, signer auth method, signer source, and signing-session retention domains.
5. [x] Update remaining router/client/server call sites to use the shared constants instead of repeated inline string unions.
        Guard coverage now includes server parser/store/routes plus client SDK,
        wallet-iframe, SigningEngine, and Email OTP worker boundaries, so
        shared wire literals cannot be reintroduced in those surfaces.
6. [x] Add a guard test preventing Email OTP parser/client/store modules from redeclaring shared Email OTP wire literal types.
7. [x] Add guard tests that fail on duplicated hard-coded literals in wallet auth-mode resolution and signer-slot lifecycle code.
8. [ ] Avoid compatibility aliases for renamed values; this codebase is still in development, so breaking cleanup is preferred over legacy symbols.
9. [x] Decide whether any shared string-union domains should become real enums. Default to `as const` maps plus derived types; use enums only when runtime enum semantics are actually needed.
10. [x] Replace local helper copies such as `toOptionalTrimmedString`, `optionalClaimString`, local object/string guards, and equivalent normalizers with shared validation/normalization helpers where behavior matches.
        `optionalClaimString` was removed from
        both session routers and `relayWebhooks.ts` now imports shared string
        normalization. Matching non-array object guards now use shared
        `isPlainObject`; local helpers remain only where semantics differ or
        where the helper is the central router utility.
11. [ ] Extract duplicated Email OTP server route logic shared by Express and Cloudflare: request validation, app-session claim extraction, export-policy authorization, audit payload construction, and response shaping.
        Completed slices: request parsing, export-policy authorization/audit
        payloads, status mapping, wallet-id claim extraction, Google OIDC
        detection, OIDC account-mode parsing, Email OTP wire constants, and
        Email OTP challenge response shaping are shared. Remaining work is
        enrollment-finalize, unseal, and dev-outbox response shaping if
        Express/Cloudflare route bodies keep diverging.
12. [x] Add guard tests preventing route files from reintroducing local copies of generic validation or claim-normalization helpers.

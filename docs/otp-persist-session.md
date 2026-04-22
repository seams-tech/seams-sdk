# Email OTP Sealed Refresh Persistence

Last updated: 2026-04-22

## Goal

Implement a sealed-refresh path for Email OTP accounts so a same-browser accidental page refresh can restore the active wallet signing session without requiring a new Google SSO, Email OTP, or passkey prompt.

This plan generalizes the existing passkey sealed-refresh system so session persistence is auth-method neutral:

1. passkey accounts restore from a sealed passkey-derived signing-session secret
2. Email OTP accounts restore from a sealed Email OTP-derived signing-session secret
3. both auth methods rehydrate the same `walletSigningSessionId` budget semantics
4. Ed25519 and ECDSA remain separate threshold capabilities, but share one wallet-level TTL and `remainingUses` budget
5. private-key export and link-device/add-signer flows still require fresh operation-scoped auth and must not reuse or clobber the transaction signing session

## Resolved Design Decisions

These decisions close the main ambiguity before implementation starts.

1. `K = signing_session_secret32` is session-scoped, not account-scoped.
2. The persisted artifact is `E_session_s(K)`, not `E_session_s(S)` and not `E_enrollment_s(S)`.
3. Ed25519 restore derives an Ed25519 restore seed from `K` and reconnects the recorded Ed25519 threshold session; the worker owns the seed and resulting signing handle.
4. Restore should default to all curves recorded in the sealed record, with room to lazy-restore optional curves later only after the all-curves path is stable.
5. Iframe-origin IndexedDB store name is `signing_session_seals_v1`.
6. IndexedDB primary key is `walletSigningSessionId`.
7. The sealed record stores threshold session ids only. It must not store raw threshold-session JWTs or ambiguous JWT refs.
8. Server routes derive authoritative binding metadata from threshold-session server state and treat client-supplied metadata only as assertions.
9. The route names are:
   - `POST /threshold/signing-session-seal/apply-server-seal`
   - `POST /threshold/signing-session-seal/remove-server-seal`
10. The env/config names are:
    - `SIGNING_SESSION_SEAL_KEY_VERSION`
    - `SIGNING_SESSION_SHAMIR_P_B64U`
    - `SIGNING_SESSION_SEAL_E_S_B64U`
    - `SIGNING_SESSION_SEAL_D_S_B64U`
    - `VITE_SIGNING_SESSION_PERSISTENCE_MODE`
    - `VITE_SIGNING_SESSION_SEAL_KEY_VERSION`
    - `VITE_SIGNING_SESSION_SHAMIR_P_B64U`
11. Rate-limit defaults are:
    - apply: 5 per threshold session per 5 minutes
    - remove: 10 per threshold session per 5 minutes
    - per-user combined apply/remove cap: 30 per 5 minutes
12. IndexedDB persistence is still an accidental-refresh feature, not browser-restart persistence. A `runtimeSessionId` in `sessionStorage` binds the IndexedDB record to the current browser session.
13. Multi-tab behavior uses a storage lease around restore. Multiple tabs may eventually restore while server budget remains valid, but only one restore attempt per wallet signing session should run at a time.
14. Logout, lock, account switch, revocation, TTL expiry, and use exhaustion must delete the IndexedDB store records, not just `sessionStorage`.
15. Migration order is generic passkey first, PRF cleanup second, Email OTP enablement third. Do not build Email OTP persistence on names we already plan to delete.
16. Email OTP and signing-session persistence must fail closed instead of using backfills, fallbacks, compatibility aliases, or alternate secret/auth routes.

## Current Passkey Sealed-Refresh Note

The existing passkey implementation already uses `shamir3pass` to persist enough client signing material to survive a same-tab page refresh.

Current flow:

1. passkey auth yields `PRF.first` in the passkey confirmation worker
2. the worker keeps `PRF.first` in memory under a threshold session id
3. when `signingSessionPersistenceMode = sealed_refresh_v1`, `TouchConfirmManager` asks the worker to seal that warm-session material
4. the worker creates an ephemeral `shamir3pass` client lock over `PRF.first`
5. the server applies its signing-session seal through `/threshold/signing-session-seal/apply-server-seal`
6. the worker removes its client lock and returns `E_session_s(PRF.first)`
7. the main thread stores a `signingSessionSealedStore` record in wallet-origin IndexedDB
8. after a page refresh, `TouchConfirmManager` sees the worker warm session is missing, reads the sealed record, and asks the worker to rehydrate
9. the worker adds a fresh client lock to `E_session_s(PRF.first)`, calls `/threshold/signing-session-seal/remove-server-seal`, removes the client lock, and restores `PRF.first` into memory
10. threshold signing can continue without a new WebAuthn prompt while the threshold-session TTL and `remainingUses` budget remain valid

Important current boundaries:

1. this path exists for passkey-based accounts only
2. it seals the passkey secret source `PRF.first`, not an auth-method-neutral `signing_session_secret32`
3. the sealed-refresh file, record field, route, and env/config names have been migrated to signing-session names without compatibility aliases
4. it stores the sealed record in iframe-origin IndexedDB, bound to the current browser session by a `sessionStorage` `runtimeSessionId`
5. it relies on threshold-session auth and server policy to remove the server seal
6. it does not persist plaintext `PRF.first`

The Email OTP work should reuse the same `shamir3pass` commutative-lock shape, but the persisted secret should be the canonical `signing_session_secret32` derived from Email OTP secret `S`, not the long-lived enrollment escrow and not a raw client signing share.

## Feasibility Judgment

The proposed flow is coherent and feasible if we tighten the persistence boundary.

Cleaner model:

```text
enrollment escrow:
  server stores E_enrollment_s(S)
  client does not store it

Email OTP unlock:
  1. User authenticates with Google SSO.
  2. User verifies 6-digit Email OTP.
  3. Server authorizes one unseal of the enrollment escrow.
  4. Email OTP worker performs shamir3pass unseal.
  5. Worker recovers S in memory.
  6. Worker derives signing_session_secret32 from S.
  7. Worker bootstraps Ed25519/ECDSA signing sessions.
  8. Worker creates a separate session-refresh artifact:
     E_session_s(signing_session_secret32)
  9. Client stores only E_session_s(signing_session_secret32) in iframe-origin IndexedDB.
```

The client must not request and persist `E_enrollment_s(S)` as the refresh artifact. The enrollment escrow is involved only during the real OTP unlock ceremony. After that, the refresh artifact is derived from the already-unlocked session secret and sealed under a separate signing-session seal namespace.

The reload path is:

```text
1. Client reads E_session_s(signing_session_secret32) from IndexedDB.
2. Worker computes E_c(E_session_s(signing_session_secret32)).
3. Server removes the session seal:
   D_session_s(E_c(E_session_s(K))) = E_c(K)
4. Worker removes client lock:
   D_c(E_c(K)) = K
5. Worker rebuilds signing material from K.
```

Where `K = signing_session_secret32`.

This keeps the server enrollment escrow out of browser storage and keeps sealed refresh scoped to the active signing session only.

Recommended tightened model:

```text
enrollment escrow, server-owned only:
  E_enrollment_s(S)

session refresh artifact, client persisted:
  E_session_s(signing_session_secret32)
```

The implementation target is to persist a sealed `signing_session_secret32`, not a sealed raw `S`. That keeps passkey and Email OTP on the same downstream interface and avoids storing an artifact that directly unwraps the root Email OTP secret.

## Security Position

This feature improves UX and is reasonable for `email_otp_auth_policy = session`, but it is intentionally weaker than a memory-only Email OTP posture. Keep it bounded to the active browser signing session and server-authoritative session budget.

Security rules:

1. do not persist plaintext `S`
2. do not persist plaintext `signing_session_secret32`
3. do not mirror the long-lived server enrollment escrow `E_enrollment_s(S)` into browser storage
4. persist only a session-scoped sealed refresh artifact
5. require live server participation to remove the server seal
6. require a valid threshold-session authority for sealed refresh removal
7. bind the artifact to `walletSigningSessionId`, wallet id, user id, signing root, auth method, TTL, remaining uses, and seal key version
8. delete the artifact on logout, lock, account switch, revocation, TTL expiry, remaining-use exhaustion, or threshold-session invalidation
9. never use sealed refresh for `per_operation`
10. never use sealed refresh for export private key, link-device, or add-signer operation auth

Threat-model impact:

1. stolen IndexedDB alone must not recover `S` or signing material
2. stolen IndexedDB plus a still-valid threshold session may restore the active signing session until TTL or use limits expire
3. XSS or malicious browser extensions can still attack an active session, so TTL and remaining-use limits must stay tight
4. server compromise remains in the Email OTP custody path because the server controls the seal key and enrollment escrow
5. passkey remains the recommended stronger default because it does not escrow the passkey PRF output through Email OTP infrastructure

## Storage Decision

Use iframe-origin IndexedDB for the Email OTP sealed refresh record.

Rationale:

1. the wallet iframe origin already owns wallet-local durable metadata
2. app-origin storage must not receive secret-bearing refresh artifacts
3. IndexedDB is more robust than `sessionStorage` across iframe reload and app remount behavior
4. the record is still logically session-scoped, even if IndexedDB is durable
5. server-enforced TTL, remaining uses, and revocation are mandatory because IndexedDB may outlive the page runtime

Required storage cleanup:

1. delete on explicit wallet lock
2. delete on logout
3. delete on account switch
4. delete on server revocation
5. delete on TTL expiry
6. delete on remaining-use exhaustion
7. delete on schema mismatch
8. delete on auth-method mismatch
9. delete on signing-root mismatch
10. delete on failed unseal

## Target Record

Replace the passkey-specific sealed refresh record with an auth-method-neutral record.

```ts
type SealedSigningSessionRecord = {
  v: 1;
  alg: 'shamir3pass-v1';
  storageScope: 'iframe_origin_indexeddb';
  runtimeSessionId: string;
  authMethod: 'passkey' | 'email_otp';
  secretKind: 'signing_session_secret32';
  walletId: string;
  userId: string;
  signingRootId: string;
  signingRootVersion?: string;
  walletSigningSessionId: string;
  thresholdSessionIds: {
    ed25519?: string;
    ecdsa?: string;
  };
  sealedSecretB64u: string;
  sealKeyVersion: string;
  shamirPrimeB64u: string;
  issuedAtMs: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs: number;
};
```

IndexedDB keying:

1. database: existing wallet iframe client database, or `tatchi_wallet_v1` if a new database is required
2. object store: `signing_session_seals_v1`
3. primary key: `walletSigningSessionId`
4. indexes: `walletId`, `userId`, `authMethod`, `signingRootId`, `expiresAtMs`
5. uniqueness rule: keep at most one active record per `(walletId, signingRootId, authMethod)`
6. write rule: writing a new active record for the same `(walletId, signingRootId, authMethod)` deletes older records first
7. restart rule: if `runtimeSessionId` is missing from `sessionStorage` or does not match, delete the IndexedDB record before attempting restore

Threshold session auth:

1. the sealed record stores threshold session ids only
2. raw threshold-session JWTs remain in the canonical threshold-session stores
3. restore resolves threshold-session auth through `WarmSessionManager`
4. if canonical threshold-session auth is missing, expired, revoked, or mismatched, restore fails closed
5. do not add `thresholdSessionJwtRefs` unless a concrete ref mechanism exists; the current target is no refs

App-session auth for fresh-auth operations:

1. export/link-device/add-signer still require fresh operation-scoped auth after reload
2. Email OTP export challenge issuance after sealed refresh uses restored signing-session authority, not a JS-readable persisted `app_session_v1` JWT
3. app-session JWTs may be kept in memory during the active page lifetime, but are not written to `sessionStorage` or IndexedDB as a reload continuity primitive
4. restored signing-session authority can only request a fresh OTP challenge; it cannot directly authorize export/link-device/add-signer
5. app-session JWTs must never be substituted for threshold-session JWTs, or vice versa

Fresh-auth challenge target:

The target is to stop treating a JS-readable `app_session_v1` JWT as the reload continuity primitive for sensitive-operation challenge issuance.

For Email OTP accounts, a restored signing session may authorize only the request to send a fresh sensitive-operation OTP challenge to the server-known verified email. The restored signing session must not authorize the sensitive operation itself.

Target flow:

```text
1. Reload restores K from the sealed signing-session refresh artifact.
2. Worker restores threshold signing state.
3. Client requests an export/link-device/add-signer OTP challenge using restored signing-session authority.
4. Server validates the restored signing-session lane and sends OTP to the account email from server-side state.
5. User verifies the fresh OTP.
6. OTP verification creates a short-lived operation-scoped authorization.
7. The sensitive operation executes with that operation authorization.
```

This avoids storing app-session JWTs in browser storage and fits "bring your own auth" integrations where the customer may not want relay-owned HttpOnly cookies.

Security boundary:

1. restored signing-session authority may initiate a fresh Email OTP challenge only
2. restored signing-session authority must never directly authorize key export, link-device, add-signer, or other sensitive operations
3. the OTP destination must be derived from server-side account state, never from client input
4. OTP challenge issuance through this lane must be separately rate-limited and audited
5. OTP verification must mint a narrow single-purpose operation grant, not a general app session and not a renewed transaction signing session
6. passkey accounts continue to use WebAuthn/passkey fresh auth for sensitive operations and must not use Email OTP challenge issuance

## Server-Owned Email OTP Enrollment Identity

The session-persistence work exposed a pre-existing bad invariant: an active Email OTP enrollment can currently exist without a server-owned verified email. That was tolerable while sensitive-operation export flows could lean on app-session email, but signing-session-authorized challenge issuance needs a canonical enrollment email that is independent of app-session continuity.

Target invariant:

```text
active Email OTP enrollment => server-owned verified email exists
```

The Email OTP enrollment record should be the canonical source of the mailbox used for login, export, link-device, and add-signer OTP challenges. Login OTP verification must not repair enrollment identity as a normal side effect. A successful login OTP proves control of the challenge mailbox for that login ceremony; it must not silently mutate the long-lived enrollment binding.

Target enrollment shape:

```ts
type EmailOtpEnrollment = {
  walletId: string;
  authSubjectId: string;
  verifiedEmailNormalized: string;
  verifiedEmailHash: string;
  emailVerifiedAtMs: number;
  enrollmentVersion: number;
  enrollmentStatus: 'active';
  enrollmentEscrowRefs: unknown;
  thresholdVerifierRefs: unknown;
  createdAtMs: number;
  updatedAtMs: number;
};
```

Rules:

1. active Email OTP enrollment creation must require a server-verified email
2. Email OTP challenge routes must resolve the destination email from active enrollment state, never from client input
3. app-session email may help select or validate an enrollment during fresh login, but it must not replace the enrolled mailbox
4. signing-session-authorized operation challenges must use the same enrolled mailbox resolution as app-session-authorized login challenges
5. OTP verify routes may mint operation grants or login grants, but must not repair missing enrollment email
6. invalid active enrollments without a verified email must fail closed with a re-enrollment-required error
7. any repair of existing invalid data must be an explicit one-time migration or local data reset, not request-path behavior

No backfills or fallbacks rule:

1. no request path may repair missing Email OTP enrollment identity
2. no Email OTP challenge path may fall back to app-session email, client-provided email, or login challenge email
3. no signing-session seal path may fall back to a default seal key version or generic Redis/Postgres/Upstash environment variables
4. no sealed-refresh path may accept legacy route names, config names, storage names, or secret artifacts
5. invalid, missing, or ambiguous state must return an explicit error and require re-enrollment, reauth, or operator migration outside the request path

Do not use these names in the new steady-state API:

1. `prfSessionSealedStore`
2. `sealedPrfFirstB64u`
3. `prfFirstB64u` for generic session persistence
4. `PRF session seal` for route names

Breaking rename target:

1. `prfSessionSealedStore` -> `signingSessionSealedStore`
2. `sealedPrfFirstB64u` -> `sealedSecretB64u`
3. `prfFirstB64u` at generic boundaries -> `signingSessionSecretB64u` or `secretSourceB64u`
4. `/threshold-ecdsa/prf-seal/*` -> `/threshold/signing-session-seal/*`

Do not keep legacy aliases after migration.

## Canonical Secret Model

Use one downstream secret type:

```ts
type SigningSessionSecretKind = 'signing_session_secret32';
```

Passkey derivation:

```text
PRF.first
  -> HKDF(
       domain = "tatchi/passkey/signing-session-secret/v1",
       fields = [
         wallet_id,
         user_id,
         signing_root_id,
         signing_root_version,
         wallet_signing_session_id,
         auth_method
       ]
     )
  -> signing_session_secret32
```

Email OTP derivation:

```text
S
  -> HKDF(
       domain = "tatchi/email-otp/signing-session-secret/v1",
       fields = [
         wallet_id,
         user_id,
         signing_root_id,
         signing_root_version,
         wallet_signing_session_id,
         auth_method
       ]
     )
  -> signing_session_secret32
```

`walletSigningSessionId` must participate in deriving `K`. This prevents a sealed refresh artifact from becoming a reusable account-level derivative.

Then:

```text
signing_session_secret32
  -> Ed25519 threshold client material
  -> ECDSA threshold client material
```

This keeps passkey and Email OTP behavior parallel while preserving domain separation.

## Restore Material Reconstruction

Reload restore reconstructs worker state from `K = signing_session_secret32`. It must not recover `S`, fetch `E_enrollment_s(S)`, or call Email OTP challenge/verify routes.

Inputs available to the worker during restore:

1. `K`, recovered inside the worker by removing the session seal
2. `SealedSigningSessionRecord` metadata, validated by the main thread before worker restore
3. threshold-session auth and threshold-session records resolved by `WarmSessionManager` from canonical session stores
4. server-side threshold session state, validated again by the signing-session seal route

K-derived restore branches:

These derivations use the canonical `encode_tuple` field encoding from the Email OTP specs.

```text
session_restore_root =
  HKDF-SHA-256(
    ikm=K,
    salt="tatchi/signing-session/restore-root/v1",
    info=encode_tuple([
      auth_method,
      wallet_id,
      user_id,
      signing_root_id,
      signing_root_version,
      wallet_signing_session_id
    ])
  )

ed25519_restore_seed32 =
  HKDF-SHA-256(
    ikm=session_restore_root,
    salt="tatchi/signing-session/threshold-ed25519/v1",
    info=encode_tuple([
      ed25519_threshold_session_id,
      sorted_participant_ids,
      relayer_key_id
    ])
  )

ecdsa_restore_client_root_share32 =
  HKDF-SHA-256(
    ikm=session_restore_root,
    salt="tatchi/signing-session/threshold-ecdsa-client-root/v1",
    info=encode_tuple([
      ecdsa_threshold_session_id,
      ecdsa_threshold_key_id,
      chain,
      derivation_path,
      sorted_participant_ids,
      relayer_key_id
    ])
  )
```

Restore steps:

1. The main thread reads the sealed record and resolves threshold-session auth through `WarmSessionManager`; the sealed record must not contain raw threshold-session JWTs.
2. The Email OTP worker unseals `K` through the signing-session seal remove route.
3. The worker derives `session_restore_root`.
4. For Ed25519, the worker derives `ed25519_restore_seed32`, rehydrates the Ed25519 warm signing material for the recorded Ed25519 threshold session, and marks it ready only if the threshold-session record and server policy still match.
5. For ECDSA, the worker derives `ecdsa_restore_client_root_share32`, reruns the ECDSA HSS reconnect/bootstrap path for the recorded ECDSA threshold session and `walletSigningSessionId`, receives the refreshed worker-held `clientAdditiveShare32` material, stores it behind an opaque Email OTP worker session handle, and zeroizes transient root-share/additive-share buffers after handoff.
6. `WarmSessionManager` marks the wallet signing session ready only after every required curve for the account is ready under the same `walletSigningSessionId`.

Ed25519 restore meaning:

1. `ed25519_restore_seed32` is the Email OTP/passkey-neutral replacement for the current `thresholdEd25519PrfFirstB64u` style input.
2. It is not a NEAR private key and must not be exported or persisted.
3. Ed25519 restore must run the same reconnect/bootstrap validation needed to reattach to the recorded threshold Ed25519 session.
4. The worker should expose an opaque Ed25519 signing handle, not raw seed bytes, after restore.
5. Any compatibility field that still carries Ed25519 secret-derived bytes across the main thread is temporary and must be removed in the same refactor if possible.

Curve restore rule:

1. restore all curves recorded in `thresholdSessionIds` for the initial implementation
2. mark wallet signing session ready only after every recorded curve required by the account capability set is ready
3. lazy per-operation restore may be added later for latency, but only after all-curves restore is covered by tests
4. never restore a curve that is not present in the account signer metadata or threshold-session server state

Rules:

1. `K` never leaves the worker after unseal.
2. `ed25519_restore_seed32`, `ecdsa_restore_client_root_share32`, and ECDSA additive-share bytes never persist to IndexedDB.
3. The main thread may receive only sanitized threshold-session metadata and opaque worker handles.
4. If any required threshold-session record, auth material, signing root, participant set, or server policy check is missing or mismatched, restore fails closed and the sealed record is deleted.
5. Operation-scoped flows such as export and link-device/add-signer must not use this reconstruction path.

## Server Validation Specs

The signing-session seal routes are separate from the Email OTP enrollment escrow routes. They operate only on `E_session_s(signing_session_secret32)` artifacts and must never accept, fetch, or return `E_enrollment_s(S)`.

Both `apply-server-seal` and `remove-server-seal` must validate:

1. the request uses threshold-session auth, not app-session auth
2. the threshold session exists, belongs to the authenticated user, and is not expired, revoked, or exhausted
3. the threshold session is `session` retention, not `per_operation`
4. the threshold session is authorized for the requested wallet id, `walletSigningSessionId`, signing root id/version, auth method, participant set, and curve
5. the requested seal key version belongs to the signing-session seal namespace and is active or explicitly accepted for rotation
6. the ciphertext is valid base64url, in the configured `shamir3pass` field, non-empty, and non-degenerate
7. idempotency keys, if supplied or derived, are scoped by operation, user id, threshold session id, seal key version, and ciphertext hash
8. rate limits pass for the operation, user id, and threshold session id

Client request metadata:

1. requests may include `walletSigningSessionId`, `walletId`, `authMethod`, `signingRootId`, `signingRootVersion`, `thresholdSessionId`, `secretKind`, `sealKeyVersion`, and ciphertext
2. the server must derive authoritative values from threshold-session state wherever possible
3. client-supplied metadata is an assertion and must match server state
4. mismatches fail closed before seal application or removal
5. server state wins over IndexedDB record contents

Additional route rules:

1. `apply-server-seal` is allowed only after successful OTP unlock and threshold-session bootstrap; it must not create or extend a threshold session.
2. `remove-server-seal` is allowed only for an existing signing-session sealed-refresh artifact; it must not consume or replace Email OTP enrollment escrow.
3. neither route may return plaintext `K`, plaintext `S`, threshold-session JWTs, raw enrollment escrow, or raw server seal key material
4. responses may include sanitized policy metadata such as `expiresAtMs`, `remainingUses`, and `sealKeyVersion`
5. audit logs must include operation, user id, threshold session id, wallet signing session id when known, key version, result code, and duration; they must not log OTP codes, plaintext secrets, raw ciphertexts, JWTs, or enrollment escrow blobs

## Budget Decision

Sealed refresh apply/remove is transaction-use neutral and separately rate-limited.

Rules:

1. transaction signing consumes the shared wallet-level `remainingUses` budget
2. sealed refresh apply/remove does not decrement transaction signing `remainingUses`
3. sealed refresh apply/remove must enforce separate per-user, per-threshold-session, and per-operation rate limits
4. sealed refresh apply/remove must be idempotent for duplicate retries with the same operation, session, key version, and ciphertext hash
5. sealed refresh apply/remove must never extend server-side TTL or increase transaction signing `remainingUses`
6. restore must fail closed if the underlying threshold session is expired, revoked, exhausted, missing, or no longer bound to the sealed record metadata

Concrete rate-limit defaults:

1. `apply-server-seal`: 5 requests per threshold session per 5 minutes
2. `remove-server-seal`: 10 requests per threshold session per 5 minutes
3. combined per-user apply/remove cap: 30 requests per 5 minutes
4. combined per-wallet apply/remove cap: 30 requests per 5 minutes
5. malformed ciphertext failures count against the limit
6. authorization failures count against the limit
7. retryable network failures that do not reach the server do not count
8. duplicate idempotent retries with the same idempotency key and ciphertext hash should not multiply side effects, but may still count toward abuse limits after a small retry allowance

## Browser Restart And Multi-Tab Semantics

IndexedDB durability must not silently turn sealed refresh into long-lived persistence.

Browser-session marker:

1. generate `runtimeSessionId` when the wallet iframe starts and no marker exists
2. store `runtimeSessionId` in wallet iframe `sessionStorage`
3. copy `runtimeSessionId` into each `SealedSigningSessionRecord`
4. on startup, if `sessionStorage.runtimeSessionId` is missing, delete all `signing_session_seals_v1` records before restore
5. on startup, if a record `runtimeSessionId` does not match the current marker, delete that record before restore

This preserves refresh/remount robustness while avoiding a product promise that Email OTP sessions survive browser restart.

Multi-tab restore:

1. use an IndexedDB lease record keyed by `walletSigningSessionId`
2. lease fields: `ownerId`, `startedAtMs`, `expiresAtMs`, and `attemptId`
3. only the lease holder may run restore for that wallet signing session
4. expired leases may be stolen after a short timeout
5. successful restore updates the sealed record policy metadata and releases the lease
6. failed restore deletes the sealed record only if the failure is terminal; transient network failures release the lease and allow retry
7. transaction signing still consumes the shared server-side budget, so multiple tabs cannot extend uses by racing

## Cleanup Propagation

Because sealed records move to IndexedDB, every existing cleanup path must be updated.

Delete `signing_session_seals_v1` records on:

1. explicit wallet lock
2. logout
3. account switch
4. active signer switch
5. auth method switch
6. server revocation event
7. threshold-session expiry
8. threshold-session exhaustion
9. threshold-session `not_found`
10. signing-root mismatch
11. seal key version rejection
12. failed unseal with terminal error
13. user clears wallet state

Do not rely on `sessionStorage.clear()` or old PRF-store cleanup paths after this migration.

## Protocol

Notation:

1. `S`: Email OTP secret recovered through OTP-authorized `shamir3pass`
2. `K`: canonical `signing_session_secret32`
3. `E_s(x)`: server commutative seal for signing-session refresh
4. `E_c(x)`: worker-ephemeral client commutative lock
5. `D_s(x)`: server removes its seal
6. `D_c(x)`: worker removes its lock

### Initial Email OTP Unlock

```mermaid
sequenceDiagram
  participant UI as "App / UI"
  participant Main as "Wallet iframe main thread"
  participant Email as "Email OTP worker"
  participant S3P as "shamir3pass worker"
  participant Server as "Relay server"
  participant Store as "Iframe-origin IndexedDB"

  UI->>Server: "Google SSO / app-session exchange"
  Server-->>UI: "app_session_v1"
  UI->>Server: "Request Email OTP challenge"
  Server-->>UI: "challengeId"
  UI->>Server: "Verify 6-digit OTP"
  Server-->>UI: "OTP grant"
  Main->>Email: "Unlock with OTP grant"
  Email->>S3P: "Recover S via server-assisted unseal"
  S3P->>Server: "OTP-authorized shamir3pass round trip"
  Server-->>S3P: "Unseal response"
  S3P-->>Email: "S bytes"
  Email->>Email: "Derive K = signing_session_secret32"
  Email->>Server: "Bootstrap Ed25519/ECDSA threshold sessions"
  Server-->>Email: "threshold-session auth + walletSigningSessionId"
  Email->>S3P: "Seal K for refresh"
  S3P->>Server: "Apply server signing-session seal"
  Server-->>S3P: "E_s(E_c(K))"
  S3P-->>Email: "E_s(K)"
  Email-->>Main: "sealed refresh metadata only"
  Main->>Store: "Persist SealedSigningSessionRecord"
```

### Same-Browser Reload Restore

```mermaid
sequenceDiagram
  participant UI as "App / UI"
  participant Main as "Wallet iframe main thread"
  participant Email as "Email OTP worker"
  participant S3P as "shamir3pass worker"
  participant Server as "Relay server"
  participant Store as "Iframe-origin IndexedDB"

  UI->>Main: "Reload / remount"
  Main->>Store: "Read SealedSigningSessionRecord"
  Main->>Main: "Validate metadata, TTL, auth method, signing root"
  Main->>Email: "Restore Email OTP signing session"
  Email->>S3P: "Add client lock: E_c(E_s(K))"
  S3P->>Server: "Remove server seal using threshold-session auth"
  Server-->>S3P: "E_c(K)"
  S3P-->>Email: "K"
  Email->>Email: "Rebuild Ed25519 and ECDSA worker state"
  Email-->>Main: "Warm signing session ready"
  Main-->>UI: "Sign without OTP prompt"
```

## Auth Rules

Keep app-session and threshold-session lanes separate.

Use app-session auth for:

1. Google SSO exchange
2. Email OTP challenge issuance
3. Email OTP verification
4. initial OTP-authorized unseal
5. sensitive-operation OTP challenges for export and link-device/add-signer

Use threshold-session auth for:

1. signing-session sealed refresh apply-server-seal
2. signing-session sealed refresh remove-server-seal
3. threshold Ed25519 signing
4. threshold ECDSA signing
5. threshold HSS continuation after bootstrap

Do not use app-session auth to restore a threshold signing session from a sealed refresh artifact. App-session auth answers "is the user logged in"; threshold-session auth answers "is this signing capability still valid."

### Threshold-Session JWT Identity

Threshold-session JWTs must carry an explicit `walletId` claim:

```ts
{
  kind: 'threshold_ecdsa_session_v1',
  sub: walletId,
  walletId,
  sessionId,
  walletSigningSessionId,
  relayerKeyId,
  rpId,
  thresholdExpiresAtMs,
  participantIds,
}
```

`sub` remains only as the standard JWT subject alias. Parsers must require `walletId === sub`, but route and business logic must read `walletId` when authorizing threshold-session scope. This avoids colliding with app-session `sub`, which can be a Google/OIDC provider subject.

## Auth-Lane Plumbing Refactor

The implementation centralizes `appSessionJwt`, generic `routeAuth`, cookie sessions, and stored threshold-session JWTs into one typed Email OTP auth lane before worker payloads or route choices are built.

Target shape:

```ts
type EmailOtpAuthLane =
  | { kind: 'app_session'; jwt: string }
  | {
      kind: 'signing_session';
      jwt: string;
      thresholdSessionId: string;
      walletSigningSessionId?: string;
      curve?: 'ed25519' | 'ecdsa';
    }
  | { kind: 'cookie' };

type EmailOtpRoutePlan = {
  routeFamily: 'login' | 'registration' | 'signing_session';
  authLane: EmailOtpAuthLane;
  operation: WalletEmailOtpLoginOperation;
};
```

Design rules:

1. public SDK and iframe message boundaries may accept `appSessionJwt` for fresh Google SSO/Email OTP unlock and registration flows
2. deeper Email OTP coordinator, signing, and worker APIs should receive an `EmailOtpRoutePlan` or resolved `EmailOtpAuthLane`, not raw `appSessionJwt`
3. stored threshold-session JWTs must be read only from canonical threshold-session records, never from sealed refresh records
4. normal unlock and registration must resolve to `app_session` or `cookie`, never `signing_session`
5. transaction signing and sensitive-operation OTP challenge issuance after sealed refresh should resolve to `signing_session`
6. app-session JWTs and threshold-session JWTs must never be silently substituted for each other
7. route selection should be a result of the plan, not a local worker heuristic spread across call sites

Todo:

1. [x] Add shared `EmailOtpAuthLane` and `EmailOtpRoutePlan` types near the Email OTP coordinator or shared Email OTP domain module.
2. [x] Add `resolveEmailOtpAuthLane(...)` for converting edge inputs into one lane:
   - `appSessionJwt` -> `{ kind: 'app_session', jwt }` for JWT fresh unlock/registration
   - `sessionKind: 'cookie'` -> `{ kind: 'cookie' }`
   - Email OTP warm-session record with threshold-session JWT -> `{ kind: 'signing_session', jwt, thresholdSessionId, walletSigningSessionId, curve }`
3. [x] Add `buildEmailOtpRoutePlan(...)` for choosing `login`, `registration`, or `signing_session` route family from ceremony type, operation, and resolved auth lane.
4. [x] Refactor `EmailOtpThresholdSessionCoordinator` so `loginWithEcdsaCapabilityInternal`, `enrollAndLoginWithEcdsaCapabilityInternal`, `requestChallengeForSigning`, `loginWithEd25519CapabilityForSigning`, and `loginWithEcdsaCapabilityForSigning` call the resolver instead of hand-normalizing auth.
5. [x] Refactor NEAR and EVM transaction signing adapters to call one shared helper for deriving signing-session auth from Email OTP warm-session records.
6. [x] Refactor `createOrchestrationDependencyBundle` to forward resolved auth lanes for transaction-signing Email OTP challenge/verify instead of partially normalized `routeAuth` plus optional `appSessionJwt`.
7. [x] Refactor the Email OTP worker to receive an explicit route plan and remove local route-family inference except for validation assertions.
8. [x] Keep lower-level threshold HSS bootstrap auth separate. If renamed, use a precise name such as `thresholdBootstrapAuth` or `hssRouteAuth`, not generic `routeAuth`.
9. [x] Add tests for the resolver matrix:
   - fresh unlock with `appSessionJwt`
   - fresh unlock with cookie session
   - registration with `appSessionJwt`
   - transaction signing after sealed refresh with Ed25519 threshold-session auth
   - transaction signing after sealed refresh with ECDSA threshold-session auth
   - sensitive-operation challenge after sealed refresh with signing-session auth
   - mismatched or missing auth lane fails closed
10. [x] Add static guards that prevent raw `appSessionJwt` from crossing below the public SDK/iframe boundary into worker payload builders, except where the route plan explicitly serializes an app-session lane.
11. [x] Add static guards that prevent Email OTP public/worker payload surfaces from reintroducing `thresholdRouteAuth`.
12. [x] Update docs and tests to describe "auth lanes" and "route plans" consistently, while keeping server-side validation authoritative.

## WarmSessionManager Responsibilities

`WarmSessionManager` should own policy and lifecycle, but secret bytes should stay in workers.

Responsibilities:

1. track `walletSigningSessionId`
2. track auth method for the active wallet signer
3. track session policy: `session` or `per_operation`
4. track sensitive-operation policy
5. decide whether sealed refresh is allowed
6. request worker rehydrate when local worker material is missing
7. treat server TTL and remaining uses as upper bounds
8. clear sealed records when the wallet session is invalidated
9. report "restoring signing session" instead of surfacing a generic signer-not-ready error while rehydrate is in flight

Worker responsibilities:

1. own `S`
2. own `signing_session_secret32`
3. own Ed25519 and ECDSA derived signing material
4. perform `shamir3pass` lock/unlock operations
5. zero intermediates after final use
6. expose only opaque handles or sanitized metadata to the main thread

## Policy Matrix

| Flow                             | Sealed refresh allowed? | Fresh auth required?                      | Notes                                                   |
| -------------------------------- | ----------------------- | ----------------------------------------- | ------------------------------------------------------- |
| Email OTP login, `session`       | Yes                     | Initial OTP only                          | Restores after reload while server budget remains valid |
| Email OTP login, `per_operation` | No                      | OTP per operation                         | Always discard after one sign                           |
| Passkey login, `session`         | Yes                     | Initial passkey only                      | Existing behavior, generalized naming                   |
| Passkey login, `per_operation`   | No                      | Passkey per operation                     | Always discard after one sign                           |
| Normal transaction signing       | Uses active session     | Only if session expired/exhausted         | Reauth method follows registered signer                 |
| Private-key export               | No                      | Fresh same-method auth                    | Must not clobber transaction session                    |
| Link-device/add-signer           | No                      | Fresh same-method auth or stricter policy | Must not clobber transaction session                    |
| Account lock/logout              | Deletes record          | Next unlock requires auth                 | Applies to both auth methods                            |

## Independent Key Export Flow Simplification Refactor

Key export must be independent from the transaction signing-session lifecycle.

The desired steady-state is:

1. export always shows a fresh Email OTP or passkey prompt
2. export challenge issuance may use restored signing-session authority only as route authority after reload
3. export OTP/passkey verification creates a narrow operation-scoped authorization
4. export material recovery is one-off and in-memory
5. export must not bootstrap, hydrate, replace, clear, restore, consume, or otherwise mutate transaction signing-session state
6. export must not decrement `remainingUses`
7. export must not write, update, or delete `signing_session_seals_v1` records except as part of explicit wallet/session cleanup unrelated to export

The previous auth-lane refactor made app-session and threshold-session route authority explicit, but it still left too many signing APIs shaped as "transaction signing or export." That old shape allowed export to enter signing-session login/bootstrap helpers and rely on guardrails or post-hoc session restoration. The simplification target is to remove that shape entirely.

Target flow:

```text
Email OTP key export:
  1. Resolve wallet and canonical active Email OTP enrollment.
  2. Request an export OTP challenge:
     - fresh app-session authority during active login, or
     - restored signing-session route authority after sealed refresh.
  3. Send OTP only to the server-owned verified enrollment email.
  4. Verify OTP and mint a single-purpose export authorization.
  5. Worker recovers export material in memory from the Email OTP enrollment escrow path.
  6. Worker builds the export artifact.
  7. Worker zeroizes transient root/export material.
  8. No transaction signing-session record, warm-session material, sealed-refresh record, or use budget is mutated.

Passkey key export:
  1. Always prompt WebAuthn/passkey fresh auth.
  2. Recover export material only for that operation.
  3. Do not consume or replace the transaction signing session.
```

Code-structure target:

1. transaction signing APIs speak only in transaction terms
2. key export APIs speak only in operation-export terms
3. no function named `*ForSigning` accepts or forwards `export_key`
4. no function named `requestEmailOtpChallengeForSigning` can issue export/link-device/add-signer challenges
5. export worker operations are named around export and use an export-only root-material helper
6. warm-session lifecycle helpers remain available for transaction signing, but are unreachable from export call graphs

Allowed use of signing-session route authority:

1. after sealed refresh, a restored signing-session lane may request a fresh export/link-device/add-signer challenge
2. that lane proves continuity of the wallet signing context only
3. that lane does not authorize the sensitive operation
4. challenge issuance through this lane is budget-neutral and separately rate-limited
5. OTP/passkey verification remains the operation authorization gate

Disallowed export behavior:

1. no call to `loginWithEmailOtpEd25519CapabilityForSigning` or `loginWithEmailOtpEcdsaCapabilityForSigning`
2. no call to signing-session provisioning/bootstrap helpers except HSS export routines that do not mint or persist a transaction session
3. no call to `markThresholdEd25519EmailOtpSessionConsumedForAccount`
4. no call to `markThresholdEcdsaEmailOtpSessionConsumedForAccount`
5. no call to `clearWarmSessionMaterial`
6. no claim of warm-session material for export
7. no temporary replacement of stored threshold-session records followed by "restore original record"
8. no `remainingUses` decrement
9. no sealed-refresh apply/remove during export
10. no app-session JWT persistence as an export continuity primitive

### Code Path Review And Plan Critique

Code paths affected by this refactor:

1. shared Email OTP operation types and parsers:
   - `shared/src/utils/emailOtpDomain.ts`
   - `server/src/router/emailOtpRequestValidation.ts`
   - `server/src/core/EmailOtpStores.ts`
   - `server/src/core/AuthService.ts`
2. route planning and route selection:
   - `client/src/core/signingEngine/emailOtp/authLane.ts`
   - `client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts`
   - `client/src/core/TatchiPasskey/emailOtp.ts`
3. transaction signing dependency surfaces:
   - `client/src/core/signingEngine/api/nearSigning.ts`
   - `client/src/core/signingEngine/api/evmSigning.ts`
   - `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`
   - `client/src/core/signingEngine/SigningEngine.ts`
4. public SDK and iframe surfaces:
   - `client/src/core/TatchiPasskey/index.ts`
   - `client/src/core/TatchiPasskey/interfaces.ts`
   - `client/src/core/WalletIframe/shared/messages.ts`
   - `client/src/core/WalletIframe/client/router.ts`
5. Email OTP worker operation surfaces:
   - `client/src/core/signingEngine/workerManager/workerTypes.ts`
   - `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
6. server operation-auth routes:
   - `server/src/router/emailOtpRouteHandlers.ts`
   - `server/src/router/emailOtpSessionRouteHelpers.ts`
   - `server/src/router/emailOtpExportPolicy.ts`

Critique of the current plan:

1. `export_key` must not be removed from the shared/server Email OTP operation domain. It is still the valid server operation for export challenge, verify, and unseal. The split must happen at the transaction-signing API boundary.
2. `WalletEmailOtpLoginOperation` is too broad for client signing APIs because it contains `wallet_unlock`, `transaction_sign`, and `export_key`. The name also makes export look like a login operation. The refactor should introduce narrower operation names and leave the broad union only where a route truly accepts multiple operation classes.
3. `requestChallengeForSigning` is the main leakage point. It currently issues both transaction challenges and export challenges. Renaming alone is not enough; export must move to a separate helper so transaction signing cannot pass an export operation by construction.
4. Public/iframe `requestEmailOtpChallenge` still accepts `operation?: WalletEmailOtpLoginOperation`. That keeps export available on a generic login-oriented API. If we want the final codebase to read cleanly, this public surface should either become unlock-only or be split into explicit unlock, transaction, and sensitive-operation challenge entrypoints.
5. Server routes currently allow app-session export challenge/verify through the login challenge/verify routes. That works, but the naming is confusing. The cleaner route model is to keep wallet unlock under `login/*` and move app-session-authorized export/link-device/add-signer challenges to an explicit operation-auth route family.
6. The server and worker still use `loginGrant` naming for export verification/unseal. If the grant is operation-scoped, the name should say that. Otherwise future code will keep treating export OTP verification as a kind of login.
7. `requestExportAuthorization` currently uses the generic wallet-auth resolver with a passkey adapter that only throws. In the current code, this helper lives inside the Email OTP coordinator and is reached only from the Email OTP export branch. Passkey export is handled separately by `SigningEngine.requestPasskeyExportAuthorization`. The cleanup target is therefore narrow: remove the dead passkey adapter from the Email OTP coordinator only, while preserving the passkey account export path and its fresh WebAuthn/passkey prompt.
8. The worker export cases duplicate the same "recover root share, run export, zeroize" pattern. A worker-local helper would make zeroization and "no warm-session mutation" easier to audit.
9. Static guards must be scoped. A blanket "no `export_key` in the repo" would be wrong because server export routes, export worker ops, and export tests must still reference it. The guard should forbid `export_key` only in transaction signing files and `*ForSigning` APIs.

Plan improvements:

1. Split operation types before deleting guards:
   - transaction signing surfaces accept only `transaction_sign`
   - wallet unlock surfaces accept only `wallet_unlock` or omit operation entirely
   - sensitive-operation surfaces accept `export_key` and future link-device/add-signer operations
   - server route parsers expose action-specific parse functions
2. Split challenge route families by intent:
   - wallet unlock: login challenge/verify
   - transaction signing: transaction challenge/verify
   - sensitive operation: operation challenge/verify
   - restored signing-session sensitive operation: signing-session challenge/verify/unseal
3. Keep restored signing-session route authority for export challenge issuance after reload, but do not call it a signing challenge and do not pass it through transaction signing helpers.
4. Rename export grant and worker payload fields away from `loginGrant` where they are export-operation scoped.
5. Add static guards first, in "warning mode" as explicit failing tests after the implementation patch, so the cleanup cannot be skipped.
6. Delete temporary runtime rejection guards only after the type split and static guards prove export cannot reach those functions.
7. Treat Ed25519 export HSS as an allowed export-only HSS routine. It may use threshold route authority, but it must not mint, persist, consume, or replace a transaction signing session.
8. Preserve server-side export policy checks and audit events while moving route names or operation types. This refactor is plumbing cleanup, not a policy weakening.

## Implementation Plan

### Phase 1: Freeze The Generalized Model

1. [x] Persist only `E_session_s(signing_session_secret32)`; do not add an `E_session_s(S)` fallback.
2. [x] Make `walletSigningSessionId` part of `K = signing_session_secret32` derivation.
3. [x] Freeze Ed25519 restore semantics as worker-owned `ed25519_restore_seed32` plus threshold reconnect/bootstrap.
4. [x] Freeze restore strategy as all recorded curves first, optional lazy restore later.
5. [x] Freeze IndexedDB object store name, primary key, indexes, and one-active-record rule.
6. [x] Remove `thresholdSessionJwtRefs` from the target record shape.
7. [x] Freeze route/config names with no legacy aliases.
8. [x] Freeze byte-level HKDF inputs for passkey and Email OTP session secret derivation in shared code.
9. [x] Freeze the final `SealedSigningSessionRecord` schema in shared TypeScript types.
10. [x] Freeze invalidation semantics for TTL, remaining uses, account switch, lock, logout, and revocation.
11. [x] Freeze browser restart semantics with `runtimeSessionId`.
12. [x] Freeze multi-tab restore semantics with an IndexedDB lease.
13. [x] Close sealed refresh apply/remove budget semantics: transaction-use neutral and separately rate-limited.
14. [x] Convert suggested migration guards into concrete unit/static tests before the rename work starts.

### Phase 2: Generic Passkey Migration

1. [x] Rename `prfSessionSealedStore` to `signingSessionSealedStore`.
2. [x] Move storage from passkey-only `sessionStorage` adapter to iframe-origin IndexedDB.
3. [x] Rename `sealedPrfFirstB64u` to `sealedSecretB64u`.
4. [x] Rename PRF-specific worker messages to signing-session-secret messages.
5. [x] Rename PRF-specific server routes to signing-session-seal routes.
6. [x] Rename env/config from PRF seal names to signing-session seal names.
7. [x] Update passkey code to use the new auth-method-neutral store without behavior regression.
8. [x] Add passkey parity tests before removing old code.

### Phase 3: Remove PRF-Specific Legacy Surface

1. [x] Remove old PRF route aliases and duplicate types after migration.
2. [x] Remove PRF-specific worker message names.
3. [x] Remove `prfSessionSealedStore` file and imports.
4. [x] Remove `sealedPrfFirstB64u` from active records and tests.
5. [x] Add a static guard that fails if PRF-specific generic persistence names return.
6. [x] Update specs and env examples to use signing-session-seal names only.

### Phase 4: Add Email OTP Seal-On-Unlock

1. [x] After successful Email OTP `session` unlock, derive `signing_session_secret32` inside the Email OTP worker.
2. [x] Bootstrap or reconnect Ed25519 and ECDSA threshold sessions from that secret.
3. [x] Ask the worker to create a `shamir3pass` client lock for the signing-session secret.
4. [x] Call the signing-session seal apply route with threshold-session auth.
5. [x] Persist only the resulting `SealedSigningSessionRecord` in iframe-origin IndexedDB.
6. [x] Do not persist anything for `per_operation`.
7. [x] Do not persist anything for export or link-device/add-signer operation-scoped auth.
8. [x] Ensure the main thread never receives plaintext `S` or plaintext `signing_session_secret32`.

### Phase 5: Add Email OTP Rehydrate-On-Reload

1. [x] During wallet iframe startup, load active account and threshold-session metadata.
2. [x] If worker material is missing, look for a matching `SealedSigningSessionRecord`.
3. [x] Validate auth method, wallet id, user id, signing root, threshold session ids, TTL, and remaining uses.
4. [x] Ask the Email OTP worker to rehydrate from `sealedSecretB64u`.
5. [x] Worker applies a client lock and calls remove-server-seal with threshold-session auth.
6. [x] Worker recovers `signing_session_secret32`.
7. [x] Worker rebuilds Ed25519 signing material.
8. [x] Worker rebuilds ECDSA signing material and opaque handles.
9. [x] `WarmSessionManager` marks the wallet signing session ready only after both required signers are ready.
10. [x] If restore fails, delete the sealed record and route the user to normal Email OTP reauth.

### Phase 6: Shared Budget Enforcement

1. [x] Ensure restored Ed25519 and ECDSA capabilities reference the same `walletSigningSessionId`.
2. [x] Ensure both curves consume the same server-authoritative `remainingUses` counter.
3. [x] Update IndexedDB record `remainingUses` after each successful sign.
4. [x] Delete the record when `remainingUses` reaches zero.
5. [x] Delete the record when server reports expired, revoked, exhausted, or not found.
6. [x] Ensure export/link-device/add-signer auth does not consume or replace the transaction signing-session budget.

### Phase 7: UI Behavior

1. [x] On reload, show "Restoring signing session..." while sealed refresh is in flight.
2. [x] Disable transaction confirm until restored signer readiness is known.
3. [x] If restore succeeds, proceed without OTP prompt.
4. [x] If restore fails for an Email OTP account, show Email OTP prompt, not WebAuthn.
5. [x] If restore fails for a passkey account, show WebAuthn prompt.
6. [x] Do not show scary internal errors such as "threshold signingSession auth is unavailable" when a reauth path exists.

### Phase 8: Tests

1. [x] Unit test Email OTP sealed record schema validation.
2. [x] Unit test passkey sealed record schema validation after rename.
3. [x] Unit test `per_operation` never writes a sealed refresh record.
4. [x] Unit test export never writes or consumes a transaction sealed refresh record.
5. [x] Unit test link-device/add-signer never writes or consumes a transaction sealed refresh record.
6. [x] Unit test auth-method mismatch fails closed.
7. [x] Unit test signing-root mismatch fails closed.
8. [x] Unit test expired sealed records are deleted.
9. [x] Unit test exhausted sealed records are deleted.
10. [x] Unit test stolen sealed record without valid threshold-session auth cannot unseal.
11. [x] E2E: Email OTP login, reload, NEAR sign without another OTP.
12. [x] E2E: Email OTP login, reload, Tempo sign without another OTP.
13. [x] E2E: Email OTP login, reload, Arc sign without another OTP.
14. [x] E2E: passkey login, reload, NEAR and EVM behavior unchanged.
15. [x] E2E: Email OTP session exhaustion after reload prompts OTP in Tx Confirmer.
16. [x] E2E: passkey session exhaustion after reload prompts WebAuthn.
17. [x] E2E: Email OTP export after reload requires fresh OTP and does not clobber transaction signing session.
18. [x] Storage test: no plaintext `S`, plaintext `signing_session_secret32`, or enrollment escrow mirror appears in IndexedDB.
19. [x] Unit test browser restart marker loss deletes IndexedDB sealed records.
20. [x] Unit test multi-tab lease single-flights restore.
21. [x] Unit test route metadata mismatches fail closed against server-derived threshold-session state.
22. [x] Unit test apply/remove rate-limit status mapping.

### Phase 9: Remove App-Session JWT Continuity For Sensitive-Operation Challenges

Long-term target: after sealed refresh restores an Email OTP signing session, use restored signing-session authority to request a fresh sensitive-operation OTP challenge. Do not rely on a JS-readable `app_session_v1` JWT as the same-tab reload continuity primitive.

1. [x] Add server routes for requesting and verifying sensitive-operation OTP challenges with threshold-session auth:
   `/wallet/email-otp/signing-session/challenge`,
   `/wallet/email-otp/signing-session/verify`, and
   `/wallet/email-otp/signing-session/unseal`.
2. [x] Validate restored threshold-session claims and server auth-session status are complete, unexpired, not exhausted, and bound to the same user and `walletSigningSessionId` before challenge issuance. Keep this check budget-neutral; do not consume transaction signing use count while only requesting a fresh OTP challenge.
3. [x] Restrict the signing-session challenge lane to Email OTP enrollment state and `export_key`.
4. [x] Derive the challenge destination email only from server-side enrollment state.
5. [x] Reject account identifier mismatch and ignore client-supplied email destination.
6. [x] Ensure the route only sends a fresh OTP challenge and does not mint export/link-device/add-signer authorization by itself.
7. [x] Ensure OTP verification mints a short-lived operation-scoped grant for exactly `export_key`.
8. [x] Keep transaction signing `remainingUses` unchanged by challenge issuance and enforce separate challenge rate limits.
9. [x] Add audit events for signing-session-authorized sensitive-operation challenge requests without logging OTP codes, JWTs, ciphertexts, or secrets.
10. [x] Update the Email OTP coordinator to prefer signing-session-authorized challenge issuance after reload.
11. [x] Remove the same-tab `sessionStorage` app-session JWT cache after the new challenge path is covered by tests.
12. [x] Add tests proving restored signing-session authority cannot directly export keys or mint a general app session.
13. [x] Add tests proving passkey accounts continue to use WebAuthn/passkey fresh auth and cannot use the Email OTP challenge route.
14. [x] Add tests proving expired, mismatched, exhausted, and cross-wallet threshold sessions cannot request sensitive-operation OTP challenges.
15. [x] Add budget-neutral threshold auth-session status reads for the signing-session challenge, verify, and unseal routes. These checks validate both the curve session and wallet-signing budget without calling `consumeUseCount`.

### Phase 10: Enforce Server-Owned Email OTP Enrollment Identity

Remove login-time enrollment email repair from the normal flow. Session persistence should restore signing-session authority only; it must not compensate for incomplete Email OTP enrollment identity data.

1. [x] Make active Email OTP enrollment validation require the server-owned enrolled email.
2. [x] Ensure Email OTP enrollment verify is the only normal route that creates or updates the enrolled verified email.
3. [x] Remove login OTP verify behavior that fills missing enrollment email from the verified login challenge.
4. [x] Update login challenge issuance to fail closed with `reenrollment_required` when the active enrollment is missing a verified email.
5. [x] Update signing-session operation challenge issuance to fail closed with `reenrollment_required` when the active enrollment is missing a verified email.
6. [x] Ensure app-session email can validate enrollment selection but cannot overwrite the enrolled mailbox.
7. [x] Ensure signing-session-authorized challenges and app-session-authorized login challenges use one shared server-side enrollment email resolver.
8. [x] Add unit tests proving login OTP verify never mutates enrollment email.
9. [x] Add route tests proving missing verified enrollment email fails for login challenge and signing-session operation challenge.
10. [x] Add route tests proving client-supplied email and app-session email mismatch do not change the enrolled mailbox.
11. [x] Add a static or unit guard that forbids request-path "backfill", "repair", or "fill missing email" logic in Email OTP login verify handlers.
12. [x] For development data, document re-enrollment or local store reset as the cleanup path instead of keeping compatibility code.
13. [x] If production data ever needs migration, implement it as an explicit audited migration script that only writes a verified email from historical enrollment verification evidence, not from login challenges.
14. [x] Add a static guard that forbids backfill/fallback/legacy/compatibility terms in scoped Email OTP and signing-session persistence source surfaces.

### Phase 11: Independent Key Export Flow Simplification

Goal: make key export structurally independent from transaction signing-session lifecycle code. Export must be fresh-auth, operation-scoped, and session-mutation-free by type and by tests.

Implementation order:

1. [x] Add or update focused failing tests/guards that describe the desired export split.
2. [x] Split shared operation types and client signing dependency types.
3. [x] Split transaction challenge helpers from export challenge helpers.
4. [ ] Refactor server route parsing and operation-grant naming.
5. [ ] Refactor worker export recovery through a single export-only helper.
6. [x] Remove legacy guards, aliases, and dead code after all call sites compile.
7. [x] Run type checks and focused export/signing suites.

API and type split:

1. [x] Introduce a transaction-only operation type for signing-session login/bootstrap surfaces, limited to `transaction_sign`.
2. [x] Introduce a separate sensitive-operation type for operation auth surfaces, starting with `export_key` and leaving room for link-device/add-signer.
3. [x] Keep server-side `export_key` in the shared operation domain for export challenge, verify, and unseal routes.
4. [x] Replace `EmailOtpSigningOperation = WalletEmailOtpLoginOperation` with a transaction-only alias or remove the alias entirely.
5. [x] Remove `export_key` from `loginWithEmailOtpEd25519CapabilityForSigning` argument types.
6. [x] Remove `export_key` from `loginWithEmailOtpEcdsaCapabilityForSigning` argument types.
7. [x] Remove `export_key` from transaction challenge helper argument types.
8. [x] Remove `export_key` from NEAR signing dependency types in `nearSigning.ts`.
9. [x] Remove `export_key` from EVM/Tempo signing dependency types in `evmSigning.ts`.
10. [x] Remove `export_key` from orchestration dependency bundle signing APIs in `orchestrationDependencyFactory.ts`.
11. [ ] Narrow public/iframe Email OTP challenge types so wallet unlock APIs cannot request export challenges.
12. [ ] Add action-specific server parse helpers for unlock, transaction signing, and sensitive-operation Email OTP requests.
13. [x] Delete temporary runtime guards that reject export inside `*ForSigning` helpers once the type split makes those states unrepresentable.
14. [x] Add static guards proving no `*ForSigning` API, signing dependency type, or transaction signing adapter accepts `export_key`.

Naming cleanup:

1. [x] Rename `requestEmailOtpChallengeForSigning` to a transaction-specific name such as `requestEmailOtpTransactionChallenge`.
2. [ ] Rename transaction login helpers if needed so their names say transaction/session rather than generic Email OTP capability.
3. [x] Keep export challenge helpers named around export, for example `requestExportAuthorization` or `requestEmailOtpExportChallenge`.
4. [ ] Ensure link-device/add-signer future helpers use operation-auth names, not transaction-signing names.
5. [ ] Remove tests and fixtures that describe export as "signing bootstrap" or "signing challenge."
6. [ ] Rename app-session-authorized export routes away from the login route family if route churn is acceptable, for example to an explicit operation-auth route family.
7. [ ] Rename export OTP grants from `loginGrant` to an operation-scoped grant name such as `operationGrant` or `emailOtpOperationGrant`.
8. [ ] Rename Email OTP Ed25519 export fields that still say `PrfFirst` at generic boundaries, unless the value is truly passkey PRF material.

Email OTP export simplification:

1. [ ] Verify the call graph remains split before deleting the adapter: Email OTP account export enters the Email OTP coordinator; passkey account export enters `requestPasskeyExportAuthorization`.
2. [x] Simplify `requestExportAuthorization` so the Email OTP coordinator directly requests an export challenge and renders the Email OTP prompt, without a passkey adapter that only throws.
3. [x] Keep passkey export in the passkey export path; do not model passkey as a dead branch inside Email OTP export.
4. [ ] Ensure Email OTP export challenge issuance supports exactly the allowed route authorities:
   - fresh app-session or cookie authority during active login
   - restored signing-session authority after sealed refresh
5. [ ] Ensure Email OTP export verification returns a single-purpose export authorization, not a general app session and not a renewed signing session.
6. [ ] Ensure export challenge and verify routes resolve the destination mailbox only from the active server-owned Email OTP enrollment.
7. [ ] Ensure export challenge issuance remains transaction-use neutral and separately rate-limited.
8. [ ] Preserve server export policy checks and export audit events for both app-session and restored signing-session challenge lanes.
9. [x] Ensure export challenge resend uses the same export-only route helper and does not fall back to transaction challenge helpers.
10. [ ] Ensure cancelled export prompts do not call verify, unseal, consume, clear, or sealed-refresh cleanup paths.
11. [x] Add a regression test proving passkey account export still uses fresh WebAuthn/passkey auth after removing the Email OTP coordinator's dead passkey adapter.

Worker export primitive:

1. [ ] Add a worker-local helper such as `withRecoveredEmailOtpExportRootShare(...)`.
2. [ ] The helper must require `routePlan.operation === 'export_key'`.
3. [ ] The helper must call the Email OTP unseal path and recover root/export material in memory.
4. [ ] The helper must run a callback with the recovered bytes.
5. [ ] The helper must always zeroize recovered root/export material in `finally`.
6. [ ] The helper must not call warm-session put, claim, hydrate, seal, clear, or consume helpers.
7. [ ] Refactor Ed25519 export recovery to use this helper.
8. [ ] Refactor ECDSA export to use this helper.
9. [ ] Ensure worker payload responses contain only export artifacts or sanitized metadata, never root-share bytes.
10. [ ] Ensure the helper cannot be called by login, transaction signing, sealed-refresh apply/remove, or restore worker operations.
11. [ ] Add a worker unit/static guard proving export worker cases do not call warm-session lifecycle helpers.

Session-mutation removal:

1. [ ] Remove any export call path that calls `markThresholdEd25519EmailOtpSessionConsumedForAccount`.
2. [ ] Remove any export call path that calls `markThresholdEcdsaEmailOtpSessionConsumedForAccount`.
3. [ ] Remove any export call path that calls `clearWarmSessionMaterial`.
4. [ ] Remove any export call path that claims warm-session material.
5. [ ] Remove any export call path that temporarily overwrites a canonical threshold-session record and restores it later.
6. [ ] Remove any export call path that writes a sealed-refresh record.
7. [ ] Remove any export call path that updates `remainingUses`.
8. [ ] Remove old tests that assert session restoration after export; replace them with tests that assert no mutation occurs.

Legacy removal checklist after the refactor:

1. [x] Delete `EmailOtpSigningOperation = WalletEmailOtpLoginOperation`.
2. [x] Delete any `operation?: WalletEmailOtpLoginOperation` field from transaction-signing dependency types.
3. [ ] Delete any `operation?: WalletEmailOtpLoginOperation` field from wallet unlock public APIs if unlock no longer accepts a broad operation union.
4. [x] Delete `requestChallengeForSigning` after all callers use transaction-specific or export-specific helpers.
5. [x] Delete `requestEmailOtpChallengeForSigning` from `NearSigningApiDeps`, `EvmFamilySigningDeps`, and `OrchestrationDependencyFactoryArgs`.
6. [x] Delete `operation` forwarding from transaction challenge callers where the value is always `transaction_sign`.
7. [x] Delete export rejection guards inside `loginWithEmailOtpEd25519CapabilityForSigning` and `loginWithEmailOtpEcdsaCapabilityForSigning`.
8. [ ] Delete tests whose only purpose is to prove those runtime export rejection guards throw.
9. [x] Delete dead passkey throwing adapters from Email OTP export authorization code only after passkey account export coverage proves the separate passkey path is still active.
10. [ ] Delete any temporary `restoreOriginal*SessionRecord` helpers or tests if any remain.
11. [ ] Delete any export worker operation that exports from a warm session, including `exportThresholdEcdsaHssKeyFromEmailOtpWarmSession` if it returns.
12. [ ] Delete any `claimWarmSessionMaterial` usage from export tests and fixtures.
13. [ ] Delete any `clearWarmSessionMaterial` fixture from export tests unless the test asserts it is not called.
14. [ ] Delete any export fixture that mutates stored threshold-session records to simulate a refreshed export session.
15. [ ] Delete any export path that passes `remainingUses` into worker payloads.
16. [ ] Delete any export path that passes `sessionId` as a newly minted transaction session id.
17. [ ] Delete `loginGrant` naming from export-specific server responses, worker payloads, and client helper types after operation-grant naming lands.
18. [ ] Delete app-session continuity cache code or comments that imply export after reload depends on JS-readable app-session JWT persistence.
19. [ ] Delete route aliases or helper names that call app-session export a "login" operation after operation-auth routes are introduced.
20. [ ] Delete broad static guard exceptions that were needed only while export still crossed transaction signing files.
21. [ ] Delete obsolete docs that describe export as signing-session login, bootstrap, consume, or restore.
22. [x] Add permanent static guards for the deleted names above, scoped so legitimate server/export route references to `export_key` remain allowed.

Tests and guards:

1. [ ] Unit test Email OTP Ed25519 export shows fresh OTP and does not provision, hydrate, consume, clear, or rewrite the Ed25519 signing session.
2. [ ] Unit test Email OTP ECDSA export shows fresh OTP and does not provision, hydrate, consume, clear, or rewrite the ECDSA signing session.
3. [ ] Unit test export failure after OTP verification still leaves the original signing session record unchanged.
4. [ ] Unit test export viewer failure still leaves the original signing session record unchanged.
5. [ ] Unit test export after same-tab sealed refresh can request an OTP challenge using restored signing-session authority.
6. [ ] Unit test restored signing-session authority cannot directly authorize export without fresh OTP verification.
7. [ ] Unit test export challenge issuance does not decrement transaction `remainingUses`.
8. [ ] Unit test export OTP verification does not mint or renew transaction signing sessions.
9. [ ] Unit test passkey export always performs fresh WebAuthn/passkey auth and does not mutate warm-session state.
10. [x] Static guard: no `export_key` string appears in `nearSigning.ts`, `evmSigning.ts`, or orchestration signing dependency type definitions except in explicit negative tests.
11. [ ] Static guard: no export code imports or calls signing-session consume/clear helpers.
12. [ ] Static guard: no export code calls signing-session seal apply/remove helpers.
13. [ ] Static guard: no `loginGrant` naming appears in export-specific client or worker payloads after operation-grant rename.
14. [x] Static guard: no `requestChallengeForSigning` symbol remains after the transaction/export helper split.
15. [ ] Static guard: no `WalletEmailOtpLoginOperation` type appears in transaction signing adapter files.
16. [ ] Route test: app-session-authorized export challenge still enforces export policy and enrolled-email resolution after route renaming.
17. [ ] Route test: restored signing-session export challenge still enforces threshold-session status, export policy, and enrolled-email resolution.
18. [ ] Route test: transaction signing challenge route rejects `export_key`.
19. [ ] Route test: export operation route rejects `transaction_sign`.
20. [ ] E2E: Email OTP login -> Ed25519 sign -> Ed25519 export -> Ed25519 sign still works without losing the active signing session.
21. [ ] E2E: Email OTP login -> ECDSA sign -> ECDSA export -> ECDSA sign still works without losing the active signing session.
22. [ ] E2E: Email OTP login -> refresh -> Ed25519 export -> Ed25519 sign still works with the restored signing session.
23. [ ] E2E: Email OTP login -> refresh -> ECDSA export -> ECDSA sign still works with the restored signing session.
24. [ ] E2E: failed/cancelled export prompt does not consume transaction signing budget.

Cleanup and docs:

1. [ ] Update the policy matrix and auth rules after implementation so transaction signing, sealed refresh, and sensitive-operation auth are separate flows.
2. [ ] Remove any doc language implying export "logs into" or "bootstraps" a signing session.
3. [ ] Update developer docs to say key export is operation-auth plus one-off in-memory export recovery.
4. [ ] Update comments near worker export code explaining that export is intentionally not a warm-session lifecycle operation.
5. [ ] Re-run type checks and focused Email OTP export/signing suites.

### Phase 12: Wallet Signing-Session Budget Coordinator

Goal: remove lane-specific budget accounting from transaction orchestration and dependency plumbing. Ed25519 and ECDSA may have different threshold session ids and different backing worker storage, but if they share a `walletSigningSessionId`, they must report and consume through one user-visible wallet signing-session budget.

The current implementation has too much budget knowledge in call sites:

1. NEAR Ed25519 signing knows when to consume TouchConfirm warm-session material.
2. ECDSA post-sign policy knows when to consume TouchConfirm warm-session material.
3. Email OTP Ed25519 spend code searches for matching ECDSA records to consume Email OTP worker material.
4. `WarmSessionManager` maps Email OTP ECDSA worker status back into wallet-session status reads.

That shape works, but the concept is bigger than any one curve. Name it directly.

Target model:

```ts
type SigningSessionLane = {
  curve: 'ed25519' | 'ecdsa';
  chain?: 'near' | 'tempo' | 'evm';
  source: 'passkey' | 'email_otp';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  backingMaterialSessionId: string;
};

interface WalletSigningSessionCoordinator {
  getStatus(args: {
    nearAccountId: string;
    walletSigningSessionId?: string;
  }): Promise<SigningSessionStatus | null>;

  consumeUse(args: {
    nearAccountId: string;
    walletSigningSessionId: string;
    uses: number;
    reason: 'transaction_sign';
    alreadyConsumedBackingMaterialSessionIds?: string[];
    alreadyConsumedThresholdSessionIds?: string[];
  }): Promise<SigningSessionStatus>;

  clear(args: {
    nearAccountId: string;
    walletSigningSessionId: string;
  }): Promise<void>;
}
```

Transaction signing should reduce to:

```ts
await walletSigningSessionCoordinator.consumeUse({
  nearAccountId,
  walletSigningSessionId,
  uses: usesNeeded,
  reason: 'transaction_sign',
});
```

The transaction flow should not know whether the consumed lane is:

1. Ed25519 passkey `PRF.first` cached in the TouchConfirm worker
2. Ed25519 Email OTP restored client-base material cached in the TouchConfirm worker
3. ECDSA passkey material cached in the TouchConfirm worker
4. ECDSA Email OTP worker material behind `clientAdditiveShareHandle.sessionId`
5. sealed-refresh restored material

Recommended placement:

1. Add `client/src/core/signingEngine/session/WalletSigningSessionCoordinator.ts`.
2. Keep `WarmSessionManager` focused on capability resolution, status derivation, provisioning, restore, and sealed-refresh lifecycle.
3. Keep budget consumption and clearing in the new coordinator.
4. Add worker-specific lane adapters instead of hard-coding worker details in transaction flows:
   - `TouchConfirmWarmSessionLane`
   - `EmailOtpWorkerWarmSessionLane`

Core invariant:

```text
If two lanes share walletSigningSessionId, they share one user-visible remaining-use budget.
```

Implementation checklist:

1. [x] Add `SigningSessionLane` and `WalletSigningSessionCoordinator` types under `client/src/core/signingEngine/session/WalletSigningSessionCoordinator.ts`.
2. [x] Add lane discovery from canonical Ed25519 and ECDSA session records for a given `nearAccountId`.
3. [x] Normalize each lane to `{ thresholdSessionId, walletSigningSessionId, backingMaterialSessionId }`.
4. [x] Map Ed25519 passkey lanes to TouchConfirm worker `thresholdSessionId`.
5. [x] Map Ed25519 Email OTP lanes to TouchConfirm worker `thresholdSessionId` and stored Ed25519 threshold record metadata.
6. [x] Map ECDSA passkey lanes to TouchConfirm worker `thresholdSessionId`.
7. [x] Map ECDSA Email OTP lanes to Email OTP worker `clientAdditiveShareHandle.sessionId`.
8. [x] Ensure sealed-refresh restored lanes use the same mapping after worker material is rehydrated.
9. [x] Implement `getStatus` by grouping lanes by `walletSigningSessionId` and returning the minimum active `remainingUses` and earliest active expiry across the group.
10. [x] Implement `consumeUse` so it records one logical wallet-session spend and mirrors that spend across backing lanes unless a lane already consumed its backing material during signing.
11. [x] Ensure `consumeUse` never consumes export, link-device, add-signer, challenge issuance, verify, unseal, apply-server-seal, or remove-server-seal operations.
12. [x] Implement `clear` so account lock/logout/account switch can clear all backing material and stored threshold records for the wallet signing-session group.
13. [x] Move `recordEmailOtpWarmSessionUse` out of `orchestrationDependencyFactory.ts` into the coordinator.
14. [x] Move Email OTP worker-status read mapping out of `WarmSessionManager` into reusable lane adapters.
15. [x] Update NEAR transaction signing to call `walletSigningSessionCoordinator.consumeUse(...)` after successful signing.
16. [x] Update ECDSA post-sign policy to call `walletSigningSessionCoordinator.consumeUse(...)` after successful signing.
17. [x] Update wallet-session UI status reads to call the same coordinator status path used by post-sign consumption.
18. [x] Remove direct transaction-flow calls to `touchConfirm.consumeWarmSessionUses`.
19. [x] Remove direct ECDSA post-sign calls to `touchConfirm.consumeWarmSessionUses`.
20. [x] Remove Ed25519 spend code that searches for matching ECDSA records from `orchestrationDependencyFactory.ts`.
21. [x] Keep `WarmSessionManager` as a dependency of the coordinator only where capability/status data is needed; do not fold budget side effects back into `WarmSessionManager`.
22. [x] Add a focused unit test: Ed25519 and ECDSA Email OTP lanes with the same `walletSigningSessionId` report one shared remaining-use budget.
23. [x] Add a focused unit test: consuming an Ed25519 Email OTP transaction decrements the shared wallet budget exactly once.
24. [x] Add a focused unit test: consuming an ECDSA Email OTP transaction decrements the same shared wallet budget exactly once.
25. [x] Add a focused unit test: passkey Ed25519 and passkey ECDSA lane consumption updates the same coordinator status path used by the UI.
26. [x] Add a guard test that transaction signing code does not import worker-specific warm-session consume helpers directly.
27. [x] Add a guard test that export code cannot call `WalletSigningSessionCoordinator.consumeUse`.
28. [x] Update docs to describe `remainingUses` as the wallet signing-session budget and clarify whether NEAR batches consume per threshold signature or per user-visible operation.
29. [x] Run SDK typecheck, relay-server typecheck, SDK build, and focused warm-session/Email OTP signing tests.

`remainingUses` is now treated as the wallet signing-session budget. NEAR transaction batches consume one wallet-session use per user-visible signing operation, even when that operation signs multiple NEAR transactions. This keeps Ed25519 and ECDSA behavior aligned: one confirmation modal plus one fresh auth prompt maps to one wallet-session budget spend.

## OTP Session Architecture Hardening TODO

These TODOs address the five architectural issues that caused the Email OTP session regressions. The target state is that Ed25519 and ECDSA use the same auth-routing shape, the same session-source lane rules, and the same wallet signing-session budget model.

This is lane-scoped, not account-global. Future accounts may have both Email OTP and passkey signing abilities. The transaction flow must first select the intended signing lane, then all readiness, reauth, key-ref, and budget work must stay on that lane. An exhausted Email OTP lane prompts OTP; an exhausted passkey lane prompts passkey. Neither lane silently falls back to the other.

For dual-auth accounts, `primaryAuthMethod` in the signing flow means the selected auth method for this operation, not the only auth method linked to the account. ECDSA selection must read Email OTP and passkey lanes through source-scoped helpers and must not use a source-less “account/chain ECDSA session” fallback to decide between them.

1. [x] Make ECDSA follow the Ed25519 transaction auth flow.
   - Ed25519 already has the right shape: the signer path owns session readiness, catches `fresh_email_otp_required`, and turns it into an OTP confirmation flow.
   - ECDSA must stop carrying a parallel auth planner that can independently choose passkey, warm session, or Email OTP.
   - Refactor ECDSA so `SigningEngine.signTempo` and raw EVM signing resolve auth through the same transaction confirmation boundary as Ed25519.
   - Acceptance check: an exhausted Email OTP ECDSA transaction opens the tx confirmer with Email OTP, succeeds, and the next ECDSA transaction repeats that same flow instead of surfacing passkey or a pre-thrown freshness error.

2. [x] Make `source: email_otp` mandatory for Email OTP ECDSA session reads.
   - ECDSA code must never ask for “the ECDSA session for this account/chain” when it is operating on an Email OTP account.
   - Add typed helpers for Email OTP ECDSA reads, writes, clears, key-ref resolution, and readiness checks that require `source: email_otp`.
   - Remove generic ECDSA fallbacks from Email OTP paths instead of preserving compatibility branches.
   - Acceptance check: an Email OTP account with an exhausted or missing Email OTP ECDSA session cannot drift into a passkey ECDSA lane.

3. [x] Remove implicit pre-sign ECDSA bootstrap/readiness prompts.
   - Transaction preparation must not touch WebAuthn or bootstrap ECDSA material before the tx confirmer owns the flow.
   - Demo hooks and SDK helper paths may read already-known public addresses, but they must not call readiness/bootstrap APIs that can prompt.
   - Signing material bootstrap must happen inside the signer flow after the confirmation modal is established and after the selected auth method is known.
   - Acceptance check: there is no standalone passkey prompt before the tx confirmer for Email OTP ECDSA, and passkey accounts still prompt only after the tx confirmer approval step.

4. [x] Keep `SigningEngine` as the single ECDSA policy owner.
   - `TempoSigner.signTempo` and other public wrappers must be thin routing layers only.
   - Remove wrapper-side single-use Email OTP maps, preflight policy checks, post-sign policy checks, and freshness throws.
   - The signer flow must be the only place that turns exhausted session state into fresh auth UI.
   - Acceptance check: wrapper code cannot throw `fresh_email_otp_required` before `SigningEngine` has a chance to convert it into an OTP confirmation flow.

5. [x] Collapse session budget accounting to one wallet signing-session model.
   - Threshold session records, wallet signing-session budget, per-operation Email OTP state, source lanes, and chain lanes must stay distinct in type names and APIs.
   - `WalletSigningSessionCoordinator` should be the only transaction path that consumes user-visible `remainingUses`.
   - Ed25519 and ECDSA session records should expose lane metadata to the coordinator; transaction flows should not reach into worker-specific budget helpers.
   - Fix any code that asks an Ed25519 canonical record to account for ECDSA spend, or an ECDSA record to account for Ed25519 spend.
   - Acceptance check: one successful user-visible transaction consumes exactly one wallet signing-session use, regardless of whether the backing lane is Ed25519, ECDSA, passkey, Email OTP, restored, or freshly reauthorized.

Permanent guardrails:

1. [x] Add static guards that ECDSA Email OTP transaction paths always pass `source: email_otp` when resolving ECDSA session records or key refs.
2. [x] Add static guards that public chain signer wrappers do not import Email OTP policy helpers, session-consumption helpers, or `WarmSessionManager` policy methods.
3. [x] Add integration coverage for these flows:
   - Email OTP ECDSA with remaining uses signs without OTP/passkey prompt.
   - exhausted Email OTP ECDSA prompts OTP and succeeds.
   - the next exhausted Email OTP ECDSA transaction prompts OTP again and succeeds.
   - passkey ECDSA retains passkey behavior after exhaustion.
   - Ed25519 and ECDSA sharing one `walletSigningSessionId` report and consume the same user-visible budget.

## Acceptance Criteria

1. Email OTP `session` policy survives accidental page refresh without a new OTP while the server budget remains valid.
2. Email OTP `per_operation` never survives refresh.
3. Passkey sealed refresh behavior is unchanged except for generalized naming.
4. Ed25519 and ECDSA restored sessions share one `walletSigningSessionId`.
5. Export and link-device/add-signer still require fresh auth and do not clobber the transaction signing session.
6. No plaintext `S` is persisted.
7. No plaintext `signing_session_secret32` is persisted.
8. No long-lived enrollment escrow mirror is persisted client-side.
9. Server-side TTL, remaining uses, revocation, and signing-root checks are authoritative.
10. No PRF-only sealed-refresh APIs remain after the migration.
11. Sealed refresh apply/remove does not consume transaction signing `remainingUses` and is enforced by separate rate limits.
12. Active Email OTP enrollments always have a server-owned verified email, and login OTP verify never repairs enrollment identity as a request-path side effect.
13. Key export OTP/passkey prompts are independent of transaction signing sessions and cannot mutate or consume signing-session state.
14. No transaction signing API or dependency type accepts `export_key` after the independent export refactor.

## Static Guard

`tests/unit/signingSessionSealedRefresh.noPrfSurface.guard.unit.test.ts` is now a permanent migration guard after Phase 3.

The guard should fail if these PRF-specific names survive in steady-state generic sealed-refresh boundaries:

1. `prfSessionSealedStore`
2. `sealedPrfFirstB64u`
3. `/threshold-ecdsa/prf-seal/`
4. user-facing "PRF session seal" text
5. generic worker messages named around `PRF_FIRST`

Allowed exceptions:

1. historical docs that explicitly describe the old implementation
2. migration notes in this plan
3. tests that assert the legacy names are absent
